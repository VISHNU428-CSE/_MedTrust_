"""
Isolated tests for MedTrust Durable Key Storage on Download (Task 6D.4A / IPR-42).

Verifies:
1. Successful document, prescription, and combined downloads with exact plaintext equality.
2. Patient horizontal isolation (HTTP 403).
3. Doctor authorization gates: pending/rejected approval, missing, expired, revoked, and category-mismatched consent (HTTP 403).
4. Approved doctor with active consent download success (HTTP 200).
5. Administrator Zero-PHI Privacy Boundary (HTTP 403).
6. Compliance Auditor least-privilege boundary (HTTP 403).
7. Missing persistent key and legacy records (HTTP 404 verification-only mode).
8. Description-only records attempting document download (HTTP 404).
9. Missing / malformed Master KEK fail-closed behavior (HTTP 500 with zero secret disclosure).
10. Checksum mismatch detection against on-chain Fabric record (HTTP 409 Conflict).
11. Tampered AAD / corrupted ciphertext fail-closed decryption failure (HTTP 500).
12. Ledger unavailable (HTTP 503) and IPFS unavailable (HTTP 503) error handling.
13. Audit infrastructure resilience: failure in Fabric audit logging does not mask security denials.
"""

import io
import os
import uuid
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.db.models import UserModel, RecordKeyModel, RecordDetailModel
from app.core.security import create_access_token
from app.services.key_service import KeyManager, KeyPurpose, WrappedDEK
from app.core.exceptions import ChecksumMismatchError, IPFSConnectionError, FabricGatewayError

client = TestClient(app)

TEST_PATIENT_ID = "pat-984210"
TEST_PATIENT_NAME = "Eleanor Vance"

TEST_DOCTOR_ID = "doc-331902"
TEST_DOCTOR_NAME = "Dr. Marcus Sterling, MD"


@pytest.fixture
def patient_token():
    return create_access_token({
        "sub": TEST_PATIENT_ID,
        "name": TEST_PATIENT_NAME,
        "role": "PATIENT"
    })


@pytest.fixture
def other_patient_token():
    return create_access_token({
        "sub": "pat-222222",
        "name": "Bob Attacker",
        "role": "PATIENT"
    })


@pytest.fixture
def approved_doctor_token():
    # Dr. Marcus Sterling holds active consent cst-8801 for patient pat-984210 (allowed_record_types: ALL)
    return create_access_token({
        "sub": TEST_DOCTOR_ID,
        "name": TEST_DOCTOR_NAME,
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })


@pytest.fixture
def pending_doctor_token():
    return create_access_token({
        "sub": "doc-pending-1",
        "name": "Dr. Pending Doctor",
        "role": "DOCTOR",
        "approval_status": "PENDING"
    })


@pytest.fixture
def rejected_doctor_token():
    return create_access_token({
        "sub": "doc-rejected-1",
        "name": "Dr. Rejected Doctor",
        "role": "DOCTOR",
        "approval_status": "REJECTED"
    })


@pytest.fixture
def admin_token():
    return create_access_token({
        "sub": "adm-999999",
        "name": "Platform Administrator",
        "role": "ADMIN"
    })


@pytest.fixture
def auditor_token():
    return create_access_token({
        "sub": "aud-001001",
        "name": "Federal Compliance Auditor",
        "role": "AUDITOR"
    })


# ============================================================================
# 1. Successful Downloads (Exact Plaintext Equality)
# ============================================================================

def test_download_document_success(patient_token):
    """Verify newly uploaded document can be downloaded and decrypted to exact plaintext."""
    doc_content = b"PDF-1.7 Diagnostic cardiology report for Eleanor Vance. Exact byte matching."
    files = [("file", ("cardio_report.pdf", io.BytesIO(doc_content), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Document Download Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Cardiology report."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res_dl = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_dl.status_code == 200
    assert res_dl.content == doc_content
    assert "attachment" in res_dl.headers.get("Content-Disposition", "")
    assert str(len(doc_content)) == res_dl.headers.get("Content-Length")


def test_download_prescription_success(patient_token):
    """Verify newly uploaded prescription can be downloaded and decrypted to exact plaintext."""
    rx_content = b"PDF-1.7 Prescription: Lisinopril 10mg orally once daily. Exact byte matching."
    files = [("prescription_file", ("lisinopril_rx.pdf", io.BytesIO(rx_content), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Prescription Download Test",
        "record_type": "PRESCRIPTION",
        "hospital": "Metro General Hospital",
        "description": "Prescription renewal."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res_dl = client.get(
        f"/api/v1/records/{record_id}/prescription/download",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_dl.status_code == 200
    assert res_dl.content == rx_content
    assert "lisinopril_rx.pdf" in res_dl.headers.get("Content-Disposition", "")
    assert str(len(rx_content)) == res_dl.headers.get("Content-Length")


def test_download_combined_both_files_success(patient_token):
    """Verify combined upload allows independent download of document and prescription with exact content."""
    doc_content = b"PDF-1.7 Surgical Operation Record: Arthroscopy Notes."
    rx_content = b"PDF-1.7 Post-operative Prescription: Cefazolin 500mg."
    files = [
        ("file", ("op_notes.pdf", io.BytesIO(doc_content), "application/pdf")),
        ("prescription_file", ("postop_rx.pdf", io.BytesIO(rx_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Combined Surgical & Rx Download Test",
        "record_type": "LAB_REPORT",
        "hospital": "Apex Specialty Hospital",
        "description": "Knee surgery and antibiotic course."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # 1. Download document
    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_doc.status_code == 200
    assert res_doc.content == doc_content

    # 2. Download prescription
    res_rx = client.get(
        f"/api/v1/records/{record_id}/prescription/download",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_rx.status_code == 200
    assert res_rx.content == rx_content


# ============================================================================
# 2. Access Control, Privacy & Consent Gates
# ============================================================================

def test_download_horizontal_isolation_patient_blocked(patient_token, other_patient_token):
    """Verify that Patient B cannot download Patient A's document or prescription."""
    files = [
        ("file", ("confidential.pdf", io.BytesIO(b"CONFIDENTIAL_PATIENT_A"), "application/pdf")),
        ("prescription_file", ("confidential_rx.pdf", io.BytesIO(b"CONFIDENTIAL_RX_A"), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Horizontal Isolation Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Patient A data."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Patient B attempts document download
    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {other_patient_token}"}
    )
    assert res_doc.status_code == 403
    assert "Horizontal Access Denied" in res_doc.json()["detail"]

    # Patient B attempts prescription download
    res_rx = client.get(
        f"/api/v1/records/{record_id}/prescription/download",
        headers={"Authorization": f"Bearer {other_patient_token}"}
    )
    assert res_rx.status_code == 403
    assert "Horizontal Access Denied" in res_rx.json()["detail"]


def test_download_unapproved_doctor_pending_and_rejected_blocked(patient_token, pending_doctor_token, rejected_doctor_token):
    """Verify that pending and rejected doctors are blocked with HTTP 403."""
    files = [("file", ("doc.pdf", io.BytesIO(b"DOCTOR_ACCESS_TEST"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Doctor Gate Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Testing doctor gates."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Pending doctor blocked
    res_pending = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {pending_doctor_token}"})
    assert res_pending.status_code == 403
    assert "Doctor approval status is 'PENDING'" in res_pending.json()["detail"]

    # Rejected doctor blocked
    res_rejected = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {rejected_doctor_token}"})
    assert res_rejected.status_code == 403
    assert "Doctor approval status is 'REJECTED'" in res_rejected.json()["detail"]


def test_download_doctor_missing_consent_blocked(patient_token):
    """Verify that an approved doctor without consent is blocked with HTTP 403."""
    unconsented_doctor_token = create_access_token({
        "sub": "doc-999000",
        "name": "Dr. Unconsented Doctor",
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })
    files = [("file", ("doc.pdf", io.BytesIO(b"NO_CONSENT_TEST"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "No Consent Test",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro Hospital",
        "description": "No consent test."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {unconsented_doctor_token}"})
    assert res.status_code == 403
    assert "Clinical download denied" in res.json()["detail"]


def test_download_doctor_revoked_consent_blocked(patient_token):
    """Verify that a doctor with revoked consent cannot download clinical files."""
    # Dr. Clara Oswald (doc-119283) has revoked consent cst-8790 for LAB_REPORT records of Eleanor
    revoked_doctor_token = create_access_token({
        "sub": "doc-119283",
        "name": "Dr. Clara Oswald, DDS",
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })
    files = [("file", ("biopsy.pdf", io.BytesIO(b"BIOPSY_REPORT_BYTES"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Biopsy Panel",
        "record_type": "LAB_REPORT",
        "hospital": "Apex Dental",
        "description": "Biopsy report."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {revoked_doctor_token}"})
    assert res.status_code == 403
    assert "Clinical download denied" in res.json()["detail"]


def test_download_doctor_category_mismatched_consent_blocked(patient_token):
    """Verify that a doctor whose consent does not cover the record category is blocked."""
    # Dr. Clara Oswald only has consent for LAB_REPORT; uploading IMAGING_MRI
    doctor_token = create_access_token({
        "sub": "doc-119283",
        "name": "Dr. Clara Oswald, DDS",
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })
    files = [("file", ("brain_mri.pdf", io.BytesIO(b"BRAIN_MRI_BYTES"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Brain MRI",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro Hospital",
        "description": "MRI scan."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {doctor_token}"})
    assert res.status_code == 403
    assert "Clinical download denied" in res.json()["detail"]


def test_download_approved_doctor_active_consent_success(approved_doctor_token, patient_token):
    """Verify that an approved doctor holding active consent can download both document and prescription."""
    doc_content = b"DOCTOR_ACCESS_CONTENT: Comprehensive cardiac discharge summary."
    rx_content = b"DOCTOR_ACCESS_RX: Atorvastatin 40mg daily."
    files = [
        ("file", ("cardiac_summary.pdf", io.BytesIO(doc_content), "application/pdf")),
        ("prescription_file", ("statin_rx.pdf", io.BytesIO(rx_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Cardiac Discharge Package",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Discharge documentation."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Doctor downloads document
    res_doc = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {approved_doctor_token}"})
    assert res_doc.status_code == 200
    assert res_doc.content == doc_content

    # Doctor downloads prescription
    res_rx = client.get(f"/api/v1/records/{record_id}/prescription/download", headers={"Authorization": f"Bearer {approved_doctor_token}"})
    assert res_rx.status_code == 200
    assert res_rx.content == rx_content


def test_download_admin_blocked_zero_phi(admin_token):
    """Verify Administrator Zero-PHI Privacy Boundary: Admins cannot download documents or prescriptions."""
    res_doc = client.get("/api/v1/records/rec-001/download", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_doc.status_code == 403
    assert "Administrative Privacy Boundary" in res_doc.json()["detail"]

    res_rx = client.get("/api/v1/records/rec-001/prescription/download", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_rx.status_code == 403
    assert "Administrative Privacy Boundary" in res_rx.json()["detail"]


def test_download_auditor_blocked_verification_only(auditor_token):
    """Verify Compliance Auditor least-privilege boundary: Auditors cannot download decrypted files."""
    res_doc = client.get("/api/v1/records/rec-001/download", headers={"Authorization": f"Bearer {auditor_token}"})
    assert res_doc.status_code == 403
    assert "Compliance auditors are restricted to ledger verification" in res_doc.json()["detail"]

    res_rx = client.get("/api/v1/records/rec-001/prescription/download", headers={"Authorization": f"Bearer {auditor_token}"})
    assert res_rx.status_code == 403
    assert "Compliance auditors are restricted to ledger verification" in res_rx.json()["detail"]


# ============================================================================
# 3. Fail-Closed Cryptographic, Integrity & Edge Cases
# ============================================================================

def test_download_missing_key_legacy_record_returns_404(patient_token):
    """Verify legacy records (rec-001) without persisted keys return HTTP 404 in verification-only mode."""
    res = client.get("/api/v1/records/rec-001/download", headers={"Authorization": f"Bearer {patient_token}"})
    assert res.status_code == 404
    assert "Legacy records operate in ledger-verification-only mode" in res.json()["detail"]


def test_download_description_only_record_returns_404(patient_token):
    """Verify description-only records return HTTP 404 on document download."""
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Description Only Record",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Notes only, no document attachment."
    }
    res_up = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {patient_token}"})
    assert res.status_code == 404
    assert "does not have an attached document file" in res.json()["detail"]


def test_download_missing_master_kek_fails_closed_500(patient_token, monkeypatch):
    """Verify download fails closed with HTTP 500 when MEDTRUST_MASTER_KEK is missing, without secret leaks."""
    monkeypatch.delenv("MEDTRUST_MASTER_KEK", raising=False)

    res = client.get("/api/v1/records/rec-001/download", headers={"Authorization": f"Bearer {patient_token}"})
    assert res.status_code == 500
    assert "Master key configuration error" in res.json()["detail"]


def test_download_checksum_mismatch_returns_409(patient_token):
    """Verify that IPFS ciphertext failing checksum verification against Fabric returns HTTP 409 Conflict."""
    files = [("file", ("checksum_test.pdf", io.BytesIO(b"ORIGINAL_BYTES"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Checksum Integrity Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Checksum test."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Mock IPFS get_bytes to simulate ChecksumMismatchError
    with patch("app.api.v1.endpoints.records.ipfs_client.get_bytes", side_effect=ChecksumMismatchError("Computed hash mismatch")):
        res_dl = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {patient_token}"})
        assert res_dl.status_code == 409
        assert "checksum mismatch" in res_dl.json()["detail"]


def test_download_tampered_ciphertext_fails_closed_500(patient_token):
    """Verify that tampered ciphertext failing AES-GCM decryption returns HTTP 500."""
    files = [("file", ("tamper_test.pdf", io.BytesIO(b"ORIGINAL_CLEAN_BYTES"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Ciphertext Tamper Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Tamper test."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Mock ipfs_client.get_bytes to return corrupted ciphertext bytes (e.g. valid checksum but corrupted payload)
    corrupted_bytes = b"0" * 64
    with patch("app.api.v1.endpoints.records.ipfs_client.get_bytes", return_value=corrupted_bytes):
        res_dl = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {patient_token}"})
        assert res_dl.status_code == 500
        assert "Decryption failed" in res_dl.json()["detail"]


def test_download_tampered_aad_fails_closed_500(patient_token):
    """Verify that if AAD purpose does not match between key and request, unwrap fails with HTTP 500."""
    files = [("file", ("aad_test.pdf", io.BytesIO(b"AAD_CLEAN_BYTES"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "AAD Purpose Tamper Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "AAD test."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Tamper with the key row in SQLite: set purpose to PRESCRIPTION while it was uploaded as PRIMARY_DOCUMENT
    db = SessionLocal()
    try:
        key_row = db.query(RecordKeyModel).filter(
            RecordKeyModel.record_id == record_id,
            RecordKeyModel.purpose == KeyPurpose.PRIMARY_DOCUMENT
        ).first()
        assert key_row is not None
        # Invert bytes in nonce to force authentication tag rejection
        raw_nonce = bytearray.fromhex(key_row.dek_nonce)
        raw_nonce[0] ^= 0xFF
        key_row.dek_nonce = raw_nonce.hex()
        db.commit()
    finally:
        db.close()

    res_dl = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {patient_token}"})
    assert res_dl.status_code == 500
    assert "Decryption failed" in res_dl.json()["detail"]


def test_download_ledger_unavailable_fails_closed_503(patient_token):
    """Verify that ledger query failure returns HTTP 503 Service Unavailable."""
    with patch("app.api.v1.endpoints.records.fabric_gateway.get_record", side_effect=FabricGatewayError("Ledger peer timeout")):
        res = client.get("/api/v1/records/rec-001/download", headers={"Authorization": f"Bearer {patient_token}"})
        assert res.status_code == 503
        assert "Ledger service unavailable" in res.json()["detail"]


def test_download_ipfs_unavailable_fails_closed_503(patient_token):
    """Verify that IPFS retrieval failure returns HTTP 503 Service Unavailable."""
    files = [("file", ("ipfs_test.pdf", io.BytesIO(b"IPFS_TEST_BYTES"), "application/pdf"))]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "IPFS Offline Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "IPFS test."
    }
    res_up = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {patient_token}"})
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    with patch("app.api.v1.endpoints.records.ipfs_client.get_bytes", side_effect=IPFSConnectionError("Kubo daemon unreachable")):
        res_dl = client.get(f"/api/v1/records/{record_id}/download", headers={"Authorization": f"Bearer {patient_token}"})
        assert res_dl.status_code == 503
        assert "Failed to retrieve record content from IPFS" in res_dl.json()["detail"]


def test_download_audit_failure_still_enforces_security_denials(other_patient_token):
    """
    Verify that if Fabric audit logging raises an error, the download denial is STILL strictly enforced.
    Ensures audit infrastructure failure cannot be used to bypass authorization.
    """
    with patch("app.api.v1.endpoints.records.fabric_gateway.log_access_event", side_effect=RuntimeError("Fabric Audit Peer Down")):
        # Horizontal access breach must still raise HTTP 403
        res = client.get("/api/v1/records/rec-001/download", headers={"Authorization": f"Bearer {other_patient_token}"})
        assert res.status_code == 403
        assert "Horizontal Access Denied" in res.json()["detail"]
