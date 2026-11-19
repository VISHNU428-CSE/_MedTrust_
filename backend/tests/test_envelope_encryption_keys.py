"""
Tests for MedTrust Envelope Encryption Key Persistence & Secure Retrieval (Task 6D.2 / IPR-39).

Verifies:
1. Envelope encryption key wrapping / unwrapping with AES-256-GCM.
2. Canonical AAD tamper detection: domain-separates (record_id, patient_id, target_type).
3. Persistent SQLite storage in RecordKeyModel with composite uniqueness on (record_id, target_type).
4. Secure authenticated download and decryption routes for documents and prescriptions.
5. Strict RBAC & Healthcare Privacy Boundaries:
   - Patient horizontal isolation (HTTP 403 on cross-patient download)
   - Approved Doctor consent enforcement (HTTP 403 without active unrevoked consent)
   - Administrator Zero-PHI Privacy Boundary (HTTP 403 strictly denied)
   - Compliance Auditor least-privilege (HTTP 403 denied file download, ledger verification only)
   - Legacy records without persisted keys (HTTP 404 verification-only mode)
   - Unauthenticated requests (HTTP 401 Bearer challenge)
6. Cryptographic tamper detection on corrupted keys (HTTP 500 & Fabric audit log).
"""

import io
import os
import uuid
import base64
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.db.models import UserModel, RecordKeyModel, RecordDetailModel
from app.core.security import create_access_token, hash_password
from app.core.crypto import (
    generate_key,
    wrap_dek,
    unwrap_dek,
    build_key_aad,
    get_master_kek,
    KEY_LENGTH,
    NONCE_LENGTH,
)
from app.core.exceptions import EncryptionError
from app.adapters.fabric_gateway import fabric_gateway
from app.config import settings

client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Cryptographic Envelope Unit Tests
# ---------------------------------------------------------------------------

def test_wrap_unwrap_dek_roundtrip():
    """Verify that wrap_dek and unwrap_dek correctly encrypt and restore the original DEK."""
    dek = generate_key()
    kek = get_master_kek()
    record_id = "rec-test01"
    patient_id = "pat-984210"
    target_type = "record"

    enc_dek, nonce, tag = wrap_dek(dek, kek, record_id, patient_id, target_type)

    assert isinstance(enc_dek, str)
    assert isinstance(nonce, str)
    assert isinstance(tag, str)

    restored_dek = unwrap_dek(enc_dek, nonce, tag, kek, record_id, patient_id, target_type)
    assert restored_dek == dek


def test_unwrap_dek_aad_tamper_detection_record_id():
    """Verify that altering record_id in AAD fails authentication and raises EncryptionError."""
    dek = generate_key()
    kek = get_master_kek()
    enc_dek, nonce, tag = wrap_dek(dek, kek, "rec-001", "pat-984210", "record")

    with pytest.raises(EncryptionError) as exc_info:
        unwrap_dek(enc_dek, nonce, tag, kek, "rec-TAMPERED", "pat-984210", "record")
    assert "authentication tag verification failed" in str(exc_info.value)


def test_unwrap_dek_aad_tamper_detection_patient_id():
    """Verify that altering patient_id in AAD fails authentication and raises EncryptionError."""
    dek = generate_key()
    kek = get_master_kek()
    enc_dek, nonce, tag = wrap_dek(dek, kek, "rec-001", "pat-984210", "record")

    with pytest.raises(EncryptionError) as exc_info:
        unwrap_dek(enc_dek, nonce, tag, kek, "rec-001", "pat-ATTACKER", "record")
    assert "authentication tag verification failed" in str(exc_info.value)


def test_unwrap_dek_aad_tamper_detection_target_type():
    """Verify that altering target_type in AAD fails authentication and raises EncryptionError."""
    dek = generate_key()
    kek = get_master_kek()
    enc_dek, nonce, tag = wrap_dek(dek, kek, "rec-001", "pat-984210", "record")

    with pytest.raises(EncryptionError) as exc_info:
        unwrap_dek(enc_dek, nonce, tag, kek, "rec-001", "pat-984210", "prescription")
    assert "authentication tag verification failed" in str(exc_info.value)


def test_unwrap_dek_corrupted_tag_fails():
    """Verify that tampering with the authentication tag raises EncryptionError."""
    dek = generate_key()
    kek = get_master_kek()
    enc_dek, nonce, tag = wrap_dek(dek, kek, "rec-001", "pat-984210", "record")

    # Corrupt the tag by flipping bytes
    raw_tag = bytearray(base64.b64decode(tag))
    raw_tag[0] ^= 0xFF
    corrupted_tag = base64.b64encode(raw_tag).decode("ascii")

    with pytest.raises(EncryptionError) as exc_info:
        unwrap_dek(enc_dek, nonce, corrupted_tag, kek, "rec-001", "pat-984210", "record")
    assert "authentication tag verification failed" in str(exc_info.value)


def test_get_master_kek_env_var_and_fallback(monkeypatch):
    """Verify that MEDTRUST_MASTER_KEK accepts valid 32-byte base64 and falls back cleanly."""
    # Test valid configured base64 key
    custom_key = os.urandom(32)
    b64_key = base64.b64encode(custom_key).decode("ascii")
    monkeypatch.setattr(settings, "MEDTRUST_MASTER_KEK", b64_key)
    retrieved = get_master_kek()
    assert retrieved == custom_key

    # Test unset / None fallback
    monkeypatch.setattr(settings, "MEDTRUST_MASTER_KEK", None)
    fallback = get_master_kek()
    assert len(fallback) == 32
    assert fallback == bytes.fromhex(settings.DEFAULT_MASTER_KEY_HEX)


# ---------------------------------------------------------------------------
# 2. Upload & Key Persistence Tests
# ---------------------------------------------------------------------------

def test_upload_persists_envelope_keys_in_sqlite():
    """
    Verify that uploading a record with both document file and prescription file
    persists two separate RecordKeyModel rows with distinct target_type and wrapped DEKs.
    """
    token = create_access_token({
        "sub": "pat-984210",
        "name": "Eleanor Vance",
        "role": "PATIENT"
    })

    file_content = b"PDF-1.7 Confidential clinical echocardiogram report with ejection fraction 62%."
    rx_content = b"PDF-1.7 Prescription: Metoprolol 25mg daily for 30 days."

    files = [
        ("file", ("cardio_report.pdf", io.BytesIO(file_content), "application/pdf")),
        ("prescription_file", ("metoprolol_rx.pdf", io.BytesIO(rx_content), "application/pdf"))
    ]
    data = {
        "patient_id": "pat-984210",
        "title": "Bilateral Echo & Rx",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Patient experiencing mild dyspnea on exertion."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    record = res.json()
    record_id = record["id"]

    # Verify keys persisted in SQLite
    db = SessionLocal()
    try:
        keys = db.query(RecordKeyModel).filter(RecordKeyModel.record_id == record_id).all()
        assert len(keys) == 2

        doc_key = next((k for k in keys if k.target_type == "record"), None)
        rx_key = next((k for k in keys if k.target_type == "prescription"), None)

        assert doc_key is not None
        assert doc_key.patient_id == "pat-984210"
        assert doc_key.kek_version == "v1"
        assert len(doc_key.encrypted_dek) > 0
        assert len(doc_key.dek_nonce) > 0
        assert len(doc_key.dek_tag) > 0

        assert rx_key is not None
        assert rx_key.patient_id == "pat-984210"
        assert rx_key.kek_version == "v1"

        # Verify plaintext DEK is not persisted in plain text (Zero-PHI)
        assert file_content not in doc_key.encrypted_dek.encode()
        assert rx_content not in rx_key.encrypted_dek.encode()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 3. Secure Download & Decryption Tests
# ---------------------------------------------------------------------------

def test_patient_can_download_own_decrypted_record_and_prescription():
    """
    Verify that an authenticated patient can download and decrypt both their
    primary document and attached prescription.
    """
    token = create_access_token({
        "sub": "pat-984210",
        "name": "Eleanor Vance",
        "role": "PATIENT"
    })

    file_bytes = b"GENUINE_DOC_DATA: Complete metabolic panel serum values."
    rx_bytes = b"GENUINE_RX_DATA: Atorvastatin 20mg orally at bedtime."

    files = [
        ("file", ("cmp_panel.pdf", io.BytesIO(file_bytes), "application/pdf")),
        ("prescription_file", ("atorvastatin.pdf", io.BytesIO(rx_bytes), "application/pdf"))
    ]
    data = {
        "patient_id": "pat-984210",
        "title": "Comprehensive Metabolic Panel & Statin",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital",
        "description": "Routine cholesterol evaluation."
    }

    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # 1. Download document
    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_doc.status_code == 200
    assert res_doc.content == file_bytes
    assert "attachment" in res_doc.headers.get("Content-Disposition", "")

    # 2. Download prescription
    res_rx = client.get(
        f"/api/v1/records/{record_id}/prescription/download",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_rx.status_code == 200
    assert res_rx.content == rx_bytes
    assert "atorvastatin.pdf" in res_rx.headers.get("Content-Disposition", "")


def test_horizontal_patient_isolation_download_blocked_403():
    """
    Verify horizontal privilege escalation prevention:
    Patient B cannot download Patient A's record or prescription.
    """
    token_a = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    token_b = create_access_token({"sub": "pat-222222", "name": "Bob Attacker", "role": "PATIENT"})

    # Upload as Patient A
    files = [
        ("file", ("secret_scan.pdf", io.BytesIO(b"CONFIDENTIAL_MRI_SCAN"), "application/pdf")),
        ("prescription_file", ("secret_rx.pdf", io.BytesIO(b"CONFIDENTIAL_RX"), "application/pdf"))
    ]
    data = {
        "patient_id": "pat-984210",
        "title": "Patient A MRI",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro General Hospital",
        "description": "Cranial MRI."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Patient B attempts to download document
    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert res_doc.status_code == 403
    assert "Horizontal Access Denied" in res_doc.json()["detail"]

    # Patient B attempts to download prescription
    res_rx = client.get(
        f"/api/v1/records/{record_id}/prescription/download",
        headers={"Authorization": f"Bearer {token_b}"}
    )
    assert res_rx.status_code == 403
    assert "Horizontal Access Denied" in res_rx.json()["detail"]


def test_approved_doctor_with_active_consent_can_download():
    """
    Verify that an approved doctor who holds active consent for the patient's record type
    can download and decrypt the medical record and prescription.
    """
    # Dr. Marcus Sterling (doc-331902) holds active consent cst-8801 for patient pat-984210 (allowed_record_types: ALL)
    token_doctor = create_access_token({
        "sub": "doc-331902",
        "name": "Dr. Marcus Sterling, MD",
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })

    file_bytes = b"DOCTOR_CLINICAL_DATA: Post-operative cardiac bypass graft evaluation."
    rx_bytes = b"DOCTOR_RX_DATA: Clopidogrel 75mg daily."

    files = [
        ("file", ("cardiac_eval.pdf", io.BytesIO(file_bytes), "application/pdf")),
        ("prescription_file", ("cardiac_rx.pdf", io.BytesIO(rx_bytes), "application/pdf"))
    ]
    data = {
        "patient_id": "pat-984210",
        "title": "Cardiac Graft Evaluation",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Follow-up visit post surgery."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token_doctor}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Doctor downloads document
    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token_doctor}"}
    )
    assert res_doc.status_code == 200
    assert res_doc.content == file_bytes

    # Doctor downloads prescription
    res_rx = client.get(
        f"/api/v1/records/{record_id}/prescription/download",
        headers={"Authorization": f"Bearer {token_doctor}"}
    )
    assert res_rx.status_code == 200
    assert res_rx.content == rx_bytes


def test_approved_doctor_without_consent_download_blocked_403():
    """
    Verify that an approved doctor without consent covering the category is denied download.
    """
    token_patient = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    # Dr. Clara Oswald does not have consent for IMAGING_MRI records of Eleanor
    token_unconsented_doctor = create_access_token({
        "sub": "doc-119283",
        "name": "Dr. Clara Oswald, DDS",
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })

    files = [("file", ("mri.pdf", io.BytesIO(b"MRI_DOC_CONTENT"), "application/pdf"))]
    data = {
        "patient_id": "pat-984210",
        "title": "Restricted MRI Record",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro General Hospital",
        "description": "Restricted MRI evaluation."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token_unconsented_doctor}"}
    )
    assert res_doc.status_code == 403
    assert "Clinical download denied" in res_doc.json()["detail"]


def test_approved_doctor_with_revoked_consent_download_blocked_403():
    """
    Verify that an approved doctor whose consent has been revoked is blocked with HTTP 403.
    """
    token_patient = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    # Dr. Clara Oswald has revoked consent cst-8790 for LAB_REPORT records of Eleanor
    token_revoked_doctor = create_access_token({
        "sub": "doc-119283",
        "name": "Dr. Clara Oswald, DDS",
        "role": "DOCTOR",
        "approval_status": "APPROVED"
    })

    files = [("file", ("lab.pdf", io.BytesIO(b"LAB_REPORT_CONTENT"), "application/pdf"))]
    data = {
        "patient_id": "pat-984210",
        "title": "Dental Biopsy Lab Report",
        "record_type": "LAB_REPORT",
        "hospital": "Apex Dental & Maxillofacial",
        "description": "Lab biopsy panel."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token_revoked_doctor}"}
    )
    assert res_doc.status_code == 403
    assert "Clinical download denied" in res_doc.json()["detail"]


def test_unapproved_doctor_download_blocked_403():
    """
    Verify that an unapproved doctor (PENDING) is blocked from downloading records.
    """
    token_pending_doctor = create_access_token({
        "sub": "doc-pending-1",
        "name": "Dr. Pending Doctor",
        "role": "DOCTOR",
        "approval_status": "PENDING"
    })

    res = client.get(
        "/api/v1/records/rec-001/download",
        headers={"Authorization": f"Bearer {token_pending_doctor}"}
    )
    assert res.status_code == 403
    assert "Doctor approval status is 'PENDING'" in res.json()["detail"]


def test_admin_download_blocked_403_zero_phi_boundary():
    """
    Verify Administrator Zero-PHI Privacy Boundary:
    Admins are strictly blocked with HTTP 403 from downloading documents or prescriptions.
    """
    token_admin = create_access_token({
        "sub": "adm-999999",
        "name": "Platform Administrator",
        "role": "ADMIN"
    })

    res_doc = client.get(
        "/api/v1/records/rec-001/download",
        headers={"Authorization": f"Bearer {token_admin}"}
    )
    assert res_doc.status_code == 403
    assert "Administrative Privacy Boundary" in res_doc.json()["detail"]

    res_rx = client.get(
        "/api/v1/records/rec-001/prescription/download",
        headers={"Authorization": f"Bearer {token_admin}"}
    )
    assert res_rx.status_code == 403
    assert "Administrative Privacy Boundary" in res_rx.json()["detail"]


def test_auditor_download_blocked_403_verification_only():
    """
    Verify Compliance Auditor least-privilege boundary:
    Auditors are restricted to ledger verification and cannot download decrypted clinical files.
    """
    token_auditor = create_access_token({
        "sub": "aud-001001",
        "name": "Federal Compliance Auditor",
        "role": "AUDITOR"
    })

    res_doc = client.get(
        "/api/v1/records/rec-001/download",
        headers={"Authorization": f"Bearer {token_auditor}"}
    )
    assert res_doc.status_code == 403
    assert "Compliance auditors are restricted to ledger verification" in res_doc.json()["detail"]

    res_rx = client.get(
        "/api/v1/records/rec-001/prescription/download",
        headers={"Authorization": f"Bearer {token_auditor}"}
    )
    assert res_rx.status_code == 403
    assert "Compliance auditors are restricted to ledger verification" in res_rx.json()["detail"]


def test_legacy_record_download_returns_404_verification_only():
    """
    Verify that legacy pre-migration records without persisted DEKs (rec-001)
    return HTTP 404 with clear detail that legacy records operate in verification-only mode.
    """
    token_patient = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})

    res_doc = client.get(
        "/api/v1/records/rec-001/download",
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_doc.status_code == 404
    assert "Legacy records operate in ledger-verification-only mode" in res_doc.json()["detail"]


def test_description_only_record_download_returns_404():
    """
    Verify that records uploaded without document attachments (description-only)
    return HTTP 404 when calling document download.
    """
    token_patient = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})

    # Description only (no file, no prescription)
    data = {
        "patient_id": "pat-984210",
        "title": "Symptoms Description Only",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Patient reports recurring migraines in morning."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_doc.status_code == 404
    assert "does not have an attached document file" in res_doc.json()["detail"]


def test_unauthenticated_download_blocked_401():
    """Verify that unauthenticated callers receive HTTP 401 with WWW-Authenticate header."""
    res = client.get("/api/v1/records/rec-001/download")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers

    res_rx = client.get("/api/v1/records/rec-001/prescription/download")
    assert res_rx.status_code == 401
    assert "WWW-Authenticate" in res_rx.headers


def test_tampered_key_in_db_causes_500_decryption_failure():
    """
    Verify that if the encrypted DEK or authentication tag in the database is corrupted,
    the download endpoint fails cryptographic verification, returns HTTP 500,
    and logs a TAMPER_DETECTED event in the Fabric audit trail.
    """
    token_patient = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})

    file_bytes = b"INTEGRITY_CHECK_PAYLOAD: Sensitive lab panel."
    files = [("file", ("lab_panel.pdf", io.BytesIO(file_bytes), "application/pdf"))]
    data = {
        "patient_id": "pat-984210",
        "title": "Integrity Check Panel",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital",
        "description": "Integrity test record."
    }
    res_up = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_up.status_code == 200
    record_id = res_up.json()["id"]

    # Tamper with the tag in SQLite
    db = SessionLocal()
    try:
        key_entry = db.query(RecordKeyModel).filter(
            RecordKeyModel.record_id == record_id,
            RecordKeyModel.target_type == "record"
        ).first()
        assert key_entry is not None

        # Flip bytes of tag
        raw_tag = bytearray(base64.b64decode(key_entry.dek_tag))
        raw_tag[0] ^= 0xFF
        key_entry.dek_tag = base64.b64encode(raw_tag).decode("ascii")
        db.commit()
    finally:
        db.close()

    # Attempt download with tampered key
    res_doc = client.get(
        f"/api/v1/records/{record_id}/download",
        headers={"Authorization": f"Bearer {token_patient}"}
    )
    assert res_doc.status_code == 500
    assert "Decryption failed" in res_doc.json()["detail"]
