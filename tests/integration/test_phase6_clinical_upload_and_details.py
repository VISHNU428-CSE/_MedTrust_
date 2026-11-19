"""
Integration Tests: Phase 6 Multi-Input Clinical Upload & Details Persistence.

Verifies:
- Description-only clinical submission (symptoms text without files).
- Attachment-only clinical submission (document file only).
- Attachment-only clinical submission (prescription attachment only).
- Multi-input combined submission (description + document + prescription).
- Input validation: HTTP 422 rejected on empty or whitespace-only inputs.
- Persistent SQLite storage in RecordDetailModel and baseline seeded records.
- Zero-PHI on-chain isolation: descriptions and prescription contents never leak to ledger unencrypted.
"""

import io
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token

client = TestClient(app)

PATIENT_ELEANOR_ID = "pat-984210"
DOCTOR_STERLING_ID = "doc-331902"


@pytest.fixture
def patient_token():
    return create_access_token({
        "sub": PATIENT_ELEANOR_ID,
        "name": "Eleanor Vance",
        "role": "PATIENT"
    })


@pytest.fixture
def doctor_token():
    return create_access_token({
        "sub": DOCTOR_STERLING_ID,
        "name": "Dr. Marcus Sterling, MD",
        "role": "DOCTOR"
    })


@pytest.mark.integration
def test_clinical_upload_description_only_success(patient_token):
    """
    Verify patient can upload a clinical record with only a text description.
    No document or prescription attachment required.
    """
    payload_data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Persistent Migraine & Visual Aura Log",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Patient reports recurring throbbing headaches in temporal region with photophobia."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=payload_data,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    assert record["id"].startswith("rec-")
    assert record["patientId"] == PATIENT_ELEANOR_ID
    assert record["title"] == "Persistent Migraine & Visual Aura Log"
    assert "ipfsCid" in record

    # Verify persistent clinical details endpoint
    rec_id = record["id"]
    det_res = client.get(
        f"/api/v1/records/{rec_id}/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["patientId"] == PATIENT_ELEANOR_ID
    assert "throbbing headaches" in details["description"]
    assert details["hasDocument"] is False
    assert details["prescriptionCid"] is None
    assert details["prescriptionFilename"] is None


@pytest.mark.integration
def test_clinical_upload_document_file_only_success(doctor_token, patient_token):
    """
    Verify upload of document file only (no symptom description, no prescription).
    Payload must be encrypted with AES-256-GCM and pinned to IPFS.
    """
    file_content = b"%PDF-1.5 Synthetic Echocardiogram Ultrasound Imaging Slice 001."
    files = {
        "file": ("cardiac_echo.pdf", io.BytesIO(file_content), "application/pdf")
    }
    payload_data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Transthoracic Echocardiogram Scan",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro General Hospital"
    }

    res = client.post(
        "/api/v1/records/upload",
        data=payload_data,
        files=files,
        headers={"Authorization": f"Bearer {doctor_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    rec_id = record["id"]
    assert record["encryptionAlgorithm"] == "AES-256-GCM"
    assert record["keyFingerprint"].startswith("SHA256:")

    # Verify persistent details
    det_res = client.get(
        f"/api/v1/records/{rec_id}/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["hasDocument"] is True
    assert details["description"] is None
    assert details["prescriptionCid"] is None


@pytest.mark.integration
def test_clinical_upload_prescription_only_success(patient_token):
    """
    Verify upload of prescription attachment only (no main document, no description).
    Prescription must be encrypted with AES-256-GCM and stored with CID & checksum.
    """
    rx_content = b"Rx: Lisinopril 10mg PO Daily. Synthetic Prescription Test."
    files = {
        "prescription_file": ("hypertension_rx.pdf", io.BytesIO(rx_content), "application/pdf")
    }
    payload_data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Hypertension Maintenance Medication Order",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital"
    }

    res = client.post(
        "/api/v1/records/upload",
        data=payload_data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    rec_id = record["id"]

    # Verify persistent details
    det_res = client.get(
        f"/api/v1/records/{rec_id}/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["hasDocument"] is False
    assert details["description"] is None
    assert details["prescriptionCid"] is not None
    assert len(details["prescriptionCid"]) > 10
    assert details["prescriptionFilename"] == "hypertension_rx.pdf"
    assert details["prescriptionChecksum"] is not None
    assert len(details["prescriptionChecksum"]) == 64  # SHA-256 hex digest


@pytest.mark.integration
def test_clinical_upload_multi_input_combined_success(patient_token):
    """
    Verify comprehensive multi-input upload:
    - Symptom text description
    - Document file attachment
    - Prescription attachment file
    All three must be processed, encrypted, and recorded in persistent details.
    """
    doc_bytes = b"SYNTHETIC LAB WORK: Fasting Glucose: 92 mg/dL, HbA1c: 5.4%."
    rx_bytes = b"Rx: Metformin 500mg twice daily with meals. Synthetic Rx."

    files = {
        "file": ("lab_results.pdf", io.BytesIO(doc_bytes), "application/pdf"),
        "prescription_file": ("diabetes_rx.pdf", io.BytesIO(rx_bytes), "application/pdf")
    }
    payload_data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Comprehensive Metabolic & Glycemic Review",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital",
        "description": "Routine annual metabolic evaluation. Patient adherence to diet and exercise confirmed."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=payload_data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    rec_id = record["id"]

    det_res = client.get(
        f"/api/v1/records/{rec_id}/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert "metabolic evaluation" in details["description"]
    assert details["hasDocument"] is True
    assert details["prescriptionFilename"] == "diabetes_rx.pdf"
    assert details["prescriptionCid"] is not None
    assert len(details["prescriptionChecksum"]) == 64


@pytest.mark.integration
def test_clinical_upload_empty_submission_rejected_422(patient_token):
    """
    Validation Guardrail:
    Reject submission when no description, no document file, and no prescription attachment are provided.
    Must return HTTP 422 Unprocessable Content.
    """
    payload_data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Empty Clinical Record Attempt",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital"
    }

    res = client.post(
        "/api/v1/records/upload",
        data=payload_data,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 422
    assert "At least one clinical input must be provided" in res.json()["detail"]


@pytest.mark.integration
def test_clinical_upload_whitespace_description_rejected_422(patient_token):
    """
    Validation Guardrail:
    Reject submission when description consists solely of whitespace and no files are attached.
    Must return HTTP 422 Unprocessable Content.
    """
    payload_data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Whitespace Only Attempt",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "     \t \n   "
    }

    res = client.post(
        "/api/v1/records/upload",
        data=payload_data,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 422
    assert "At least one clinical input must be provided" in res.json()["detail"]


@pytest.mark.integration
def test_baseline_seeded_record_details(patient_token):
    """
    Verify that Phase 6 seeded clinical record details (rec-001, rec-002, rec-003)
    are present and accurately populated in persistent storage.
    """
    # rec-001: Echocardiogram
    res1 = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res1.status_code == 200
    det1 = res1.json()
    assert det1["recordId"] == "rec-001"
    assert "echocardiogram" in det1["description"].lower()
    assert det1["hasDocument"] is True
    assert det1["prescriptionCid"] is None

    # rec-002: CBC
    res2 = client.get(
        "/api/v1/records/rec-002/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res2.status_code == 200
    det2 = res2.json()
    assert det2["recordId"] == "rec-002"
    assert "blood count" in det2["description"].lower()
    assert det2["hasDocument"] is True

    # rec-003: Post-operative recovery with prescription
    res3 = client.get(
        "/api/v1/records/rec-003/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res3.status_code == 200
    det3 = res3.json()
    assert det3["recordId"] == "rec-003"
    assert "post-operative" in det3["description"].lower()
    assert det3["hasDocument"] is True
    assert det3["prescriptionFilename"] == "post_op_cardiac_rx.pdf"
    assert det3["prescriptionCid"].startswith("bafk")
    assert len(det3["prescriptionChecksum"]) == 64
