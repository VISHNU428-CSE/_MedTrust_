import io
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token

client = TestClient(app)


def test_get_records_unauthenticated_rejected():
    res = client.get("/api/v1/records")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers


def test_get_records_default():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    res = client.get("/api/v1/records", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    records = res.json()
    assert len(records) >= 3
    # Check camelCase fields match frontend interface
    first = records[0]
    assert "patientId" in first
    assert "ipfsCid" in first
    assert "recordType" in first
    assert "keyFingerprint" in first


def test_admin_privacy_boundary_blocks_medical_records():
    admin_token = create_access_token({
        "sub": "adm-999999",
        "name": "Platform Administrator",
        "role": "ADMIN"
    })
    # Listing records as Admin must return 403
    res_list = client.get("/api/v1/records", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_list.status_code == 403
    assert "Administrative Privacy Boundary" in res_list.json()["detail"]

    # Accessing specific record by ID as Admin must return 403
    res_detail = client.get("/api/v1/records/rec-001", headers={"Authorization": f"Bearer {admin_token}"})
    assert res_detail.status_code == 403
    assert "Administrative Privacy Boundary" in res_detail.json()["detail"]


def test_horizontal_escalation_blocked():
    # Token for Patient A
    token_a = create_access_token({"sub": "pat-111", "name": "Patient Alice", "role": "PATIENT"})
    # Patient A attempts to view Patient B's records
    res = client.get(
        "/api/v1/records?patient_id=pat-222",
        headers={"Authorization": f"Bearer {token_a}"}
    )
    assert res.status_code == 403
    assert "Horizontal Access Denied" in res.json()["detail"]


def test_upload_medical_record():
    token = create_access_token({
        "sub": "doc-331902",
        "name": "Dr. Marcus Sterling, MD",
        "role": "DOCTOR"
    })
    
    file_content = b"PDF-1.4 Comprehensive echocardiogram blood flow doppler output."
    files = {
        "file": ("echocardiogram.pdf", io.BytesIO(file_content), "application/pdf")
    }
    data = {
        "patient_id": "pat-984210",
        "title": "Comprehensive Doppler Assessment",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro General Hospital"
    }
    
    res = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    record = res.json()
    assert record["title"] == "Comprehensive Doppler Assessment"
    assert record["patientId"] == "pat-984210"
    assert "ipfsCid" in record
    assert record["encryptionAlgorithm"] == "AES-256-GCM"
    assert record["keyFingerprint"].startswith("SHA256:")


def test_verify_record_status_verified(monkeypatch):
    """Assert 'VERIFIED' when IPFS payload matches Fabric ledger registered checksum."""
    from app.adapters.ipfs_client import ipfs_client

    matching_payload = b"INTACT ENCRYPTED RECORD PAYLOAD - AES-256-GCM"
    expected_hash = "0951db7048aa8abdf35b63a56747df4608be1ea8b2eeaa7344ced80615762cef"

    monkeypatch.setattr("app.services.record_service.compute_sha256", lambda b: expected_hash)
    monkeypatch.setattr(ipfs_client, "get_bytes", lambda cid, expected_sha256=None: matching_payload)

    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    headers = {"Authorization": f"Bearer {pat_token}"}

    # Test POST endpoint
    res_post = client.post("/api/v1/records/rec-001/verify", headers=headers)
    assert res_post.status_code == 200
    data_post = res_post.json()
    assert data_post["recordId"] == "rec-001"
    assert data_post["status"] == "VERIFIED"
    assert data_post["checksumMatches"] is True
    assert data_post["ledgerChecksum"] == expected_hash
    assert data_post["computedSha256"] == expected_hash
    assert "verified" in data_post["detail"].lower()

    # Test GET endpoint
    res_get = client.get("/api/v1/records/rec-001/verify", headers=headers)
    assert res_get.status_code == 200
    data_get = res_get.json()
    assert data_get["status"] == "VERIFIED"
    assert data_get["checksumMatches"] is True


def test_verify_record_status_checksum_mismatch(monkeypatch):
    """Assert 'CHECKSUM_MISMATCH' when IPFS payload has been tampered or corrupted."""
    from app.adapters.ipfs_client import ipfs_client
    from app.core.exceptions import ChecksumMismatchError

    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    headers = {"Authorization": f"Bearer {pat_token}"}

    # 1. Raised ChecksumMismatchError from IPFS client verification
    def mock_tampered_get_bytes(cid, expected_sha256=None):
        raise ChecksumMismatchError(
            f"CRITICAL SECURITY ALERT: Checksum mismatch for CID {cid}! "
            f"Expected {expected_sha256}, calculated tampered_digest_999."
        )

    monkeypatch.setattr(ipfs_client, "get_bytes", mock_tampered_get_bytes)

    res = client.post("/api/v1/records/rec-001/verify", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert data["status"] == "CHECKSUM_MISMATCH"
    assert data["checksumMatches"] is False
    assert data["computedSha256"] == "MISMATCH"
    assert "checksum mismatch" in data["detail"].lower()

    # 2. Return tampered bytes where computed hash does not match expected
    monkeypatch.setattr(ipfs_client, "get_bytes", lambda cid, expected_sha256=None: b"TAMPERED_BYTES")
    monkeypatch.setattr("app.services.record_service.compute_sha256", lambda b: "mismatched_sha256_hash_value")

    res_tampered = client.get("/api/v1/records/rec-001/verify", headers=headers)
    assert res_tampered.status_code == 200
    data_tampered = res_tampered.json()
    assert data_tampered["status"] == "CHECKSUM_MISMATCH"
    assert data_tampered["checksumMatches"] is False
    assert data_tampered["computedSha256"] == "mismatched_sha256_hash_value"


def test_verify_record_status_ipfs_unavailable(monkeypatch):
    """Assert 'IPFS_UNAVAILABLE' when Kubo daemon times out or is unreachable."""
    from app.adapters.ipfs_client import ipfs_client
    from app.core.exceptions import IPFSConnectionError

    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    headers = {"Authorization": f"Bearer {pat_token}"}

    def mock_ipfs_timeout(cid, expected_sha256=None):
        raise IPFSConnectionError(
            "Cannot connect to IPFS Kubo RPC at http://127.0.0.1:5001/api/v0: ConnectTimeout"
        )

    monkeypatch.setattr(ipfs_client, "get_bytes", mock_ipfs_timeout)

    res = client.post("/api/v1/records/rec-001/verify", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert data["status"] == "IPFS_UNAVAILABLE"
    assert data["checksumMatches"] is False
    assert data["computedSha256"] == "UNAVAILABLE"
    assert "could not retrieve payload from ipfs" in data["detail"].lower()


def test_verify_record_status_ledger_unavailable():
    """Assert 'LEDGER_UNAVAILABLE' when record ID is missing on Hyperledger Fabric ledger."""
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    headers = {"Authorization": f"Bearer {pat_token}"}

    res = client.post("/api/v1/records/rec-nonexistent-999999/verify", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-nonexistent-999999"
    assert data["status"] == "LEDGER_UNAVAILABLE"
    assert data["checksumMatches"] is False
    assert data["ledgerChecksum"] == "UNAVAILABLE"
    assert data["computedSha256"] == "UNAVAILABLE"
    assert "not found on fabric ledger" in data["detail"].lower()


def test_verify_record_status_ledger_unavailable_get():
    """Assert GET /verify returns structured response directly without raising HTTP 404."""
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    headers = {"Authorization": f"Bearer {pat_token}"}

    res = client.get("/api/v1/records/rec-nonexistent-888888/verify", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-nonexistent-888888"
    assert data["status"] == "LEDGER_UNAVAILABLE"
    assert data["checksumMatches"] is False
    assert "not found on fabric ledger" in data["detail"].lower()


def test_admin_clinical_records_access_denied():
    """Asserts that Platform Administrators are strictly prohibited from viewing or uploading medical records."""
    admin_token = create_access_token({
        "sub": "adm-000001",
        "name": "System Administrator",
        "role": "ADMIN"
    })
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Listing records -> 403
    res_list = client.get("/api/v1/records", headers=headers)
    assert res_list.status_code == 403
    assert "Administrative Privacy Boundary" in res_list.json()["detail"]

    # 2. Fetching single record -> 403
    res_single = client.get("/api/v1/records/rec-001", headers=headers)
    assert res_single.status_code == 403
    assert "Administrative Privacy Boundary" in res_single.json()["detail"]

    # 3. Uploading record -> 403
    file_content = b"Mock PDF payload"
    files = {"file": ("test.pdf", io.BytesIO(file_content), "application/pdf")}
    data = {
        "patient_id": "pat-984210",
        "title": "Admin Attempted Upload",
        "record_type": "LAB_REPORT",
        "hospital": "Metro Hospital"
    }
    res_upload = client.post("/api/v1/records/upload", data=data, files=files, headers=headers)
    assert res_upload.status_code == 403
    assert "Administrative Privacy Boundary" in res_upload.json()["detail"]


# --- Phase 6: Multi-Input Upload & Protected Clinical Detail Tests ---

def test_upload_multi_input_file_only():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    file_content = b"PDF report content only"
    files = {"file": ("report.pdf", io.BytesIO(file_content), "application/pdf")}
    data = {
        "patient_id": "pat-984210",
        "title": "Document Only Consultation",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital"
    }
    res = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    rec = res.json()
    rec_id = rec["id"]

    # Verify details
    det_res = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {token}"})
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["patientId"] == "pat-984210"
    assert details["hasDocument"] is True
    assert details["description"] is None
    assert details["prescriptionCid"] is None


def test_upload_multi_input_description_only():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    data = {
        "patient_id": "pat-984210",
        "title": "Symptom Journal Entry",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Patient experiencing intermittent bilateral temple headaches for 3 consecutive days."
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    rec = res.json()
    rec_id = rec["id"]

    # Verify details
    det_res = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {token}"})
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["hasDocument"] is False
    assert "intermittent bilateral temple headaches" in details["description"]
    assert details["prescriptionCid"] is None


def test_upload_multi_input_prescription_only():
    token = create_access_token({"sub": "doc-331902", "name": "Dr. Marcus Sterling, MD", "role": "DOCTOR"})
    rx_content = b"Rx: Amoxicillin 500mg TID x 10 days"
    files = {"prescription_file": ("amoxicillin_rx.pdf", io.BytesIO(rx_content), "application/pdf")}
    data = {
        "patient_id": "pat-984210",
        "title": "Antibiotic Prescription Regimen",
        "record_type": "PRESCRIPTION",
        "hospital": "Metro General Hospital"
    }
    res = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    rec = res.json()
    rec_id = rec["id"]

    # Verify details
    det_res = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {token}"})
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["hasDocument"] is False
    assert details["description"] is None
    assert details["prescriptionFilename"] == "amoxicillin_rx.pdf"
    assert details["prescriptionCid"] is not None
    assert len(details["prescriptionChecksum"]) == 64


def test_upload_multi_input_all_three():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    file_content = b"PDF-1.4 Comprehensive echocardiogram blood flow doppler output."
    rx_content = b"Rx: Atorvastatin 20mg daily"
    files = {
        "file": ("cardio_report.pdf", io.BytesIO(file_content), "application/pdf"),
        "prescription_file": ("statin_rx.pdf", io.BytesIO(rx_content), "application/pdf")
    }
    data = {
        "patient_id": "pat-984210",
        "title": "Cardiology Comprehensive Consultation",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro General Hospital",
        "description": "Post-diagnostic evaluation with statin initiation."
    }
    res = client.post("/api/v1/records/upload", data=data, files=files, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    rec = res.json()
    rec_id = rec["id"]

    det_res = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {token}"})
    assert det_res.status_code == 200
    details = det_res.json()
    assert details["recordId"] == rec_id
    assert details["hasDocument"] is True
    assert details["description"] == "Post-diagnostic evaluation with statin initiation."
    assert details["prescriptionFilename"] == "statin_rx.pdf"
    assert details["prescriptionCid"] is not None


def test_upload_validation_no_inputs_rejected_422():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    data = {
        "patient_id": "pat-984210",
        "title": "Empty Submission",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital"
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 422
    assert "At least one clinical input must be provided" in res.json()["detail"]


def test_upload_validation_whitespace_description_rejected_422():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    data = {
        "patient_id": "pat-984210",
        "title": "Whitespace Only Submission",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital",
        "description": "     "
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 422
    assert "At least one clinical input must be provided" in res.json()["detail"]


def test_get_record_details_patient_cross_access_denied_403():
    # Patient Eleanor Vance uploads a record
    pat1_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    data = {
        "patient_id": "pat-984210",
        "title": "Private Medical Journal",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Sensitive mental health reflection."
    }
    res_up = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {pat1_token}"})
    assert res_up.status_code == 200
    rec_id = res_up.json()["id"]

    # Patient Bob attempts to view Eleanor's details
    pat2_token = create_access_token({"sub": "pat-777888", "name": "Bob Patient", "role": "PATIENT"})
    res_det = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {pat2_token}"})
    assert res_det.status_code == 403
    assert "Access denied" in res_det.json()["detail"]


def test_get_record_details_doctor_with_and_without_consent():
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    data = {
        "patient_id": "pat-984210",
        "title": "Oncology Screening",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital",
        "description": "Laboratory biomarker levels within normal reference range."
    }
    res_up = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {pat_token}"})
    assert res_up.status_code == 200
    rec_id = res_up.json()["id"]

    # Doctor Dr. Marcus Sterling (doc-331902) has ACTIVE consent (cst-8801) for pat-984210
    doc_with_consent = create_access_token({"sub": "doc-331902", "name": "Dr. Marcus Sterling, MD", "role": "DOCTOR"})
    res_allowed = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {doc_with_consent}"})
    assert res_allowed.status_code == 200
    assert res_allowed.json()["recordId"] == rec_id

    # Doctor Dr. Clara Oswald (doc-119283) has REVOKED consent (cst-8790)
    doc_revoked = create_access_token({"sub": "doc-119283", "name": "Dr. Clara Oswald, DDS", "role": "DOCTOR"})
    res_revoked = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {doc_revoked}"})
    assert res_revoked.status_code == 403
    assert "Access denied: Doctor does not have active consent" in res_revoked.json()["detail"]

    # Unknown doctor without any consent
    doc_no_consent = create_access_token({"sub": "doc-999999", "name": "Dr. Unknown, MD", "role": "DOCTOR"})
    res_no_consent = client.get(f"/api/v1/records/{rec_id}/details", headers={"Authorization": f"Bearer {doc_no_consent}"})
    assert res_no_consent.status_code == 403
    assert "Access denied: Doctor does not have active consent" in res_no_consent.json()["detail"]


def test_get_record_details_admin_privacy_boundary_403():
    admin_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    res = client.get("/api/v1/records/rec-001/details", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 403
    assert "Administrative Privacy Boundary" in res.json()["detail"]


def test_get_record_details_auditor_allowed():
    auditor_token = create_access_token({"sub": "aud-001001", "name": "Federal Compliance Auditor", "role": "AUDITOR"})
    res = client.get("/api/v1/records/rec-001/details", headers={"Authorization": f"Bearer {auditor_token}"})
    assert res.status_code == 200
    details = res.json()
    assert details["recordId"] == "rec-001"
    assert details["patientId"] == "pat-984210"


def test_get_record_details_nonexistent_record_404():
    token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    res = client.get("/api/v1/records/rec-nonexistent-12345/details", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 404



