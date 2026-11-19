from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token

client = TestClient(app)


def test_get_consents_unauthenticated_rejected():
    res = client.get("/api/v1/consents")
    assert res.status_code == 401


def test_get_consents_list():
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    res = client.get("/api/v1/consents", headers={"Authorization": f"Bearer {pat_token}"})
    assert res.status_code == 200
    consents = res.json()
    assert len(consents) >= 3
    first = consents[0]
    assert "patientId" in first
    assert "doctorId" in first
    assert "status" in first
    assert "txHash" in first


def test_request_and_grant_consent_flow():
    # Doctor requests consent
    doc_token = create_access_token({
        "sub": "doc-555",
        "name": "Dr. Sarah Lin, MD",
        "role": "DOCTOR",
        "hospital": "Metro Labs & Diagnostics"
    })
    
    payload = {
        "patientId": "pat-984210",
        "doctorId": "doc-555",
        "purpose": "Comprehensive endocrine workup",
        "durationDays": 45,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    
    req_res = client.post(
        "/api/v1/consents/request",
        json=payload,
        headers={"Authorization": f"Bearer {doc_token}"}
    )
    assert req_res.status_code == 200
    consent_id = req_res.json()["id"]
    assert consent_id.startswith("cst-")
    
    # Patient grants consent
    pat_token = create_access_token({
        "sub": "pat-984210",
        "name": "Eleanor Vance",
        "role": "PATIENT"
    })
    
    grant_res = client.post(
        f"/api/v1/consents/{consent_id}/grant",
        headers={"Authorization": f"Bearer {pat_token}"}
    )
    assert grant_res.status_code == 200
    assert grant_res.json()["success"] is True
    assert grant_res.json()["txHash"].startswith("0x")
    
    # Verify access
    verify_res = client.get(
        f"/api/v1/consents/verify?doctor_id=doc-555&patient_id=pat-984210&record_type=LAB_REPORT",
        headers={"Authorization": f"Bearer {doc_token}"}
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["allowed"] is True
    
    # Patient revokes consent
    revoke_res = client.post(
        f"/api/v1/consents/{consent_id}/revoke",
        headers={"Authorization": f"Bearer {pat_token}"}
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["success"] is True
    
    # Verify access after revocation
    verify_after = client.get(
        f"/api/v1/consents/verify?doctor_id=doc-555&patient_id=pat-984210&record_type=LAB_REPORT",
        headers={"Authorization": f"Bearer {doc_token}"}
    )
    assert verify_after.status_code == 200
    assert verify_after.json()["allowed"] is False
    assert verify_after.json()["reason"] == "CONSENT_REVOKED"
