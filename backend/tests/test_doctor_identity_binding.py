"""
Focused Regression Test Suite: Doctor Identity Binding on Consent Requests (Task 6B.2B).

Verifies:
1. Approved doctor requesting consent using their own identity succeeds (HTTP 200).
2. Approved doctor requesting consent omitting doctor_id succeeds with automatic identity binding (HTTP 200).
3. Approved doctor attempting to supply another doctor's ID is rejected with HTTP 403 Forbidden.
4. Unauthenticated consent request is rejected with HTTP 401 Unauthorized.
5. Pending or rejected doctor attempting consent request is rejected with HTTP 403 Forbidden.
6. Patient caller attempting consent request is rejected with HTTP 403 Forbidden.
7. Full consent request -> patient grant lifecycle remains completely intact.
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.adapters.fabric_gateway import fabric_gateway
from app.core.security import create_access_token, hash_password
from app.db.session import SessionLocal
from app.db.models import UserModel


@pytest.fixture(autouse=True)
def clean_fabric_consents_state():
    """Isolates in-memory gateway consent and record state for each test."""
    original_consents = dict(fabric_gateway._consents)
    yield
    fabric_gateway._consents = original_consents


@pytest.fixture
def approved_doctor():
    """Provides an approved doctor in the test database."""
    doc_id = f"doc-approved-{uuid.uuid4().hex[:6]}"
    email = f"{doc_id}@hospital.org"
    db = SessionLocal()
    try:
        user = UserModel(
            id=doc_id,
            name="Dr. Validated Clinician",
            email=email,
            role="DOCTOR",
            password_hash=hash_password("DocSecurePass123!"),
            hospital="St. Jude Diagnostic Center",
            specialty="Cardiovascular Medicine",
            license_number="LIC-MD-VALID-01",
            approval_status="APPROVED",
            is_active=True
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    token = create_access_token({
        "sub": doc_id,
        "name": "Dr. Validated Clinician",
        "role": "DOCTOR",
        "hospital": "St. Jude Diagnostic Center",
        "specialty": "Cardiovascular Medicine"
    })
    return {"id": doc_id, "token": token, "headers": {"Authorization": f"Bearer {token}"}}


@pytest.fixture
def other_doctor():
    """Provides a second distinct approved doctor in the test database."""
    doc_id = f"doc-victim-{uuid.uuid4().hex[:6]}"
    email = f"{doc_id}@hospital.org"
    db = SessionLocal()
    try:
        user = UserModel(
            id=doc_id,
            name="Dr. Unsuspecting Victim",
            email=email,
            role="DOCTOR",
            password_hash=hash_password("DocSecurePass123!"),
            hospital="Metro General",
            specialty="Pediatrics",
            license_number="LIC-MD-VICTIM-02",
            approval_status="APPROVED",
            is_active=True
        )
        db.add(user)
        db.commit()
    finally:
        db.close()

    token = create_access_token({
        "sub": doc_id,
        "name": "Dr. Unsuspecting Victim",
        "role": "DOCTOR"
    })
    return {"id": doc_id, "token": token}


def test_approved_doctor_request_consent_with_own_identity(approved_doctor):
    """An approved doctor requesting consent using their own matching doctor_id succeeds (HTTP 200)."""
    client = TestClient(app)
    payload = {
        "doctorId": approved_doctor["id"],
        "patientId": "pat-984210",
        "purpose": "Routine follow-up clinical assessment",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT", "CLINICAL_SUMMARY"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers=approved_doctor["headers"])
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "id" in data
    consent_id = data["id"]

    # Verify on-chain ledger record bound doctor_id strictly to caller
    consent_record = fabric_gateway.get_consent(consent_id)
    assert consent_record["doctor_id"] == approved_doctor["id"]
    assert consent_record["status"] == "PENDING"


def test_approved_doctor_request_consent_omitting_doctor_id(approved_doctor):
    """An approved doctor omitting doctor_id succeeds with automatic identity binding to current_user.id."""
    client = TestClient(app)
    payload = {
        "patientId": "pat-984210",
        "purpose": "Comprehensive endocrine panel",
        "durationDays": 14,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers=approved_doctor["headers"])
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    consent_id = data["id"]

    consent_record = fabric_gateway.get_consent(consent_id)
    assert consent_record["doctor_id"] == approved_doctor["id"]
    assert consent_record["status"] == "PENDING"


def test_doctor_attempt_to_supply_another_doctor_id_blocked_403(approved_doctor, other_doctor):
    """
    CRITICAL SECURITY GATE:
    An approved doctor attempting to request consent under another doctor's ID
    must be rejected with HTTP 403 Forbidden.
    """
    client = TestClient(app)
    impersonation_payload = {
        "doctorId": other_doctor["id"],  # Supplying another doctor's ID!
        "patientId": "pat-984210",
        "purpose": "Unauthorized impersonation attempt",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    res = client.post("/api/v1/consents/request", json=impersonation_payload, headers=approved_doctor["headers"])
    assert res.status_code == 403
    error_detail = res.json()["detail"]
    assert "cannot submit consent requests on behalf of" in error_detail
    assert approved_doctor["id"] in error_detail
    assert other_doctor["id"] in error_detail


def test_unauthenticated_consent_request_blocked_401():
    """An unauthenticated request without a Bearer token must be rejected with HTTP 401."""
    client = TestClient(app)
    payload = {
        "patientId": "pat-984210",
        "purpose": "Unauthenticated probe",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    res = client.post("/api/v1/consents/request", json=payload)
    assert res.status_code == 401
    assert "authentication required" in res.json()["detail"].lower()


def test_pending_doctor_request_blocked_403():
    """A doctor whose account status is PENDING is blocked with HTTP 403."""
    client = TestClient(app)
    doc_id = f"doc-pending-{uuid.uuid4().hex[:6]}"
    db = SessionLocal()
    try:
        p_doc = UserModel(
            id=doc_id,
            name="Dr. Awaiting Review",
            email=f"{doc_id}@clinic.org",
            role="DOCTOR",
            password_hash=hash_password("pw123"),
            hospital="Regional Clinic",
            specialty="Dermatology",
            license_number="LIC-PEND-TEST",
            approval_status="PENDING",
            is_active=False
        )
        db.add(p_doc)
        db.commit()
    finally:
        db.close()

    token = create_access_token({"sub": doc_id, "name": "Dr. Awaiting Review", "role": "DOCTOR"})
    payload = {
        "patientId": "pat-984210",
        "purpose": "Dermatology assessment",
        "durationDays": 30,
        "allowedRecordTypes": ["CLINICAL_SUMMARY"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "pending administrator approval" in res.json()["detail"].lower() or "approval status is 'pending'" in res.json()["detail"].lower()


def test_rejected_doctor_request_blocked_403():
    """A doctor whose account status is REJECTED is blocked with HTTP 403."""
    client = TestClient(app)
    doc_id = f"doc-rejected-{uuid.uuid4().hex[:6]}"
    db = SessionLocal()
    try:
        r_doc = UserModel(
            id=doc_id,
            name="Dr. Denied Application",
            email=f"{doc_id}@clinic.org",
            role="DOCTOR",
            password_hash=hash_password("pw123"),
            hospital="Regional Clinic",
            specialty="Dermatology",
            license_number="LIC-REJ-TEST",
            approval_status="REJECTED",
            rejection_reason="Invalid medical license credential",
            is_active=False
        )
        db.add(r_doc)
        db.commit()
    finally:
        db.close()

    token = create_access_token({"sub": doc_id, "name": "Dr. Denied Application", "role": "DOCTOR"})
    payload = {
        "patientId": "pat-984210",
        "purpose": "Dermatology assessment",
        "durationDays": 30,
        "allowedRecordTypes": ["CLINICAL_SUMMARY"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403
    assert "clinical access denied" in res.json()["detail"].lower() or "rejected" in res.json()["detail"].lower()


def test_patient_caller_request_blocked_403():
    """A patient caller attempting POST /api/v1/consents/request is blocked with HTTP 403."""
    client = TestClient(app)
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    payload = {
        "patientId": "pat-984210",
        "purpose": "Patient cannot request consent",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers={"Authorization": f"Bearer {pat_token}"})
    assert res.status_code == 403
    assert "restricted to doctors" in res.json()["detail"].lower()


def test_doctor_request_consent_nonexistent_patient_rejected_404(approved_doctor):
    """Attempting to request consent for a nonexistent patient ID returns HTTP 404."""
    client = TestClient(app)
    payload = {
        "doctorId": approved_doctor["id"],
        "patientId": "pat-nonexistent-999999",
        "purpose": "Endocrine examination",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers=approved_doctor["headers"])
    assert res.status_code == 404
    data = res.json()
    assert "detail" in data
    assert "pat-nonexistent-999999" in data["detail"]
    assert "not found in platform records" in data["detail"].lower()


def test_doctor_request_consent_target_non_patient_account_rejected_404(approved_doctor):
    """Attempting to request consent targeting a non-patient user (e.g. admin or doctor) returns HTTP 404."""
    client = TestClient(app)
    # adm-999999 is seeded with role ADMIN
    payload = {
        "doctorId": approved_doctor["id"],
        "patientId": "adm-999999",
        "purpose": "Cardiology consultation",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT"]
    }
    res = client.post("/api/v1/consents/request", json=payload, headers=approved_doctor["headers"])
    assert res.status_code == 404
    data = res.json()
    assert "adm-999999" in data["detail"]
    assert "not found in platform records" in data["detail"].lower()


def test_existing_consent_grant_and_verify_flow_intact(approved_doctor):
    """
    Verifies that the complete lifecycle works seamlessly:
    Doctor requests consent under own identity -> Patient grants consent -> Doctor verifies consent.
    """
    client = TestClient(app)
    pat_id = "pat-lifecycle-test"

    # Seed patient in test database
    db = SessionLocal()
    try:
        p = db.query(UserModel).filter(UserModel.id == pat_id).first()
        if not p:
            p = UserModel(
                id=pat_id,
                email=f"{pat_id}@example.com",
                name="Lifecycle Patient",
                role="PATIENT",
                password_hash=hash_password("pw123"),
                approval_status="APPROVED",
                is_active=True
            )
            db.add(p)
            db.commit()
    finally:
        db.close()

    # 1. Doctor requests consent
    req_res = client.post("/api/v1/consents/request", json={
        "doctorId": approved_doctor["id"],
        "patientId": pat_id,
        "purpose": "Pre-operative cardiology consultation",
        "durationDays": 30,
        "allowedRecordTypes": ["LAB_REPORT"]
    }, headers=approved_doctor["headers"])
    assert req_res.status_code == 200
    consent_id = req_res.json()["id"]

    # 2. Patient grants consent
    pat_token = create_access_token({"sub": pat_id, "name": "Lifecycle Patient", "role": "PATIENT"})
    grant_res = client.post(
        f"/api/v1/consents/{consent_id}/grant",
        headers={"Authorization": f"Bearer {pat_token}"}
    )
    assert grant_res.status_code == 200
    assert grant_res.json()["success"] is True

    # 3. Doctor checks verification via verify endpoint
    verify_res = client.get(
        f"/api/v1/consents/verify?doctor_id={approved_doctor['id']}&patient_id={pat_id}&record_type=LAB_REPORT",
        headers={"Authorization": f"Bearer {approved_doctor['token']}"}
    )
    assert verify_res.status_code == 200
    assert verify_res.json()["allowed"] is True
    assert verify_res.json()["reason"] == "CONSENT_ACTIVE"
    assert verify_res.json()["consentId"] == consent_id
