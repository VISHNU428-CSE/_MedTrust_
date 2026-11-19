"""
Security & Regression Tests: Task 6B.1 Patient-Data Authorization Gates.

Verifies:
1. GET /api/v1/records:
   - Prevents global record listing by doctors (unconsented patient records strictly excluded).
   - Doctor without active consent querying a patient's records is blocked with HTTP 403.
   - Doctor with active consent querying a patient's records succeeds (HTTP 200).
2. GET /api/v1/records/{record_id}:
   - Doctor without active consent for the record's patient/category is blocked with HTTP 403.
   - Doctor with revoked consent is blocked with HTTP 403.
   - Doctor with active consent retrieves metadata (HTTP 200).
3. GET /api/v1/consents and GET /api/v1/audit:
   - Strict patient ownership: Patient A querying Patient B's consents is rejected with HTTP 403.
   - Strict patient ownership: Patient A querying Patient B's audit history is rejected with HTTP 403.
   - Doctor least-privilege: Doctor only views consents where they are the clinician.
   - Doctor least-privilege: Doctor only views audit events where they are the actor.
   - Auditor compliance access: Auditor can query consents and audit logs for oversight.
4. POST /api/v1/records/upload:
   - Target patient validation: Uploading for a nonexistent patient ID returns HTTP 404.
   - Patient horizontal isolation: Patient A uploading under Patient B's ID is rejected with HTTP 403.
   - Doctor authorization: Doctor without active consent uploading for a patient is rejected with HTTP 403.
   - Doctor authorization: Doctor with active consent uploading for a patient succeeds (HTTP 200).
"""

import io
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from app.db.session import SessionLocal
from app.db.models import UserModel
from app.core.security import hash_password

client = TestClient(app)

PATIENT_ELEANOR_ID = "pat-984210"
PATIENT_BOB_ID = "pat-777888"
DOCTOR_STERLING_ACTIVE_ID = "doc-331902"   # Active consent cst-8801 for pat-984210 (ALL types)
DOCTOR_OSWALD_REVOKED_ID = "doc-119283"    # Revoked consent cst-8790 for pat-984210
DOCTOR_UNKNOWN_NO_CONSENT_ID = "doc-999999" # No consent for pat-984210
AUDITOR_ID = "aud-001001"
ADMIN_ID = "adm-999999"


@pytest.fixture(autouse=True)
def ensure_patient_bob_exists():
    """Seeds Patient Bob in the isolated test database for horizontal isolation tests."""
    db = SessionLocal()
    try:
        bob = db.query(UserModel).filter(UserModel.id == PATIENT_BOB_ID).first()
        if not bob:
            bob = UserModel(
                id=PATIENT_BOB_ID,
                name="Bob Martinez",
                email="bob.martinez@example.med",
                role="PATIENT",
                password_hash=hash_password("password123"),
                approval_status="APPROVED",
                is_active=True
            )
            db.add(bob)
            db.commit()
    finally:
        db.close()


@pytest.fixture
def eleanor_token():
    return create_access_token({"sub": PATIENT_ELEANOR_ID, "name": "Eleanor Vance", "role": "PATIENT"})


@pytest.fixture
def bob_token():
    return create_access_token({"sub": PATIENT_BOB_ID, "name": "Bob Martinez", "role": "PATIENT"})


@pytest.fixture
def doctor_sterling_token():
    return create_access_token({"sub": DOCTOR_STERLING_ACTIVE_ID, "name": "Dr. Marcus Sterling, MD", "role": "DOCTOR"})


@pytest.fixture
def doctor_oswald_token():
    return create_access_token({"sub": DOCTOR_OSWALD_REVOKED_ID, "name": "Dr. Clara Oswald, DDS", "role": "DOCTOR"})


@pytest.fixture
def doctor_no_consent_token():
    return create_access_token({"sub": DOCTOR_UNKNOWN_NO_CONSENT_ID, "name": "Dr. Unknown, MD", "role": "DOCTOR"})


@pytest.fixture
def auditor_token():
    return create_access_token({"sub": AUDITOR_ID, "name": "Federal Compliance Auditor", "role": "AUDITOR"})


# ==============================================================================
# 1. GET /api/v1/records: Consent Scoping & Global Listing Prevention
# ==============================================================================

def test_records_doctor_without_consent_blocked_403(doctor_no_consent_token):
    """Doctor without consent querying a specific patient's records is rejected with HTTP 403."""
    res = client.get(
        f"/api/v1/records?patient_id={PATIENT_ELEANOR_ID}",
        headers={"Authorization": f"Bearer {doctor_no_consent_token}"}
    )
    assert res.status_code == 403
    assert "active consent" in res.json()["detail"].lower()


def test_records_doctor_revoked_consent_blocked_403(doctor_oswald_token):
    """Doctor with revoked consent querying patient's records is rejected with HTTP 403."""
    res = client.get(
        f"/api/v1/records?patient_id={PATIENT_ELEANOR_ID}",
        headers={"Authorization": f"Bearer {doctor_oswald_token}"}
    )
    assert res.status_code == 403
    assert "active consent" in res.json()["detail"].lower()


def test_records_doctor_with_consent_allowed_200(doctor_sterling_token):
    """Doctor with active on-chain consent querying patient's records succeeds with HTTP 200."""
    res = client.get(
        f"/api/v1/records?patient_id={PATIENT_ELEANOR_ID}",
        headers={"Authorization": f"Bearer {doctor_sterling_token}"}
    )
    assert res.status_code == 200
    records = res.json()
    assert len(records) >= 1
    for r in records:
        assert r["patientId"] == PATIENT_ELEANOR_ID


def test_records_doctor_global_listing_prevents_unconsented_records(doctor_no_consent_token, doctor_sterling_token):
    """
    Doctor querying without patient_id must NEVER see global unconsented records:
    - Doctor with zero consents receives an empty list.
    - Doctor with consent for Eleanor only receives Eleanor's records.
    """
    # 1. Doctor with no active consent receives empty list, NOT all platform records
    res_no_consent = client.get(
        "/api/v1/records",
        headers={"Authorization": f"Bearer {doctor_no_consent_token}"}
    )
    assert res_no_consent.status_code == 200
    assert len(res_no_consent.json()) == 0

    # 2. Doctor Sterling receives only records for Eleanor Vance
    res_sterling = client.get(
        "/api/v1/records",
        headers={"Authorization": f"Bearer {doctor_sterling_token}"}
    )
    assert res_sterling.status_code == 200
    sterling_records = res_sterling.json()
    assert len(sterling_records) >= 1
    for r in sterling_records:
        assert r["patientId"] == PATIENT_ELEANOR_ID


# ==============================================================================
# 2. GET /api/v1/records/{record_id}: Consent Gating for Metadata
# ==============================================================================

def test_single_record_doctor_without_consent_blocked_403(doctor_no_consent_token):
    """Doctor without consent attempting to fetch record metadata is rejected with HTTP 403."""
    res = client.get(
        "/api/v1/records/rec-001",
        headers={"Authorization": f"Bearer {doctor_no_consent_token}"}
    )
    assert res.status_code == 403
    assert "active consent" in res.json()["detail"].lower()


def test_single_record_doctor_revoked_consent_blocked_403(doctor_oswald_token):
    """Doctor with revoked consent attempting to fetch record metadata is rejected with HTTP 403."""
    res = client.get(
        "/api/v1/records/rec-001",
        headers={"Authorization": f"Bearer {doctor_oswald_token}"}
    )
    assert res.status_code == 403
    assert "active consent" in res.json()["detail"].lower()


def test_single_record_doctor_with_active_consent_allowed_200(doctor_sterling_token):
    """Doctor with active consent retrieves single record metadata successfully with HTTP 200."""
    res = client.get(
        "/api/v1/records/rec-001",
        headers={"Authorization": f"Bearer {doctor_sterling_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    assert record["id"] == "rec-001"
    assert record["patientId"] == PATIENT_ELEANOR_ID


# ==============================================================================
# 3. GET /api/v1/consents and GET /api/v1/audit: Strict Ownership & Least Privilege
# ==============================================================================

def test_consents_patient_horizontal_isolation_blocked_403(bob_token):
    """Patient Bob querying Eleanor's consent records is rejected with HTTP 403."""
    res = client.get(
        f"/api/v1/consents?patient_id={PATIENT_ELEANOR_ID}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert res.status_code == 403
    assert "Horizontal Access Denied" in res.json()["detail"]


def test_audit_patient_horizontal_isolation_blocked_403(bob_token):
    """Patient Bob querying Eleanor's audit log history is rejected with HTTP 403."""
    res = client.get(
        f"/api/v1/audit?patient_id={PATIENT_ELEANOR_ID}",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert res.status_code == 403
    assert "Horizontal Access Denied" in res.json()["detail"]


def test_consents_doctor_least_privilege_scoping(doctor_sterling_token, doctor_no_consent_token):
    """
    Doctor querying consents only receives consents where they are the attending clinician.
    Never sees third-party doctor consents.
    """
    # Doctor Sterling sees consents where doctorId == doc-331902
    res_sterling = client.get("/api/v1/consents", headers={"Authorization": f"Bearer {doctor_sterling_token}"})
    assert res_sterling.status_code == 200
    for c in res_sterling.json():
        assert c["doctorId"] == DOCTOR_STERLING_ACTIVE_ID

    # Doctor with no consents receives empty list
    res_unknown = client.get("/api/v1/consents", headers={"Authorization": f"Bearer {doctor_no_consent_token}"})
    assert res_unknown.status_code == 200
    assert len(res_unknown.json()) == 0


def test_audit_doctor_least_privilege_scoping(doctor_sterling_token, doctor_no_consent_token):
    """
    Doctor querying audit trail only receives audit logs where they were the actor.
    Never sees third-party actions.
    """
    res_sterling = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {doctor_sterling_token}"})
    assert res_sterling.status_code == 200
    sterling_logs = res_sterling.json()
    assert len(sterling_logs) >= 1
    for log in sterling_logs:
        assert log["actorId"] == DOCTOR_STERLING_ACTIVE_ID

    # Doctor with no active consent only sees events where they were the actor (e.g. their own access attempts)
    res_unknown = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {doctor_no_consent_token}"})
    assert res_unknown.status_code == 200
    unknown_logs = res_unknown.json()
    for log in unknown_logs:
        assert log["actorId"] == DOCTOR_UNKNOWN_NO_CONSENT_ID
    # Rigorously verify zero exposure of Dr. Marcus Sterling or Eleanor Vance's actions
    assert not any(l["actorId"] == DOCTOR_STERLING_ACTIVE_ID for l in unknown_logs)
    assert not any(l["actorId"] == PATIENT_ELEANOR_ID for l in unknown_logs)


def test_auditor_compliance_oversight_consents_and_audit(auditor_token):
    """Auditor can query consents and audit records for compliance monitoring."""
    res_consents = client.get("/api/v1/consents", headers={"Authorization": f"Bearer {auditor_token}"})
    assert res_consents.status_code == 200
    assert len(res_consents.json()) >= 1

    res_audit = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {auditor_token}"})
    assert res_audit.status_code == 200
    assert len(res_audit.json()) >= 1


# ==============================================================================
# 4. POST /api/v1/records/upload: Target Patient & Authorization Validation
# ==============================================================================

def test_upload_nonexistent_patient_rejected_404(eleanor_token):
    """Uploading for a nonexistent patient ID returns HTTP 404."""
    data = {
        "patient_id": "pat-nonexistent-99999",
        "title": "Invalid Patient Test",
        "record_type": "LAB_REPORT",
        "hospital": "Metro Hospital",
        "description": "Valid clinical description."
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {eleanor_token}"})
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_upload_patient_horizontal_injection_blocked_403(bob_token):
    """Patient Bob attempting to upload a record under Eleanor's ID is rejected with HTTP 403."""
    data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Cross-Patient Injected Record",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Unauthorized injection attempt into another patient's vault."
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {bob_token}"})
    assert res.status_code == 403
    assert "Horizontal Access Denied" in res.json()["detail"]


def test_upload_doctor_without_consent_blocked_403(doctor_no_consent_token):
    """Doctor without consent attempting to upload for a patient is rejected with HTTP 403."""
    data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Unconsented Doctor Upload Attempt",
        "record_type": "LAB_REPORT",
        "hospital": "Metro Hospital",
        "description": "Clinical report submitted without consent."
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {doctor_no_consent_token}"})
    assert res.status_code == 403
    assert "active consent" in res.json()["detail"].lower()


def test_upload_doctor_with_active_consent_allowed_200(doctor_sterling_token):
    """Doctor with active on-chain consent uploading for patient succeeds with HTTP 200."""
    data = {
        "patient_id": PATIENT_ELEANOR_ID,
        "title": "Authorized Post-Op Clinical Consultation",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Authorized post-operative observation record uploaded under active consent."
    }
    res = client.post("/api/v1/records/upload", data=data, headers={"Authorization": f"Bearer {doctor_sterling_token}"})
    assert res.status_code == 200
    record = res.json()
    assert record["patientId"] == PATIENT_ELEANOR_ID
    assert record["title"] == "Authorized Post-Op Clinical Consultation"
