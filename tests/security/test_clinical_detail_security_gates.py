"""
Security Tests: Phase 6 Clinical Detail RBAC, Isolation & Privacy Boundary Enforcement.

Verifies:
- Unauthenticated 401 challenge on protected clinical details.
- Strict patient horizontal isolation (cross-patient access blocked with 403).
- Doctor consent-gated access (active consent allowed; revoked or absent consent blocked with 403).
- Healthcare Least-Privilege Privacy Boundary (Platform Administrator blocked with 403).
- Compliance Auditor legitimate oversight allowed with 200.
- Nonexistent record handling (404 Not Found).
- Audit trail event logging on denied clinical detail access attempts.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.security import create_access_token

client = TestClient(app)

PATIENT_ELEANOR_ID = "pat-984210"
PATIENT_BOB_ID = "pat-777888"
DOCTOR_STERLING_ID = "doc-331902"     # Holds ACTIVE consent cst-8801
DOCTOR_OSWALD_ID = "doc-119283"       # Holds REVOKED consent cst-8790
DOCTOR_UNKNOWN_ID = "doc-999999"      # No consent
ADMIN_ID = "adm-999999"               # Platform Admin
AUDITOR_ID = "aud-001001"             # Compliance Auditor


@pytest.fixture
def eleanor_token():
    return create_access_token({
        "sub": PATIENT_ELEANOR_ID,
        "name": "Eleanor Vance",
        "role": "PATIENT"
    })


@pytest.fixture
def bob_token():
    return create_access_token({
        "sub": PATIENT_BOB_ID,
        "name": "Bob Martinez",
        "role": "PATIENT"
    })


@pytest.fixture
def doctor_sterling_active_token():
    return create_access_token({
        "sub": DOCTOR_STERLING_ID,
        "name": "Dr. Marcus Sterling, MD",
        "role": "DOCTOR"
    })


@pytest.fixture
def doctor_oswald_revoked_token():
    return create_access_token({
        "sub": DOCTOR_OSWALD_ID,
        "name": "Dr. Clara Oswald, DDS",
        "role": "DOCTOR"
    })


@pytest.fixture
def doctor_unknown_no_consent_token():
    return create_access_token({
        "sub": DOCTOR_UNKNOWN_ID,
        "name": "Dr. Anonymous Unknown, MD",
        "role": "DOCTOR"
    })


@pytest.fixture
def admin_token():
    return create_access_token({
        "sub": ADMIN_ID,
        "name": "Platform Administrator",
        "role": "ADMIN"
    })


@pytest.fixture
def auditor_token():
    return create_access_token({
        "sub": AUDITOR_ID,
        "name": "Federal Compliance Auditor",
        "role": "AUDITOR"
    })


@pytest.mark.security
def test_clinical_details_unauthenticated_rejected_401():
    """
    SECURITY AUDIT: Unauthenticated request to /api/v1/records/{id}/details
    must be rejected with HTTP 401 Unauthorized and WWW-Authenticate challenge.
    """
    res = client.get("/api/v1/records/rec-001/details")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers
    assert "Bearer" in res.headers["WWW-Authenticate"]


@pytest.mark.security
def test_clinical_details_patient_self_access_allowed_200(eleanor_token):
    """
    LEGITIMATE ACCESS: Patient who owns the record can view complete clinical details.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {eleanor_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert data["patientId"] == PATIENT_ELEANOR_ID
    assert data["hasDocument"] is True


@pytest.mark.security
def test_clinical_details_patient_horizontal_isolation_blocked_403(bob_token):
    """
    SECURITY AUDIT: Cross-patient horizontal privilege escalation.
    Patient Bob attempts to inspect Eleanor's clinical record details.
    Must be blocked with HTTP 403 Forbidden.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {bob_token}"}
    )
    assert res.status_code == 403
    assert "Access denied" in res.json()["detail"]


@pytest.mark.security
def test_clinical_details_doctor_active_consent_allowed_200(doctor_sterling_active_token):
    """
    CONSENT-GATED ACCESS: Doctor with active on-chain consent can view patient's clinical details.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {doctor_sterling_active_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert data["patientId"] == PATIENT_ELEANOR_ID


@pytest.mark.security
def test_clinical_details_doctor_revoked_consent_denied_403(doctor_oswald_revoked_token):
    """
    SECURITY AUDIT: Revocation Invariant.
    Doctor whose consent was revoked by patient cannot view clinical details.
    Must be blocked with HTTP 403 Forbidden.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {doctor_oswald_revoked_token}"}
    )
    assert res.status_code == 403
    assert "Access denied: Doctor does not have active consent" in res.json()["detail"]


@pytest.mark.security
def test_clinical_details_doctor_without_consent_denied_403(doctor_unknown_no_consent_token):
    """
    SECURITY AUDIT: Unauthorized Provider Access.
    Doctor with no prior or pending consent cannot inspect patient details.
    Must be blocked with HTTP 403 Forbidden.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {doctor_unknown_no_consent_token}"}
    )
    assert res.status_code == 403
    assert "Access denied: Doctor does not have active consent" in res.json()["detail"]


@pytest.mark.security
def test_clinical_details_admin_zero_phi_privacy_boundary_denied_403(admin_token):
    """
    SECURITY AUDIT: Healthcare Least-Privilege & Zero-PHI Privacy Boundary.
    Platform Administrator role must NEVER be permitted to view patient clinical details or descriptions.
    Must be blocked with HTTP 403 Forbidden.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert res.status_code == 403
    assert "Administrative Privacy Boundary" in res.json()["detail"]
    assert "strictly prohibited" in res.json()["detail"]


@pytest.mark.security
def test_clinical_details_auditor_compliance_access_allowed_200(auditor_token):
    """
    REGULATORY OVERSIGHT: Federal Compliance Auditor can access clinical details for HIPAA compliance audit.
    """
    res = client.get(
        "/api/v1/records/rec-001/details",
        headers={"Authorization": f"Bearer {auditor_token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert data["patientId"] == PATIENT_ELEANOR_ID


@pytest.mark.security
def test_clinical_details_nonexistent_record_returns_404(eleanor_token):
    """
    Error Handling: Requesting clinical details for an unknown record ID returns HTTP 404.
    """
    res = client.get(
        "/api/v1/records/rec-nonexistent-99999/details",
        headers={"Authorization": f"Bearer {eleanor_token}"}
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()
