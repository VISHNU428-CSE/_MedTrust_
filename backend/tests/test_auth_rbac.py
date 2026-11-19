import time
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token, verify_and_decode_token
from app.core.exceptions import AccessDeniedError

client = TestClient(app)


def test_login_patient_success():
    res = client.post("/api/v1/auth/login", json={
        "email": "e.vance@example.med",
        "password": "password123"
    })
    assert res.status_code == 200
    data = res.json()
    assert ("accessToken" in data) or ("access_token" in data)
    assert data["user"]["role"] == "PATIENT"
    assert data["user"]["name"] == "Eleanor Vance"


def test_login_doctor_success():
    res = client.post("/api/v1/auth/login", json={
        "email": "m.sterling@metrohealth.org",
        "password": "password123"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["role"] == "DOCTOR"
    assert data["user"]["hospital"] == "Metro General Hospital"


def test_login_admin_success():
    res = client.post("/api/v1/auth/login", json={
        "email": "admin@medtrust.org",
        "password": "admin123"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["role"] == "ADMIN"
    assert data["user"]["name"] == "Platform Administrator"


def test_login_auditor_success():
    res = client.post("/api/v1/auth/login", json={
        "email": "auditor@medtrust.gov",
        "password": "password123"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["role"] == "AUDITOR"
    assert data["user"]["name"] == "Federal Compliance Auditor"



def test_login_invalid_password_rejected():
    res = client.post("/api/v1/auth/login", json={
        "email": "e.vance@example.med",
        "password": "wrong-password"
    })
    assert res.status_code == 401


def test_register_non_patient_role_blocked():
    """Confirms public self-registration is restricted to Patients only."""
    import uuid
    doc_email = f"dr.house.{uuid.uuid4().hex[:6]}@princetonplainsboro.med"
    res = client.post("/api/v1/auth/register", json={
        "name": "Dr. Gregory House, MD",
        "email": doc_email,
        "password": "diagnostics123",
        "role": "DOCTOR",
        "hospital": "Princeton-Plainsboro",
        "specialty": "Diagnostic Medicine"
    })
    assert res.status_code == 403
    assert "restricted to Patients only" in res.json()["detail"]


def test_register_new_patient_success():
    """Confirms public self-registration succeeds for Patients."""
    import uuid
    patient_email = f"new.patient.{uuid.uuid4().hex[:6]}@example.med"
    res = client.post("/api/v1/auth/register", json={
        "name": "Jane Doe",
        "email": patient_email,
        "password": "securepassword123",
        "role": "PATIENT"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["user"]["email"] == patient_email
    assert data["user"]["role"] == "PATIENT"


def test_unauthenticated_request_rejected():
    """Confirms endpoints protected by get_current_user reject unauthenticated callers."""
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers


def test_logout_flow():
    """Confirms user can safely log out and revoke their active session."""
    login_res = client.post("/api/v1/auth/login", json={
        "email": "e.vance@example.med",
        "password": "password123"
    })
    token = login_res.json().get("accessToken") or login_res.json().get("access_token")
    logout_res = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200
    assert logout_res.json()["success"] is True

    # Re-accessing protected endpoint with revoked token must now be rejected with 401
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 401


def test_password_recovery_request():
    """Confirms password recovery accepts registered emails with safe responses."""
    res = client.post("/api/v1/auth/recover", json={"email": "e.vance@example.med"})
    assert res.status_code == 200
    assert res.json()["success"] is True


def test_admin_management_endpoints():
    """Confirms Administrator console endpoints work and block non-admins."""
    pat_token = create_access_token({"sub": "pat-984210", "role": "PATIENT"})
    admin_token = create_access_token({"sub": "adm-999999", "role": "ADMIN"})

    # Non-admin attempting to list users -> 403
    forbidden_res = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {pat_token}"})
    assert forbidden_res.status_code == 403

    # Admin listing users -> 200
    users_res = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert users_res.status_code == 200
    users = users_res.json()
    assert len(users) >= 4
    # Ensure password hash is not exposed
    assert "password_hash" not in users[0]
    assert "passwordHash" not in users[0]

    # Admin telemetry -> 200
    telem_res = client.get("/api/v1/admin/telemetry", headers={"Authorization": f"Bearer {admin_token}"})
    assert telem_res.status_code == 200
    telem = telem_res.json()
    assert telem["privacyBoundaryEnforced"] is True
    assert telem["adminClinicalAccessBanned"] is True

    # Admin security events -> 200
    sec_res = client.get("/api/v1/admin/security-events", headers={"Authorization": f"Bearer {admin_token}"})
    assert sec_res.status_code == 200
    sec_events = sec_res.json()
    assert isinstance(sec_events, list)

    # Admin suspend user -> 200
    try:
        suspend_res = client.patch(
            "/api/v1/admin/users/aud-001001/status",
            json={"isActive": False},
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert suspend_res.status_code == 200
        assert suspend_res.json()["isActive"] is False

        # Suspended user login -> 403
        suspended_login = client.post("/api/v1/auth/login", json={
            "email": "auditor@medtrust.gov",
            "password": "password123"
        })
        assert suspended_login.status_code == 403
    finally:
        # Guarantee user is always reactivated so other tests aren't poisoned
        client.patch(
            "/api/v1/admin/users/aud-001001/status",
            json={"isActive": True},
            headers={"Authorization": f"Bearer {admin_token}"}
        )


def test_auth_me_with_bearer_token():
    login_res = client.post("/api/v1/auth/login", json={
        "email": "e.vance@example.med",
        "password": "password123"
    })
    token = login_res.json().get("accessToken") or login_res.json().get("access_token")
    
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["id"] == "pat-984210"
    assert me_data["role"] == "PATIENT"


def test_tampered_token_signature_rejected():
    token = create_access_token({"sub": "pat-984210", "role": "PATIENT"})
    parts = token.split(".")
    parts[1] = parts[1] + "tamper"
    tampered_token = ".".join(parts)
    
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401
