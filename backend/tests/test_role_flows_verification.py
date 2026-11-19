"""
MedTrust Role-Based Login & Dashboard Routing Verification Test Suite.
Validates all four platform roles (Patient, Doctor, Administrator, Auditor):
- Account availability & persistent credentials verification
- Live authentication & JWT session hydration
- Dynamic dashboard data retrieval & role authorization
- Cross-role isolation & Healthcare Least-Privilege privacy boundaries
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.schemas import UserRole
from app.db.session import SessionLocal
from app.db.models import UserModel


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


class TestRoleBasedLoginAndRouting:
    """Verifies all four role flows end-to-end."""

    def test_01_verify_available_accounts_in_database(self):
        """Verifies that all 4 platform roles exist in the persistent SQLite database."""
        db = SessionLocal()
        try:
            expected_accounts = {
                "PATIENT": "e.vance@example.med",
                "DOCTOR": "m.sterling@metrohealth.org",
                "ADMIN": "admin@medtrust.org",
                "AUDITOR": "auditor@medtrust.gov"
            }
            for role_name, email in expected_accounts.items():
                user = db.query(UserModel).filter(UserModel.email == email).first()
                assert user is not None, f"Account for role {role_name} ({email}) must exist in SQLite database"
                assert user.role == role_name, f"Account {email} must have role {role_name}, got {user.role}"
                assert user.is_active is True, f"Account {email} must be active"
        finally:
            db.close()

    def test_02_patient_login_and_vault_routing(self, client):
        """Tests Patient login, JWT claims, and patient vault data routing."""
        # 1. Authenticate as Patient
        login_res = client.post("/api/v1/auth/login", json={
            "email": "e.vance@example.med",
            "password": "password123"
        })
        assert login_res.status_code == 200
        data = login_res.json()
        token = data["accessToken"]
        user = data["user"]

        assert user["role"] == "PATIENT"
        assert user["id"] == "pat-984210"
        assert user["name"] == "Eleanor Vance"

        headers = {"Authorization": f"Bearer {token}"}

        # 2. Verify /auth/me hydration
        me_res = client.get("/api/v1/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["role"] == "PATIENT"

        # 3. Patient Vault Data: records & consents scoped to patient
        records_res = client.get(f"/api/v1/records?patient_id={user['id']}", headers=headers)
        assert records_res.status_code == 200
        records = records_res.json()
        assert len(records) >= 1
        for rec in records:
            assert rec["patientId"] == user["id"]

        consents_res = client.get(f"/api/v1/consents?patient_id={user['id']}", headers=headers)
        assert consents_res.status_code == 200

        # 4. Horizontal Isolation: Patient cannot access another patient's vault
        other_patient_res = client.get("/api/v1/records?patient_id=pat-999999", headers=headers)
        assert other_patient_res.status_code == 403

    def test_03_doctor_login_and_clinical_portal_routing(self, client):
        """Tests Doctor login, JWT claims, and clinical portal data routing."""
        # 1. Authenticate as Doctor
        login_res = client.post("/api/v1/auth/login", json={
            "email": "m.sterling@metrohealth.org",
            "password": "password123"
        })
        assert login_res.status_code == 200
        data = login_res.json()
        token = data["accessToken"]
        user = data["user"]

        assert user["role"] == "DOCTOR"
        assert user["id"] == "doc-331902"
        assert "Marcus Sterling" in user["name"]
        assert user["specialty"] == "Cardiovascular Surgery"

        headers = {"Authorization": f"Bearer {token}"}

        # 2. Verify /auth/me hydration
        me_res = client.get("/api/v1/auth/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["role"] == "DOCTOR"

        # 3. Doctor Clinical Portal: Query records and consents
        records_res = client.get("/api/v1/records", headers=headers)
        assert records_res.status_code == 200
        assert len(records_res.json()) >= 1

        consents_res = client.get("/api/v1/consents", headers=headers)
        assert consents_res.status_code == 200

    def test_04_admin_login_and_console_routing(self, client):
        """Tests Administrator login, telemetry routing, and Zero-PHI boundary."""
        # 1. Authenticate as Admin
        login_res = client.post("/api/v1/auth/login", json={
            "email": "admin@medtrust.org",
            "password": "admin123"
        })
        assert login_res.status_code == 200
        data = login_res.json()
        token = data["accessToken"]
        user = data["user"]

        assert user["role"] == "ADMIN"
        assert user["id"] == "adm-999999"

        headers = {"Authorization": f"Bearer {token}"}

        # 2. Admin Console: Telemetry, User Listing, and Security Events
        telemetry_res = client.get("/api/v1/admin/telemetry", headers=headers)
        assert telemetry_res.status_code == 200
        telemetry = telemetry_res.json()
        assert telemetry["privacyBoundaryEnforced"] is True
        assert telemetry["adminClinicalAccessBanned"] is True

        users_res = client.get("/api/v1/admin/users", headers=headers)
        assert users_res.status_code == 200
        assert len(users_res.json()) >= 4

        events_res = client.get("/api/v1/admin/security-events", headers=headers)
        assert events_res.status_code == 200

        # 3. Healthcare Least-Privilege Privacy Boundary: Admin cannot access medical records
        records_res = client.get("/api/v1/records", headers=headers)
        assert records_res.status_code == 403
        assert "Administrative Privacy Boundary" in records_res.json()["detail"]

    def test_05_auditor_login_and_compliance_ledger_routing(self, client):
        """Tests Auditor login, audit log querying, and cryptographic chain verification."""
        # 1. Authenticate as Auditor
        login_res = client.post("/api/v1/auth/login", json={
            "email": "auditor@medtrust.gov",
            "password": "password123"
        })
        assert login_res.status_code == 200
        data = login_res.json()
        token = data["accessToken"]
        user = data["user"]

        assert user["role"] == "AUDITOR"
        assert user["id"] == "aud-001001"

        headers = {"Authorization": f"Bearer {token}"}

        # 2. Auditor Dashboard: Query immutable audit logs
        logs_res = client.get("/api/v1/audit", headers=headers)
        assert logs_res.status_code == 200
        logs = logs_res.json()
        assert len(logs) >= 1

        # 3. Cryptographic Merkle/Hash-Chain Verification
        chain_res = client.get("/api/v1/audit/verify", headers=headers)
        assert chain_res.status_code == 200
        chain_data = chain_res.json()
        assert chain_data["chainIntact"] is True

    def test_06_registration_role_gate_enforcement(self, client):
        """Verifies that public self-registration is strictly locked to PATIENT."""
        # Attempt to self-register as DOCTOR must be rejected with 403
        doc_reg = client.post("/api/v1/auth/register", json={
            "name": "Dr. Hacker, MD",
            "email": "hacker.doc@evil.med",
            "password": "password123",
            "role": "DOCTOR"
        })
        assert doc_reg.status_code == 403
        assert "restricted to Patients only" in doc_reg.json()["detail"]

        # Attempt to self-register as ADMIN must be rejected with 403
        adm_reg = client.post("/api/v1/auth/register", json={
            "name": "Fake Admin",
            "email": "fake.admin@evil.med",
            "password": "password123",
            "role": "ADMIN"
        })
        assert adm_reg.status_code == 403
        assert "restricted to Patients only" in adm_reg.json()["detail"]
