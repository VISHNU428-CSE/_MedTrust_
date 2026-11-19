"""
MedTrust Patient Identity Verification Suite.
Directly validates FastAPI backend authentication, registration, login, session hydration,
and patient-scoped record isolation.
"""

import sys
import os
import uuid
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
# Ensure current working directory is backend directory so sqlite:///./medtrust.db resolves accurately
os.chdir(str(backend_dir))
sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from app.db.session import SessionLocal
from app.db.models import UserModel


def run_verification():
    print("=== MedTrust Patient Identity Verification Suite ===")
    client = TestClient(app)

    # 1. Existing registered user 'vishnu'
    print("\n[Step 1] Verifying existing user 'vishnu' profile via /api/v1/auth/me...")
    db = SessionLocal()
    try:
        db_vishnu = db.query(UserModel).filter(UserModel.email == "99230040807@klu.ac.in").first()
        assert db_vishnu is not None, "User 'vishnu' (99230040807@klu.ac.in) must exist in database"
        vishnu_id = db_vishnu.id
        vishnu_name = db_vishnu.name
        vishnu_role = db_vishnu.role
        print(f"  -> DB Record: id={vishnu_id}, name={vishnu_name}, role={vishnu_role}")
    finally:
        db.close()

    vishnu_claims = {
        "sub": vishnu_id,
        "name": vishnu_name,
        "email": "99230040807@klu.ac.in",
        "role": vishnu_role,
    }
    token = create_access_token(vishnu_claims)
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    me_resp = res.json()
    print(f"  -> Profile Name: {me_resp.get('name')}")
    print(f"  -> Patient ID:   {me_resp.get('id')}")
    print(f"  -> Role:         {me_resp.get('role')}")
    assert me_resp["name"] == vishnu_name, f"Expected '{vishnu_name}', got '{me_resp.get('name')}'"
    assert me_resp["id"] == vishnu_id
    assert me_resp["role"] == "PATIENT"
    print("  [PASS] Existing user 'vishnu' authenticated profile verified.")

    # 2. Register a new unique patient
    rand_tag = uuid.uuid4().hex[:6]
    test_name = f"Test Subject {rand_tag}"
    test_email = f"patient.{rand_tag}@example.med"
    print(f"\n[Step 2] Registering new patient '{test_name}' ({test_email})...")
    reg_res = client.post("/api/v1/auth/register", json={
        "name": test_name,
        "email": test_email,
        "password": "Password123!",
        "role": "PATIENT"
    })
    assert reg_res.status_code == 200, f"Expected 200, got {reg_res.status_code}: {reg_res.text}"
    reg_data = reg_res.json()
    new_user = reg_data["user"]
    new_token = reg_data.get("accessToken") or reg_data.get("access_token")
    print(f"  -> Registered ID:   {new_user['id']}")
    print(f"  -> Registered Name: {new_user['name']}")
    print(f"  -> Registered Role: {new_user['role']}")
    assert new_user["name"] == test_name
    assert new_user["role"] == "PATIENT"
    assert new_user["id"].startswith("pat-") or new_user["id"].startswith("usr-")
    assert new_token is not None
    print("  [PASS] Registration returns exact registered name and patient ID.")

    # 3. Login with newly registered credentials
    print(f"\n[Step 3] Logging in with '{test_email}'...")
    login_res = client.post("/api/v1/auth/login", json={
        "email": test_email,
        "password": "Password123!"
    })
    assert login_res.status_code == 200, f"Expected 200, got {login_res.status_code}: {login_res.text}"
    login_data = login_res.json()
    login_user = login_data["user"]
    login_token = login_data.get("accessToken") or login_data.get("access_token")
    print(f"  -> Login ID:   {login_user['id']}")
    print(f"  -> Login Name: {login_user['name']}")
    assert login_user["name"] == test_name
    assert login_user["id"] == new_user["id"]
    print("  [PASS] Login returns exact registered profile.")

    # 4. Page refresh / session hydration simulation via /auth/me
    print("\n[Step 4] Simulating page refresh: Hydrating session via /auth/me with login Bearer token...")
    hydrate_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {login_token}"})
    assert hydrate_res.status_code == 200, f"Expected 200, got {hydrate_res.status_code}: {hydrate_res.text}"
    hydrate_data = hydrate_res.json()
    print(f"  -> Hydrated ID:   {hydrate_data['id']}")
    print(f"  -> Hydrated Name: {hydrate_data['name']}")
    assert hydrate_data["name"] == test_name
    assert hydrate_data["id"] == new_user["id"]
    print("  [PASS] Page refresh hydration (/auth/me) preserves registered name and patient ID.")

    # 5. Patient records isolation check
    print("\n[Step 5] Checking medical records isolation for new patient...")
    records_res = client.get(
        f"/api/v1/records?patient_id={new_user['id']}",
        headers={"Authorization": f"Bearer {login_token}"}
    )
    assert records_res.status_code == 200, f"Expected 200, got {records_res.status_code}: {records_res.text}"
    records = records_res.json()
    print(f"  -> Records count for {new_user['id']}: {len(records)}")
    assert len(records) == 0, f"Expected 0 records, found {len(records)} leaked records"
    print("  [PASS] Records are strictly isolated; zero leakage from demo patient (Eleanor Vance).")

    # 6. Upload a record with dynamic patient name resolution
    print("\n[Step 6] Testing record upload with dynamic patient name resolution...")
    dummy_pdf = b"%PDF-1.4 Mock Clinical Report Content For Test"
    upload_res = client.post(
        "/api/v1/records/upload",
        data={
            "patient_id": new_user["id"],
            "title": "Comprehensive Test Health Check",
            "record_type": "LAB_REPORT",
            "hospital": "Metro General Hospital",
        },
        files={
            "file": ("test_report.pdf", dummy_pdf, "application/pdf")
        },
        headers={"Authorization": f"Bearer {login_token}"}
    )
    assert upload_res.status_code == 200, f"Expected 200, got {upload_res.status_code}: {upload_res.text}"
    uploaded_record = upload_res.json()
    print(f"  -> Uploaded Record ID:   {uploaded_record.get('id')}")
    print(f"  -> Patient Name on Rec: {uploaded_record.get('patientName') or uploaded_record.get('patient_name')}")
    print(f"  -> Patient ID on Rec:   {uploaded_record.get('patientId') or uploaded_record.get('patient_id')}")
    resolved_name = uploaded_record.get('patientName') or uploaded_record.get('patient_name')
    assert resolved_name == test_name, f"Expected '{test_name}', got '{resolved_name}' (Eleanor Vance mismatch prevented!)"
    print("  [PASS] Uploaded record resolves dynamic patient name without fallback to 'Eleanor Vance'.")

    # 7. Horizontal isolation test: new patient cannot query Eleanor Vance records
    print("\n[Step 7] Testing horizontal privilege escalation barrier...")
    unauth_query = client.get(
        "/api/v1/records?patient_id=pat-984210",
        headers={"Authorization": f"Bearer {login_token}"}
    )
    print(f"  -> Attempting to access pat-984210 records with {new_user['id']} token: status={unauth_query.status_code}")
    assert unauth_query.status_code == 403, f"Expected 403 Forbidden, got {unauth_query.status_code}"
    print("  [PASS] Horizontal security invariant intact: patient cannot access other patients' records.")

    print("\n>>> ALL 7 PATIENT IDENTITY & SECURITY VERIFICATION TESTS PASSED SUCCESSFULLY! <<<\n")


if __name__ == "__main__":
    run_verification()
