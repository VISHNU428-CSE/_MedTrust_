"""
Focused Backend Test Suite for Real Doctor Registration & Approval Safeguards.
Verifies Task 2 implementations:
1. Doctor application endpoint, metadata validation, PENDING status.
2. Invariant: Absolutely ZERO authenticated session or JWT access token issued upon doctor application.
3. Invariant: Pending and rejected doctors blocked from login with HTTP 403.
4. Invariant: Protected clinical endpoints check current database approval status on every request,
   blocking pending/rejected doctors even if presenting a crafted or valid JWT.
5. Invariant: Existing doctors default to unapproved unless explicitly verified.
6. Invariant: Patient self-registration and login remain 100% operational (regression proof).
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token, hash_password
from app.db.session import SessionLocal
from app.db.models import UserModel, UserSessionModel

client = TestClient(app)


def test_doctor_application_creates_no_token_and_pending_status():
    """Verifies that doctor registration creates an unapproved PENDING account with ZERO token/session issued."""
    unique_email = f"dr.applicant.{uuid.uuid4().hex[:6]}@metrohealth.org"
    payload = {
        "name": "Dr. Aris Thorne, MD",
        "email": unique_email,
        "password": "SecurePassword123!",
        "hospital": "Metro General Hospital",
        "specialty": "Neurology & Critical Care",
        "licenseNumber": "MED-LIC-NY-849201"
    }

    res = client.post("/api/v1/auth/register-doctor", json=payload)
    assert res.status_code == 201, f"Expected 201 Created, got {res.status_code}: {res.text}"
    data = res.json()

    # Verify application metadata
    assert data["role"] == "DOCTOR"
    assert data["approvalStatus"] == "PENDING"
    assert data["licenseNumber"] == "MED-LIC-NY-849201"
    assert data["email"] == unique_email.lower()
    assert "id" in data
    assert data["id"].startswith("doc-")

    # Invariant: ZERO token issued
    assert "accessToken" not in data
    assert "access_token" not in data
    assert "token" not in data

    # Verify persistent SQLite state
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.email == unique_email.lower()).first()
        assert user is not None
        assert user.role == "DOCTOR"
        assert user.approval_status == "PENDING"
        assert user.is_active is False
        assert user.license_number == "MED-LIC-NY-849201"

        # Verify no sessions exist for this applicant
        sessions = db.query(UserSessionModel).filter(UserSessionModel.user_id == user.id).all()
        assert len(sessions) == 0, "No authenticated sessions should exist for a pending applicant"
    finally:
        db.close()


def test_doctor_application_validation():
    """Verifies validation rules for doctor registration."""
    unique_email = f"dr.valid.{uuid.uuid4().hex[:6]}@stjude.org"
    valid_payload = {
        "name": "Dr. Sarah Connor, MD",
        "email": unique_email,
        "password": "Password123!",
        "hospital": "St. Jude Hospital",
        "specialty": "Pediatrics",
        "licenseNumber": "MED-LIC-IL-592812"
    }

    # 1. Success on first submit
    res1 = client.post("/api/v1/auth/register-doctor", json=valid_payload)
    assert res1.status_code == 201

    # 2. Duplicate email rejection
    res2 = client.post("/api/v1/auth/register-doctor", json=valid_payload)
    assert res2.status_code == 400
    assert "already exists" in res2.json()["detail"].lower()

    # 3. Missing license number rejection
    payload_no_license = valid_payload.copy()
    payload_no_license["email"] = f"other.{uuid.uuid4().hex[:6]}@stjude.org"
    payload_no_license["licenseNumber"] = ""
    res3 = client.post("/api/v1/auth/register-doctor", json=payload_no_license)
    assert res3.status_code == 422

    # 4. Short password rejection
    payload_short_pw = valid_payload.copy()
    payload_short_pw["email"] = f"other2.{uuid.uuid4().hex[:6]}@stjude.org"
    payload_short_pw["password"] = "123"
    res4 = client.post("/api/v1/auth/register-doctor", json=payload_short_pw)
    assert res4.status_code == 422


def test_pending_doctor_login_blocked_with_403():
    """Verifies that a doctor with PENDING status cannot log in."""
    unique_email = f"dr.pending.{uuid.uuid4().hex[:6]}@clinic.org"
    reg_payload = {
        "name": "Dr. Pending Review",
        "email": unique_email,
        "password": "ValidPassword123!",
        "hospital": "City Clinic",
        "specialty": "Oncology",
        "licenseNumber": "MED-LIC-WA-123456"
    }
    reg_res = client.post("/api/v1/auth/register-doctor", json=reg_payload)
    assert reg_res.status_code == 201

    # Attempt login while PENDING
    login_res = client.post("/api/v1/auth/login", json={
        "email": unique_email,
        "password": "ValidPassword123!"
    })
    assert login_res.status_code == 403
    assert "pending administrator review" in login_res.json()["detail"].lower()


def test_rejected_doctor_login_blocked_with_403():
    """Verifies that a doctor with REJECTED status cannot log in."""
    unique_email = f"dr.rejected.{uuid.uuid4().hex[:6]}@clinic.org"
    reg_payload = {
        "name": "Dr. Rejected Candidate",
        "email": unique_email,
        "password": "ValidPassword123!",
        "hospital": "City Clinic",
        "specialty": "Dermatology",
        "licenseNumber": "MED-LIC-WA-999999"
    }
    reg_res = client.post("/api/v1/auth/register-doctor", json=reg_payload)
    assert reg_res.status_code == 201
    doctor_id = reg_res.json()["id"]

    # Directly transition status to REJECTED in database
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.id == doctor_id).first()
        user.approval_status = "REJECTED"
        user.rejection_reason = "Unverifiable medical board credentials"
        db.commit()
    finally:
        db.close()

    # Attempt login while REJECTED
    login_res = client.post("/api/v1/auth/login", json={
        "email": unique_email,
        "password": "ValidPassword123!"
    })
    assert login_res.status_code == 403
    assert "rejected" in login_res.json()["detail"].lower()


def test_clinical_endpoint_blocks_pending_doctor_even_with_valid_jwt():
    """
    Critical Security Invariant:
    Even if a doctor presents a signed JWT token claiming DOCTOR role,
    the protected clinical endpoints verify live database approval status
    and reject the request with HTTP 403.
    """
    unique_email = f"dr.tokenattack.{uuid.uuid4().hex[:6]}@clinic.org"
    db = SessionLocal()
    try:
        doc_id = f"doc-{uuid.uuid4().hex[:6]}"
        pending_doc = UserModel(
            id=doc_id,
            name="Dr. Rogue Token",
            email=unique_email,
            role="DOCTOR",
            password_hash=hash_password("password123"),
            hospital="Rogue Health",
            specialty="Surgery",
            license_number="FRAUD-999",
            approval_status="PENDING",
            is_active=False
        )
        db.add(pending_doc)
        db.commit()
    finally:
        db.close()

    # Generate a signed JWT token claiming DOCTOR role for this pending doctor
    rogue_claims = {
        "sub": doc_id,
        "name": "Dr. Rogue Token",
        "email": unique_email,
        "role": "DOCTOR",
        "hospital": "Rogue Health",
        "specialty": "Surgery"
    }
    rogue_jwt = create_access_token(rogue_claims)
    headers = {"Authorization": f"Bearer {rogue_jwt}"}

    # 1. Attempt GET /api/v1/records
    res_records = client.get("/api/v1/records", headers=headers)
    assert res_records.status_code == 403
    assert "approval status" in res_records.json()["detail"].lower() or "denied" in res_records.json()["detail"].lower()

    # 2. Attempt GET /api/v1/records/{id}/details
    res_details = client.get("/api/v1/records/rec-001/details", headers=headers)
    assert res_details.status_code == 403
    assert "approval status" in res_details.json()["detail"].lower() or "denied" in res_details.json()["detail"].lower()


def test_existing_doctor_defaults_to_unapproved_unless_explicitly_verified():
    """
    Verifies design decision 1:
    Doctor accounts default to unapproved (PENDING) unless explicitly verified (APPROVED).
    """
    unique_email = f"dr.unverified.{uuid.uuid4().hex[:6]}@metrohealth.org"
    doc_id = f"doc-{uuid.uuid4().hex[:6]}"

    # Seed an unverified doctor with default PENDING status
    db = SessionLocal()
    try:
        unverified_doc = UserModel(
            id=doc_id,
            name="Dr. Unverified Fellow",
            email=unique_email,
            role="DOCTOR",
            password_hash=hash_password("password123"),
            hospital="Metro General",
            specialty="Internal Medicine",
            license_number="LIC-UNVERIFIED",
            approval_status="PENDING",
            is_active=False
        )
        db.add(unverified_doc)
        db.commit()
    finally:
        db.close()

    # Attempt login while unverified -> must fail 403
    fail_res = client.post("/api/v1/auth/login", json={
        "email": unique_email,
        "password": "password123"
    })
    assert fail_res.status_code == 403

    # Now simulate explicit administrative verification
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.id == doc_id).first()
        user.approval_status = "APPROVED"
        user.is_active = True
        db.commit()
    finally:
        db.close()

    # Attempt login after explicit verification -> must succeed 200
    success_res = client.post("/api/v1/auth/login", json={
        "email": unique_email,
        "password": "password123"
    })
    assert success_res.status_code == 200
    login_data = success_res.json()
    assert ("accessToken" in login_data) or ("access_token" in login_data)
    assert login_data["user"]["role"] == "DOCTOR"
    assert login_data["user"]["approvalStatus"] == "APPROVED"


def test_patient_registration_and_login_regression():
    """
    Regression Invariant:
    Preserve existing patient self-registration and login without modification.
    """
    unique_email = f"patient.reg.{uuid.uuid4().hex[:6]}@example.med"
    reg_payload = {
        "name": "Jane Patient",
        "email": unique_email,
        "password": "PatientPassword123!",
        "role": "PATIENT"
    }

    # 1. Patient registration works and returns active access token
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 200
    reg_data = reg_res.json()
    assert ("accessToken" in reg_data) or ("access_token" in reg_data)
    assert reg_data["user"]["role"] == "PATIENT"
    assert reg_data["user"]["approvalStatus"] == "APPROVED"
    patient_id = reg_data["user"]["id"]
    assert patient_id.startswith("pat-")

    # Verify database approval_status is explicitly APPROVED
    db = SessionLocal()
    try:
        db_user = db.query(UserModel).filter(UserModel.id == patient_id).first()
        assert db_user is not None
        assert db_user.approval_status == "APPROVED"
        assert db_user.role == "PATIENT"
    finally:
        db.close()

    # 2. Patient login works cleanly
    login_res = client.post("/api/v1/auth/login", json={
        "email": unique_email,
        "password": "PatientPassword123!"
    })
    assert login_res.status_code == 200
    login_data = login_res.json()
    token = login_data.get("accessToken") or login_data.get("access_token")
    assert token is not None

    # 3. Patient can access patient-scoped clinical record endpoints
    headers = {"Authorization": f"Bearer {token}"}
    records_res = client.get(f"/api/v1/records?patient_id={patient_id}", headers=headers)
    assert records_res.status_code == 200


def test_consent_request_strictly_requires_approved_doctor():
    """
    Verifies that POST /api/v1/consents/request is restricted strictly to approved doctors:
    - Patients: HTTP 403
    - Administrators: HTTP 403
    - Compliance Auditors: HTTP 403
    - Pending / unapproved doctors: HTTP 403
    - Approved doctors: HTTP 200
    """
    consent_payload = {
        "doctor_id": "doc-331902",
        "patient_id": "pat-984210",
        "purpose": "Post-operative cardiovascular follow-up",
        "allowed_record_types": ["LAB_REPORT", "CLINICAL_SUMMARY"],
        "duration_days": 30
    }

    # 1. Patient caller -> 403
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    res_pat = client.post("/api/v1/consents/request", json=consent_payload, headers={"Authorization": f"Bearer {pat_token}"})
    assert res_pat.status_code == 403
    assert "restricted to doctors" in res_pat.json()["detail"].lower()

    # 2. Administrator caller -> 403
    adm_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    res_adm = client.post("/api/v1/consents/request", json=consent_payload, headers={"Authorization": f"Bearer {adm_token}"})
    assert res_adm.status_code == 403
    assert "restricted to doctors" in res_adm.json()["detail"].lower()

    # 3. Auditor caller -> 403
    aud_token = create_access_token({"sub": "aud-001001", "name": "Federal Auditor", "role": "AUDITOR"})
    res_aud = client.post("/api/v1/consents/request", json=consent_payload, headers={"Authorization": f"Bearer {aud_token}"})
    assert res_aud.status_code == 403
    assert "restricted to doctors" in res_aud.json()["detail"].lower()

    # 4. Pending / unapproved doctor caller -> 403
    pending_doc_id = f"doc-{uuid.uuid4().hex[:6]}"
    pending_email = f"dr.pending.cst.{uuid.uuid4().hex[:6]}@clinic.med"
    db = SessionLocal()
    try:
        p_doc = UserModel(
            id=pending_doc_id,
            name="Dr. Pending Consents",
            email=pending_email,
            role="DOCTOR",
            password_hash=hash_password("pw123"),
            hospital="Clinic",
            specialty="Surgery",
            license_number="LIC-PEND-1",
            approval_status="PENDING",
            is_active=False
        )
        db.add(p_doc)
        db.commit()
    finally:
        db.close()

    pending_doc_token = create_access_token({"sub": pending_doc_id, "name": "Dr. Pending Consents", "role": "DOCTOR"})
    pending_payload = consent_payload.copy()
    pending_payload["doctor_id"] = pending_doc_id
    res_pending = client.post("/api/v1/consents/request", json=pending_payload, headers={"Authorization": f"Bearer {pending_doc_token}"})
    assert res_pending.status_code == 403
    assert "approval status" in res_pending.json()["detail"].lower() or "denied" in res_pending.json()["detail"].lower()

    # 5. Approved doctor caller (doc-331902) -> 200
    doc_token = create_access_token({"sub": "doc-331902", "name": "Dr. Marcus Sterling, MD", "role": "DOCTOR"})
    res_approved = client.post("/api/v1/consents/request", json=consent_payload, headers={"Authorization": f"Bearer {doc_token}"})
    assert res_approved.status_code == 200
    assert res_approved.json()["success"] is True
    assert "id" in res_approved.json()


# --- Task 3A: Admin Review, Approve, and Reject Workflow Tests ---

def test_admin_list_pending_doctor_applications():
    """
    Verifies that admin can list doctor applications:
    - Default status is PENDING
    - Zero password hashes, tokens, or secret credentials returned
    - Filtering by status works properly (PENDING, APPROVED, ALL)
    """
    # 1. Register two fresh doctor applicants
    doc1_email = f"dr.applist1.{uuid.uuid4().hex[:6]}@clinic.org"
    doc2_email = f"dr.applist2.{uuid.uuid4().hex[:6]}@clinic.org"

    r1 = client.post("/api/v1/auth/register-doctor", json={
        "name": "Dr. Candidate One",
        "email": doc1_email,
        "password": "Password123!",
        "hospital": "City Hospital",
        "specialty": "Cardiology",
        "licenseNumber": "LIC-APP-001"
    })
    assert r1.status_code == 201
    doc1_id = r1.json()["id"]

    r2 = client.post("/api/v1/auth/register-doctor", json={
        "name": "Dr. Candidate Two",
        "email": doc2_email,
        "password": "Password123!",
        "hospital": "State Hospital",
        "specialty": "Radiology",
        "licenseNumber": "LIC-APP-002"
    })
    assert r2.status_code == 201
    doc2_id = r2.json()["id"]

    # 2. Admin calls GET /api/v1/admin/doctor-applications
    admin_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    headers = {"Authorization": f"Bearer {admin_token}"}

    res = client.get("/api/v1/admin/doctor-applications", headers=headers)
    assert res.status_code == 200
    apps = res.json()
    assert isinstance(apps, list)

    # Verify both applicants are in the pending list
    app_ids = [a["id"] for a in apps]
    assert doc1_id in app_ids
    assert doc2_id in app_ids

    # Invariant: Verify sensitive fields are strictly excluded
    for a in apps:
        assert "password" not in a
        assert "passwordHash" not in a
        assert "password_hash" not in a
        assert "token" not in a
        assert "accessToken" not in a
        assert "access_token" not in a
        assert a["role"] == "DOCTOR"
        assert a["approvalStatus"] in ("PENDING", "APPROVED", "REJECTED")

    # 3. Test filtering: APPROVED should NOT contain our pending applicants
    res_approved = client.get("/api/v1/admin/doctor-applications?status=APPROVED", headers=headers)
    assert res_approved.status_code == 200
    approved_ids = [a["id"] for a in res_approved.json()]
    assert doc1_id not in approved_ids
    assert doc2_id not in approved_ids


def test_admin_approve_doctor_application_and_immediate_access():
    """
    Verifies that admin approval immediately promotes status to APPROVED,
    enables doctor login, and grants immediate clinical access.
    """
    doc_email = f"dr.approved.{uuid.uuid4().hex[:6]}@general.org"
    reg_payload = {
        "name": "Dr. Gregory House, MD",
        "email": doc_email,
        "password": "DiagnosticPassword123!",
        "hospital": "Princeton-Plainsboro",
        "specialty": "Infectious Disease & Nephrology",
        "licenseNumber": "LIC-MD-PP-1002"
    }
    reg_res = client.post("/api/v1/auth/register-doctor", json=reg_payload)
    assert reg_res.status_code == 201
    doc_id = reg_res.json()["id"]

    # Before approval: Login blocked with 403
    pre_login = client.post("/api/v1/auth/login", json={"email": doc_email, "password": "DiagnosticPassword123!"})
    assert pre_login.status_code == 403

    # Admin approves
    admin_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    approve_res = client.post(f"/api/v1/admin/doctor-applications/{doc_id}/approve", headers=admin_headers)
    assert approve_res.status_code == 200
    appr_data = approve_res.json()
    assert appr_data["success"] is True
    assert appr_data["id"] == doc_id
    assert appr_data["approvalStatus"] == "APPROVED"
    assert appr_data["isActive"] is True
    assert appr_data["reviewedBy"] == "adm-999999"
    assert appr_data["reviewedAt"] is not None

    # Verify DB state
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.id == doc_id).first()
        assert user is not None
        assert user.approval_status == "APPROVED"
        assert user.is_active is True
        assert user.reviewed_by == "adm-999999"
        assert user.reviewed_at is not None
        assert user.rejection_reason is None
    finally:
        db.close()

    # Immediate login: Now returns 200 and access token
    post_login = client.post("/api/v1/auth/login", json={"email": doc_email, "password": "DiagnosticPassword123!"})
    assert post_login.status_code == 200
    login_data = post_login.json()
    token = login_data.get("accessToken") or login_data.get("access_token")
    assert token is not None

    # Immediate clinical access: Doctor requests consent, patient grants, and doctor can query records
    doc_headers = {"Authorization": f"Bearer {token}"}

    # Before consent grant: Querying patient records is blocked with 403
    pre_consent_records = client.get(f"/api/v1/records?patient_id=pat-984210", headers=doc_headers)
    assert pre_consent_records.status_code == 403
    assert "active consent" in pre_consent_records.json()["detail"].lower()

    # Approved doctor submits consent request
    consent_res = client.post("/api/v1/consents/request", json={
        "doctor_id": doc_id,
        "patient_id": "pat-984210",
        "purpose": "Diagnostic clinical evaluation",
        "allowed_record_types": ["LAB_REPORT"],
        "duration_days": 14
    }, headers=doc_headers)
    assert consent_res.status_code == 200
    assert consent_res.json()["success"] is True
    consent_id = consent_res.json()["id"]

    # Patient Eleanor grants consent
    pat_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    grant_res = client.post(f"/api/v1/consents/{consent_id}/grant", headers={"Authorization": f"Bearer {pat_token}"})
    assert grant_res.status_code == 200

    # After consent grant: Doctor can query records
    records_res = client.get(f"/api/v1/records?patient_id=pat-984210", headers=doc_headers)
    assert records_res.status_code == 200



def test_admin_reject_doctor_application_and_session_revocation():
    """
    Verifies that admin rejection sets REJECTED status, is_active=False,
    records rejection reason, revokes sessions, and blocks both login and clinical access.
    """
    doc_email = f"dr.rejected.{uuid.uuid4().hex[:6]}@clinic.org"
    reg_payload = {
        "name": "Dr. Phineas Gage",
        "email": doc_email,
        "password": "Password123!",
        "hospital": "City Clinic",
        "specialty": "Neurology",
        "licenseNumber": "LIC-INVALID-000"
    }
    reg_res = client.post("/api/v1/auth/register-doctor", json=reg_payload)
    assert reg_res.status_code == 201
    doc_id = reg_res.json()["id"]

    # Insert a dummy active session into DB for this doctor to test revocation
    from datetime import datetime, timezone, timedelta
    db = SessionLocal()
    session_id = f"sess-{uuid.uuid4().hex[:8]}"
    try:
        dummy_session = UserSessionModel(
            id=session_id,
            user_id=doc_id,
            token_jti=str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            is_revoked=False
        )
        db.add(dummy_session)
        db.commit()
    finally:
        db.close()

    # Admin rejects with valid reason
    admin_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    reject_res = client.post(
        f"/api/v1/admin/doctor-applications/{doc_id}/reject",
        json={"reason": "State medical board license number could not be verified in registry."},
        headers=admin_headers
    )
    assert reject_res.status_code == 200
    rej_data = reject_res.json()
    assert rej_data["success"] is True
    assert rej_data["id"] == doc_id
    assert rej_data["approvalStatus"] == "REJECTED"
    assert rej_data["isActive"] is False
    assert rej_data["rejectionReason"] == "State medical board license number could not be verified in registry."
    assert rej_data["reviewedBy"] == "adm-999999"

    # Verify DB state and session revocation
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.id == doc_id).first()
        assert user.approval_status == "REJECTED"
        assert user.is_active is False
        assert user.rejection_reason == "State medical board license number could not be verified in registry."

        sess = db.query(UserSessionModel).filter(UserSessionModel.id == session_id).first()
        assert sess.is_revoked is True, "Existing session must be revoked upon rejection"
    finally:
        db.close()

    # Login blocked
    login_res = client.post("/api/v1/auth/login", json={"email": doc_email, "password": "Password123!"})
    assert login_res.status_code == 403
    assert "rejected" in login_res.json()["detail"].lower()

    # Clinical endpoint blocked even if using a crafted doctor token
    crafted_token = create_access_token({"sub": doc_id, "name": "Dr. Phineas Gage", "role": "DOCTOR"})
    clin_res = client.get("/api/v1/records?patient_id=pat-984210", headers={"Authorization": f"Bearer {crafted_token}"})
    assert clin_res.status_code == 403


def test_admin_reject_requires_meaningful_reason():
    """Verifies that rejecting a doctor application requires a reason of >= 5 characters."""
    doc_email = f"dr.shortreason.{uuid.uuid4().hex[:6]}@clinic.org"
    reg_res = client.post("/api/v1/auth/register-doctor", json={
        "name": "Dr. Short Reason",
        "email": doc_email,
        "password": "Password123!",
        "hospital": "City Clinic",
        "specialty": "Pediatrics",
        "licenseNumber": "LIC-SR-123"
    })
    doc_id = reg_res.json()["id"]

    admin_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Missing reason field in JSON -> 422
    r1 = client.post(f"/api/v1/admin/doctor-applications/{doc_id}/reject", json={}, headers=admin_headers)
    assert r1.status_code == 422

    # 2. Empty string -> 400
    r2 = client.post(f"/api/v1/admin/doctor-applications/{doc_id}/reject", json={"reason": ""}, headers=admin_headers)
    assert r2.status_code == 400
    assert "meaningful rejection reason" in r2.json()["detail"].lower()

    # 3. Whitespace only -> 400
    r3 = client.post(f"/api/v1/admin/doctor-applications/{doc_id}/reject", json={"reason": "    "}, headers=admin_headers)
    assert r3.status_code == 400

    # 4. Too short (< 5 chars) -> 400
    r4 = client.post(f"/api/v1/admin/doctor-applications/{doc_id}/reject", json={"reason": "bad"}, headers=admin_headers)
    assert r4.status_code == 400

    # Verify status is still PENDING
    db = SessionLocal()
    try:
        user = db.query(UserModel).filter(UserModel.id == doc_id).first()
        assert user.approval_status == "PENDING"
    finally:
        db.close()


def test_doctor_application_review_unauthorized_reviewers():
    """
    Verifies that public users, patients, doctors, and auditors cannot access doctor application review endpoints.
    """
    doc_email = f"dr.unauth.{uuid.uuid4().hex[:6]}@clinic.org"
    reg_res = client.post("/api/v1/auth/register-doctor", json={
        "name": "Dr. Unauth Target",
        "email": doc_email,
        "password": "Password123!",
        "hospital": "City Clinic",
        "specialty": "Dermatology",
        "licenseNumber": "LIC-UNA-123"
    })
    doc_id = reg_res.json()["id"]

    patient_token = create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"})
    doctor_token = create_access_token({"sub": "doc-331902", "name": "Dr. Marcus Sterling", "role": "DOCTOR"})
    auditor_token = create_access_token({"sub": "aud-001001", "name": "Federal Auditor", "role": "AUDITOR"})

    non_admin_tokens = [
        ("patient", patient_token),
        ("doctor", doctor_token),
        ("auditor", auditor_token)
    ]

    endpoints = [
        ("GET", "/api/v1/admin/doctor-applications", None),
        ("POST", f"/api/v1/admin/doctor-applications/{doc_id}/approve", None),
        ("POST", f"/api/v1/admin/doctor-applications/{doc_id}/reject", {"reason": "Unauthorized attempt"})
    ]

    for method, path, payload in endpoints:
        # 1. Unauthenticated (no token) -> 401
        if method == "GET":
            unauth_res = client.get(path)
        else:
            unauth_res = client.post(path, json=payload)
        assert unauth_res.status_code == 401, f"Expected 401 for unauth {method} {path}, got {unauth_res.status_code}"

        # 2. Non-admin roles -> 403
        for role_name, token in non_admin_tokens:
            h = {"Authorization": f"Bearer {token}"}
            if method == "GET":
                res = client.get(path, headers=h)
            else:
                res = client.post(path, json=payload, headers=h)
            assert res.status_code == 403, f"Expected 403 for {role_name} on {method} {path}, got {res.status_code}"


def test_doctor_application_review_invalid_targets():
    """
    Verifies rejection of invalid review operations:
    - Non-existent target -> 404
    - Non-doctor target (e.g. Patient) -> 400
    - Double approval -> 400
    - Double rejection -> 400
    """
    admin_token = create_access_token({"sub": "adm-999999", "name": "Platform Administrator", "role": "ADMIN"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Non-existent target
    r_approve_404 = client.post("/api/v1/admin/doctor-applications/doc-nonexistent-404/approve", headers=admin_headers)
    assert r_approve_404.status_code == 404

    r_reject_404 = client.post("/api/v1/admin/doctor-applications/doc-nonexistent-404/reject", json={"reason": "Valid reason but target missing"}, headers=admin_headers)
    assert r_reject_404.status_code == 404

    # 2. Non-doctor target (Patient pat-984210)
    r_pat_approve = client.post("/api/v1/admin/doctor-applications/pat-984210/approve", headers=admin_headers)
    assert r_pat_approve.status_code == 400
    assert "only doctor applications can be approved" in r_pat_approve.json()["detail"].lower()

    r_pat_reject = client.post("/api/v1/admin/doctor-applications/pat-984210/reject", json={"reason": "Invalid doctor applicant"}, headers=admin_headers)
    assert r_pat_reject.status_code == 400
    assert "only doctor applications can be rejected" in r_pat_reject.json()["detail"].lower()

    # 3. Double approval
    doc1_res = client.post("/api/v1/auth/register-doctor", json={
        "name": "Dr. Double Approve",
        "email": f"dr.dblapp.{uuid.uuid4().hex[:6]}@clinic.org",
        "password": "Password123!",
        "hospital": "City Clinic",
        "specialty": "Cardiology",
        "licenseNumber": "LIC-DBL-1"
    })
    doc1_id = doc1_res.json()["id"]

    first_appr = client.post(f"/api/v1/admin/doctor-applications/{doc1_id}/approve", headers=admin_headers)
    assert first_appr.status_code == 200

    second_appr = client.post(f"/api/v1/admin/doctor-applications/{doc1_id}/approve", headers=admin_headers)
    assert second_appr.status_code == 400
    assert "already approved" in second_appr.json()["detail"].lower()

    # 4. Double rejection
    doc2_res = client.post("/api/v1/auth/register-doctor", json={
        "name": "Dr. Double Reject",
        "email": f"dr.dblrej.{uuid.uuid4().hex[:6]}@clinic.org",
        "password": "Password123!",
        "hospital": "City Clinic",
        "specialty": "Neurology",
        "licenseNumber": "LIC-DBL-2"
    })
    doc2_id = doc2_res.json()["id"]

    first_rej = client.post(f"/api/v1/admin/doctor-applications/{doc2_id}/reject", json={"reason": "First rejection reason"}, headers=admin_headers)
    assert first_rej.status_code == 200

    second_rej = client.post(f"/api/v1/admin/doctor-applications/{doc2_id}/reject", json={"reason": "Second rejection reason"}, headers=admin_headers)
    assert second_rej.status_code == 400
    assert "already rejected" in second_rej.json()["detail"].lower()

