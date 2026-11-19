"""
Unit and Integration Tests for Verification Endpoints Security & Hardening (Task 6B.2C).
Enforces strict RBAC and relationship binding across:
1. GET/POST /api/v1/records/{record_id}/verify
2. GET /api/v1/consents/verify
3. GET /api/v1/audit/verify
"""

import time
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token
from app.adapters.fabric_gateway import fabric_gateway
from app.db.session import SessionLocal
from app.db.models import UserModel

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_users_and_consents():
    """Seeds test users and active consents in test database and Fabric gateway."""
    db = SessionLocal()
    try:
        # 1. Approved Doctor 1
        d1 = db.query(UserModel).filter(UserModel.id == "doc-sec-01").first()
        if not d1:
            d1 = UserModel(
                id="doc-sec-01",
                email="doc-sec-01@medtrust.local",
                name="Dr. Verified Security",
                role="DOCTOR",
                password_hash="hashed_pw_mock_1",
                approval_status="APPROVED",
                hospital="Central Security Clinic",
                license_number="SEC-MD-01",
                is_active=True
            )
            db.add(d1)

        # 2. Approved Doctor 2 (Unrelated clinician)
        d2 = db.query(UserModel).filter(UserModel.id == "doc-sec-02").first()
        if not d2:
            d2 = UserModel(
                id="doc-sec-02",
                email="doc-sec-02@medtrust.local",
                name="Dr. Unrelated Clinician",
                role="DOCTOR",
                password_hash="hashed_pw_mock_2",
                approval_status="APPROVED",
                hospital="Other Hospital",
                license_number="SEC-MD-02",
                is_active=True
            )
            db.add(d2)

        # 3. Pending Doctor
        dp = db.query(UserModel).filter(UserModel.id == "doc-sec-pending").first()
        if not dp:
            dp = UserModel(
                id="doc-sec-pending",
                email="doc-sec-pending@medtrust.local",
                name="Dr. Pending Applicant",
                role="DOCTOR",
                password_hash="hashed_pw_mock_p",
                approval_status="PENDING",
                hospital="Applicant Clinic",
                license_number="SEC-PEND-01",
                is_active=True
            )
            db.add(dp)

        # 4. Patient 1 (Owner of rec-001)
        p1 = db.query(UserModel).filter(UserModel.id == "pat-984210").first()
        if not p1:
            p1 = UserModel(
                id="pat-984210",
                email="pat-984210@medtrust.local",
                name="Eleanor Vance",
                role="PATIENT",
                password_hash="hashed_pw_mock_pat1",
                approval_status="APPROVED",
                is_active=True
            )
            db.add(p1)

        # 5. Patient 2 (Unrelated patient)
        p2 = db.query(UserModel).filter(UserModel.id == "pat-sec-other").first()
        if not p2:
            p2 = UserModel(
                id="pat-sec-other",
                email="pat-sec-other@medtrust.local",
                name="Other Patient",
                role="PATIENT",
                password_hash="hashed_pw_mock_pat2",
                approval_status="APPROVED",
                is_active=True
            )
            db.add(p2)

        db.commit()
    finally:
        db.close()

    # Seed Fabric gateway consents for doc-sec-01 and pat-984210
    # A. Active consent for IMAGING_MRI (matching rec-001)
    c1 = fabric_gateway.request_consent(
        patient_id="pat-984210",
        patient_name="Eleanor Vance",
        doctor_id="doc-sec-01",
        doctor_name="Dr. Verified Security",
        doctor_hospital="Central Security Clinic",
        record_type="IMAGING_MRI",
        allowed_record_types=["IMAGING_MRI"],
        purpose="Cardiovascular imaging review",
        duration_days=30
    )
    fabric_gateway.grant_consent(c1["id"], "pat-984210", "Eleanor Vance")

    # B. Revoked consent for CLINICAL_SUMMARY
    c2 = fabric_gateway.request_consent(
        patient_id="pat-984210",
        patient_name="Eleanor Vance",
        doctor_id="doc-sec-01",
        doctor_name="Dr. Verified Security",
        doctor_hospital="Central Security Clinic",
        record_type="CLINICAL_SUMMARY",
        allowed_record_types=["CLINICAL_SUMMARY"],
        purpose="Old summary review",
        duration_days=30
    )
    fabric_gateway.grant_consent(c2["id"], "pat-984210", "Eleanor Vance")
    fabric_gateway.revoke_consent(c2["id"], "pat-984210", "Eleanor Vance")

    # Seed record for CLINICAL_SUMMARY matching revoked consent c2
    fabric_gateway._records["rec-sec-summary"] = {
        "id": "rec-sec-summary",
        "patient_id": "pat-984210",
        "patient_name": "Eleanor Vance",
        "title": "Clinical Summary Report",
        "record_type": "CLINICAL_SUMMARY",
        "ipfs_cid": "bafkreiajkhnxasfkrk67gw3duvtupx2gbc7b5kfs52vhgrgo3adbk5rm54",
        "file_size": "2.4 MB",
        "mime_type": "application/pdf",
        "created_at": "2026-10-01T10:00:00Z",
        "created_by_doctor": "Dr. Marcus Sterling, MD",
        "hospital": "Central Security Clinic",
        "encryption_algorithm": "AES-256-GCM",
        "key_fingerprint": "SHA256:20e9c1985f3becb5...3cba",
        "checksum_sha256": "0951db7048aa8abdf35b63a56747df4608be1ea8b2eeaa7344ced80615762cef",
        "tx_hash": "0x334901ba7162e91024b819203a7491bb4029183746112a9bc8301726a992014b",
    }

    # C. Expired consent for PRESCRIPTION (matching rec-003)
    c3 = fabric_gateway.request_consent(
        patient_id="pat-984210",
        patient_name="Eleanor Vance",
        doctor_id="doc-sec-01",
        doctor_name="Dr. Verified Security",
        doctor_hospital="Central Security Clinic",
        record_type="PRESCRIPTION",
        allowed_record_types=["PRESCRIPTION"],
        purpose="Past prescription audit",
        duration_days=1
    )
    fabric_gateway.grant_consent(c3["id"], "pat-984210", "Eleanor Vance")
    c3_id = c3["id"]
    fabric_gateway._consents[c3_id]["valid_until_epoch"] = int(time.time()) - 3600
    fabric_gateway._consents[c3_id]["expires_at"] = "2020-01-01T00:00:00Z"

    tokens = {
        "doc1": create_access_token({"sub": "doc-sec-01", "name": "Dr. Verified Security", "role": "DOCTOR", "approval_status": "APPROVED"}),
        "doc2": create_access_token({"sub": "doc-sec-02", "name": "Dr. Unrelated Clinician", "role": "DOCTOR", "approval_status": "APPROVED"}),
        "doc_pending": create_access_token({"sub": "doc-sec-pending", "name": "Dr. Pending Applicant", "role": "DOCTOR", "approval_status": "PENDING"}),
        "patient1": create_access_token({"sub": "pat-984210", "name": "Eleanor Vance", "role": "PATIENT"}),
        "patient2": create_access_token({"sub": "pat-sec-other", "name": "Other Patient", "role": "PATIENT"}),
        "auditor": create_access_token({"sub": "aud-001001", "name": "Federal Auditor", "role": "AUDITOR"}),
        "admin": create_access_token({"sub": "adm-000001", "name": "System Administrator", "role": "ADMIN"}),
    }
    try:
        yield tokens
    finally:
        fabric_gateway._records.pop("rec-sec-summary", None)
        fabric_gateway._consents.pop(c3_id, None)


# ==============================================================================
# 1. Unauthenticated Requests (HTTP 401 Unauthorized)
# ==============================================================================

def test_record_verify_unauthenticated_rejected_401():
    """Assert unauthenticated GET and POST /records/{id}/verify return HTTP 401."""
    res_get = client.get("/api/v1/records/rec-001/verify")
    assert res_get.status_code == 401
    assert "WWW-Authenticate" in res_get.headers

    res_post = client.post("/api/v1/records/rec-001/verify")
    assert res_post.status_code == 401
    assert "WWW-Authenticate" in res_post.headers


def test_consent_verify_unauthenticated_rejected_401():
    """Assert unauthenticated GET /consents/verify returns HTTP 401."""
    res = client.get(
        "/api/v1/consents/verify?doctor_id=doc-sec-01&patient_id=pat-984210&record_type=IMAGING_MRI"
    )
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers


def test_audit_verify_unauthenticated_rejected_401():
    """Assert unauthenticated GET /audit/verify returns HTTP 401."""
    res = client.get("/api/v1/audit/verify")
    assert res.status_code == 401
    assert "WWW-Authenticate" in res.headers


# ==============================================================================
# 2. Endpoint 1: GET/POST /api/v1/records/{record_id}/verify Security Gates & Oracle Elimination
# ==============================================================================

def test_record_verify_patient_own_record_success(setup_users_and_consents):
    """Patient verifying their own record succeeds with structured response."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-001/verify",
        headers={"Authorization": f"Bearer {tokens['patient1']}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert "status" in data
    assert "checksumMatches" in data


def test_record_verify_patient_cross_patient_matches_nonexistent_record_response(setup_users_and_consents):
    """
    Task 6C.3 Elimination of Record-Existence Oracle:
    Assert that a patient querying another patient's existing record receives the exact same
    HTTP status code (200) and structured response body as querying a completely nonexistent record.
    Prevents enumeration attacks while leaking zero PHI, zero CIDs, zero checksums, and zero categories.
    """
    tokens = setup_users_and_consents
    headers = {"Authorization": f"Bearer {tokens['patient2']}"}

    # Cross-patient query: patient2 queries patient1's real record 'rec-001'
    res_cross_get = client.get("/api/v1/records/rec-001/verify", headers=headers)
    res_cross_post = client.post("/api/v1/records/rec-001/verify", headers=headers)

    # Nonexistent record query: patient2 queries non-existent record 'rec-missing-999999'
    res_missing_get = client.get("/api/v1/records/rec-missing-999999/verify", headers=headers)
    res_missing_post = client.post("/api/v1/records/rec-missing-999999/verify", headers=headers)

    for res_cross, res_missing, method in [
        (res_cross_get, res_missing_get, "GET"),
        (res_cross_post, res_missing_post, "POST"),
    ]:
        assert res_cross.status_code == 200, f"{method} cross-patient query should return HTTP 200"
        assert res_missing.status_code == 200, f"{method} nonexistent query should return HTTP 200"

        data_cross = res_cross.json()
        data_missing = res_missing.json()

        # Both must return LEDGER_UNAVAILABLE status
        assert data_cross["status"] == "LEDGER_UNAVAILABLE"
        assert data_missing["status"] == "LEDGER_UNAVAILABLE"

        # Both must return identical non-revealing sentinel values
        assert data_cross["checksumMatches"] is False
        assert data_missing["checksumMatches"] is False
        assert data_cross["ledgerChecksum"] == "UNAVAILABLE"
        assert data_missing["ledgerChecksum"] == "UNAVAILABLE"
        assert data_cross["computedSha256"] == "UNAVAILABLE"
        assert data_missing["computedSha256"] == "UNAVAILABLE"
        assert data_cross["ipfsCid"] == "UNKNOWN"
        assert data_missing["ipfsCid"] == "UNKNOWN"

        # Detail must follow standard nonexistent format echoing only the queried recordId
        assert data_cross["detail"] == "Record 'rec-001' not found on Fabric ledger."
        assert data_missing["detail"] == "Record 'rec-missing-999999' not found on Fabric ledger."

        # Zero metadata leakage verification: assert no sensitive fields leaked in raw text
        raw_text = res_cross.text
        assert "pat-984210" not in raw_text, "Target patient ID leaked in response!"
        assert "Eleanor Vance" not in raw_text, "Patient name leaked in response!"
        assert "IMAGING_MRI" not in raw_text, "Clinical category leaked in response!"
        assert "bafk" not in raw_text, "IPFS CID leaked in response!"
        assert "0951db7048aa8abdf35b63a56747df4608be1ea8b2eeaa7344ced80615762cef" not in raw_text, "Ledger checksum leaked in response!"


def test_record_verify_patient_cross_patient_audit_event_logged(setup_users_and_consents):
    """Assert cross-patient verification attempt is logged as DENIED in Fabric audit trail."""
    tokens = setup_users_and_consents
    headers = {"Authorization": f"Bearer {tokens['patient2']}"}

    client.get("/api/v1/records/rec-001/verify", headers=headers)

    # Verify audit chain records denial event
    denial_logs = [
        log for log in fabric_gateway._audit_chain
        if log.get("actor_id") == "pat-sec-other"
        and log.get("action") == "VERIFY"
        and log.get("status") == "DENIED"
        and log.get("record_id") == "rec-001"
    ]
    assert len(denial_logs) >= 1
    assert denial_logs[-1]["target_patient_id"] == "pat-984210"


def test_record_verify_admin_privacy_boundary_blocked_403(setup_users_and_consents):
    """Administrator attempting to verify record is blocked by Zero-PHI boundary with HTTP 403."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-001/verify",
        headers={"Authorization": f"Bearer {tokens['admin']}"}
    )
    assert res.status_code == 403
    assert "Administrative Privacy Boundary" in res.json()["detail"]


def test_record_verify_pending_doctor_blocked_403(setup_users_and_consents):
    """Doctor with PENDING approval status cannot verify clinical records (HTTP 403)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-001/verify",
        headers={"Authorization": f"Bearer {tokens['doc_pending']}"}
    )
    assert res.status_code == 403
    assert "approval status is 'PENDING'" in res.json()["detail"]


def test_record_verify_doctor_without_consent_blocked_403(setup_users_and_consents):
    """Approved doctor with no consent for target patient is blocked with HTTP 403 (NO_CONSENT_FOUND)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-001/verify",
        headers={"Authorization": f"Bearer {tokens['doc2']}"}
    )
    assert res.status_code == 403
    assert "does not have active consent" in res.json()["detail"]
    assert "NO_CONSENT_FOUND" in res.json()["detail"]


def test_record_verify_doctor_with_active_consent_success(setup_users_and_consents):
    """Approved doctor with active consent for IMAGING_MRI can verify rec-001."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-001/verify",
        headers={"Authorization": f"Bearer {tokens['doc1']}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"
    assert "status" in data


def test_record_verify_doctor_with_revoked_consent_blocked_403(setup_users_and_consents):
    """Approved doctor with revoked consent for category is blocked with HTTP 403 (CONSENT_REVOKED)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-sec-summary/verify",
        headers={"Authorization": f"Bearer {tokens['doc1']}"}
    )
    assert res.status_code == 403
    assert "does not have active consent" in res.json()["detail"]
    assert "CONSENT_REVOKED" in res.json()["detail"]


def test_record_verify_doctor_with_expired_consent_blocked_403(setup_users_and_consents):
    """Approved doctor with expired consent for category is blocked with HTTP 403 (CONSENT_EXPIRED)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-003/verify",
        headers={"Authorization": f"Bearer {tokens['doc1']}"}
    )
    assert res.status_code == 403
    assert "does not have active consent" in res.json()["detail"]
    assert "CONSENT_EXPIRED" in res.json()["detail"]


def test_record_verify_doctor_with_out_of_scope_consent_blocked_403(setup_users_and_consents):
    """Approved doctor with consent for IMAGING_MRI cannot verify rec-002 (LAB_REPORT) (CONSENT_SCOPE_EXCLUDED)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-002/verify",
        headers={"Authorization": f"Bearer {tokens['doc1']}"}
    )
    assert res.status_code == 403
    assert "does not have active consent" in res.json()["detail"]
    assert "CONSENT_SCOPE_EXCLUDED" in res.json()["detail"]


def test_record_verify_auditor_compliance_success(setup_users_and_consents):
    """Auditor can verify any record for cryptographic compliance audit."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-001/verify",
        headers={"Authorization": f"Bearer {tokens['auditor']}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-001"


def test_record_verify_nonexistent_preserves_ledger_unavailable(setup_users_and_consents):
    """Non-existent record returns 200 LEDGER_UNAVAILABLE without crashing or raising 404."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/records/rec-missing-999999/verify",
        headers={"Authorization": f"Bearer {tokens['patient1']}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recordId"] == "rec-missing-999999"
    assert data["status"] == "LEDGER_UNAVAILABLE"
    assert data["checksumMatches"] is False


# ==============================================================================
# 3. Endpoint 2: GET /api/v1/consents/verify Security Gates
# ==============================================================================

def test_consent_verify_admin_blocked_403(setup_users_and_consents):
    """Admin cannot query consent verification (HTTP 403)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/consents/verify?doctor_id=doc-sec-01&patient_id=pat-984210&record_type=IMAGING_MRI",
        headers={"Authorization": f"Bearer {tokens['admin']}"}
    )
    assert res.status_code == 403
    assert "Administrative Privacy Boundary" in res.json()["detail"]


def test_consent_verify_doctor_cross_doctor_impersonation_blocked_403(setup_users_and_consents):
    """Doctor 1 attempting to verify Doctor 2's consent is blocked with HTTP 403."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/consents/verify?doctor_id=doc-sec-02&patient_id=pat-984210&record_type=IMAGING_MRI",
        headers={"Authorization": f"Bearer {tokens['doc1']}"}
    )
    assert res.status_code == 403
    assert "Horizontal Access Denied: Doctor 'doc-sec-01' cannot verify consent issued to doctor 'doc-sec-02'" in res.json()["detail"]


def test_consent_verify_pending_doctor_blocked_403(setup_users_and_consents):
    """Pending doctor cannot verify consent relationships (HTTP 403)."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/consents/verify?doctor_id=doc-sec-pending&patient_id=pat-984210&record_type=IMAGING_MRI",
        headers={"Authorization": f"Bearer {tokens['doc_pending']}"}
    )
    assert res.status_code == 403
    assert "approval status is 'PENDING'" in res.json()["detail"]


def test_consent_verify_patient_cross_patient_blocked_403(setup_users_and_consents):
    """Patient 2 attempting to verify Patient 1's consent is blocked with HTTP 403."""
    tokens = setup_users_and_consents
    res = client.get(
        "/api/v1/consents/verify?doctor_id=doc-sec-01&patient_id=pat-984210&record_type=IMAGING_MRI",
        headers={"Authorization": f"Bearer {tokens['patient2']}"}
    )
    assert res.status_code == 403
    assert "Horizontal Access Denied: Patient 'pat-sec-other' cannot verify consent relationships of patient 'pat-984210'" in res.json()["detail"]


def test_consent_verify_authorized_parties_and_auditor(setup_users_and_consents):
    """Authorized doctor, owning patient, and compliance auditor can evaluate consent."""
    tokens = setup_users_and_consents
    url = "/api/v1/consents/verify?doctor_id=doc-sec-01&patient_id=pat-984210&record_type=IMAGING_MRI"

    # 1. Attending Doctor
    res_doc = client.get(url, headers={"Authorization": f"Bearer {tokens['doc1']}"})
    assert res_doc.status_code == 200
    assert res_doc.json()["allowed"] is True
    assert res_doc.json()["reason"] == "CONSENT_ACTIVE"

    # 2. Granting Patient
    res_pat = client.get(url, headers={"Authorization": f"Bearer {tokens['patient1']}"})
    assert res_pat.status_code == 200
    assert res_pat.json()["allowed"] is True

    # 3. Compliance Auditor
    res_aud = client.get(url, headers={"Authorization": f"Bearer {tokens['auditor']}"})
    assert res_aud.status_code == 200
    assert res_aud.json()["allowed"] is True


def test_consent_verify_revocation_denial(setup_users_and_consents):
    """Verifying revoked CLINICAL_SUMMARY consent returns allowed=False and CONSENT_REVOKED."""
    tokens = setup_users_and_consents
    url = "/api/v1/consents/verify?doctor_id=doc-sec-01&patient_id=pat-984210&record_type=CLINICAL_SUMMARY"

    res = client.get(url, headers={"Authorization": f"Bearer {tokens['doc1']}"})
    assert res.status_code == 200
    assert res.json()["allowed"] is False
    assert res.json()["reason"] == "CONSENT_REVOKED"


# ==============================================================================
# 4. Endpoint 3: GET /api/v1/audit/verify Security Gates (Option B)
# ==============================================================================

def test_audit_verify_all_authenticated_roles_permitted(setup_users_and_consents):
    """All authenticated personas can run cryptographic verification; returns zero PHI."""
    tokens = setup_users_and_consents

    for role_name in ["patient1", "doc1", "auditor", "admin"]:
        res = client.get(
            "/api/v1/audit/verify",
            headers={"Authorization": f"Bearer {tokens[role_name]}"}
        )
        assert res.status_code == 200, f"Failed for {role_name}: {res.text}"
        data = res.json()
        assert "chainIntact" in data
        assert isinstance(data["chainIntact"], bool)
        assert "message" in data
        # Ensure zero PHI, zero actor IDs, zero patient IDs in response
        assert "pat-" not in str(data)
        assert "doc-" not in str(data)
