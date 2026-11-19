"""
Security Tests: RBAC & JWT Unauthorized Access Attempt Verification.

Validates that:
- Tampered cryptographic signatures are rejected.
- Expired JWT tokens are rejected.
- Horizontal privilege escalation (cross-patient access) is blocked.
- Vertical privilege escalation (unauthorized role claims) is blocked.
- Doctor access without explicit active consent is denied.
"""

import pytest
from fixtures.auth_tokens import (
    get_patient_token,
    get_doctor_token,
    get_expired_token,
    get_tampered_signature_token,
    get_role_escalated_token,
    verify_and_decode_jwt
)
from fixtures.synthetic_records import (
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    DOCTOR_DR_SMITH_ID,
    ATTACKER_EVE_ID
)
from core_harness import AccessDeniedError


@pytest.mark.security
def test_valid_patient_jwt_verification():
    """Verify that a legitimate patient token is successfully verified and decoded."""
    token = get_patient_token(patient_id=PATIENT_ALICE_ID)
    is_valid, payload, err = verify_and_decode_jwt(token)
    assert is_valid is True
    assert err == ""
    assert payload["sub"] == PATIENT_ALICE_ID
    assert payload["role"] == "PATIENT"


@pytest.mark.security
def test_tampered_jwt_signature_rejected():
    """Verify that a token signed with an invalid/attacker key is rejected."""
    token = get_tampered_signature_token(user_id=PATIENT_ALICE_ID)
    is_valid, payload, err = verify_and_decode_jwt(token)
    assert is_valid is False
    assert "Cryptographic signature verification failed" in err


@pytest.mark.security
def test_tampered_payload_content_rejected():
    """Verify that manually tampering with the JWT payload string invalidates the token."""
    valid_token = get_patient_token(patient_id=PATIENT_ALICE_ID)
    parts = valid_token.split(".")
    # Tamper payload part by replacing a character
    tampered_parts = [parts[0], parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B"), parts[2]]
    tampered_token = ".".join(tampered_parts)

    is_valid, payload, err = verify_and_decode_jwt(tampered_token)
    assert is_valid is False
    assert "Cryptographic signature verification failed" in err


@pytest.mark.security
def test_expired_jwt_token_rejected():
    """Verify that an expired JWT token is rejected."""
    token = get_expired_token(user_id=PATIENT_ALICE_ID, role="PATIENT")
    is_valid, payload, err = verify_and_decode_jwt(token)
    assert is_valid is False
    assert "Token has expired" in err


@pytest.mark.security
def test_malformed_token_structure_rejected():
    """Verify that malformed token strings are safely rejected without crashing."""
    malformed_tokens = [
        "",
        "not.a.valid.jwt.with.too.many.parts",
        "only-two.parts",
        "invalid@@base64.chars??.signature"
    ]
    for bad_token in malformed_tokens:
        is_valid, _, err = verify_and_decode_jwt(bad_token)
        assert is_valid is False
        assert len(err) > 0


@pytest.mark.security
def test_patient_self_access_allowed(rbac_authorizer):
    """Verify patient can access their own record."""
    _, payload, _ = verify_and_decode_jwt(get_patient_token(PATIENT_ALICE_ID))
    allowed = rbac_authorizer.authorize_record_access(
        token_payload=payload,
        target_patient_id=PATIENT_ALICE_ID,
        record_id="REC-LAB-001",
        record_type="LAB_REPORT"
    )
    assert allowed is True


@pytest.mark.security
def test_horizontal_privilege_escalation_blocked(rbac_authorizer):
    """
    SECURITY AUDIT: Cross-patient data isolation test.
    Patient Alice attempts to access Patient Bob's medical record.
    Must be blocked with AccessDeniedError.
    """
    _, alice_payload, _ = verify_and_decode_jwt(get_patient_token(PATIENT_ALICE_ID))
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=alice_payload,
            target_patient_id=PATIENT_BOB_ID,
            record_id="REC-RAD-003",
            record_type="RADIOLOGY_REPORT"
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "UNAUTHORIZED_HORIZONTAL_ACCESS"


@pytest.mark.security
def test_doctor_access_without_active_consent_denied(rbac_authorizer):
    """
    SECURITY AUDIT: Doctor accessing patient record without prior consent.
    Must be denied with AccessDeniedError (NO_CONSENT_FOUND).
    """
    _, doctor_payload, _ = verify_and_decode_jwt(get_doctor_token(DOCTOR_DR_SMITH_ID))
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=doctor_payload,
            target_patient_id=PATIENT_ALICE_ID,
            record_id="REC-LAB-001",
            record_type="LAB_REPORT"
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "NO_CONSENT_FOUND"


@pytest.mark.security
def test_unauthorized_role_denied(rbac_authorizer):
    """Verify an arbitrary or untrusted role is rejected from clinical access."""
    attacker_payload = {
        "sub": ATTACKER_EVE_ID,
        "role": "EXTERNAL_VENDOR",
        "exp": 9999999999
    }
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=attacker_payload,
            target_patient_id=PATIENT_ALICE_ID,
            record_id="REC-LAB-001",
            record_type="LAB_REPORT"
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "INVALID_ROLE"


@pytest.mark.security
def test_admin_clinical_records_access_denied_zero_phi_boundary(rbac_authorizer):
    """
    SECURITY AUDIT: Platform Administrator access attempt to clinical record.
    Must be strictly denied (Zero-PHI boundary) with AccessDeniedError.
    """
    admin_payload = {
        "sub": "adm-000001",
        "role": "ADMIN",
        "exp": 9999999999
    }
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=admin_payload,
            target_patient_id=PATIENT_ALICE_ID,
            record_id="REC-LAB-001",
            record_type="LAB_REPORT"
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "INVALID_ROLE"

