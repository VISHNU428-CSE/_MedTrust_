"""
Security Tests: Decentralized Consent Lifecycle & Revocation Enforcement.

Verifies:
- Active consent permits doctor access.
- Revocation immediately takes effect with zero propagation lag.
- Expired consent is automatically blocked.
- Scoped consent (e.g. lab report only) enforces strict record boundaries.
- Cross-patient revocation tampering is blocked.
"""

import pytest
import time
from fixtures.auth_tokens import get_doctor_token, verify_and_decode_jwt
from fixtures.synthetic_records import (
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    DOCTOR_DR_SMITH_ID
)
from core_harness import AccessDeniedError


@pytest.mark.security
@pytest.mark.consent
def test_active_consent_permits_doctor_access(rbac_authorizer, consent_engine):
    """Verify doctor can access record when valid, active consent exists."""
    consent_id = "CONSENT-ALICE-SMITH-001"
    consent_engine.grant_consent(
        consent_id=consent_id,
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=int(time.time()) + 3600
    )

    _, doctor_payload, _ = verify_and_decode_jwt(get_doctor_token(DOCTOR_DR_SMITH_ID))
    allowed = rbac_authorizer.authorize_record_access(
        token_payload=doctor_payload,
        target_patient_id=PATIENT_ALICE_ID,
        record_id="REC-LAB-ALICE-001",
        record_type="LAB_REPORT"
    )
    assert allowed is True


@pytest.mark.security
@pytest.mark.consent
def test_immediate_access_block_upon_consent_revocation(rbac_authorizer, consent_engine):
    """
    CRITICAL SECURITY INVARIANT:
    Immediate revocation enforcement.
    Once a patient revokes consent, access MUST be instantly blocked.
    """
    consent_id = "CONSENT-ALICE-SMITH-002"
    consent_engine.grant_consent(
        consent_id=consent_id,
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT", "CARDIOLOGY_VISIT"],
        valid_until_epoch=int(time.time()) + 3600
    )

    _, doctor_payload, _ = verify_and_decode_jwt(get_doctor_token(DOCTOR_DR_SMITH_ID))

    # 1. Verify access succeeds before revocation
    assert rbac_authorizer.authorize_record_access(
        token_payload=doctor_payload,
        target_patient_id=PATIENT_ALICE_ID,
        record_id="REC-LAB-ALICE-001",
        record_type="LAB_REPORT"
    ) is True

    # 2. Patient Alice revokes consent
    revocation = consent_engine.revoke_consent(
        consent_id=consent_id,
        requesting_patient_id=PATIENT_ALICE_ID
    )
    assert revocation["status"] == "REVOKED"
    assert revocation["revoked_at"] is not None

    # 3. Doctor attempts access immediately after revocation
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=doctor_payload,
            target_patient_id=PATIENT_ALICE_ID,
            record_id="REC-LAB-ALICE-001",
            record_type="LAB_REPORT"
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "CONSENT_REVOKED"


@pytest.mark.security
@pytest.mark.consent
def test_expired_consent_blocks_access(rbac_authorizer, consent_engine):
    """Verify that a time-bound consent automatically expires and blocks access."""
    consent_id = "CONSENT-ALICE-SMITH-EXPIRED"
    # Set expiration 10 seconds in the past
    consent_engine.grant_consent(
        consent_id=consent_id,
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["ALL"],
        valid_until_epoch=int(time.time()) - 10
    )

    _, doctor_payload, _ = verify_and_decode_jwt(get_doctor_token(DOCTOR_DR_SMITH_ID))
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=doctor_payload,
            target_patient_id=PATIENT_ALICE_ID,
            record_id="REC-LAB-ALICE-001",
            record_type="LAB_REPORT"
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "CONSENT_EXPIRED"


@pytest.mark.security
@pytest.mark.consent
def test_consent_scope_isolation_enforced(rbac_authorizer, consent_engine):
    """Verify that granting LAB_REPORT does not allow CARDIOLOGY_VISIT access."""
    consent_id = "CONSENT-ALICE-SMITH-LAB-ONLY"
    consent_engine.grant_consent(
        consent_id=consent_id,
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT"],  # Only lab reports
        valid_until_epoch=int(time.time()) + 3600
    )

    _, doctor_payload, _ = verify_and_decode_jwt(get_doctor_token(DOCTOR_DR_SMITH_ID))
    with pytest.raises(AccessDeniedError) as exc_info:
        rbac_authorizer.authorize_record_access(
            token_payload=doctor_payload,
            target_patient_id=PATIENT_ALICE_ID,
            record_id="REC-CARD-ALICE-002",
            record_type="CARDIOLOGY_VISIT"  # Out of scope
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "CONSENT_SCOPE_EXCLUDED"


@pytest.mark.security
@pytest.mark.consent
def test_unauthorized_patient_cannot_revoke_third_party_consent(consent_engine):
    """Verify that Patient Bob cannot revoke consent granted by Patient Alice."""
    consent_id = "CONSENT-ALICE-SMITH-005"
    consent_engine.grant_consent(
        consent_id=consent_id,
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["ALL"],
        valid_until_epoch=int(time.time()) + 3600
    )

    # Bob attempts to revoke Alice's consent
    with pytest.raises(AccessDeniedError) as exc_info:
        consent_engine.revoke_consent(
            consent_id=consent_id,
            requesting_patient_id=PATIENT_BOB_ID
        )
    assert exc_info.value.reason == "REVOCATION_OWNERSHIP_VIOLATION"
