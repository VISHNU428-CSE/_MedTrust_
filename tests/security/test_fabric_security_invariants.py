"""
Security Tests: Hyperledger Fabric Security Invariants & Attack Resistance.

Verifies:
1. Strict Zero-PHI enforcement on all chaincode payloads (rejection of SSNs, private keys, passwords).
2. Access denial for unauthorized actors and horizontal privilege escalation (cross-patient consent tampering).
3. Consent scope isolation (out-of-scope clinical record access denied).
4. Non-repudiation and cryptographic audit chain tamper resistance on ledger.
"""

import pytest
import time
from fixtures.synthetic_records import (
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    DOCTOR_DR_SMITH_ID,
    DOCTOR_DR_JONES_ID,
    ATTACKER_EVE_ID
)
from app.core.exceptions import AccessDeniedError, ConsentNotFoundError


@pytest.mark.security
def test_fabric_zero_phi_rejection_ssn(real_fabric_client):
    """
    QUALITY GATE 1: Zero-PHI On-Chain Enforcement.
    Attempting to submit an SSN in any chaincode argument must raise a critical ValueError.
    """
    with pytest.raises(ValueError, match="CRITICAL ZERO-PHI VIOLATION: SSN pattern detected"):
        real_fabric_client.register_record(
            record_id="REC-LEAK-001",
            patient_id=PATIENT_ALICE_ID,
            ipfs_cid="bafybeidummycid",
            checksum="0000000000000000000000000000000000000000000000000000000000000000",
            record_type="LAB_REPORT",
            facility="Metro Hospital",
            registered_by=DOCTOR_DR_SMITH_ID,
            title="Lab record for patient with SSN 123-45-6789"  # Forbidden real SSN
        )


@pytest.mark.security
def test_fabric_zero_phi_rejection_private_key(real_fabric_client):
    """
    QUALITY GATE 1: Zero-PHI On-Chain Enforcement.
    Attempting to leak a private key in chaincode arguments must be blocked.
    """
    private_key_leak = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    with pytest.raises(ValueError, match="CRITICAL ZERO-PHI VIOLATION: Private key detected"):
        real_fabric_client.request_consent(
            consent_id="cst-leak-key",
            patient_id=PATIENT_ALICE_ID,
            doctor_id=DOCTOR_DR_SMITH_ID,
            allowed_record_types=["ALL"],
            valid_until_epoch=int(time.time()) + 3600,
            purpose=f"Attacker payload: {private_key_leak}"
        )


@pytest.mark.security
def test_fabric_zero_phi_rejection_plaintext_password(real_fabric_client):
    """
    QUALITY GATE 1: Zero-PHI On-Chain Enforcement.
    Attempting to leak plain passwords in chaincode arguments must be blocked.
    """
    with pytest.raises(ValueError, match="CRITICAL ZERO-PHI VIOLATION: Plain password detected"):
        real_fabric_client.log_access_event(
            event_type="UNAUTHORIZED_LOGIN",
            actor_id="attacker",
            actor_role="UNKNOWN",
            target_patient_id=PATIENT_ALICE_ID,
            status="DENIED",
            detail="User attempted password: SecretPass123!"
        )


@pytest.mark.security
def test_fabric_cross_patient_consent_grant_denied(real_fabric_client):
    """
    SECURITY AUDIT: Horizontal privilege escalation.
    Patient Bob attempts to approve or grant consent for Patient Alice's records.
    Must raise AccessDeniedError (UNAUTHORIZED_GRANT).
    """
    req = real_fabric_client.request_consent(
        consent_id="cst-cross-grant-01",
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=int(time.time()) + 3600,
        purpose="Consultation"
    )

    # Bob attempts to grant Alice's consent
    with pytest.raises(AccessDeniedError) as exc_info:
        real_fabric_client.grant_consent(
            consent_id=req["id"],
            patient_id=PATIENT_BOB_ID  # Wrong patient
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "UNAUTHORIZED_GRANT"


@pytest.mark.security
def test_fabric_cross_patient_consent_revocation_denied(real_fabric_client):
    """
    SECURITY AUDIT: Horizontal privilege escalation.
    Patient Bob attempts to revoke Patient Alice's active consent.
    Must raise AccessDeniedError (REVOCATION_OWNERSHIP_VIOLATION).
    """
    req = real_fabric_client.request_consent(
        consent_id="cst-cross-revoke-02",
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=int(time.time()) + 3600,
        purpose="Consultation"
    )
    real_fabric_client.grant_consent(req["id"], PATIENT_ALICE_ID)

    # Bob attempts to revoke Alice's consent
    with pytest.raises(AccessDeniedError) as exc_info:
        real_fabric_client.revoke_consent(
            consent_id=req["id"],
            requesting_patient_id=PATIENT_BOB_ID  # Wrong patient
        )
    assert exc_info.value.code == 403
    assert exc_info.value.reason == "REVOCATION_OWNERSHIP_VIOLATION"


@pytest.mark.security
def test_fabric_consent_scope_confinement(real_fabric_client):
    """
    SECURITY AUDIT: Scoped consent isolation.
    Doctor granted LAB_REPORT access cannot query RADIOLOGY_REPORT records.
    """
    req = real_fabric_client.request_consent(
        consent_id="cst-scope-test-03",
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_JONES_ID,
        allowed_record_types=["LAB_REPORT"],  # Only LAB_REPORT
        valid_until_epoch=int(time.time()) + 3600,
        purpose="Lab analysis"
    )
    real_fabric_client.grant_consent(req["id"], PATIENT_ALICE_ID)

    # Doctor queries out-of-scope record type
    check = real_fabric_client.verify_consent(
        doctor_id=DOCTOR_DR_JONES_ID,
        patient_id=PATIENT_ALICE_ID,
        record_type="IMAGING_MRI"  # Excluded from scope
    )
    assert check["allowed"] is False
    assert check["reason"] == "CONSENT_SCOPE_EXCLUDED"


@pytest.mark.security
def test_fabric_unregistered_doctor_access_denied(real_fabric_client):
    """
    SECURITY AUDIT: Unknown or malicious third party queries patient record.
    Must return NO_CONSENT_FOUND.
    """
    check = real_fabric_client.verify_consent(
        doctor_id=ATTACKER_EVE_ID,
        patient_id=PATIENT_ALICE_ID,
        record_type="LAB_REPORT"
    )
    assert check["allowed"] is False
    assert check["reason"] == "NO_CONSENT_FOUND"


@pytest.mark.security
def test_fabric_on_chain_audit_tamper_resistance(real_fabric_client):
    """
    SECURITY AUDIT: On-chain audit trail non-repudiation.
    Detects any retroactive tampering with on-chain audit history blocks.
    """
    # Verify chain intact before tampering
    intact_check = real_fabric_client.verify_audit_chain()
    assert intact_check["isIntact"] is True

    # Attacker alters an audit entry directly in ledger state
    adapter = getattr(real_fabric_client, "_fallback_adapter", real_fabric_client)
    adapter._audit_chain[0]["action"] = "MUTATED_BY_ATTACKER"

    # Integrity verification must catch broken chain
    tampered_check = real_fabric_client.verify_audit_chain()
    assert tampered_check["isIntact"] is False
    assert "Corrupted entry hash" in tampered_check["message"]
