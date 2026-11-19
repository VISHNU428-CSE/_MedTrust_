"""
Integration Tests: Audit Trail Completeness & Non-Repudiation.

Verifies:
- Every access attempt (allowed or denied) generates a durable audit entry.
- Audit entries contain complete context: actor, role, target, record, consent, status, timestamp.
- The cryptographic hash chain ensures tamper-evident audit logs.
- Modifying, deleting, or reordering log entries is immediately detected.
"""

import pytest
import time
from fixtures.auth_tokens import get_patient_token, get_doctor_token, verify_and_decode_jwt
from fixtures.synthetic_records import (
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    DOCTOR_DR_SMITH_ID
)
from core_harness import AccessDeniedError, AuditTrailLedger


@pytest.mark.integration
@pytest.mark.audit
def test_audit_event_logged_on_authorized_read(rbac_authorizer, audit_ledger):
    """Verify authorized patient self-read records an ALLOWED audit event."""
    _, alice_payload, _ = verify_and_decode_jwt(get_patient_token(PATIENT_ALICE_ID))

    initial_count = len(audit_ledger.entries)
    rbac_authorizer.authorize_record_access(
        token_payload=alice_payload,
        target_patient_id=PATIENT_ALICE_ID,
        record_id="REC-LAB-001",
        record_type="LAB_REPORT"
    )

    assert len(audit_ledger.entries) == initial_count + 1
    latest_entry = audit_ledger.entries[-1]
    assert latest_entry["actor_id"] == PATIENT_ALICE_ID
    assert latest_entry["actor_role"] == "PATIENT"
    assert latest_entry["target_patient_id"] == PATIENT_ALICE_ID
    assert latest_entry["record_id"] == "REC-LAB-001"
    assert latest_entry["status"] == "ALLOWED"
    assert "entry_hash" in latest_entry
    assert "prev_hash" in latest_entry


@pytest.mark.integration
@pytest.mark.audit
def test_audit_event_logged_on_denied_attempt(rbac_authorizer, audit_ledger):
    """Verify unauthorized horizontal access attempt records a DENIED audit event."""
    _, alice_payload, _ = verify_and_decode_jwt(get_patient_token(PATIENT_ALICE_ID))

    initial_count = len(audit_ledger.entries)
    with pytest.raises(AccessDeniedError):
        rbac_authorizer.authorize_record_access(
            token_payload=alice_payload,
            target_patient_id=PATIENT_BOB_ID,  # Alice trying to access Bob
            record_id="REC-RAD-003",
            record_type="RADIOLOGY_REPORT"
        )

    assert len(audit_ledger.entries) == initial_count + 1
    latest_entry = audit_ledger.entries[-1]
    assert latest_entry["actor_id"] == PATIENT_ALICE_ID
    assert latest_entry["target_patient_id"] == PATIENT_BOB_ID
    assert latest_entry["status"] == "DENIED"
    assert latest_entry["event_type"] == "HORIZONTAL_ACCESS_ATTEMPT"


@pytest.mark.integration
@pytest.mark.audit
def test_audit_hash_chain_integrity(rbac_authorizer, consent_engine, audit_ledger):
    """
    Verify that an extensive sequence of mixed access events produces an
    unbroken, cryptographically valid audit hash chain.
    """
    # 1. Grant consent
    consent_engine.grant_consent(
        consent_id="CONSENT-ALICE-SMITH-AUDIT",
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=int(time.time()) + 3600
    )

    _, alice_payload, _ = verify_and_decode_jwt(get_patient_token(PATIENT_ALICE_ID))
    _, doctor_payload, _ = verify_and_decode_jwt(get_doctor_token(DOCTOR_DR_SMITH_ID))

    # Event 1: Alice reads own record (ALLOWED)
    rbac_authorizer.authorize_record_access(alice_payload, PATIENT_ALICE_ID, "REC-LAB-001", "LAB_REPORT")

    # Event 2: Doctor reads Alice record with active consent (ALLOWED)
    rbac_authorizer.authorize_record_access(doctor_payload, PATIENT_ALICE_ID, "REC-LAB-001", "LAB_REPORT")

    # Event 3: Alice attempts to read Bob record (DENIED)
    try:
        rbac_authorizer.authorize_record_access(alice_payload, PATIENT_BOB_ID, "REC-RAD-003", "RADIOLOGY_REPORT")
    except AccessDeniedError:
        pass

    # Event 4: Alice revokes consent (logged to audit ledger)
    consent_engine.revoke_consent("CONSENT-ALICE-SMITH-AUDIT", PATIENT_ALICE_ID)
    audit_ledger.log_event(
        event_type="CONSENT_REVOCATION",
        actor_id=PATIENT_ALICE_ID,
        actor_role="PATIENT",
        target_patient_id=PATIENT_ALICE_ID,
        record_id=None,
        consent_id="CONSENT-ALICE-SMITH-AUDIT",
        status="ALLOWED",
        detail="Consent revoked by patient"
    )

    # Event 5: Doctor attempts read after revocation (DENIED)
    try:
        rbac_authorizer.authorize_record_access(doctor_payload, PATIENT_ALICE_ID, "REC-LAB-001", "LAB_REPORT")
    except AccessDeniedError:
        pass

    # Verify that the chain has 5 entries and passes cryptographic audit
    assert len(audit_ledger.entries) == 5
    is_intact, msg = audit_ledger.verify_chain_integrity()
    assert is_intact is True
    assert "cryptographically intact" in msg


@pytest.mark.integration
@pytest.mark.audit
def test_audit_tamper_detection_on_modified_log(audit_ledger):
    """
    SECURITY AUDIT: Detect unauthorized retrospective tampering of audit records.
    If an attacker alters an audit log entry in storage, the chain integrity check must fail.
    """
    audit_ledger.log_event("TEST_EVENT_1", "ACTOR-1", "PATIENT", "PAT-1", "REC-1", None, "ALLOWED", "Init")
    audit_ledger.log_event("TEST_EVENT_2", "ACTOR-2", "DOCTOR", "PAT-1", "REC-1", "CON-1", "ALLOWED", "Read")
    audit_ledger.log_event("TEST_EVENT_3", "ACTOR-3", "ATTACKER", "PAT-2", "REC-2", None, "DENIED", "Attack")

    # Verify chain intact before tampering
    is_intact, _ = audit_ledger.verify_chain_integrity()
    assert is_intact is True

    # Attacker tries to alter event status from DENIED to ALLOWED in history
    audit_ledger.entries[2]["status"] = "ALLOWED"

    # Integrity verification must catch the corruption
    is_intact, err = audit_ledger.verify_chain_integrity()
    assert is_intact is False
    assert "Corrupted entry hash" in err


@pytest.mark.integration
@pytest.mark.audit
def test_audit_tamper_detection_on_deleted_entry(audit_ledger):
    """
    SECURITY AUDIT: Detect deletion or removal of an audit entry.
    Removing an entry breaks the prev_hash link of subsequent entries.
    """
    audit_ledger.log_event("EVENT_1", "A-1", "PATIENT", "P-1", "R-1", None, "ALLOWED", "1")
    audit_ledger.log_event("EVENT_2", "A-2", "DOCTOR", "P-1", "R-1", "C-1", "ALLOWED", "2")
    audit_ledger.log_event("EVENT_3", "A-3", "PATIENT", "P-1", "R-2", None, "ALLOWED", "3")

    # Attacker deletes entry 2 to cover tracks
    del audit_ledger.entries[1]

    is_intact, err = audit_ledger.verify_chain_integrity()
    assert is_intact is False
    assert "Broken chain link" in err
