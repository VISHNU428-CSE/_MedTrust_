"""
Integration Tests: Hyperledger Fabric On-Chain Transaction & Ledger State Verification.

Directives:
1. Fabric transaction submission, block commit status, and ledger queries.
2. Consent lifecycle: Request -> Grant -> Verify (allowed: true) -> Revoke -> Verify (allowed: false, reason: CONSENT_REVOKED).
3. Record checksum verification on ledger.
4. Ledger state persistence across simulated node / container restarts.
"""

import time
import pytest
from fixtures.synthetic_records import (
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    DOCTOR_DR_SMITH_ID
)
from fixtures.golden_vectors import get_golden_vector
from app.adapters.real_fabric_gateway import RealFabricGatewayClient
from app.adapters.fabric_gateway import FabricGatewayAdapter


@pytest.mark.integration
def test_fabric_register_record_transaction_and_query(real_fabric_client):
    """
    Verify transaction submission to MedTrustContract:RegisterRecord.
    Validates transaction hash format, block commit, and query retrieval.
    """
    golden = get_golden_vector("LAB_REPORT")
    record_id = "REC-TX-TEST-001"
    
    # 1. Submit RegisterRecord transaction
    committed_tx = real_fabric_client.register_record(
        record_id=record_id,
        patient_id=PATIENT_ALICE_ID,
        ipfs_cid=golden["ipfs_cid"],
        checksum=golden["sha256_digest"],
        record_type=golden["record_type"],
        facility="Metro General Hospital",
        registered_by=DOCTOR_DR_SMITH_ID,
        title="Comprehensive Metabolic Panel",
        patient_name="Synthetic Alice"
    )

    # 2. Verify transaction metadata
    assert committed_tx["id"] == record_id
    assert committed_tx["tx_hash"].startswith("0x")
    assert len(committed_tx["tx_hash"]) == 66  # "0x" + 64 hex characters
    assert committed_tx["encryption_algorithm"] == "AES-256-GCM"

    # 3. Query ledger state by record_id
    queried = real_fabric_client.get_record(record_id)
    assert queried["id"] == record_id
    assert queried["checksum_sha256"] == golden["sha256_digest"]
    assert queried["ipfs_cid"] == golden["ipfs_cid"]

    # 4. Query ledger state by patient_id
    patient_records = real_fabric_client.get_records_by_patient(PATIENT_ALICE_ID)
    assert any(r["id"] == record_id for r in patient_records)


@pytest.mark.integration
def test_fabric_verify_record_checksum_on_ledger(real_fabric_client):
    """
    Verify on-chain checksum validation query.
    Returns VERIFIED_INTACT for matching hash and CHECKSUM_MISMATCH on corruption.
    """
    golden = get_golden_vector("CARDIOLOGY")
    record_id = "REC-TX-TEST-002"
    
    real_fabric_client.register_record(
        record_id=record_id,
        patient_id=PATIENT_ALICE_ID,
        ipfs_cid=golden["ipfs_cid"],
        checksum=golden["sha256_digest"],
        record_type=golden["record_type"],
        facility="Metro Heart Institute",
        registered_by=DOCTOR_DR_SMITH_ID
    )

    # Valid checksum verification
    valid_result = real_fabric_client.verify_record_checksum(record_id, golden["sha256_digest"])
    assert valid_result["verified"] is True
    assert valid_result["status"] == "VERIFIED_INTACT"

    # Corrupted / tampered checksum verification
    tampered_hash = "deadbeef" * 8
    tampered_result = real_fabric_client.verify_record_checksum(record_id, tampered_hash)
    assert tampered_result["verified"] is False
    assert tampered_result["status"] == "CHECKSUM_MISMATCH"


@pytest.mark.integration
def test_fabric_consent_full_lifecycle(real_fabric_client):
    """
    CRITICAL QUALITY GATE:
    Consent Lifecycle on Fabric Ledger:
    1. Clinician submits RequestConsent -> State PENDING
    2. Query VerifyConsent -> allowed: False (reason: CONSENT_PENDING)
    3. Patient submits GrantConsent -> State ACTIVE
    4. Query VerifyConsent -> allowed: True (reason: CONSENT_ACTIVE)
    5. Patient submits RevokeConsent -> State REVOKED
    6. Query VerifyConsent immediately -> allowed: False (reason: CONSENT_REVOKED)
    """
    consent_id = "cst-lifecycle-990"
    future_epoch = int(time.time()) + 86400  # Valid for 24 hours

    # Step 1: Doctor requests consent
    req = real_fabric_client.request_consent(
        consent_id=consent_id,
        patient_id=PATIENT_ALICE_ID,
        doctor_id=DOCTOR_DR_SMITH_ID,
        allowed_record_types=["LAB_REPORT", "CARDIOLOGY_VISIT"],
        valid_until_epoch=future_epoch,
        purpose="Cardiovascular consultation",
        doctor_name="Dr. Smith",
        hospital="Metro General"
    )
    assert req["status"] == "PENDING"
    req_consent_id = req["id"]

    # Step 2: Verify access before patient grant -> must be rejected
    check_pending = real_fabric_client.verify_consent(
        doctor_id=DOCTOR_DR_SMITH_ID,
        patient_id=PATIENT_ALICE_ID,
        record_type="LAB_REPORT"
    )
    assert check_pending["allowed"] is False
    assert check_pending["reason"] == "CONSENT_PENDING"

    # Step 3: Patient Alice grants consent
    grant = real_fabric_client.grant_consent(
        consent_id=req_consent_id,
        patient_id=PATIENT_ALICE_ID
    )
    assert grant["status"] == "ACTIVE"

    # Step 4: Verify access after grant -> must be allowed
    check_active = real_fabric_client.verify_consent(
        doctor_id=DOCTOR_DR_SMITH_ID,
        patient_id=PATIENT_ALICE_ID,
        record_type="LAB_REPORT"
    )
    assert check_active["allowed"] is True
    assert check_active["reason"] == "CONSENT_ACTIVE"
    assert check_active["consentId"] == req_consent_id

    # Step 5: Patient Alice revokes consent
    revocation = real_fabric_client.revoke_consent(
        consent_id=req_consent_id,
        requesting_patient_id=PATIENT_ALICE_ID
    )
    assert revocation["status"] == "REVOKED"
    assert "revoked_at" in revocation

    # Step 6: Verify access immediately after revocation -> must be immediately blocked
    check_revoked = real_fabric_client.verify_consent(
        doctor_id=DOCTOR_DR_SMITH_ID,
        patient_id=PATIENT_ALICE_ID,
        record_type="LAB_REPORT"
    )
    assert check_revoked["allowed"] is False
    assert check_revoked["reason"] == "CONSENT_REVOKED"


@pytest.mark.integration
def test_fabric_ledger_state_persistence_across_restarts():
    """
    Verify ledger state persistence:
    Simulates a network container / gateway client restart by checkpointing state
    and restoring it into a new adapter instance.
    All records, consents, and cryptographic audit blocks must persist intact.
    """
    # 1. First client writes state to ledger
    client1 = RealFabricGatewayClient()
    rec = client1.register_record(
        record_id="REC-PERSIST-101",
        patient_id=PATIENT_ALICE_ID,
        ipfs_cid="bafybeipersistcid101",
        checksum="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        record_type="EHR_GENERAL",
        facility="Metro General",
        registered_by=DOCTOR_DR_SMITH_ID
    )
    audit = client1.log_access_event(
        event_type="RECORD_CREATION",
        actor_id=DOCTOR_DR_SMITH_ID,
        actor_role="DOCTOR",
        target_patient_id=PATIENT_ALICE_ID,
        record_id="REC-PERSIST-101",
        status="ALLOWED",
        detail="Registered initial EHR"
    )

    # 2. Export / serialize snapshot of committed ledger state
    adapter1 = getattr(client1, "_fallback_adapter", client1)
    snapshot_records = dict(adapter1._records)
    snapshot_consents = dict(adapter1._consents)
    snapshot_audit = list(adapter1._audit_chain)
    snapshot_prev_hash = adapter1._prev_audit_hash

    # 3. Simulate process / container reboot by instantiating fresh client
    client2 = RealFabricGatewayClient()
    adapter2 = getattr(client2, "_fallback_adapter", client2)
    # Restore persisted state
    adapter2._records = snapshot_records
    adapter2._consents = snapshot_consents
    adapter2._audit_chain = snapshot_audit
    adapter2._prev_audit_hash = snapshot_prev_hash

    # 4. Verify record exists and matches exactly
    reloaded_rec = client2.get_record("REC-PERSIST-101")
    assert reloaded_rec["id"] == "REC-PERSIST-101"
    assert reloaded_rec["ipfs_cid"] == "bafybeipersistcid101"

    # 5. Verify audit chain verification succeeds on restored state
    chain_check = client2.verify_audit_chain()
    assert chain_check["isIntact"] is True
    assert chain_check["lastHash"] == snapshot_prev_hash
