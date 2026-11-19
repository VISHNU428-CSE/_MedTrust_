"""
Integration Tests: IPFS CID Retrieval & Checksum Tampering Detection.

Verifies:
- Genuine payloads stored on IPFS/Kubo match registered ledger SHA-256 checksums.
- Any unauthorized payload alteration, bit flip, or MITM truncation on IPFS is detected.
- System raises ChecksumMismatchError before passing corrupt/tampered records to client.
"""

import pytest
import json
from fixtures.synthetic_records import (
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    compute_sha256,
    PATIENT_ALICE_ID
)
from core_harness import ChecksumMismatchError


@pytest.mark.integration
def test_valid_ipfs_retrieval_and_checksum_verification(ipfs_node, ipfs_verifier):
    """Verify that untampered content pinned to IPFS passes checksum verification."""
    record = get_synthetic_lab_report(PATIENT_ALICE_ID)
    raw_payload = json.dumps(record, sort_keys=True).encode("utf-8")
    expected_sha256 = compute_sha256(raw_payload)
    cid = record["ipfs_cid"]

    # Pin to IPFS node
    ipfs_node.pin_content(cid, raw_payload)

    # Retrieve and verify via IPFSVerifier
    retrieved_bytes = ipfs_verifier.fetch_and_verify(cid, expected_sha256)
    assert retrieved_bytes == raw_payload

    # Parse and confirm content integrity
    retrieved_data = json.loads(retrieved_bytes.decode("utf-8"))
    assert retrieved_data["record_id"] == record["record_id"]


@pytest.mark.integration
def test_ipfs_tampered_payload_triggers_critical_alert(ipfs_node, ipfs_verifier):
    """
    SECURITY AUDIT: IPFS payload tampering detection.
    Simulate an attacker altering lab results (e.g. changing Glucose value) directly on storage.
    Must raise ChecksumMismatchError.
    """
    record = get_synthetic_lab_report(PATIENT_ALICE_ID)
    raw_payload = json.dumps(record, sort_keys=True).encode("utf-8")
    expected_sha256 = compute_sha256(raw_payload)
    cid = record["ipfs_cid"]

    # Pin original payload
    ipfs_node.pin_content(cid, raw_payload)

    # Attacker tampers with content in IPFS storage
    tampered_data = dict(record)
    tampered_data["clinical_data"]["results"][0]["value"] = 350  # Tampered glucose level
    tampered_payload = json.dumps(tampered_data, sort_keys=True).encode("utf-8")
    ipfs_node.simulate_tampering(cid, tampered_payload)

    # Verification must fail and raise ChecksumMismatchError
    with pytest.raises(ChecksumMismatchError) as exc_info:
        ipfs_verifier.fetch_and_verify(cid, expected_sha256)

    assert "CRITICAL SECURITY ALERT: Checksum mismatch" in str(exc_info.value)
    assert cid in str(exc_info.value)


@pytest.mark.integration
def test_ipfs_truncated_payload_detected(ipfs_node, ipfs_verifier):
    """Verify that a truncated or incomplete payload transfer is caught."""
    record = get_synthetic_cardiology_encounter(PATIENT_ALICE_ID)
    raw_payload = json.dumps(record, sort_keys=True).encode("utf-8")
    expected_sha256 = compute_sha256(raw_payload)
    cid = record["ipfs_cid"]

    # Pin truncated payload
    truncated_payload = raw_payload[: len(raw_payload) // 2]
    ipfs_node.pin_content(cid, truncated_payload)

    with pytest.raises(ChecksumMismatchError):
        ipfs_verifier.fetch_and_verify(cid, expected_sha256)


@pytest.mark.integration
def test_ipfs_cid_not_found(ipfs_verifier):
    """Verify that querying an unknown or unpinned CID raises KeyError."""
    with pytest.raises(KeyError, match="IPFS CID not found"):
        ipfs_verifier.fetch_and_verify("bafybeimdt_nonexistent_cid", "dummy_hash")


# =========================================================================
# Targeted Tests: Verify Ledger 4 Distinct States (IPR-16)
# =========================================================================

@pytest.mark.integration
def test_verify_ledger_state_verified(monkeypatch):
    """Assert 'VERIFIED' status when live IPFS payload matches Fabric ledger registered checksum."""
    from app.services.record_service import record_service
    from app.adapters.ipfs_client import ipfs_client

    record_id = "rec-001"
    target_record = record_service.gateway.get_record(record_id)
    expected_sha = target_record["checksum_sha256"]

    mock_payload = b"GENUINE_UNALTERED_CLINICAL_PAYLOAD_CIPHERTEXT"

    monkeypatch.setattr(ipfs_client, "get_bytes", lambda cid, expected_sha256=None: mock_payload)
    monkeypatch.setattr("app.services.record_service.compute_sha256", lambda b: expected_sha)

    verification = record_service.verify_record_integrity(record_id)

    assert verification["status"] == "VERIFIED"
    assert verification["checksumMatches"] is True
    assert verification["recordId"] == record_id
    assert verification["ledgerChecksum"].lower() == expected_sha.lower()
    assert verification["computedSha256"].lower() == expected_sha.lower()
    assert "verified" in verification["detail"].lower()


@pytest.mark.integration
def test_verify_ledger_state_checksum_mismatch(monkeypatch):
    """Assert 'CHECKSUM_MISMATCH' status when payload data is tampered or corrupted."""
    from app.services.record_service import record_service
    from app.adapters.ipfs_client import ipfs_client
    from app.core.exceptions import ChecksumMismatchError

    record_id = "rec-001"

    # Scenario A: IPFS adapter raises ChecksumMismatchError
    def mock_tampered_fetch(cid, expected_sha256=None):
        raise ChecksumMismatchError(
            f"CRITICAL SECURITY ALERT: Checksum mismatch for CID {cid}! "
            f"Expected {expected_sha256}, calculated bad_checksum_1234."
        )

    monkeypatch.setattr(ipfs_client, "get_bytes", mock_tampered_fetch)

    res_a = record_service.verify_record_integrity(record_id)
    assert res_a["status"] == "CHECKSUM_MISMATCH"
    assert res_a["checksumMatches"] is False
    assert res_a["computedSha256"] == "MISMATCH"
    assert "checksum mismatch" in res_a["detail"].lower()

    # Scenario B: Return tampered payload where computed sha differs
    monkeypatch.setattr(ipfs_client, "get_bytes", lambda cid, expected_sha256=None: b"CORRUPTED_BYTES")
    monkeypatch.setattr("app.services.record_service.compute_sha256", lambda b: "forged_sha256_digest_xyz")

    res_b = record_service.verify_record_integrity(record_id)
    assert res_b["status"] == "CHECKSUM_MISMATCH"
    assert res_b["checksumMatches"] is False
    assert res_b["computedSha256"] == "forged_sha256_digest_xyz"


@pytest.mark.integration
def test_verify_ledger_state_ipfs_unavailable(monkeypatch):
    """Assert 'IPFS_UNAVAILABLE' status when Kubo daemon RPC times out or is unreachable."""
    from app.services.record_service import record_service
    from app.adapters.ipfs_client import ipfs_client
    from app.core.exceptions import IPFSConnectionError

    record_id = "rec-001"

    def mock_ipfs_offline(cid, expected_sha256=None):
        raise IPFSConnectionError("Cannot connect to IPFS Kubo RPC at http://127.0.0.1:5001/api/v0: ConnectTimeout")

    monkeypatch.setattr(ipfs_client, "get_bytes", mock_ipfs_offline)

    res = record_service.verify_record_integrity(record_id)
    assert res["status"] == "IPFS_UNAVAILABLE"
    assert res["checksumMatches"] is False
    assert res["computedSha256"] == "UNAVAILABLE"
    assert "could not retrieve payload from ipfs" in res["detail"].lower()


@pytest.mark.integration
def test_verify_ledger_state_ledger_unavailable():
    """Assert 'LEDGER_UNAVAILABLE' status when record ID is missing on Hyperledger Fabric ledger."""
    from app.services.record_service import record_service

    missing_record_id = "rec-missing-nonexistent-777"
    res = record_service.verify_record_integrity(missing_record_id)

    assert res["status"] == "LEDGER_UNAVAILABLE"
    assert res["checksumMatches"] is False
    assert res["recordId"] == missing_record_id
    assert res["ledgerChecksum"] == "UNAVAILABLE"
    assert res["computedSha256"] == "UNAVAILABLE"
    assert "not found on fabric ledger" in res["detail"].lower()

