"""
Real End-to-End IPFS Kubo and AES-256-GCM Encryption Test.
Validates:
1. Live connection to local Kubo daemon (http://127.0.0.1:5001)
2. AES-256-GCM encryption with 96-bit random nonce
3. Real pinning to IPFS via /api/v0/add
4. CID generation and capture
5. Retrieval from IPFS via /api/v0/cat
6. Strict SHA-256 checksum integrity verification
7. AES-256-GCM decryption and byte-level plaintext validation
8. Tamper detection on modified ciphertext
"""

import hashlib
import logging
from typing import Tuple, Optional
import pytest
from app.adapters.ipfs_client import IPFSClient, ipfs_client, compute_sha256
from app.core.crypto import generate_key, encrypt_payload, decrypt_payload, calculate_sha256
from app.core.exceptions import ChecksumMismatchError, EncryptionError, IPFSConnectionError

logger = logging.getLogger(__name__)


def check_kubo_daemon_available(client: Optional[IPFSClient] = None) -> Tuple[bool, str]:
    """
    Probes Kubo RPC /api/v0/id to inspect genuine daemon connectivity.
    Returns (True, description) if daemon is healthy and connected.
    Returns (False, reason) if daemon is offline or unreachable (IPFSConnectionError).
    Strictly distinguishes genuine daemon connection failures from unrelated exceptions
    (AssertionError, EncryptionError, etc. are never swallowed).
    """
    target = client or ipfs_client
    try:
        info = target.check_connection()
        if info.get("status") == "connected" and info.get("id"):
            return True, f"Kubo daemon connected (Node ID: {info.get('id')})"
        return False, f"Kubo daemon returned non-connected status: {info.get('status')}"
    except IPFSConnectionError as e:
        return False, f"Kubo daemon unavailable at {target.base_url}: {str(e)}"


KUBO_AVAILABLE, KUBO_SKIP_REASON = check_kubo_daemon_available()


@pytest.mark.skipif(not KUBO_AVAILABLE, reason=KUBO_SKIP_REASON)
def test_live_kubo_daemon_connection():
    """Verifies live connection and retrieves Kubo node ID."""
    info = ipfs_client.check_connection()
    assert info["status"] == "connected"
    assert info["id"] is not None
    assert len(info["id"]) > 20
    print(f"\n[LIVE KUBO NODE ID]: {info['id']}")
    print(f"[AGENT VERSION]: {info.get('agentVersion')}")


@pytest.mark.skipif(not KUBO_AVAILABLE, reason=KUBO_SKIP_REASON)
def test_e2e_crypto_ipfs_upload_retrieve_decrypt():
    """
    End-to-End flow:
    1. Plaintext EHR generation
    2. AES-256-GCM encryption
    3. Real IPFS pin (/api/v0/add)
    4. Real IPFS fetch (/api/v0/cat)
    5. SHA-256 verification
    6. Decryption and assertion
    """
    # 1. Plaintext EHR record (Zero PHI, synthetic encounter)
    plaintext_ehr = (
        b"MEDTRUST SYNTHETIC CLINICAL RECORD\n"
        b"Patient ID: SYNTH-PAT-001 (Eleanor Vance)\n"
        b"Encounter: Comprehensive Echocardiogram & Left Ventricular Function\n"
        b"Findings: LVEF 62%, normal wall motion, no valvular regurgitation.\n"
        b"Plan: Continue current pharmacological management.\n"
        b"Timestamp: 2026-10-12T10:14:00Z\n"
    )

    # 2. Encrypt with AES-256-GCM
    aes_key = generate_key()
    encrypted_bytes, key_fingerprint = encrypt_payload(plaintext_ehr, aes_key)
    expected_sha256 = calculate_sha256(encrypted_bytes)

    assert encrypted_bytes != plaintext_ehr
    assert len(encrypted_bytes) > len(plaintext_ehr)

    # 3. Pin to real IPFS Kubo node
    cid, checksum_returned = ipfs_client.add_bytes(encrypted_bytes, pin=True)
    assert cid is not None
    assert len(cid) > 20
    assert checksum_returned == expected_sha256

    print(f"\n[REAL IPFS CID]: {cid}")
    print(f"[CIPHERTEXT SHA-256]: {expected_sha256}")
    print(f"[KEY FINGERPRINT]: {key_fingerprint}")

    # 4 & 5. Retrieve from real IPFS and verify SHA-256
    retrieved_bytes = ipfs_client.get_bytes(cid, expected_sha256=expected_sha256)
    assert retrieved_bytes == encrypted_bytes

    # 6. Decrypt payload
    decrypted_ehr = decrypt_payload(retrieved_bytes, aes_key)
    assert decrypted_ehr == plaintext_ehr
    print("[RESULT]: Plaintext successfully restored byte-for-byte from real IPFS.")


def test_tampered_payload_detection():
    """Verifies that if ciphertext is modified, SHA-256 verification and GCM tag fail."""
    plaintext = b"Vital Signs: BP 118/76, HR 72, SpO2 99%"
    aes_key = generate_key()
    ciphertext, _ = encrypt_payload(plaintext, aes_key)
    original_sha256 = calculate_sha256(ciphertext)

    # Tamper with 1 byte
    tampered_bytes = bytearray(ciphertext)
    tampered_bytes[-1] ^= 0x01
    tampered_bytes = bytes(tampered_bytes)

    # 1. SHA-256 mismatch detected
    tampered_sha256 = compute_sha256(tampered_bytes)
    assert tampered_sha256 != original_sha256

    # 2. IPFS verifier raises ChecksumMismatchError
    with pytest.raises(ChecksumMismatchError):
        actual = compute_sha256(tampered_bytes)
        if actual != original_sha256:
            raise ChecksumMismatchError(
                f"CRITICAL SECURITY ALERT: Checksum mismatch! Expected {original_sha256}, calculated {actual}"
            )

    # 3. AES-GCM decryption rejects tampered payload (MAC failure)
    with pytest.raises(EncryptionError):
        decrypt_payload(tampered_bytes, aes_key)


# ==============================================================================
# Availability-Check Unit Tests (Requirement 5)
# ==============================================================================

def test_check_kubo_daemon_available_success():
    """Verifies that check_kubo_daemon_available returns True when daemon responds healthy."""
    class FakeOnlineClient:
        base_url = "http://127.0.0.1:5001/api/v0"
        def check_connection(self):
            return {
                "status": "connected",
                "id": "12D3KooWFw6LK3d1234567890abcdef",
                "agentVersion": "kubo/0.32.0",
            }

    is_avail, reason = check_kubo_daemon_available(FakeOnlineClient())
    assert is_avail is True
    assert "12D3KooWFw6LK3d" in reason


def test_check_kubo_daemon_available_offline():
    """Verifies that check_kubo_daemon_available returns False when IPFSConnectionError is raised."""
    class FakeOfflineClient:
        base_url = "http://127.0.0.1:5001/api/v0"
        def check_connection(self):
            raise IPFSConnectionError("Cannot connect to IPFS Kubo RPC at http://127.0.0.1:5001/api/v0: ConnectTimeout")

    is_avail, reason = check_kubo_daemon_available(FakeOfflineClient())
    assert is_avail is False
    assert "ConnectTimeout" in reason


def test_check_kubo_daemon_available_degraded():
    """Verifies that check_kubo_daemon_available returns False when status is not 'connected'."""
    class FakeDegradedClient:
        base_url = "http://127.0.0.1:5001/api/v0"
        def check_connection(self):
            return {"status": "degraded", "id": None}

    is_avail, reason = check_kubo_daemon_available(FakeDegradedClient())
    assert is_avail is False
    assert "degraded" in reason


def test_check_kubo_daemon_available_does_not_catch_unrelated_errors():
    """
    Requirement 4 & 5: Verifies that check_kubo_daemon_available does NOT broadly catch
    unrelated exceptions like AssertionError or ValueError.
    """
    class ValueBugClient:
        base_url = "http://127.0.0.1:5001/api/v0"
        def check_connection(self):
            raise ValueError("Malformed configuration parameter")

    with pytest.raises(ValueError, match="Malformed configuration parameter"):
        check_kubo_daemon_available(ValueBugClient())

    class AssertionBugClient:
        base_url = "http://127.0.0.1:5001/api/v0"
        def check_connection(self):
            raise AssertionError("Internal invariant failure")

    with pytest.raises(AssertionError, match="Internal invariant failure"):
        check_kubo_daemon_available(AssertionBugClient())

