"""
Unit Tests: Checksum Calculation & Tamper Detection Sensitivity.
"""

import pytest
import hashlib
from fixtures.synthetic_records import compute_sha256


@pytest.mark.unit
def test_checksum_deterministic():
    """Verify that identical payloads produce identical SHA-256 digests."""
    data = b'{"record_id": "REC-001", "diagnosis": "Hypertension"}'
    hash1 = compute_sha256(data)
    hash2 = compute_sha256(data)
    assert hash1 == hash2
    assert len(hash1) == 64


@pytest.mark.unit
def test_checksum_avalanche_effect_single_byte_flip():
    """Verify that altering a single byte produces completely different checksum."""
    original = b'{"record_id": "REC-001", "dosage_mg": 10}'
    tampered = b'{"record_id": "REC-001", "dosage_mg": 20}'
    hash_orig = compute_sha256(original)
    hash_tamp = compute_sha256(tampered)
    assert hash_orig != hash_tamp


@pytest.mark.unit
def test_checksum_handles_empty_payload():
    """Verify checksum works on empty input and matches known SHA-256 standard."""
    empty_bytes = b""
    expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert compute_sha256(empty_bytes) == expected
