import pytest
from app.core.crypto import (
    generate_key,
    encrypt_payload,
    decrypt_payload,
    calculate_sha256,
    calculate_key_fingerprint
)
from app.core.exceptions import EncryptionError


def test_encryption_decryption_roundtrip():
    key = generate_key()
    original_data = b"Confidential Medical Diagnostic EHR: Patient exhibits sinus bradycardia."
    
    ciphertext, fingerprint = encrypt_payload(original_data, key)
    assert ciphertext != original_data
    assert fingerprint.startswith("SHA256:")
    
    decrypted = decrypt_payload(ciphertext, key)
    assert decrypted == original_data


def test_decryption_with_wrong_key_fails():
    key1 = generate_key()
    key2 = generate_key()
    original_data = b"Patient vitals: BP 120/80"
    
    ciphertext, _ = encrypt_payload(original_data, key1)
    with pytest.raises(EncryptionError):
        decrypt_payload(ciphertext, key2)


def test_decryption_tampered_ciphertext_fails():
    key = generate_key()
    original_data = b"Laboratory Analysis: Glucose 95 mg/dL"
    ciphertext, _ = encrypt_payload(original_data, key)
    
    # Tamper with single byte
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF
    with pytest.raises(EncryptionError):
        decrypt_payload(bytes(tampered), key)


def test_sha256_deterministic():
    data = b"MedTrust Decentralized Protocol"
    hash1 = calculate_sha256(data)
    hash2 = calculate_sha256(data)
    assert hash1 == hash2
    assert len(hash1) == 64


def test_key_fingerprint_format():
    key = generate_key()
    fp = calculate_key_fingerprint(key)
    assert fp.startswith("SHA256:")
    assert "..." in fp
