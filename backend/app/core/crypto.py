"""
Cryptographic module for MedTrust.
Implements:
- AES-256-GCM client/server encryption & decryption for off-chain health records
- Cryptographic SHA-256 checksum calculation for tamper detection
- Key generation and key fingerprint derivation
- Master KEK provisioning and AES-256-GCM DEK envelope wrapping with strict AAD binding
"""

import base64
import hashlib
import logging
import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.exceptions import EncryptionError

logger = logging.getLogger(__name__)

NONCE_LENGTH = 12  # Standard 96-bit nonce for AES-GCM
KEY_LENGTH = 32    # 256-bit symmetric key


def generate_key() -> bytes:
    """Generates a cryptographically secure 256-bit symmetric key."""
    return AESGCM.generate_key(bit_length=256)


def calculate_sha256(data: bytes) -> str:
    """Computes deterministic SHA-256 hexadecimal checksum."""
    return hashlib.sha256(data).hexdigest()


def calculate_key_fingerprint(key: bytes) -> str:
    """Derives a human-readable SHA256 key fingerprint."""
    digest = hashlib.sha256(key).hexdigest()
    return f"SHA256:{digest[:16]}...{digest[-4:]}"


def encrypt_payload(data: bytes, key: bytes) -> Tuple[bytes, str]:
    """
    Encrypts raw bytes using AES-256-GCM.
    Returns:
        (encrypted_bytes, key_fingerprint)
        where encrypted_bytes format is: nonce (12 bytes) + ciphertext_with_tag
    """
    if len(key) != KEY_LENGTH:
        raise EncryptionError(f"Invalid AES key length: expected {KEY_LENGTH} bytes, got {len(key)}")

    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(NONCE_LENGTH)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
        payload = nonce + ciphertext
        fingerprint = calculate_key_fingerprint(key)
        return payload, fingerprint
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt payload: {str(e)}") from e


def decrypt_payload(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-256-GCM encrypted payload.
    Expects: nonce (12 bytes) + ciphertext_with_tag
    """
    if len(key) != KEY_LENGTH:
        raise EncryptionError(f"Invalid AES key length: expected {KEY_LENGTH} bytes, got {len(key)}")

    if len(encrypted_data) < NONCE_LENGTH + 16:
        raise EncryptionError("Encrypted payload too short (missing nonce or authentication tag)")

    try:
        aesgcm = AESGCM(key)
        nonce = encrypted_data[:NONCE_LENGTH]
        ciphertext = encrypted_data[NONCE_LENGTH:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext
    except Exception as e:
        raise EncryptionError(f"Decryption failed or authentication tag mismatch: {str(e)}") from e


def get_master_kek() -> bytes:
    """
    Retrieves the Master Key Encryption Key (KEK) for envelope encryption.
    Hierarchy:
    1. MEDTRUST_MASTER_KEK (32-byte base64 encoded) from settings / environment.
    2. Safe development fallback with loud warning if unset.
    """
    from app.config import settings

    raw_kek = settings.MEDTRUST_MASTER_KEK
    if raw_kek and raw_kek.strip():
        raw_str = raw_kek.strip()
        # Try base64 decoding first
        try:
            decoded = base64.b64decode(raw_str)
            if len(decoded) == KEY_LENGTH:
                return decoded
        except Exception:
            pass

        # Try hex decoding if 64 hex characters
        try:
            decoded = bytes.fromhex(raw_str)
            if len(decoded) == KEY_LENGTH:
                return decoded
        except Exception:
            pass

        raise EncryptionError(
            f"Configured MEDTRUST_MASTER_KEK is invalid: expected {KEY_LENGTH}-byte base64 or 64-character hex string."
        )

    # Fallback to deterministic development/test KEK with security warning
    logger.warning(
        "SECURITY WARNING: MEDTRUST_MASTER_KEK is not configured in environment. "
        "Using development fallback Master KEK. DO NOT USE IN PRODUCTION."
    )
    return bytes.fromhex(settings.DEFAULT_MASTER_KEY_HEX)


def build_key_aad(record_id: str, patient_id: str, target_type: str) -> bytes:
    """
    Builds canonical authenticated associated data (AAD) for DEK wrapping.
    Binding format:
    'medtrust:v1:record={record_id}:patient={patient_id}:purpose={target_type}'
    Enforces cryptographic domain separation and prevents cross-record key substitution attacks.
    """
    return f"medtrust:v1:record={record_id}:patient={patient_id}:purpose={target_type}".encode("utf-8")


def wrap_dek(
    dek: bytes,
    kek: bytes,
    record_id: str,
    patient_id: str,
    target_type: str
) -> Tuple[str, str, str]:
    """
    Wraps (encrypts) a 32-byte Data Encryption Key (DEK) with Master KEK using AES-256-GCM.
    Strictly binds canonical AAD:
    'medtrust:v1:record={record_id}:patient={patient_id}:purpose={target_type}'.

    Returns:
        (encrypted_dek_b64, dek_nonce_b64, dek_tag_b64)
    """
    if len(dek) != KEY_LENGTH:
        raise EncryptionError(f"Invalid DEK length: expected {KEY_LENGTH} bytes, got {len(dek)}")
    if len(kek) != KEY_LENGTH:
        raise EncryptionError(f"Invalid KEK length: expected {KEY_LENGTH} bytes, got {len(kek)}")

    try:
        aesgcm = AESGCM(kek)
        nonce = os.urandom(NONCE_LENGTH)
        aad = build_key_aad(record_id, patient_id, target_type)
        ciphertext_with_tag = aesgcm.encrypt(nonce, dek, associated_data=aad)

        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]

        enc_dek_b64 = base64.b64encode(ciphertext).decode("ascii")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        tag_b64 = base64.b64encode(tag).decode("ascii")

        return enc_dek_b64, nonce_b64, tag_b64
    except Exception as e:
        raise EncryptionError(f"Failed to wrap DEK: {str(e)}") from e


def unwrap_dek(
    encrypted_dek: str,
    dek_nonce: str,
    dek_tag: str,
    kek: bytes,
    record_id: str,
    patient_id: str,
    target_type: str
) -> bytes:
    """
    Unwraps (decrypts) a Data Encryption Key (DEK) using Master KEK via AES-256-GCM.
    Strictly authenticates canonical AAD:
    'medtrust:v1:record={record_id}:patient={patient_id}:purpose={target_type}'.
    Raises EncryptionError if AAD mismatch, wrong KEK, or corrupted tag.
    """
    if len(kek) != KEY_LENGTH:
        raise EncryptionError(f"Invalid KEK length: expected {KEY_LENGTH} bytes, got {len(kek)}")

    try:
        # Decode encrypted_dek (support both base64 and hex)
        try:
            ciphertext = base64.b64decode(encrypted_dek)
        except Exception:
            ciphertext = bytes.fromhex(encrypted_dek)

        # Decode dek_nonce
        try:
            nonce = base64.b64decode(dek_nonce)
        except Exception:
            nonce = bytes.fromhex(dek_nonce)

        # Decode dek_tag
        try:
            tag = base64.b64decode(dek_tag)
        except Exception:
            tag = bytes.fromhex(dek_tag)

        if len(nonce) != NONCE_LENGTH:
            raise EncryptionError(f"Invalid nonce length: expected {NONCE_LENGTH} bytes, got {len(nonce)}")

        ciphertext_with_tag = ciphertext + tag
        aad = build_key_aad(record_id, patient_id, target_type)

        aesgcm = AESGCM(kek)
        dek = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=aad)
        if len(dek) != KEY_LENGTH:
            raise EncryptionError(f"Unwrapped DEK has invalid length: expected {KEY_LENGTH} bytes, got {len(dek)}")
        return dek
    except Exception as e:
        raise EncryptionError(
            f"Key unwrapping failed: authentication tag verification failed. AAD mismatch or corrupted key ({str(e)})"
        ) from e

