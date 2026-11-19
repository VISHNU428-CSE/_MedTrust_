"""
MedTrust Key Management Service (Task 6D.2 / IPR-39).
Implements envelope encryption (KEK/DEK) key lifecycle and persistence:
- Secure Master KEK loading from environment/config without hardcoded defaults
- AES-256-GCM wrapping and unwrapping of Data Encryption Keys (DEKs)
- Cryptographic binding of record_id, patient_id, and purpose via AAD
- Explicit KEK version management
- Additive database persistence via RecordKeyModel
"""

import base64
import binascii
import hashlib
import logging
import os
from dataclasses import dataclass
from typing import Dict, Optional, Union, Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.db.models import RecordKeyModel

logger = logging.getLogger(__name__)

# Constants
KEY_LENGTH = 32        # 256-bit AES key
NONCE_LENGTH = 12      # 96-bit CSPRNG nonce
TAG_LENGTH = 16        # 128-bit authentication tag


class KeyPurpose:
    """Canonical purpose identifiers for envelope encryption keys."""
    PRIMARY_DOCUMENT = "PRIMARY_DOCUMENT"
    PRESCRIPTION = "PRESCRIPTION"


VALID_PURPOSES = {KeyPurpose.PRIMARY_DOCUMENT, KeyPurpose.PRESCRIPTION}


class KeyManagementError(Exception):
    """Base exception for Key Management operations."""
    pass


class KeyConfigurationError(KeyManagementError):
    """Raised when KEK configuration is missing, malformed, invalid length, or unknown version."""
    pass


class KeyUnwrapError(KeyManagementError):
    """Raised when unwrapping a DEK fails due to wrong KEK, invalid tag, or corrupted data."""
    pass


class KeyTamperingError(KeyUnwrapError):
    """Raised when AAD verification fails due to tampered record_id, patient_id, or purpose."""
    pass


class KeyNotFoundError(KeyManagementError):
    """Raised when a requested record key is not found in database persistence."""
    pass


class KeyConflictError(KeyManagementError):
    """Raised when attempting to overwrite an existing persistent key for a record and purpose."""
    pass


@dataclass(frozen=True)
class WrappedDEK:
    """Represents a wrapped DEK with its cryptographic envelope components."""
    encrypted_dek: bytes      # Ciphertext of DEK (32 bytes)
    nonce: bytes              # 12-byte CSPRNG nonce
    tag: bytes                # 16-byte AES-GCM authentication tag
    kek_version: str          # Master KEK version identifier (e.g. "v1")
    key_fingerprint: str      # SHA-256 fingerprint for verification/audit

    def to_hex_dict(self) -> Dict[str, str]:
        """Returns hex-encoded dictionary representation suitable for serialization/storage."""
        return {
            "encrypted_dek": self.encrypted_dek.hex(),
            "dek_nonce": self.nonce.hex(),
            "dek_tag": self.tag.hex(),
            "kek_version": self.kek_version,
            "key_fingerprint": self.key_fingerprint,
        }

    @classmethod
    def from_hex_dict(cls, data: Dict[str, Any]) -> "WrappedDEK":
        """Instantiates WrappedDEK from hex-encoded dictionary."""
        return cls(
            encrypted_dek=bytes.fromhex(data["encrypted_dek"]),
            nonce=bytes.fromhex(data["dek_nonce"]),
            tag=bytes.fromhex(data["dek_tag"]),
            kek_version=data["kek_version"],
            key_fingerprint=data.get("key_fingerprint", ""),
        )


class KeyManager:
    """
    Manages cryptographic envelopes for MedTrust records and prescriptions.
    
    Hard boundaries enforced:
    - Never uses a hardcoded default KEK.
    - Requires explicit KEK provisioning via environment variable or parameters.
    - Binds record_id, patient_id, and purpose into AES-GCM Additional Authenticated Data (AAD).
    - Preserves multi-version KEK rotation readiness.
    """

    def __init__(
        self,
        kek: Optional[Union[bytes, str]] = None,
        kek_version: str = "v1",
        env_var: str = "MEDTRUST_MASTER_KEK",
        keks: Optional[Dict[str, Union[bytes, str]]] = None,
    ):
        self.active_version = kek_version
        self.env_var = env_var
        self._keks: Dict[str, bytes] = {}

        # 1. Resolve and validate active KEK
        resolved_active = self._resolve_active_kek(kek, env_var)
        self._keks[self.active_version] = self._validate_and_parse_key(
            resolved_active, f"active KEK (version '{self.active_version}')"
        )

        # 2. Register any additional historical/rotation KEK versions
        if keks:
            for v, k in keks.items():
                if v not in self._keks:
                    self._keks[v] = self._validate_and_parse_key(k, f"KEK version '{v}'")

    def _resolve_active_kek(self, kek: Optional[Union[bytes, str]], env_var: str) -> Union[bytes, str]:
        """Resolves the active KEK from explicit parameter or environment variable."""
        if kek is not None:
            return kek

        env_val = os.environ.get(env_var)
        if env_val and env_val.strip():
            return env_val.strip()

        raise KeyConfigurationError(
            f"Master KEK is not configured. Environment variable '{env_var}' is unset or empty, "
            "and no explicit KEK was provided. Hardcoded defaults and silent in-memory fallbacks are strictly prohibited."
        )

    @staticmethod
    def _validate_and_parse_key(key_input: Union[bytes, str], context: str) -> bytes:
        """
        Validates format and decodes key into exactly 32 bytes.
        Supports:
        - raw 32 bytes
        - 64-character hex string
        - base64-encoded 32-byte string
        """
        if isinstance(key_input, bytes):
            if len(key_input) != KEY_LENGTH:
                raise KeyConfigurationError(
                    f"Invalid key length for {context}: expected {KEY_LENGTH} bytes, got {len(key_input)} bytes."
                )
            return key_input

        if isinstance(key_input, str):
            trimmed = key_input.strip()
            # Try hex decoding (64 hex characters = 32 bytes)
            if len(trimmed) == 64:
                try:
                    decoded = bytes.fromhex(trimmed)
                    if len(decoded) == KEY_LENGTH:
                        return decoded
                except ValueError:
                    pass

            # Try base64 decoding (44 chars = 32 bytes base64)
            try:
                decoded = base64.b64decode(trimmed, validate=True)
                if len(decoded) == KEY_LENGTH:
                    return decoded
                raise KeyConfigurationError(
                    f"Invalid key length for {context}: base64 decoded to {len(decoded)} bytes, expected {KEY_LENGTH}."
                )
            except (binascii.Error, ValueError) as e:
                raise KeyConfigurationError(
                    f"Invalid key encoding for {context}: string must be a 64-character hex string "
                    f"or base64-encoded 32-byte key. Error: {str(e)}"
                ) from e

        raise KeyConfigurationError(
            f"Unsupported key type for {context}: expected bytes or str, got {type(key_input).__name__}."
        )

    def get_kek(self, version: Optional[str] = None) -> bytes:
        """Retrieves raw KEK bytes for the specified version (or active version)."""
        target_version = version or self.active_version
        if target_version not in self._keks:
            raise KeyConfigurationError(
                f"Master KEK version '{target_version}' is not configured. Known versions: {sorted(self._keks.keys())}"
            )
        return self._keks[target_version]

    @staticmethod
    def build_aad(record_id: str, patient_id: str, purpose: str) -> bytes:
        """
        Constructs canonical Additional Authenticated Data (AAD) for AES-256-GCM.
        Strictly binds record_id, patient_id, and purpose to prevent cross-record key substitution attacks.
        Format: medtrust:v1:record={record_id}:patient={patient_id}:purpose={purpose}
        """
        if not record_id or not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("record_id must be a non-empty string")
        if not patient_id or not isinstance(patient_id, str) or not patient_id.strip():
            raise ValueError("patient_id must be a non-empty string")
        if purpose not in VALID_PURPOSES:
            raise ValueError(
                f"Invalid key purpose '{purpose}'. Must be one of: {sorted(VALID_PURPOSES)}"
            )
        return f"medtrust:v1:record={record_id.strip()}:patient={patient_id.strip()}:purpose={purpose}".encode("utf-8")

    @staticmethod
    def generate_dek() -> bytes:
        """Generates a fresh cryptographically secure 256-bit symmetric DEK."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def calculate_fingerprint(key_bytes: bytes) -> str:
        """Computes a SHA-256 fingerprint for audit logging without revealing key material."""
        digest = hashlib.sha256(key_bytes).hexdigest()
        return f"SHA256:{digest[:16]}...{digest[-4:]}"

    def wrap_dek(
        self,
        dek: bytes,
        record_id: str,
        patient_id: str,
        purpose: str = KeyPurpose.PRIMARY_DOCUMENT,
        kek_version: Optional[str] = None,
    ) -> WrappedDEK:
        """
        Wraps (encrypts) a 32-byte DEK under the Master KEK using AES-256-GCM.
        Binds record_id, patient_id, and purpose into the authentication tag via AAD.
        """
        if not isinstance(dek, bytes) or len(dek) != KEY_LENGTH:
            raise KeyManagementError(f"DEK must be {KEY_LENGTH} raw bytes, got {len(dek) if isinstance(dek, bytes) else 'non-bytes'}")

        target_version = kek_version or self.active_version
        kek = self.get_kek(target_version)
        nonce = os.urandom(NONCE_LENGTH)
        aad = self.build_aad(record_id, patient_id, purpose)

        try:
            aesgcm = AESGCM(kek)
            ciphertext_with_tag = aesgcm.encrypt(nonce, dek, associated_data=aad)
            encrypted_dek = ciphertext_with_tag[:-TAG_LENGTH]
            tag = ciphertext_with_tag[-TAG_LENGTH:]
            fingerprint = self.calculate_fingerprint(dek)

            return WrappedDEK(
                encrypted_dek=encrypted_dek,
                nonce=nonce,
                tag=tag,
                kek_version=target_version,
                key_fingerprint=fingerprint,
            )
        except Exception as e:
            raise KeyManagementError(f"Failed to wrap DEK: {str(e)}") from e

    def unwrap_dek(
        self,
        wrapped: Union[WrappedDEK, RecordKeyModel, Dict[str, Any]],
        record_id: str,
        patient_id: str,
        purpose: str = KeyPurpose.PRIMARY_DOCUMENT,
    ) -> bytes:
        """
        Unwraps (decrypts) a DEK using the Master KEK and verifies AAD.
        Accepts WrappedDEK, RecordKeyModel, or hex-dictionary.
        Raises KeyUnwrapError on authentication tag mismatch, wrong KEK, or tampered AAD.
        """
        # 1. Parse fields according to input type
        try:
            if isinstance(wrapped, RecordKeyModel):
                encrypted_dek = bytes.fromhex(wrapped.encrypted_dek)
                nonce = bytes.fromhex(wrapped.dek_nonce)
                tag = bytes.fromhex(wrapped.dek_tag)
                version = wrapped.kek_version
            elif isinstance(wrapped, WrappedDEK):
                encrypted_dek = wrapped.encrypted_dek
                nonce = wrapped.nonce
                tag = wrapped.tag
                version = wrapped.kek_version
            elif isinstance(wrapped, dict):
                parsed = WrappedDEK.from_hex_dict(wrapped)
                encrypted_dek = parsed.encrypted_dek
                nonce = parsed.nonce
                tag = parsed.tag
                version = parsed.kek_version
            else:
                raise KeyManagementError(f"Unsupported wrapped key type: {type(wrapped).__name__}")
        except (ValueError, binascii.Error) as e:
            raise KeyUnwrapError(f"Corrupted or invalid hex encoding in stored key envelope: {str(e)}") from e

        # 2. Retrieve appropriate KEK version
        kek = self.get_kek(version)

        # 3. Construct canonical AAD
        aad = self.build_aad(record_id, patient_id, purpose)
        ciphertext_with_tag = encrypted_dek + tag

        # 4. Decrypt and verify
        try:
            aesgcm = AESGCM(kek)
            plaintext_dek = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=aad)
            if len(plaintext_dek) != KEY_LENGTH:
                raise KeyUnwrapError(f"Unwrapped DEK length invalid: expected {KEY_LENGTH}, got {len(plaintext_dek)}")
            return plaintext_dek
        except InvalidTag as e:
            raise KeyUnwrapError(
                "Cryptographic unwrap verification failed: invalid authentication tag or tampered AAD "
                f"(record_id='{record_id}', patient_id='{patient_id}', purpose='{purpose}', kek_version='{version}')."
            ) from e
        except Exception as e:
            if isinstance(e, KeyManagementError):
                raise
            raise KeyUnwrapError(f"Failed to unwrap DEK: {str(e)}") from e

    def save_record_key(
        self,
        db: Session,
        record_id: str,
        patient_id: str,
        purpose: str,
        wrapped: WrappedDEK,
    ) -> RecordKeyModel:
        """
        Persists a wrapped DEK into SQLite via RecordKeyModel.
        Enforces composite uniqueness on (record_id, purpose) and immutable key persistence.
        Raises KeyConflictError if a key already exists for the given (record_id, purpose).
        """
        if purpose not in VALID_PURPOSES:
            raise ValueError(f"Invalid purpose '{purpose}'. Must be one of: {sorted(VALID_PURPOSES)}")

        existing = (
            db.query(RecordKeyModel)
            .filter(RecordKeyModel.record_id == record_id, RecordKeyModel.purpose == purpose)
            .first()
        )

        hex_data = wrapped.to_hex_dict()

        if existing:
            logger.warning(
                "Rejected attempt to overwrite existing encryption key: record_id=%s, purpose=%s, existing_fingerprint=%s, incoming_fingerprint=%s",
                record_id,
                purpose,
                existing.key_fingerprint,
                hex_data.get("key_fingerprint"),
            )
            raise KeyConflictError(
                f"Encryption key already exists for record_id '{record_id}' with purpose '{purpose}'. "
                "Active record encryption keys are immutable to prevent ciphertext corruption."
            )

        new_key = RecordKeyModel(
            record_id=record_id,
            patient_id=patient_id,
            purpose=purpose,
            encrypted_dek=hex_data["encrypted_dek"],
            dek_nonce=hex_data["dek_nonce"],
            dek_tag=hex_data["dek_tag"],
            kek_version=hex_data["kek_version"],
            key_fingerprint=hex_data["key_fingerprint"],
        )
        db.add(new_key)
        db.commit()
        db.refresh(new_key)
        logger.info("Persisted new record key: record_id=%s, purpose=%s", record_id, purpose)
        return new_key

    def get_record_key(
        self,
        db: Session,
        record_id: str,
        purpose: str = KeyPurpose.PRIMARY_DOCUMENT,
    ) -> Optional[RecordKeyModel]:
        """Queries RecordKeyModel by record_id and purpose."""
        return (
            db.query(RecordKeyModel)
            .filter(RecordKeyModel.record_id == record_id, RecordKeyModel.purpose == purpose)
            .first()
        )

    def unwrap_record_key(
        self,
        db: Session,
        record_id: str,
        patient_id: str,
        purpose: str = KeyPurpose.PRIMARY_DOCUMENT,
    ) -> bytes:
        """
        Retrieves wrapped key from database and unwraps the plaintext DEK.
        Raises KeyNotFoundError if key does not exist.
        """
        model = self.get_record_key(db, record_id, purpose)
        if not model:
            raise KeyNotFoundError(
                f"No persistent encryption key found for record_id '{record_id}' with purpose '{purpose}'."
            )
        return self.unwrap_dek(model, record_id, patient_id, purpose)
