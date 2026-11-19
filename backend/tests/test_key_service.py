"""
Unit test suite for MedTrust Key Management Service (Task 6D.2 / IPR-39).
Tests envelope encryption key persistence, format validation, KEK versioning,
AAD cryptographic binding, tamper resistance, and SQLite persistence under test DB isolation.
"""

import base64
import os
import pytest
from sqlalchemy.orm import Session

from app.db.session import engine, Base, SessionLocal
from app.db.models import RecordKeyModel
from app.services.key_service import (
    KeyManager,
    KeyPurpose,
    WrappedDEK,
    KeyManagementError,
    KeyConfigurationError,
    KeyUnwrapError,
    KeyNotFoundError,
    KeyConflictError,
    KEY_LENGTH,
    NONCE_LENGTH,
    TAG_LENGTH,
)

# Test fixtures and constants
TEST_KEK_BYTES = b"01234567890123456789012345678901"  # Exactly 32 bytes
TEST_KEK_HEX = TEST_KEK_BYTES.hex()
TEST_KEK_B64 = base64.b64encode(TEST_KEK_BYTES).decode("utf-8")

ALT_KEK_BYTES = b"abcdefghijklmnopqrstuvwxyz123456"  # Exactly 32 bytes
ALT_KEK_HEX = ALT_KEK_BYTES.hex()


@pytest.fixture
def key_manager():
    """Provides a KeyManager instance initialized with a known 32-byte test KEK."""
    return KeyManager(kek=TEST_KEK_BYTES, kek_version="v1")


@pytest.fixture
def db_session():
    """Provides an isolated database session bound to the test database."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


# ============================================================================
# 1. Configuration & Validation Tests
# ============================================================================

def test_key_manager_init_with_valid_32_bytes():
    km = KeyManager(kek=TEST_KEK_BYTES, kek_version="v1")
    assert km.get_kek("v1") == TEST_KEK_BYTES
    assert km.active_version == "v1"


def test_key_manager_init_with_valid_64_char_hex():
    km = KeyManager(kek=TEST_KEK_HEX, kek_version="v1")
    assert km.get_kek("v1") == TEST_KEK_BYTES


def test_key_manager_init_with_valid_base64():
    km = KeyManager(kek=TEST_KEK_B64, kek_version="v1")
    assert km.get_kek("v1") == TEST_KEK_BYTES


def test_key_manager_init_from_env_var(monkeypatch):
    monkeypatch.setenv("MEDTRUST_TEST_KEK_VAR", TEST_KEK_HEX)
    km = KeyManager(env_var="MEDTRUST_TEST_KEK_VAR")
    assert km.get_kek() == TEST_KEK_BYTES


def test_key_manager_init_missing_kek_raises_error(monkeypatch):
    """Verifies that KeyManager strictly requires a configured KEK and does not use hardcoded defaults."""
    monkeypatch.delenv("MEDTRUST_MISSING_KEK_VAR", raising=False)
    with pytest.raises(KeyConfigurationError) as exc_info:
        KeyManager(env_var="MEDTRUST_MISSING_KEK_VAR")
    assert "Master KEK is not configured" in str(exc_info.value)
    assert "Hardcoded defaults and silent in-memory fallbacks are strictly prohibited" in str(exc_info.value)


def test_key_manager_init_empty_env_var_raises_error(monkeypatch):
    monkeypatch.setenv("MEDTRUST_EMPTY_KEK_VAR", "   ")
    with pytest.raises(KeyConfigurationError) as exc_info:
        KeyManager(env_var="MEDTRUST_EMPTY_KEK_VAR")
    assert "Master KEK is not configured" in str(exc_info.value)


def test_key_manager_init_invalid_length_fails():
    with pytest.raises(KeyConfigurationError) as exc_info:
        KeyManager(kek=b"too-short-16-bytes")
    assert "Invalid key length" in str(exc_info.value)


def test_key_manager_init_invalid_format_fails():
    with pytest.raises(KeyConfigurationError) as exc_info:
        KeyManager(kek="not-valid-hex-or-base64-!@#$%^&*()")
    assert "Invalid key encoding" in str(exc_info.value)


# ============================================================================
# 2. Wrap & Unwrap Roundtrip Tests
# ============================================================================

def test_wrap_unwrap_roundtrip_primary_document(key_manager):
    """Verifies wrap/unwrap roundtrip for the canonical PRIMARY_DOCUMENT purpose."""
    dek = KeyManager.generate_dek()
    record_id = "rec-test-001"
    patient_id = "pat-test-999"

    wrapped = key_manager.wrap_dek(
        dek=dek,
        record_id=record_id,
        patient_id=patient_id,
        purpose=KeyPurpose.PRIMARY_DOCUMENT,
    )

    assert isinstance(wrapped, WrappedDEK)
    assert len(wrapped.encrypted_dek) == KEY_LENGTH
    assert len(wrapped.nonce) == NONCE_LENGTH
    assert len(wrapped.tag) == TAG_LENGTH
    assert wrapped.kek_version == "v1"
    assert wrapped.key_fingerprint.startswith("SHA256:")

    unwrapped = key_manager.unwrap_dek(
        wrapped=wrapped,
        record_id=record_id,
        patient_id=patient_id,
        purpose=KeyPurpose.PRIMARY_DOCUMENT,
    )
    assert unwrapped == dek


def test_wrap_unwrap_roundtrip_prescription(key_manager):
    """Verifies wrap/unwrap roundtrip for the PRESCRIPTION purpose."""
    dek = KeyManager.generate_dek()
    record_id = "rec-test-002"
    patient_id = "pat-test-999"

    wrapped = key_manager.wrap_dek(
        dek=dek,
        record_id=record_id,
        patient_id=patient_id,
        purpose=KeyPurpose.PRESCRIPTION,
    )

    unwrapped = key_manager.unwrap_dek(
        wrapped=wrapped,
        record_id=record_id,
        patient_id=patient_id,
        purpose=KeyPurpose.PRESCRIPTION,
    )
    assert unwrapped == dek


def test_wrapped_dek_hex_serialization(key_manager):
    """Verifies hex dictionary serialization roundtrip for WrappedDEK."""
    dek = KeyManager.generate_dek()
    wrapped = key_manager.wrap_dek(dek, "rec-003", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)

    hex_dict = wrapped.to_hex_dict()
    assert isinstance(hex_dict["encrypted_dek"], str)
    assert len(hex_dict["encrypted_dek"]) == KEY_LENGTH * 2
    assert len(hex_dict["dek_nonce"]) == NONCE_LENGTH * 2
    assert len(hex_dict["dek_tag"]) == TAG_LENGTH * 2

    restored = WrappedDEK.from_hex_dict(hex_dict)
    assert restored.encrypted_dek == wrapped.encrypted_dek
    assert restored.nonce == wrapped.nonce
    assert restored.tag == wrapped.tag
    assert restored.kek_version == wrapped.kek_version

    # Unwrap from restored dictionary
    unwrapped = key_manager.unwrap_dek(hex_dict, "rec-003", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)
    assert unwrapped == dek


# ============================================================================
# 3. Wrong KEK & Cryptographic Integrity Tests
# ============================================================================

def test_unwrap_with_wrong_kek_fails():
    """Unwrapping with a different Master KEK must fail cryptographic authentication."""
    km_a = KeyManager(kek=TEST_KEK_BYTES, kek_version="v1")
    km_b = KeyManager(kek=ALT_KEK_BYTES, kek_version="v1")

    dek = KeyManager.generate_dek()
    wrapped = km_a.wrap_dek(dek, "rec-004", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)

    with pytest.raises(KeyUnwrapError) as exc_info:
        km_b.unwrap_dek(wrapped, "rec-004", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)
    assert "Cryptographic unwrap verification failed" in str(exc_info.value)


def test_corrupted_tag_fails_unwrap(key_manager):
    """Tampering with a single byte in the authentication tag must trigger an unwrap error."""
    dek = KeyManager.generate_dek()
    wrapped = key_manager.wrap_dek(dek, "rec-005", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)

    corrupted_tag = bytearray(wrapped.tag)
    corrupted_tag[0] ^= 0xFF
    corrupted_wrapped = WrappedDEK(
        encrypted_dek=wrapped.encrypted_dek,
        nonce=wrapped.nonce,
        tag=bytes(corrupted_tag),
        kek_version=wrapped.kek_version,
        key_fingerprint=wrapped.key_fingerprint,
    )

    with pytest.raises(KeyUnwrapError):
        key_manager.unwrap_dek(corrupted_wrapped, "rec-005", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)


def test_corrupted_ciphertext_fails_unwrap(key_manager):
    """Tampering with encrypted DEK ciphertext must be caught by AES-GCM tag verification."""
    dek = KeyManager.generate_dek()
    wrapped = key_manager.wrap_dek(dek, "rec-006", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)

    corrupted_ct = bytearray(wrapped.encrypted_dek)
    corrupted_ct[0] ^= 0x01
    corrupted_wrapped = WrappedDEK(
        encrypted_dek=bytes(corrupted_ct),
        nonce=wrapped.nonce,
        tag=wrapped.tag,
        kek_version=wrapped.kek_version,
        key_fingerprint=wrapped.key_fingerprint,
    )

    with pytest.raises(KeyUnwrapError):
        key_manager.unwrap_dek(corrupted_wrapped, "rec-006", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)


# ============================================================================
# 4. AAD Tampering & Purpose Binding Tests
# ============================================================================

def test_aad_tamper_record_id_fails(key_manager):
    """Unwrapping under a different record_id must fail AAD integrity check."""
    dek = KeyManager.generate_dek()
    wrapped = key_manager.wrap_dek(dek, "rec-genuine", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)

    with pytest.raises(KeyUnwrapError):
        key_manager.unwrap_dek(wrapped, "rec-tampered", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)


def test_aad_tamper_patient_id_fails(key_manager):
    """Unwrapping under a different patient_id must fail AAD integrity check."""
    dek = KeyManager.generate_dek()
    wrapped = key_manager.wrap_dek(dek, "rec-007", "pat-patient-A", KeyPurpose.PRIMARY_DOCUMENT)

    with pytest.raises(KeyUnwrapError):
        key_manager.unwrap_dek(wrapped, "rec-007", "pat-patient-B", KeyPurpose.PRIMARY_DOCUMENT)


def test_aad_tamper_purpose_fails(key_manager):
    """A key wrapped for PRIMARY_DOCUMENT cannot be unwrapped as PRESCRIPTION."""
    dek = KeyManager.generate_dek()
    wrapped = key_manager.wrap_dek(dek, "rec-008", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)

    with pytest.raises(KeyUnwrapError):
        key_manager.unwrap_dek(wrapped, "rec-008", "pat-001", KeyPurpose.PRESCRIPTION)


def test_invalid_purpose_rejected(key_manager):
    """Invalid purpose string must be immediately rejected before cryptographic operations."""
    dek = KeyManager.generate_dek()
    with pytest.raises(ValueError) as exc_info:
        key_manager.wrap_dek(dek, "rec-009", "pat-001", "INVALID_PURPOSE")
    assert "Invalid key purpose" in str(exc_info.value)

    with pytest.raises(ValueError):
        key_manager.build_aad("rec-009", "pat-001", "INVALID_PURPOSE")


def test_empty_record_or_patient_id_rejected():
    with pytest.raises(ValueError):
        KeyManager.build_aad("", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)
    with pytest.raises(ValueError):
        KeyManager.build_aad("rec-001", "", KeyPurpose.PRIMARY_DOCUMENT)


# ============================================================================
# 5. KEK Versioning & Multi-Version Lifecycle Tests
# ============================================================================

def test_multi_version_kek_handling():
    """Verifies that KeyManager can unwrap keys encrypted under older KEK versions."""
    km = KeyManager(
        kek=TEST_KEK_BYTES,
        kek_version="v2",
        keks={"v1": ALT_KEK_BYTES, "v2": TEST_KEK_BYTES},
    )

    dek_v1 = KeyManager.generate_dek()
    dek_v2 = KeyManager.generate_dek()

    # Wrap explicitly under v1
    wrapped_v1 = km.wrap_dek(dek_v1, "rec-v1", "pat-001", KeyPurpose.PRIMARY_DOCUMENT, kek_version="v1")
    assert wrapped_v1.kek_version == "v1"

    # Wrap under active v2
    wrapped_v2 = km.wrap_dek(dek_v2, "rec-v2", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)
    assert wrapped_v2.kek_version == "v2"

    # Both unwrap successfully using their respective versioned KEKs
    assert km.unwrap_dek(wrapped_v1, "rec-v1", "pat-001", KeyPurpose.PRIMARY_DOCUMENT) == dek_v1
    assert km.unwrap_dek(wrapped_v2, "rec-v2", "pat-001", KeyPurpose.PRIMARY_DOCUMENT) == dek_v2


def test_unknown_kek_version_raises_configuration_error():
    km = KeyManager(kek=TEST_KEK_BYTES, kek_version="v1")
    with pytest.raises(KeyConfigurationError) as exc_info:
        km.get_kek("v99")
    assert "version 'v99' is not configured" in str(exc_info.value)


# ============================================================================
# 6. Database Persistence & Additive Schema Tests (Isolated Test DB)
# ============================================================================

def test_record_keys_table_exists_and_additive_schema_valid():
    """Verifies record_keys table exists in test DB with correct columns and constraints."""
    with engine.connect() as conn:
        result = conn.exec_driver_sql("PRAGMA table_info(record_keys)")
        cols = {row[1]: row[2] for row in result.fetchall()}

        assert "id" in cols
        assert "record_id" in cols
        assert "patient_id" in cols
        assert "purpose" in cols
        assert "encrypted_dek" in cols
        assert "dek_nonce" in cols
        assert "dek_tag" in cols
        assert "kek_version" in cols
        assert "key_fingerprint" in cols
        assert "created_at" in cols


def test_db_persistence_save_and_unwrap_record_key(key_manager, db_session):
    """Verifies end-to-end saving of WrappedDEK to RecordKeyModel and subsequent retrieval and unwrap."""
    dek = KeyManager.generate_dek()
    record_id = "rec-db-test-101"
    patient_id = "pat-db-984210"

    wrapped = key_manager.wrap_dek(dek, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    saved_model = key_manager.save_record_key(
        db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT, wrapped
    )

    assert saved_model.id is not None
    assert saved_model.record_id == record_id
    assert saved_model.patient_id == patient_id
    assert saved_model.purpose == KeyPurpose.PRIMARY_DOCUMENT
    assert saved_model.kek_version == "v1"

    # Fetch and unwrap directly from DB
    unwrapped_dek = key_manager.unwrap_record_key(
        db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT
    )
    assert unwrapped_dek == dek


def test_db_composite_uniqueness_allows_document_and_prescription(key_manager, db_session):
    """
    Verifies that the composite unique constraint (record_id, purpose) allows
    a primary document key AND a prescription key for the same record_id.
    """
    record_id = "rec-composite-202"
    patient_id = "pat-984210"

    dek_doc = KeyManager.generate_dek()
    dek_rx = KeyManager.generate_dek()

    wrapped_doc = key_manager.wrap_dek(dek_doc, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    wrapped_rx = key_manager.wrap_dek(dek_rx, record_id, patient_id, KeyPurpose.PRESCRIPTION)

    key_manager.save_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT, wrapped_doc)
    key_manager.save_record_key(db_session, record_id, patient_id, KeyPurpose.PRESCRIPTION, wrapped_rx)

    # Both keys coexist and unwrap independently
    fetched_doc = key_manager.unwrap_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    fetched_rx = key_manager.unwrap_record_key(db_session, record_id, patient_id, KeyPurpose.PRESCRIPTION)

    assert fetched_doc == dek_doc
    assert fetched_rx == dek_rx
    assert fetched_doc != fetched_rx


def test_db_save_record_key_updates_existing(key_manager, db_session):
    """
    Verifies that a second save with a different DEK for the same (record_id, purpose)
    is rejected with KeyConflictError and that the original persisted key can still be unwrapped.
    """
    record_id = "rec-update-303"
    patient_id = "pat-984210"

    dek1 = KeyManager.generate_dek()
    wrapped1 = key_manager.wrap_dek(dek1, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    saved_key = key_manager.save_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT, wrapped1)

    initial_ct = saved_key.encrypted_dek
    initial_nonce = saved_key.dek_nonce
    initial_tag = saved_key.dek_tag
    initial_version = saved_key.kek_version
    initial_fingerprint = saved_key.key_fingerprint
    initial_created_at = saved_key.created_at

    dek2 = KeyManager.generate_dek()
    wrapped2 = key_manager.wrap_dek(dek2, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)

    # Second save with a different DEK must be rejected with KeyConflictError
    with pytest.raises(KeyConflictError) as exc_info:
        key_manager.save_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT, wrapped2)

    assert "already exists" in str(exc_info.value)
    assert "immutable" in str(exc_info.value)

    # Verify original row attributes remain completely unchanged and uncorrupted
    db_session.expire_all()
    persisted = key_manager.get_record_key(db_session, record_id, KeyPurpose.PRIMARY_DOCUMENT)
    assert persisted is not None
    assert persisted.encrypted_dek == initial_ct
    assert persisted.dek_nonce == initial_nonce
    assert persisted.dek_tag == initial_tag
    assert persisted.kek_version == initial_version
    assert persisted.key_fingerprint == initial_fingerprint
    assert persisted.created_at == initial_created_at

    # Verify that the original persisted key still unwraps to the original dek1
    unwrapped = key_manager.unwrap_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    assert unwrapped == dek1
    assert unwrapped != dek2


def test_db_save_record_key_conflict_with_different_fingerprint(key_manager, db_session):
    """
    Verifies that saving the same record/purpose cannot overwrite the key
    even when the incoming key has a different fingerprint.
    """
    record_id = "rec-diff-fp-404"
    patient_id = "pat-984210"

    dek_orig = KeyManager.generate_dek()
    wrapped_orig = key_manager.wrap_dek(dek_orig, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    saved_row = key_manager.save_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT, wrapped_orig)
    orig_fingerprint = saved_row.key_fingerprint

    # Generate second key with a different fingerprint
    dek_diff = KeyManager.generate_dek()
    wrapped_diff = key_manager.wrap_dek(dek_diff, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT)
    assert wrapped_diff.key_fingerprint != orig_fingerprint

    # Attempting to save under same (record_id, purpose) must raise KeyConflictError
    with pytest.raises(KeyConflictError) as exc_info:
        key_manager.save_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT, wrapped_diff)

    assert "already exists" in str(exc_info.value)

    # Verify database still retains original key and fingerprint
    db_session.expire_all()
    persisted = key_manager.get_record_key(db_session, record_id, KeyPurpose.PRIMARY_DOCUMENT)
    assert persisted.key_fingerprint == orig_fingerprint
    assert key_manager.unwrap_record_key(db_session, record_id, patient_id, KeyPurpose.PRIMARY_DOCUMENT) == dek_orig


def test_db_unwrap_nonexistent_key_raises_not_found(key_manager, db_session):
    with pytest.raises(KeyNotFoundError) as exc_info:
        key_manager.unwrap_record_key(db_session, "nonexistent-record-id", "pat-001", KeyPurpose.PRIMARY_DOCUMENT)
    assert "No persistent encryption key found" in str(exc_info.value)
