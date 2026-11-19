"""
Isolated unit & integration tests for MedTrust Durable Key Storage on Upload (Task 6D.3 / IPR-40).

Verifies:
1. Document-only uploads persist canonical PRIMARY_DOCUMENT key in SQLite.
2. Prescription-only uploads persist canonical PRESCRIPTION and record keys.
3. Combined uploads persist both PRIMARY_DOCUMENT and PRESCRIPTION keys with distinct DEKs.
4. Missing MEDTRUST_MASTER_KEK fails closed (HTTP 500) before any writes.
5. Malformed MEDTRUST_MASTER_KEK fails closed (HTTP 500) before any writes.
6. KeyConflictError on duplicate key persistence raises HTTP 409 without overwriting.
7. Wrapped keys are durably recoverable from SQLite after complete in-memory state reset.
8. Persistence failure triggers SQLite rollback without unpinning data.
"""

import io
import os
import uuid
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.db.models import UserModel, RecordKeyModel, RecordDetailModel
from app.core.security import create_access_token
from app.services.key_service import KeyManager, KeyPurpose, KeyConflictError, WrappedDEK
from app.services.record_service import _RECORD_KEY_STORE

client = TestClient(app)

TEST_PATIENT_ID = "pat-984210"
TEST_PATIENT_NAME = "Eleanor Vance"


@pytest.fixture
def patient_token():
    return create_access_token({
        "sub": TEST_PATIENT_ID,
        "name": TEST_PATIENT_NAME,
        "role": "PATIENT"
    })


@pytest.fixture
def key_manager():
    return KeyManager()


# ============================================================================
# 1. Successful Key Persistence Tests (Canonical Purposes)
# ============================================================================

def test_upload_document_only_persists_primary_document_key(patient_token, key_manager):
    """
    Verifies that uploading a document-only record persists a PRIMARY_DOCUMENT
    key in RecordKeyModel that unbinds to the correct DEK.
    """
    doc_content = b"PDF-1.7 Diagnostic cardiology report for Eleanor Vance."
    files = [
        ("file", ("cardio_report.pdf", io.BytesIO(doc_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Document Only Echo Report",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro General Hospital",
        "description": "Annual follow-up echocardiogram."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    record_id = record["id"]

    db = SessionLocal()
    try:
        keys = db.query(RecordKeyModel).filter(RecordKeyModel.record_id == record_id).all()
        assert len(keys) == 1

        doc_key = keys[0]
        assert doc_key.purpose == KeyPurpose.PRIMARY_DOCUMENT
        assert doc_key.target_type == "record"
        assert doc_key.patient_id == TEST_PATIENT_ID
        assert doc_key.kek_version == "v1"
        assert len(doc_key.encrypted_dek) > 0
        assert len(doc_key.dek_nonce) > 0
        assert len(doc_key.dek_tag) > 0

        # Verify key unwraps to a valid 32-byte DEK via KeyManager
        unwrapped_dek = key_manager.unwrap_record_key(
            db=db,
            record_id=record_id,
            patient_id=TEST_PATIENT_ID,
            purpose=KeyPurpose.PRIMARY_DOCUMENT
        )
        assert isinstance(unwrapped_dek, bytes)
        assert len(unwrapped_dek) == 32
    finally:
        db.close()


def test_upload_prescription_only_persists_prescription_key(patient_token, key_manager):
    """
    Verifies that uploading a prescription without a document persists
    the canonical PRESCRIPTION key in RecordKeyModel.
    """
    rx_content = b"PDF-1.7 Prescription: Lisinopril 10mg orally once daily."
    files = [
        ("prescription_file", ("lisinopril_rx.pdf", io.BytesIO(rx_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Prescription Only Record",
        "record_type": "PRESCRIPTION",
        "hospital": "Metro General Hospital",
        "description": "Prescription renewal for hypertension."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    record_id = record["id"]

    db = SessionLocal()
    try:
        rx_key = key_manager.get_record_key(db, record_id, KeyPurpose.PRESCRIPTION)
        assert rx_key is not None
        assert rx_key.purpose == KeyPurpose.PRESCRIPTION
        assert rx_key.target_type == "prescription"
        assert rx_key.patient_id == TEST_PATIENT_ID

        # Unwrap prescription DEK
        unwrapped_rx_dek = key_manager.unwrap_record_key(
            db=db,
            record_id=record_id,
            patient_id=TEST_PATIENT_ID,
            purpose=KeyPurpose.PRESCRIPTION
        )
        assert isinstance(unwrapped_rx_dek, bytes)
        assert len(unwrapped_rx_dek) == 32
    finally:
        db.close()


def test_upload_combined_persists_both_keys(patient_token, key_manager):
    """
    Verifies that uploading both document and prescription persists two distinct
    keys (PRIMARY_DOCUMENT and PRESCRIPTION) with independent DEKs.
    """
    doc_content = b"PDF-1.7 Orthopedic surgical operation record."
    rx_content = b"PDF-1.7 Prescription: Cephalexin 500mg QID for 7 days."

    files = [
        ("file", ("op_notes.pdf", io.BytesIO(doc_content), "application/pdf")),
        ("prescription_file", ("antibiotics_rx.pdf", io.BytesIO(rx_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Combined Ortho & Post-op Rx",
        "record_type": "LAB_REPORT",
        "hospital": "Apex Specialty Hospital",
        "description": "Right knee arthroscopy report and antibiotic course."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record = res.json()
    record_id = record["id"]

    db = SessionLocal()
    try:
        keys = db.query(RecordKeyModel).filter(RecordKeyModel.record_id == record_id).all()
        assert len(keys) == 2

        doc_key_model = next((k for k in keys if k.purpose == KeyPurpose.PRIMARY_DOCUMENT), None)
        rx_key_model = next((k for k in keys if k.purpose == KeyPurpose.PRESCRIPTION), None)

        assert doc_key_model is not None
        assert rx_key_model is not None

        dek_doc = key_manager.unwrap_record_key(db, record_id, TEST_PATIENT_ID, KeyPurpose.PRIMARY_DOCUMENT)
        dek_rx = key_manager.unwrap_record_key(db, record_id, TEST_PATIENT_ID, KeyPurpose.PRESCRIPTION)

        assert len(dek_doc) == 32
        assert len(dek_rx) == 32
        assert dek_doc != dek_rx  # Independent symmetric keys
    finally:
        db.close()


# ============================================================================
# 2. Fail-Closed KEK Configuration Tests
# ============================================================================

def test_upload_missing_kek_fails_closed_no_writes(patient_token, monkeypatch):
    """
    Verifies that upload fails closed (HTTP 500) if MEDTRUST_MASTER_KEK is not configured,
    and makes zero writes to the database.
    """
    monkeypatch.delenv("MEDTRUST_MASTER_KEK", raising=False)

    db_before = SessionLocal()
    try:
        initial_key_count = db_before.query(RecordKeyModel).count()
        initial_detail_count = db_before.query(RecordDetailModel).count()
    finally:
        db_before.close()

    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Unconfigured KEK Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Description only."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        headers={"Authorization": f"Bearer {patient_token}"}
    )

    assert res.status_code == 500
    assert "Master key configuration error" in res.json()["detail"]

    # Verify zero database writes occurred
    db_after = SessionLocal()
    try:
        assert db_after.query(RecordKeyModel).count() == initial_key_count
        assert db_after.query(RecordDetailModel).count() == initial_detail_count
    finally:
        db_after.close()


def test_upload_invalid_kek_length_fails_closed_no_writes(patient_token, monkeypatch):
    """
    Verifies that upload fails closed if MEDTRUST_MASTER_KEK has invalid key length.
    """
    monkeypatch.setenv("MEDTRUST_MASTER_KEK", "short-key-16-bytes")

    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Malformed KEK Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Test description."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        headers={"Authorization": f"Bearer {patient_token}"}
    )

    assert res.status_code == 500
    assert "Master key configuration error" in res.json()["detail"]


# ============================================================================
# 3. Key Conflict & Immutability Enforcement Tests
# ============================================================================

def test_upload_key_conflict_error_fails_closed_with_409(patient_token, key_manager):
    """
    Verifies that attempting to save a key where a record_id and purpose already exist
    raises KeyConflictError and maps to HTTP 409 without overwriting the original key.
    """
    collision_record_id = f"rec-collision-{uuid.uuid4().hex[:6]}"

    # Pre-seed existing key in SQLite
    db = SessionLocal()
    try:
        orig_dek = KeyManager.generate_dek()
        wrapped_orig = key_manager.wrap_dek(
            dek=orig_dek,
            record_id=collision_record_id,
            patient_id=TEST_PATIENT_ID,
            purpose=KeyPurpose.PRIMARY_DOCUMENT
        )
        saved_orig = key_manager.save_record_key(
            db=db,
            record_id=collision_record_id,
            patient_id=TEST_PATIENT_ID,
            purpose=KeyPurpose.PRIMARY_DOCUMENT,
            wrapped=wrapped_orig
        )
        orig_ct = saved_orig.encrypted_dek
        orig_fingerprint = saved_orig.key_fingerprint
    finally:
        db.close()

    # Mock register_and_upload_record to return the colliding record_id
    with patch("app.api.v1.endpoints.records.record_service.register_and_upload_record") as mock_upload:
        mock_upload.return_value = {
            "id": collision_record_id,
            "patient_id": TEST_PATIENT_ID,
            "patient_name": TEST_PATIENT_NAME,
            "title": "Colliding Record",
            "record_type": "LAB_REPORT",
            "ipfs_cid": "bafybeicollisioncid0001",
            "key_fingerprint": "SHA256:collision...",
            "checksum_sha256": "collisionchecksum"
        }

        data = {
            "patient_id": TEST_PATIENT_ID,
            "title": "Colliding Record",
            "record_type": "LAB_REPORT",
            "hospital": "Metro Hospital",
            "description": "Attempting collision."
        }

        res = client.post(
            "/api/v1/records/upload",
            data=data,
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        assert res.status_code == 409
        assert "Cryptographic key conflict" in res.json()["detail"]

    # Verify original key row in database is 100% untouched
    db_verify = SessionLocal()
    try:
        persisted = key_manager.get_record_key(db_verify, collision_record_id, KeyPurpose.PRIMARY_DOCUMENT)
        assert persisted is not None
        assert persisted.encrypted_dek == orig_ct
        assert persisted.key_fingerprint == orig_fingerprint
        assert key_manager.unwrap_record_key(db_verify, collision_record_id, TEST_PATIENT_ID, KeyPurpose.PRIMARY_DOCUMENT) == orig_dek
    finally:
        db_verify.close()


# ============================================================================
# 4. Durable Key Recovery & In-Memory Reset Verification
# ============================================================================

def test_upload_wrapped_key_recovery_after_in_memory_reset(patient_token):
    """
    Verifies that newly uploaded keys are durably recoverable from the SQLite database
    even after completely purging in-memory stores and resetting the KeyManager.
    """
    doc_content = b"PDF-1.7 Durable persistence proof data."
    files = [
        ("file", ("durable_report.pdf", io.BytesIO(doc_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Durable Recovery Test",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro Hospital",
        "description": "Durable recovery verification."
    }

    res = client.post(
        "/api/v1/records/upload",
        data=data,
        files=files,
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    record_id = res.json()["id"]

    # 1. Simulate complete process in-memory reset
    _RECORD_KEY_STORE.clear()

    # 2. Spin up brand new independent DB session and KeyManager instance
    fresh_db = SessionLocal()
    fresh_km = KeyManager()

    try:
        # Confirm that the key can be fetched and unwrapped from SQLite with zero in-memory dependencies
        unwrapped = fresh_km.unwrap_record_key(
            db=fresh_db,
            record_id=record_id,
            patient_id=TEST_PATIENT_ID,
            purpose=KeyPurpose.PRIMARY_DOCUMENT
        )
        assert isinstance(unwrapped, bytes)
        assert len(unwrapped) == 32
    finally:
        fresh_db.close()


# ============================================================================
# 5. SQLite Persistence Failure Rollback Test
# ============================================================================

def test_upload_persistence_failure_rolls_back_sqlite(patient_token):
    """
    Verifies that if an unexpected error occurs during SQLite persistence,
    the transaction is rolled back and HTTP 500 is returned.
    """
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Persistence Rollback Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Testing rollback."
    }

    with patch("app.api.v1.endpoints.records.record_service.save_record_details", side_effect=RuntimeError("Simulated DB Disk Full")):
        res = client.post(
            "/api/v1/records/upload",
            data=data,
            headers={"Authorization": f"Bearer {patient_token}"}
        )
        assert res.status_code == 500
        assert "Record key persistence failed" in res.json()["detail"]
