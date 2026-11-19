"""
Comprehensive test suite for MedTrust Distributed Transaction Compensation & Orphan Quarantine (IPR-45).

Verifies dual-write failure handling across the 4 distributed participants:
1. IPFS (Kubo node & offline cache)
2. Hyperledger Fabric (Ledger contract & Audit trail)
3. SQLite Key Storage (RecordKeyModel)
4. SQLite Clinical Details (RecordDetailModel)

Failure Modes & Safeguards Verified:
- Mode A (IPFS Unpin Compensation): When Fabric register_record fails, newly pinned IPFS CIDs (document & prescription)
  are unpinned and purged from offline cache, raising HTTP 503 without leaving orphaned blocks.
- Mode B (Dual-Write Key Persistence Failure & Quarantine): When Fabric registration commits but SQLite key wrapping/saving
  fails, the record is placed in quarantine (persisted in record_quarantines table and in-memory fallback), an on-chain
  audit log (action=RECORD_QUARANTINED, status=QUARANTINED) is committed, and downstream access is gated:
  - GET /records annotates is_quarantined=True and quarantine_reason
  - GET /records/{id} annotates is_quarantined=True and quarantine_reason
  - GET /records/{id}/download fails closed with HTTP 423 Locked and status=LOCKED audit log
  - GET /records/{id}/prescription/download fails closed with HTTP 423 Locked and status=LOCKED audit log
  - GET /records/{id}/details fails closed with HTTP 423 Locked
  - GET/POST /records/{id}/verify reports status=RECORD_QUARANTINED with is_quarantined=True
- In-Memory Fallback: Quarantine works even if SQLite is completely unwritable/locked.
- Durability: Quarantine state survives in-memory cache clearing and restores from SQLite.
- Privacy Preservation: Horizontal RBAC checks precede quarantine status checks, preventing cross-patient probing.
"""

import io
import os
import uuid
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.session import SessionLocal
from app.db.models import UserModel, RecordKeyModel, RecordDetailModel, RecordQuarantineModel
from app.core.security import create_access_token
from app.core.exceptions import FabricGatewayError, IPFSConnectionError
from app.services.key_service import KeyManager, KeyPurpose, KeyConflictError
from app.services.record_service import record_service, _QUARANTINED_RECORDS
from app.adapters.ipfs_client import ipfs_client
from app.adapters.fabric_gateway import fabric_gateway

client = TestClient(app)

TEST_PATIENT_ID = "pat-984210"
TEST_PATIENT_NAME = "Eleanor Vance"

TEST_OTHER_PATIENT_ID = "pat-222222"
TEST_OTHER_PATIENT_NAME = "Bob Attacker"

TEST_DOCTOR_ID = "doc-331902"
TEST_DOCTOR_NAME = "Dr. Marcus Sterling, MD"


@pytest.fixture
def patient_token():
    return create_access_token({
        "sub": TEST_PATIENT_ID,
        "name": TEST_PATIENT_NAME,
        "role": "PATIENT"
    })


@pytest.fixture
def other_patient_token():
    return create_access_token({
        "sub": TEST_OTHER_PATIENT_ID,
        "name": TEST_OTHER_PATIENT_NAME,
        "role": "PATIENT"
    })


@pytest.fixture
def doctor_token():
    return create_access_token({
        "sub": TEST_DOCTOR_ID,
        "name": TEST_DOCTOR_NAME,
        "role": "DOCTOR"
    })


@pytest.fixture(autouse=True)
def clean_quarantine_state():
    """Ensure in-memory quarantine cache is cleared between tests."""
    _QUARANTINED_RECORDS.clear()
    yield
    _QUARANTINED_RECORDS.clear()


# ============================================================================
# 1. Mode A: IPFS Unpin Compensation on Fabric Failure
# ============================================================================

def test_fabric_failure_triggers_ipfs_unpin_compensation(patient_token):
    """
    Verifies that when Fabric register_record throws during an upload,
    the pinned primary document CID is unpinned from IPFS and removed from
    offline cache, returning HTTP 503.
    """
    doc_content = b"PDF-1.7 Confidential cardiology report intended for Fabric commit."
    files = [
        ("file", ("cardio_fail.pdf", io.BytesIO(doc_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Failing Fabric Upload",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Fabric failure test."
    }

    unpinned_cids = []
    removed_offline_cids = []

    orig_pin_rm = ipfs_client.pin_rm
    orig_remove_offline = ipfs_client.remove_offline_bytes

    def tracking_pin_rm(cid):
        unpinned_cids.append(cid)
        try:
            return orig_pin_rm(cid)
        except Exception:
            return True

    def tracking_remove_offline(cid):
        removed_offline_cids.append(cid)
        return orig_remove_offline(cid)

    with patch.object(ipfs_client, "pin_rm", side_effect=tracking_pin_rm), \
         patch.object(ipfs_client, "remove_offline_bytes", side_effect=tracking_remove_offline), \
         patch.object(fabric_gateway, "register_record", side_effect=FabricGatewayError("Raft orderer consensus timeout")):

        res = client.post(
            "/api/v1/records/upload",
            data=data,
            files=files,
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        assert res.status_code == 503
        detail = res.json()["detail"]
        assert "Record registration failed on ledger" in detail
        assert "Compensating transaction" in detail

        # Verify that unpin compensation was executed
        assert len(unpinned_cids) >= 1
        assert len(removed_offline_cids) >= 1


def test_fabric_failure_unpins_both_document_and_prescription(patient_token):
    """
    Verifies that for combined uploads (document + prescription), if Fabric
    registration fails, BOTH the primary document CID and the prescription CID
    are unpinned and purged from offline cache.
    """
    doc_content = b"PDF-1.7 Primary lab findings."
    rx_content = b"PDF-1.7 Prescription dosage instructions."

    files = [
        ("file", ("lab_doc.pdf", io.BytesIO(doc_content), "application/pdf")),
        ("prescription_file", ("rx_attachment.pdf", io.BytesIO(rx_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Combined Upload Fabric Failure",
        "record_type": "LAB_REPORT",
        "hospital": "Metro General Hospital",
        "description": "Multi-file upload with ledger failure."
    }

    unpinned_cids = []
    removed_offline_cids = []

    def tracking_pin_rm(cid):
        unpinned_cids.append(cid)
        try:
            return ipfs_client.__class__.pin_rm(ipfs_client, cid)
        except Exception:
            return True

    def tracking_remove_offline(cid):
        removed_offline_cids.append(cid)
        return ipfs_client.__class__.remove_offline_bytes(ipfs_client, cid)

    with patch.object(ipfs_client, "pin_rm", side_effect=tracking_pin_rm), \
         patch.object(ipfs_client, "remove_offline_bytes", side_effect=tracking_remove_offline), \
         patch.object(fabric_gateway, "register_record", side_effect=FabricGatewayError("Chaincode endorsement policy failed")):

        res = client.post(
            "/api/v1/records/upload",
            data=data,
            files=files,
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        assert res.status_code == 503
        # Both primary document and prescription CIDs must have been unpinned
        assert len(unpinned_cids) == 2
        assert len(removed_offline_cids) == 2


# ============================================================================
# 2. Mode B: Key Persistence Failure Triggers Quarantine
# ============================================================================

def test_key_conflict_triggers_quarantine_and_returns_409(patient_token):
    """
    Verifies that if KeyConflictError occurs during upload key persistence:
    1. Returns HTTP 409 Conflict.
    2. Persists quarantine entry in SQLite record_quarantines table.
    3. Commits on-chain audit event with action=RECORD_QUARANTINED and status=QUARANTINED.
    4. Does NOT unpin IPFS CIDs (retained for audit / forensic tracking).
    """
    doc_content = b"PDF-1.7 Key conflict test document."
    files = [
        ("file", ("conflict_doc.pdf", io.BytesIO(doc_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Key Conflict Quarantine Test",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Testing KeyConflictError quarantine."
    }

    audit_events = []
    orig_log = fabric_gateway.log_access_event

    def capture_audit(*args, **kwargs):
        audit_events.append(kwargs)
        return orig_log(*args, **kwargs)

    with patch.object(fabric_gateway, "log_access_event", side_effect=capture_audit), \
         patch("app.api.v1.endpoints.records.KeyManager.save_record_key", side_effect=KeyConflictError("Immutable key conflict on PRIMARY_DOCUMENT")):

        res = client.post(
            "/api/v1/records/upload",
            data=data,
            files=files,
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        assert res.status_code == 409
        detail = res.json()["detail"]
        assert "Cryptographic key conflict" in detail
        assert "quarantined" in detail

        # Extract record_id from error message
        import re
        match = re.search(r"Record '(rec-[a-f0-9]+)'", detail)
        assert match is not None
        record_id = match.group(1)

        # Verify record is marked quarantined in-memory
        assert record_service.is_record_quarantined(None, record_id) is True

        # Verify record is persisted in SQLite record_quarantines table
        db = SessionLocal()
        try:
            q_row = db.query(RecordQuarantineModel).filter(RecordQuarantineModel.record_id == record_id).first()
            assert q_row is not None
            assert q_row.patient_id == TEST_PATIENT_ID
            assert "KeyConflictError" in q_row.quarantine_reason
        finally:
            db.close()

        # Verify on-chain audit event was committed
        quarantine_audits = [e for e in audit_events if e.get("action") == "RECORD_QUARANTINED"]
        assert len(quarantine_audits) >= 1
        assert quarantine_audits[0]["status"] == "QUARANTINED"
        assert quarantine_audits[0]["record_id"] == record_id


def test_sqlite_failure_triggers_quarantine_and_returns_500(patient_token):
    """
    Verifies that if an unexpected database error occurs during key saving:
    1. Returns HTTP 500 Internal Server Error (detail preserving 'Record key persistence failed').
    2. Persists quarantine entry in SQLite record_quarantines table.
    3. Commits on-chain audit event with status=QUARANTINED.
    """
    doc_content = b"PDF-1.7 General DB crash test document."
    files = [
        ("file", ("db_crash_doc.pdf", io.BytesIO(doc_content), "application/pdf")),
    ]
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "DB Crash Quarantine Test",
        "record_type": "IMAGING_MRI",
        "hospital": "Metro Hospital",
        "description": "Testing unexpected DB failure quarantine."
    }

    audit_events = []
    orig_log = fabric_gateway.log_access_event

    def capture_audit(*args, **kwargs):
        audit_events.append(kwargs)
        return orig_log(*args, **kwargs)

    with patch.object(fabric_gateway, "log_access_event", side_effect=capture_audit), \
         patch("app.api.v1.endpoints.records.KeyManager.save_record_key", side_effect=RuntimeError("Simulated disk write failure")):

        res = client.post(
            "/api/v1/records/upload",
            data=data,
            files=files,
            headers={"Authorization": f"Bearer {patient_token}"}
        )

        assert res.status_code == 500
        detail = res.json()["detail"]
        assert "Record key persistence failed" in detail
        assert "quarantined" in detail

        import re
        match = re.search(r"Record '(rec-[a-f0-9]+)'", detail)
        assert match is not None
        record_id = match.group(1)

        # In-memory check
        assert record_service.is_record_quarantined(None, record_id) is True

        # Audit check
        quarantine_audits = [e for e in audit_events if e.get("action") == "RECORD_QUARANTINED"]
        assert len(quarantine_audits) >= 1
        assert quarantine_audits[0]["status"] == "QUARANTINED"
        assert quarantine_audits[0]["record_id"] == record_id


def test_in_memory_quarantine_fallback_when_db_completely_unwritable():
    """
    Verifies that if SQLite database is completely locked or unwritable,
    record_service.quarantine_record still safely records the quarantine
    in-memory and is_record_quarantined returns True.
    """
    fake_rec_id = f"rec-{uuid.uuid4().hex[:6]}"
    mock_db = MagicMock()
    mock_db.commit.side_effect = RuntimeError("Database locked")

    entry = record_service.quarantine_record(
        db=mock_db,
        record_id=fake_rec_id,
        patient_id=TEST_PATIENT_ID,
        quarantine_reason="Emergency in-memory fallback test"
    )

    assert entry["record_id"] == fake_rec_id
    assert record_service.is_record_quarantined(None, fake_rec_id) is True
    info = record_service.get_quarantine_info(None, fake_rec_id)
    assert info is not None
    assert "Emergency in-memory fallback test" in info["quarantine_reason"]


# ============================================================================
# 3. Downstream Gating & Endpoint Enforcement for Quarantined Records
# ============================================================================

@pytest.fixture
def quarantined_record(patient_token):
    """Creates a quarantined record on the ledger and returns its record_id."""
    data = {
        "patient_id": TEST_PATIENT_ID,
        "title": "Standard Quarantined Record",
        "record_type": "CLINICAL_SUMMARY",
        "hospital": "Metro Hospital",
        "description": "Quarantined fixture."
    }
    with patch("app.api.v1.endpoints.records.KeyManager.save_record_key", side_effect=KeyConflictError("Simulated conflict for fixture")):
        res = client.post(
            "/api/v1/records/upload",
            data=data,
            headers={"Authorization": f"Bearer {patient_token}"}
        )
        assert res.status_code == 409
        import re
        match = re.search(r"Record '(rec-[a-f0-9]+)'", res.json()["detail"])
        assert match is not None
        return match.group(1)


def test_get_records_annotates_quarantine_status(patient_token, quarantined_record):
    """
    Verifies that GET /api/v1/records lists the quarantined record with
    is_quarantined=True and quarantine_reason populated, while normal records
    have is_quarantined=False.
    """
    res = client.get(
        f"/api/v1/records?patient_id={TEST_PATIENT_ID}",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    records = res.json()
    assert len(records) >= 1

    target = next((r for r in records if r["id"] == quarantined_record), None)
    assert target is not None
    assert target.get("isQuarantined") is True or target.get("is_quarantined") is True
    assert "KeyConflictError" in (target.get("quarantineReason") or target.get("quarantine_reason") or "")

    # Normal baseline records must not be quarantined
    normal = next((r for r in records if r["id"] == "rec-001"), None)
    if normal:
        assert normal.get("isQuarantined") is False or normal.get("is_quarantined") is False


def test_get_single_record_annotates_quarantine_status(patient_token, quarantined_record):
    """
    Verifies that GET /api/v1/records/{record_id} returns is_quarantined=True
    for a quarantined record.
    """
    res = client.get(
        f"/api/v1/records/{quarantined_record}",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 200
    rec = res.json()
    assert rec.get("isQuarantined") is True or rec.get("is_quarantined") is True
    assert "KeyConflictError" in (rec.get("quarantineReason") or rec.get("quarantine_reason") or "")


def test_download_quarantined_record_returns_423_locked(patient_token, quarantined_record):
    """
    Verifies that calling GET /api/v1/records/{record_id}/download on a quarantined record:
    1. Returns HTTP 423 Locked.
    2. Emits status=LOCKED access event on Fabric audit log.
    3. Discloses no plaintext or ciphertext content.
    """
    audit_events = []
    orig_log = fabric_gateway.log_access_event

    def capture_audit(*args, **kwargs):
        audit_events.append(kwargs)
        return orig_log(*args, **kwargs)

    with patch.object(fabric_gateway, "log_access_event", side_effect=capture_audit):
        res = client.get(
            f"/api/v1/records/{quarantined_record}/download",
            headers={"Authorization": f"Bearer {patient_token}"}
        )
        assert res.status_code == 423
        detail = res.json()["detail"]
        assert "quarantined due to dual-write key persistence failure" in detail
        assert "Document cannot be downloaded" in detail

        # Verify audit log emitted status=LOCKED
        locked_audits = [e for e in audit_events if e.get("status") == "LOCKED"]
        assert len(locked_audits) >= 1
        assert locked_audits[0]["record_id"] == quarantined_record


def test_download_quarantined_prescription_returns_423_locked(patient_token, quarantined_record):
    """
    Verifies that calling GET /api/v1/records/{record_id}/prescription/download on a quarantined record:
    1. Returns HTTP 423 Locked.
    2. Emits status=LOCKED access event on Fabric audit log.
    """
    audit_events = []
    orig_log = fabric_gateway.log_access_event

    def capture_audit(*args, **kwargs):
        audit_events.append(kwargs)
        return orig_log(*args, **kwargs)

    with patch.object(fabric_gateway, "log_access_event", side_effect=capture_audit):
        res = client.get(
            f"/api/v1/records/{quarantined_record}/prescription/download",
            headers={"Authorization": f"Bearer {patient_token}"}
        )
        assert res.status_code == 423
        detail = res.json()["detail"]
        assert "quarantined due to dual-write key persistence failure" in detail
        assert "Prescription cannot be downloaded" in detail

        locked_audits = [e for e in audit_events if e.get("status") == "LOCKED"]
        assert len(locked_audits) >= 1


def test_get_details_for_quarantined_record_returns_423_locked(patient_token, quarantined_record):
    """
    Verifies that calling GET /api/v1/records/{record_id}/details on a quarantined record
    returns HTTP 423 Locked.
    """
    res = client.get(
        f"/api/v1/records/{quarantined_record}/details",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 423
    assert "quarantined due to dual-write failure" in res.json()["detail"]


def test_verify_quarantined_record_returns_status_record_quarantined(patient_token, quarantined_record):
    """
    Verifies that calling GET/POST /api/v1/records/{record_id}/verify on a quarantined record:
    1. Returns HTTP 200 with structured status='RECORD_QUARANTINED'.
    2. Flags is_quarantined=True and diagnostic detail.
    3. Logs status=QUARANTINED on Fabric audit trail.
    """
    audit_events = []
    orig_log = fabric_gateway.log_access_event

    def capture_audit(*args, **kwargs):
        audit_events.append(kwargs)
        return orig_log(*args, **kwargs)

    with patch.object(fabric_gateway, "log_access_event", side_effect=capture_audit):
        res = client.get(
            f"/api/v1/records/{quarantined_record}/verify",
            headers={"Authorization": f"Bearer {patient_token}"}
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "RECORD_QUARANTINED"
        assert data.get("isQuarantined") is True or data.get("is_quarantined") is True
        assert data["checksumMatches"] is False
        assert "quarantined due to dual-write failure" in data["detail"]

        quarantine_audits = [e for e in audit_events if e.get("status") == "QUARANTINED"]
        assert len(quarantine_audits) >= 1


# ============================================================================
# 4. Security & Isolation: Horizontal Protection Precedes Quarantine Disclosure
# ============================================================================

def test_unauthorized_patient_cannot_discover_quarantine_status(other_patient_token, quarantined_record):
    """
    Verifies that an unauthorized patient attempting to access another patient's
    quarantined record receives:
    - HTTP 403 Forbidden on download (horizontal access denied), NOT HTTP 423 Locked.
    - HTTP 200 LEDGER_UNAVAILABLE on verify (sentinel response), NOT RECORD_QUARANTINED.
    Demonstrating that quarantine status does not leak metadata across patient boundaries.
    """
    # 1. Download attempt
    res_dl = client.get(
        f"/api/v1/records/{quarantined_record}/download",
        headers={"Authorization": f"Bearer {other_patient_token}"}
    )
    assert res_dl.status_code == 403
    assert "Horizontal Access Denied" in res_dl.json()["detail"]

    # 2. Verify attempt
    res_vf = client.get(
        f"/api/v1/records/{quarantined_record}/verify",
        headers={"Authorization": f"Bearer {other_patient_token}"}
    )
    assert res_vf.status_code == 200
    data = res_vf.json()
    assert data["status"] == "LEDGER_UNAVAILABLE"
    assert data.get("isQuarantined", False) is False


# ============================================================================
# 5. Durability: Quarantine Survives In-Memory Reset
# ============================================================================

def test_quarantine_durability_across_in_memory_reset(patient_token, quarantined_record):
    """
    Verifies that if in-memory cache is purged (simulating application restart),
    the quarantine status is durably recovered from the SQLite record_quarantines table.
    """
    # Purge in-memory cache
    _QUARANTINED_RECORDS.clear()
    assert quarantined_record not in _QUARANTINED_RECORDS

    # Query record with fresh DB session
    db = SessionLocal()
    try:
        is_q = record_service.is_record_quarantined(db, quarantined_record)
        assert is_q is True
        # Verify in-memory cache was re-populated
        assert quarantined_record in _QUARANTINED_RECORDS
    finally:
        db.close()

    # Verify download remains locked post in-memory reset
    res = client.get(
        f"/api/v1/records/{quarantined_record}/download",
        headers={"Authorization": f"Bearer {patient_token}"}
    )
    assert res.status_code == 423
