"""
Focused Regression Test Suite: Multi-Consent Gateway Loop Resolution (Task 6B.2A).

Verifies:
1. Pending, expired, or category-mismatched consents do not incorrectly hide a separate
   valid active consent for the requested record category.
2. A revoked consent strictly terminates authorization for that category and cannot be
   bypassed by older grants.
3. Category-specific revocation does not revoke access for unaffected categories.
4. Re-granting consent after a prior revocation safely restores access.
5. End-to-end integration through FastAPI records endpoint accurately reflects multi-consent resolution.
"""

import time
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.adapters.fabric_gateway import fabric_gateway
from app.core.security import create_access_token
from app.db.session import SessionLocal
from app.db.models import UserModel


@pytest.fixture(autouse=True)
def clean_fabric_consents_state():
    """Isolates in-memory gateway consent state for each test."""
    original_consents = dict(fabric_gateway._consents)
    original_records = dict(fabric_gateway._records)
    yield
    fabric_gateway._consents = original_consents
    fabric_gateway._records = original_records


def test_active_grant_alongside_pending_grant_different_category():
    """
    Doctor holds:
    1. Active consent for LAB_REPORT.
    2. Pending consent request for CARDIOLOGY.
    Querying LAB_REPORT must be ALLOWED (pending CARDIOLOGY must not hide active LAB_REPORT).
    Querying CARDIOLOGY must be BLOCKED (reason: CONSENT_PENDING).
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-01"
    doctor_id = "SYNTH-DOC-MULTI-01"
    now = int(time.time())

    # 1. Active LAB_REPORT
    c1 = gateway.request_consent(
        consent_id="cst-active-lab-01",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
        purpose="Lab analysis"
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    # 2. Pending CARDIOLOGY request (submitted later)
    gateway.request_consent(
        consent_id="cst-pending-cardio-01",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["CARDIOLOGY"],
        valid_until_epoch=now + 7200,
        purpose="Cardiology consult"
    )

    # Verify LAB_REPORT access is active
    res_lab = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_lab["allowed"] is True
    assert res_lab["reason"] == "CONSENT_ACTIVE"
    assert res_lab["consentId"] == "cst-active-lab-01"

    # Verify CARDIOLOGY is blocked as pending
    res_cardio = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="CARDIOLOGY")
    assert res_cardio["allowed"] is False
    assert res_cardio["reason"] == "CONSENT_PENDING"
    assert res_cardio["consentId"] == "cst-pending-cardio-01"


def test_active_grant_alongside_expired_grant_different_category():
    """
    Doctor holds:
    1. Active consent for LAB_REPORT (unexpired).
    2. Expired consent for CARDIOLOGY.
    Querying LAB_REPORT must be ALLOWED (expired CARDIOLOGY must not hide active LAB_REPORT).
    Querying CARDIOLOGY must be BLOCKED (reason: CONSENT_EXPIRED).
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-02"
    doctor_id = "SYNTH-DOC-MULTI-02"
    now = int(time.time())

    # 1. Active LAB_REPORT
    c1 = gateway.request_consent(
        consent_id="cst-active-lab-02",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
        purpose="Lab analysis"
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    # 2. Expired CARDIOLOGY grant (expired 100 seconds ago)
    c2 = gateway.request_consent(
        consent_id="cst-expired-cardio-02",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["CARDIOLOGY"],
        valid_until_epoch=now - 100,
        purpose="Cardiology consult"
    )
    gateway.grant_consent(c2["id"], patient_id=patient_id)

    # Verify LAB_REPORT is active
    res_lab = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_lab["allowed"] is True
    assert res_lab["reason"] == "CONSENT_ACTIVE"
    assert res_lab["consentId"] == "cst-active-lab-02"

    # Verify CARDIOLOGY is expired
    res_cardio = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="CARDIOLOGY")
    assert res_cardio["allowed"] is False
    assert res_cardio["reason"] == "CONSENT_EXPIRED"
    assert res_cardio["consentId"] == "cst-expired-cardio-02"


def test_active_grant_alongside_pending_grant_same_category():
    """
    Doctor holds:
    1. Active consent for LAB_REPORT.
    2. Newer pending consent request for LAB_REPORT (e.g. extension request).
    The pending request must NOT invalidate or hide the existing valid active consent.
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-03"
    doctor_id = "SYNTH-DOC-MULTI-03"
    now = int(time.time())

    # 1. Active grant for LAB_REPORT
    c1 = gateway.request_consent(
        consent_id="cst-active-lab-03",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
        purpose="Current lab access"
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    # 2. Newer pending request for LAB_REPORT extension
    gateway.request_consent(
        consent_id="cst-pending-ext-03",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 86400,
        purpose="Extended lab access"
    )

    # Verify LAB_REPORT access remains active under cst-active-lab-03
    res_lab = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_lab["allowed"] is True
    assert res_lab["reason"] == "CONSENT_ACTIVE"
    assert res_lab["consentId"] == "cst-active-lab-03"


def test_active_grant_alongside_expired_grant_same_category():
    """
    Doctor holds:
    1. Long-term active consent for LAB_REPORT (unexpired).
    2. Short-term consent for LAB_REPORT that expired.
    The expired short-term consent must NOT hide the long-term valid active consent.
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-04"
    doctor_id = "SYNTH-DOC-MULTI-04"
    now = int(time.time())

    # 1. Long-term active grant for LAB_REPORT
    c1 = gateway.request_consent(
        consent_id="cst-longterm-lab-04",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 86400,
        purpose="Annual lab access"
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    # 2. Expired short-term grant for LAB_REPORT
    c2 = gateway.request_consent(
        consent_id="cst-expired-short-04",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now - 500,
        purpose="Emergency 1-day lab access"
    )
    gateway.grant_consent(c2["id"], patient_id=patient_id)

    # Verify LAB_REPORT access is active via the valid unexpired consent
    res_lab = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_lab["allowed"] is True
    assert res_lab["reason"] == "CONSENT_ACTIVE"
    assert res_lab["consentId"] == "cst-longterm-lab-04"


def test_category_mismatch_with_multiple_consents():
    """
    Doctor holds:
    1. Active consent for LAB_REPORT.
    2. Active consent for CARDIOLOGY.
    Querying IMAGING_MRI must be rejected with CONSENT_SCOPE_EXCLUDED.
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-05"
    doctor_id = "SYNTH-DOC-MULTI-05"
    now = int(time.time())

    c1 = gateway.request_consent(
        consent_id="cst-lab-05",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    c2 = gateway.request_consent(
        consent_id="cst-cardio-05",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["CARDIOLOGY"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c2["id"], patient_id=patient_id)

    # Out of scope category
    res = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="IMAGING_MRI")
    assert res["allowed"] is False
    assert res["reason"] == "CONSENT_SCOPE_EXCLUDED"


def test_revoked_consent_terminates_access_for_that_category():
    """
    CRITICAL SECURITY INVARIANT:
    Patient grants consent 1 for LAB_REPORT, then grants consent 2 for LAB_REPORT.
    Patient subsequently revokes consent 2.
    Querying LAB_REPORT must be BLOCKED with CONSENT_REVOKED.
    The revoked consent must NOT fall back to older consent 1 to revive access.
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-06"
    doctor_id = "SYNTH-DOC-MULTI-06"
    now = int(time.time())

    # 1. Older grant
    c1 = gateway.request_consent(
        consent_id="cst-lab-old-06",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    # 2. Newer grant
    c2 = gateway.request_consent(
        consent_id="cst-lab-new-06",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c2["id"], patient_id=patient_id)

    # 3. Patient revokes newer consent c2
    gateway.revoke_consent(c2["id"], requesting_patient_id=patient_id)

    # Must be BLOCKED; must not fall back to older c1
    res = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res["allowed"] is False
    assert res["reason"] == "CONSENT_REVOKED"
    assert res["consentId"] == "cst-lab-new-06"


def test_revoked_consent_different_category_does_not_block_active_category():
    """
    Patient grants:
    1. Active consent for LAB_REPORT.
    2. Active consent for CARDIOLOGY.
    Patient revokes consent for CARDIOLOGY.
    Querying LAB_REPORT must remain ALLOWED (CONSENT_ACTIVE).
    Querying CARDIOLOGY must be BLOCKED (CONSENT_REVOKED).
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-07"
    doctor_id = "SYNTH-DOC-MULTI-07"
    now = int(time.time())

    # 1. LAB_REPORT active
    c1 = gateway.request_consent(
        consent_id="cst-lab-07",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)

    # 2. CARDIOLOGY active, then revoked
    c2 = gateway.request_consent(
        consent_id="cst-cardio-07",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["CARDIOLOGY"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c2["id"], patient_id=patient_id)
    gateway.revoke_consent(c2["id"], requesting_patient_id=patient_id)

    # LAB_REPORT remains active
    res_lab = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_lab["allowed"] is True
    assert res_lab["reason"] == "CONSENT_ACTIVE"
    assert res_lab["consentId"] == "cst-lab-07"

    # CARDIOLOGY is revoked
    res_cardio = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="CARDIOLOGY")
    assert res_cardio["allowed"] is False
    assert res_cardio["reason"] == "CONSENT_REVOKED"
    assert res_cardio["consentId"] == "cst-cardio-07"


def test_regrant_after_revocation_allows_access():
    """
    Patient revokes consent 1 for LAB_REPORT.
    Patient subsequently grants consent 2 for LAB_REPORT.
    Querying LAB_REPORT must be ALLOWED under the newer active grant.
    """
    gateway = fabric_gateway
    patient_id = "SYNTH-PAT-MULTI-08"
    doctor_id = "SYNTH-DOC-MULTI-08"
    now = int(time.time())

    # 1. First grant, then revoked
    c1 = gateway.request_consent(
        consent_id="cst-lab-first-08",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c1["id"], patient_id=patient_id)
    gateway.revoke_consent(c1["id"], requesting_patient_id=patient_id)

    # Verify blocked
    res_blocked = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_blocked["allowed"] is False
    assert res_blocked["reason"] == "CONSENT_REVOKED"

    # 2. Patient decides to re-grant access with consent 2
    c2 = gateway.request_consent(
        consent_id="cst-lab-regrant-08",
        patient_id=patient_id,
        doctor_id=doctor_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c2["id"], patient_id=patient_id)

    # Verify access is now restored
    res_regrant = gateway.verify_consent(doctor_id=doctor_id, patient_id=patient_id, record_type="LAB_REPORT")
    assert res_regrant["allowed"] is True
    assert res_regrant["reason"] == "CONSENT_ACTIVE"
    assert res_regrant["consentId"] == "cst-lab-regrant-08"


def test_records_endpoint_integration_with_multi_consent():
    """
    Integration test via FastAPI endpoints:
    Doctor has active consent for LAB_REPORT and revoked consent for CARDIOLOGY.
    GET /records?patient_id={pid}:
      - Returns only LAB_REPORT record.
      - Filters out CARDIOLOGY record.
    GET /records/{lab_rec_id}: 200 OK.
    GET /records/{cardio_rec_id}: 403 Forbidden.
    """
    client = TestClient(app)
    gateway = fabric_gateway
    now = int(time.time())

    # Setup database accounts
    db = SessionLocal()
    pat_id = "pat-multi-integ-09"
    doc_id = "doc-multi-integ-09"
    try:
        if not db.query(UserModel).filter(UserModel.id == pat_id).first():
            p = UserModel(id=pat_id, name="Patient Multi Test", email="pat.multi@example.com", password_hash="dummy_hash", role="PATIENT", is_active=True)
            db.add(p)
        if not db.query(UserModel).filter(UserModel.id == doc_id).first():
            d = UserModel(id=doc_id, name="Dr. Multi Test", email="doc.multi@example.com", password_hash="dummy_hash", role="DOCTOR", is_active=True, approval_status="APPROVED")
            db.add(d)
        db.commit()
    finally:
        db.close()

    # Register two records on Fabric
    gateway.register_record(
        record_id="rec-multi-lab-09",
        patient_id=pat_id,
        ipfs_cid="bafybeilabmulticit99",
        checksum="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        record_type="LAB_REPORT",
        facility="Metro General"
    )
    gateway.register_record(
        record_id="rec-multi-cardio-09",
        patient_id=pat_id,
        ipfs_cid="bafybeicardiomulticit99",
        checksum="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        record_type="CARDIOLOGY",
        facility="Metro Heart Institute"
    )

    # Doctor consents: LAB_REPORT is active, CARDIOLOGY is revoked
    c_lab = gateway.request_consent(
        consent_id="cst-integ-lab-09",
        patient_id=pat_id,
        doctor_id=doc_id,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c_lab["id"], patient_id=pat_id)

    c_cardio = gateway.request_consent(
        consent_id="cst-integ-cardio-09",
        patient_id=pat_id,
        doctor_id=doc_id,
        allowed_record_types=["CARDIOLOGY"],
        valid_until_epoch=now + 7200,
    )
    gateway.grant_consent(c_cardio["id"], patient_id=pat_id)
    gateway.revoke_consent(c_cardio["id"], requesting_patient_id=pat_id)

    doc_token = create_access_token({"sub": doc_id, "name": "Dr. Multi Test", "role": "DOCTOR"})
    headers = {"Authorization": f"Bearer {doc_token}"}

    # 1. Listing records for patient: only LAB_REPORT returned
    res_list = client.get(f"/api/v1/records?patient_id={pat_id}", headers=headers)
    assert res_list.status_code == 200
    returned_records = res_list.json()
    returned_ids = [r["id"] for r in returned_records]
    assert "rec-multi-lab-09" in returned_ids
    assert "rec-multi-cardio-09" not in returned_ids

    # 2. Direct get of lab record: 200 OK
    res_lab = client.get("/api/v1/records/rec-multi-lab-09", headers=headers)
    assert res_lab.status_code == 200
    assert res_lab.json()["id"] == "rec-multi-lab-09"

    # 3. Direct get of cardio record: 403 Forbidden
    res_cardio = client.get("/api/v1/records/rec-multi-cardio-09", headers=headers)
    assert res_cardio.status_code == 403
    assert "CONSENT_REVOKED" in res_cardio.json()["detail"]
