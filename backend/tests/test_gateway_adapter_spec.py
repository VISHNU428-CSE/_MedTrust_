"""
Unit & Contract Compatibility Tests for RealFabricGatewayClient.
Validates conformance to GATEWAY_ADAPTER_SPEC.md by Kelly.
"""

import pytest
from app.adapters.real_fabric_gateway import real_fabric_gateway, assert_zero_phi_payload
from app.core.exceptions import AccessDeniedError, ConsentNotFoundError


def test_zero_phi_guardrail_blocks_ssn():
    with pytest.raises(ValueError) as exc:
        assert_zero_phi_payload("Patient SSN is 000-12-3456")
    assert "ZERO-PHI VIOLATION" in str(exc.value)


def test_zero_phi_guardrail_blocks_private_key():
    with pytest.raises(ValueError) as exc:
        assert_zero_phi_payload("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert "ZERO-PHI VIOLATION" in str(exc.value)


def test_consent_spec_full_lifecycle():
    client = real_fabric_gateway
    cid = "CONSENT-SPEC-001"
    pat = "SYNTH-PAT-001"
    doc = "SYNTH-DOC-101"

    # 1. Request Consent -> PENDING
    req = client.request_consent(
        consent_id=cid,
        patient_id=pat,
        doctor_id=doc,
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=1798000000,
        purpose="Cardiovascular follow-up"
    )
    assert req["status"] == "PENDING"

    # Verify query returns CONSENT_PENDING
    v_pending = client.verify_consent(doc, pat, "LAB_REPORT")
    assert v_pending["allowed"] is False
    assert v_pending["reason"] == "CONSENT_PENDING"

    # 2. Grant Consent -> ACTIVE / APPROVED
    granted = client.grant_consent(cid, patient_id=pat)
    assert granted["status"] == "ACTIVE"

    # Verify query returns CONSENT_ACTIVE for LAB_REPORT
    v_active = client.verify_consent(doc, pat, "LAB_REPORT")
    assert v_active["allowed"] is True
    assert v_active["reason"] == "CONSENT_ACTIVE"

    # Verify query returns CONSENT_SCOPE_EXCLUDED for IMAGING_MRI
    v_scope = client.verify_consent(doc, pat, "IMAGING_MRI")
    assert v_scope["allowed"] is False
    assert v_scope["reason"] == "CONSENT_SCOPE_EXCLUDED"

    # 3. Revoke Consent -> REVOKED
    revoked = client.revoke_consent(cid, requesting_patient_id=pat)
    assert revoked["status"] == "REVOKED"

    # Verify query returns CONSENT_REVOKED
    v_revoked = client.verify_consent(doc, pat, "LAB_REPORT")
    assert v_revoked["allowed"] is False
    assert v_revoked["reason"] == "CONSENT_REVOKED"


def test_consent_spec_rejection_flow():
    client = real_fabric_gateway
    cid = "CONSENT-REJECT-002"
    pat = "SYNTH-PAT-002"
    doc = "SYNTH-DOC-102"

    client.request_consent(
        consent_id=cid,
        patient_id=pat,
        doctor_id=doc,
        allowed_record_types=["ALL"],
        valid_until_epoch=1798000000,
        purpose="Consultation"
    )
    rejected = client.reject_consent(cid, patient_id=pat, reason="Patient refused data sharing")
    assert rejected["status"] == "REJECTED"


def test_record_spec_registration_and_checksum_verification():
    client = real_fabric_gateway
    rid = "REC-SPEC-LAB-001"
    pat = "SYNTH-PAT-001"
    cid = "bafybeimdt7318a47402636a2829210medtrust"
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    rec = client.register_record(
        record_id=rid,
        patient_id=pat,
        ipfs_cid=cid,
        checksum=sha,
        record_type="LAB_REPORT",
        facility="Synthetic General Hospital",
        registered_by="SYNTH-DOC-101"
    )
    assert rec["id"] == rid
    assert rec["ipfs_cid"] == cid

    # Verify checksum query
    res_valid = client.verify_record_checksum(rid, sha)
    assert res_valid["verified"] is True
    assert res_valid["status"] == "VERIFIED_INTACT"

    # Verify checksum tampering detection
    res_tampered = client.verify_record_checksum(rid, "0000000000000000000000000000000000000000000000000000000000000000")
    assert res_tampered["verified"] is False
    assert res_tampered["status"] == "CHECKSUM_MISMATCH"


def test_audit_trail_spec_and_chain_verification():
    client = real_fabric_gateway
    chain_info = client.verify_audit_chain()
    assert chain_info["isIntact"] is True
    assert chain_info["entryCount"] >= 4
    assert "cryptographically intact" in chain_info["message"]
