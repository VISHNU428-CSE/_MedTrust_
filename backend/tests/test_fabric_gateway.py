import pytest
from app.adapters.fabric_gateway import FabricGatewayAdapter
from app.core.exceptions import AccessDeniedError, ConsentNotFoundError, RecordNotFoundError


def test_fabric_gateway_initial_state():
    adapter = FabricGatewayAdapter()
    status = adapter.get_status()
    assert status["status"] == "connected"
    assert status["channel"] == "medtrust-channel"
    assert status["records_count"] >= 3
    assert status["consents_count"] >= 3
    assert status["audit_blocks_count"] >= 4


def test_fabric_record_registration():
    adapter = FabricGatewayAdapter()
    rec = adapter.register_record(
        record_id="rec-test-01",
        patient_id="pat-984210",
        patient_name="Eleanor Vance",
        title="Genetic Risk Panel",
        record_type="GENOMIC_DATA",
        ipfs_cid="bafybeitestcid0123456789",
        file_size="2.4 MB",
        mime_type="application/pdf",
        hospital="Metro Labs",
        key_fingerprint="SHA256:11223344...5566",
        checksum_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    )
    assert rec["id"] == "rec-test-01"
    assert rec["tx_hash"].startswith("0x")
    
    fetched = adapter.get_record("rec-test-01")
    assert fetched["title"] == "Genetic Risk Panel"


def test_fabric_consent_lifecycle():
    adapter = FabricGatewayAdapter()
    # 1. Request
    c = adapter.request_consent(
        patient_id="pat-984210",
        doctor_id="doc-999",
        doctor_name="Dr. Gregory",
        hospital="Mercy Hospital",
        specialty="General Practice",
        purpose="Annual physical checkup",
        allowed_record_types=["LAB_REPORT"],
        duration_days=14
    )
    cid = c["id"]
    assert c["status"] == "PENDING"
    
    # Verify before grant -> False
    allowed, reason, _ = adapter.verify_consent("doc-999", "pat-984210", "LAB_REPORT")
    assert allowed is False
    
    # 2. Grant by legitimate patient
    granted = adapter.grant_consent(cid, requesting_patient_id="pat-984210")
    assert granted["status"] == "ACTIVE"
    
    # Verify after grant -> True for allowed type, False for non-allowed type
    allowed, reason, _ = adapter.verify_consent("doc-999", "pat-984210", "LAB_REPORT")
    assert allowed is True
    assert reason == "CONSENT_ACTIVE"
    
    allowed_mri, reason_mri, _ = adapter.verify_consent("doc-999", "pat-984210", "IMAGING_MRI")
    assert allowed_mri is False
    assert reason_mri == "CONSENT_SCOPE_EXCLUDED"
    
    # 3. Revoke
    revoked = adapter.revoke_consent(cid, requesting_patient_id="pat-984210")
    assert revoked["status"] == "REVOKED"
    
    # Verify after revoke -> False
    allowed_after, reason_after, _ = adapter.verify_consent("doc-999", "pat-984210", "LAB_REPORT")
    assert allowed_after is False
    assert reason_after == "CONSENT_REVOKED"


def test_unauthorized_patient_cannot_revoke_third_party_consent():
    adapter = FabricGatewayAdapter()
    c = adapter.request_consent(
        patient_id="pat-984210",
        doctor_id="doc-999",
        doctor_name="Dr. Gregory",
        hospital="Mercy Hospital",
        specialty="General Practice",
        purpose="Annual physical checkup",
        allowed_record_types=["ALL"]
    )
    cid = c["id"]
    adapter.grant_consent(cid, requesting_patient_id="pat-984210")
    
    # Attacker patient attempts revocation
    with pytest.raises(AccessDeniedError):
        adapter.revoke_consent(cid, requesting_patient_id="pat-ATTACKER-999")


def test_audit_chain_cryptographic_integrity():
    adapter = FabricGatewayAdapter()
    is_intact, msg = adapter.verify_audit_chain_integrity()
    assert is_intact is True
    assert "cryptographically intact" in msg
