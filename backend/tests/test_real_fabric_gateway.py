"""
Unit and Integration Tests for RealFabricGatewayAdapter.
Validates implementation against GATEWAY_ADAPTER_SPEC.md:
1. Zero-PHI Enforcement & Compliance Invariants
2. Consent Management Lifecycle (Request -> Grant -> Verify -> Revoke)
3. Medical Record Metadata Registration & Checksum Verification
4. Tamper-Evident Cryptographic Hash Chaining on Audit Trail
5. Standby & Connection Profile Diagnostics
"""

import pytest
from app.adapters.real_fabric_gateway import (
    RealFabricGatewayAdapter,
    assert_zero_phi,
    generate_tx_hash,
)
from app.core.exceptions import (
    AccessDeniedError,
    ConsentNotFoundError,
    FabricGatewayError,
    PHIViolationError,
    RecordNotFoundError,
)


@pytest.fixture
def gateway():
    """Provides a fresh RealFabricGatewayAdapter instance for testing."""
    return RealFabricGatewayAdapter()


# ==========================================
# 1. ZERO-PHI ENFORCEMENT TESTS
# ==========================================


def test_zero_phi_clean_synthetic_payloads():
    """Synthetic identifiers and metadata pass compliance checks."""
    assert_zero_phi("SYNTH-PAT-001", "patient_id")
    assert_zero_phi("pat-984210", "patient_id")
    assert_zero_phi("Annual cardiology checkup and echocardiogram review", "purpose")
    assert_zero_phi('["LAB_REPORT", "IMAGING_MRI"]', "allowed_record_types")


def test_zero_phi_rejects_ssn_patterns():
    """Detects and rejects SSN patterns in any field."""
    with pytest.raises(PHIViolationError, match="Prohibited SSN pattern detected"):
        assert_zero_phi("Patient SSN: 123-45-6789", "purpose")

    with pytest.raises(PHIViolationError, match="Prohibited SSN pattern detected"):
        assert_zero_phi("456-78-1234", "patient_id")


def test_zero_phi_rejects_private_keys_and_passwords():
    """Detects and rejects private keys and raw password terms."""
    with pytest.raises(PHIViolationError, match="Forbidden credential or secret"):
        assert_zero_phi("-----BEGIN PRIVATE KEY-----MIIEvg...", "detail")

    with pytest.raises(PHIViolationError, match="Forbidden credential or secret"):
        assert_zero_phi('{"user": "alice", "password": "secretPassword"}', "payload")


# ==========================================
# 2. CONSENT LIFECYCLE TESTS (SPEC 2.1)
# ==========================================


def test_consent_request_and_pending_verification(gateway):
    """Requesting consent sets status to PENDING and blocks unauthorized reads."""
    consent = gateway.request_consent(
        consent_id="CONSENT-TEST-001",
        patient_id="SYNTH-PAT-001",
        doctor_id="SYNTH-DOC-101",
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=1798761599,
        purpose="Cardiology assessment",
    )

    assert consent["status"] == "PENDING"
    assert consent["tx_hash"].startswith("0x")
    assert len(consent["tx_hash"]) == 66

    # VerifyConsent returns CONSENT_PENDING
    check = gateway.verify_consent("SYNTH-DOC-101", "SYNTH-PAT-001", "LAB_REPORT")
    assert check["allowed"] is False
    assert check["reason"] == "CONSENT_PENDING"
    assert check["consentId"] == "CONSENT-TEST-001"


def test_consent_grant_and_active_verification(gateway):
    """Patient granting consent activates it for allowed scopes."""
    gateway.request_consent(
        consent_id="CONSENT-TEST-002",
        patient_id="SYNTH-PAT-002",
        doctor_id="SYNTH-DOC-102",
        allowed_record_types=["LAB_REPORT"],
        valid_until_epoch=1798761599,
        purpose="Metabolic panel review",
    )

    granted = gateway.grant_consent(
        consent_id="CONSENT-TEST-002",
        patient_id="SYNTH-PAT-002",
    )
    assert granted["status"] == "ACTIVE"

    # Verify matching scope succeeds
    check_lab = gateway.verify_consent("SYNTH-DOC-102", "SYNTH-PAT-002", "LAB_REPORT")
    assert check_lab["allowed"] is True
    assert check_lab["reason"] == "CONSENT_ACTIVE"

    # Verify out-of-scope record type is excluded
    check_mri = gateway.verify_consent("SYNTH-DOC-102", "SYNTH-PAT-002", "IMAGING_MRI")
    assert check_mri["allowed"] is False
    assert check_mri["reason"] == "CONSENT_SCOPE_EXCLUDED"


def test_consent_grant_cross_patient_protection(gateway):
    """Attempting to grant someone else's consent raises AccessDeniedError."""
    gateway.request_consent(
        consent_id="CONSENT-TEST-003",
        patient_id="SYNTH-PAT-001",
        doctor_id="SYNTH-DOC-101",
        allowed_record_types=["ALL"],
        valid_until_epoch=1798761599,
    )

    with pytest.raises(AccessDeniedError, match="UNAUTHORIZED_GRANT"):
        gateway.grant_consent("CONSENT-TEST-003", patient_id="MALICIOUS-PAT-999")


def test_immediate_consent_revocation(gateway):
    """Revoking consent takes effect immediately and prevents further reads."""
    gateway.request_consent(
        consent_id="CONSENT-TEST-004",
        patient_id="SYNTH-PAT-004",
        doctor_id="SYNTH-DOC-104",
        allowed_record_types=["ALL"],
        valid_until_epoch=1798761599,
    )
    gateway.grant_consent("CONSENT-TEST-004", "SYNTH-PAT-004")

    # Access is active
    assert gateway.verify_consent("SYNTH-DOC-104", "SYNTH-PAT-004", "LAB_REPORT")["allowed"] is True

    # Patient revokes immediately
    revoked = gateway.revoke_consent("CONSENT-TEST-004", requesting_patient_id="SYNTH-PAT-004")
    assert revoked["status"] == "REVOKED"
    assert "revoked_at" in revoked

    # Access immediately denied
    check = gateway.verify_consent("SYNTH-DOC-104", "SYNTH-PAT-004", "LAB_REPORT")
    assert check["allowed"] is False
    assert check["reason"] == "CONSENT_REVOKED"


def test_revocation_ownership_violation(gateway):
    """Third party cannot revoke a patient's consent."""
    gateway.request_consent(
        consent_id="CONSENT-TEST-005",
        patient_id="SYNTH-PAT-005",
        doctor_id="SYNTH-DOC-105",
        allowed_record_types=["ALL"],
        valid_until_epoch=1798761599,
    )

    with pytest.raises(AccessDeniedError, match="REVOCATION_OWNERSHIP_VIOLATION"):
        gateway.revoke_consent("CONSENT-TEST-005", requesting_patient_id="ATTACKER-PAT-001")


# ==========================================
# 3. MEDICAL RECORD METADATA TESTS (SPEC 2.2)
# ==========================================


def test_register_and_get_record_metadata(gateway):
    """Registers record metadata and queries by ID and patient."""
    checksum = "8b4f17a9e526d1c8502f6bc1829e013fa675914ab18239048a04b827e8a3a839"
    cid = "bafkreifl34pauk57tkthdcenvzvvdyqjsqjxlolxkzipixmsflhudgued4"

    record = gateway.register_record_metadata(
        record_id="REC-TEST-001",
        patient_id="SYNTH-PAT-001",
        ipfs_cid=cid,
        checksum=checksum,
        record_type="IMAGING_MRI",
        facility="Metro General Hospital",
        registered_by="SYNTH-DOC-101",
    )

    assert record["id"] == "REC-TEST-001"
    assert record["ipfs_cid"] == cid
    assert record["checksum_sha256"] == checksum
    assert record["tx_hash"].startswith("0x")

    # Get by ID
    fetched = gateway.get_record("REC-TEST-001")
    assert fetched["id"] == "REC-TEST-001"

    # List by patient
    pat_records = gateway.get_records_by_patient("SYNTH-PAT-001")
    assert len(pat_records) >= 1
    assert any(r["id"] == "REC-TEST-001" for r in pat_records)


def test_verify_record_checksum_intact_and_mismatch(gateway):
    """Verifies calculated IPFS checksum against registered on-chain digest."""
    checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    gateway.register_record_metadata(
        record_id="REC-TEST-002",
        patient_id="SYNTH-PAT-002",
        ipfs_cid="bafybeimdt7318a47402636a2829210medtrust",
        checksum=checksum,
        record_type="LAB_REPORT",
    )

    # Intact checksum
    result_ok = gateway.verify_record_checksum("REC-TEST-002", checksum)
    assert result_ok["verified"] is True
    assert result_ok["status"] == "VERIFIED_INTACT"

    # Tampered checksum
    tampered = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    result_bad = gateway.verify_record_checksum("REC-TEST-002", tampered)
    assert result_bad["verified"] is False
    assert result_bad["status"] == "CHECKSUM_MISMATCH"


def test_register_record_invalid_checksum_format(gateway):
    """Rejects invalid non-hex or malformed SHA-256 strings."""
    with pytest.raises(FabricGatewayError):
        gateway.register_record_metadata(
            record_id="REC-TEST-BAD",
            patient_id="SYNTH-PAT-001",
            ipfs_cid="bafybeicid",
            checksum="not-a-64-char-hex-hash",
            record_type="LAB_REPORT",
        )


# ==========================================
# 4. AUDIT TRAIL HASH CHAIN TESTS (SPEC 2.3)
# ==========================================


def test_audit_trail_hash_chain_integrity(gateway):
    """Logs multiple events and verifies unbroken SHA-256 hash chaining."""
    prev_tip = gateway._prev_audit_hash
    e1 = gateway.log_access_event(
        event_type="UPLOAD_RECORD",
        actor_id="SYNTH-DOC-101",
        actor_role="DOCTOR",
        target_patient_id="SYNTH-PAT-001",
        record_id="REC-TEST-001",
        status="SUCCESS",
        detail="Uploaded encrypted laboratory report",
    )
    assert e1["prev_hash"] == prev_tip
    assert "entry_hash" in e1

    e2 = gateway.log_access_event(
        event_type="VIEW_RECORD",
        actor_id="SYNTH-DOC-101",
        actor_role="DOCTOR",
        target_patient_id="SYNTH-PAT-001",
        record_id="REC-TEST-001",
        status="ALLOWED",
        detail="Consultation review",
    )
    assert e2["prev_hash"] == e1["entry_hash"]

    # Verify intact chain
    verification = gateway.verify_audit_chain()
    assert verification["isIntact"] is True
    assert verification["entryCount"] >= 2
    assert "intact and unbroken" in verification["message"]


def test_audit_trail_detects_corrupted_payload(gateway):
    """Detects tampered historical audit entry."""
    gateway.log_access_event("EVENT_A", "DOC-1", "DOCTOR", "PAT-1")
    gateway.log_access_event("EVENT_B", "DOC-1", "DOCTOR", "PAT-1")

    # Intact before tampering
    assert gateway.verify_audit_chain()["isIntact"] is True

    # Maliciously modify historical entry in chain
    gateway._audit_chain[0]["detail"] = "TAMPERED DETAILS"

    # Verifier must catch corruption
    verification = gateway.verify_audit_chain()
    assert verification["isIntact"] is False
    assert "Corrupted entry hash" in verification["message"]


# ==========================================
# 5. DIAGNOSTICS & PROFILE LOADING
# ==========================================


def test_peer_connectivity_diagnostics(gateway):
    """Connectivity diagnostic returns structured status."""
    info = gateway.check_peer_connectivity()
    assert "peer_endpoint" in info
    assert "mode" in info
    assert info["mode"] in ("live", "standby")
    assert info["channel"] == "medtrust-channel"
    assert info["chaincode"] == "medtrust-contract"
    assert info["credentials_loaded"] is True


def test_custom_record_type_preservation_without_downcasting(gateway, monkeypatch):
    """Verifies unknown chaincode record types (e.g. CARDIOLOGY_REPORT) are preserved faithfully."""
    from app.config import settings
    from app.models.schemas import MedicalRecord

    monkeypatch.setattr(settings, "FABRIC_USE_REAL_GATEWAY", True)

    raw_chaincode_doc = {
        "recordId": "REC-TEST-CUSTOM-01",
        "patientId": "SYNTH-PAT-001",
        "ipfsCid": "bafkreiacustom1234567890",
        "checksum": "07b06e2745fa46c995f42faf51fc90257ec675456d36f595f94cac97bc497a02",
        "recordType": "CARDIOLOGY_REPORT",
        "facility": "Metro Heart Institute",
        "registeredBy": "SYNTH-DOC-CARDIO",
        "timestamp": 1793299066,
    }

    monkeypatch.setattr(gateway, "_execute_peer_query", lambda *args, **kwargs: raw_chaincode_doc)

    fetched = gateway.get_record("REC-TEST-CUSTOM-01")
    assert fetched["record_type"] == "CARDIOLOGY_REPORT"
    assert fetched["recordType"] == "CARDIOLOGY_REPORT"

    # Must serialize into MedicalRecord schema cleanly without Pydantic ValidationError
    validated = MedicalRecord.model_validate(fetched)
    assert validated.record_type == "CARDIOLOGY_REPORT"
    assert validated.id == "REC-TEST-CUSTOM-01"


# ==========================================
# 6. DOCKER EXECUTABLE DISCOVERY & EXECUTION TESTS (IPR-54)
# ==========================================


def test_docker_binary_resolution_via_which(monkeypatch):
    """Verifies _resolve_docker_binary uses shutil.which when available."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/docker" if cmd == "docker" else None)
    assert RealFabricGatewayAdapter._resolve_docker_binary() == "/usr/local/bin/docker"


def test_docker_binary_resolution_fallback_to_candidate(monkeypatch):
    """Verifies _resolve_docker_binary falls back to standard install paths when which returns None."""
    import shutil
    import os
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    expected_path = os.path.expandvars(r"%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin\docker.exe")
    monkeypatch.setattr(os.path, "isfile", lambda p: p == expected_path)

    assert RealFabricGatewayAdapter._resolve_docker_binary() == expected_path


def test_docker_binary_resolution_default_fallback(monkeypatch):
    """Verifies _resolve_docker_binary defaults to 'docker' when no candidate exists."""
    import shutil
    import os
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    monkeypatch.setattr(os.path, "isfile", lambda p: False)

    assert RealFabricGatewayAdapter._resolve_docker_binary() == "docker"


def test_execute_peer_query_missing_docker_handling(gateway, monkeypatch):
    """Verifies _execute_peer_query produces clear diagnostic when docker binary is missing."""
    import subprocess

    def _mock_missing_run(*args, **kwargs):
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr(subprocess, "run", _mock_missing_run)

    with pytest.raises(FabricGatewayError) as exc_info:
        gateway._execute_peer_query("MedTrustContract:GetRecord", ["rec-001"])

    assert "Docker executable not found or inaccessible" in str(exc_info.value)


def test_execute_peer_invoke_missing_docker_handling(gateway, monkeypatch):
    """Verifies _execute_peer_invoke produces clear diagnostic when docker binary is missing."""
    import subprocess

    def _mock_missing_run(*args, **kwargs):
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr(subprocess, "run", _mock_missing_run)

    with pytest.raises(FabricGatewayError) as exc_info:
        gateway._execute_peer_invoke("MedTrustContract:RegisterRecord", ["rec-001"])

    assert "Docker executable not found or inaccessible" in str(exc_info.value)


def test_execute_peer_query_with_resolved_binary(gateway, monkeypatch):
    """Verifies _execute_peer_query passes resolved binary to subprocess.run."""
    import subprocess
    captured_cmd = []

    class MockProc:
        returncode = 0
        stdout = '{"status": "SUCCESS"}'
        stderr = ""

    def _mock_run(cmd, *args, **kwargs):
        captured_cmd.extend(cmd)
        return MockProc()

    monkeypatch.setattr(subprocess, "run", _mock_run)

    res = gateway._execute_peer_query("MedTrustContract:GetRecord", ["rec-001"])
    assert res == {"status": "SUCCESS"}
    assert captured_cmd[0] == gateway._resolve_docker_binary()
    assert captured_cmd[1] == "exec"


def test_execute_peer_invoke_with_resolved_binary(gateway, monkeypatch):
    """Verifies _execute_peer_invoke passes resolved binary to subprocess.run."""
    import subprocess
    captured_cmd = []

    class MockProc:
        returncode = 0
        stdout = ""
        stderr = "txid [a1b2c3d4e5f6] committed with status (VALID)"

    def _mock_run(cmd, *args, **kwargs):
        captured_cmd.extend(cmd)
        return MockProc()

    monkeypatch.setattr(subprocess, "run", _mock_run)

    res = gateway._execute_peer_invoke("MedTrustContract:RegisterRecord", ["rec-001"])
    assert res["status"] == "COMMITTED"
    assert res["tx_hash"] == "0xa1b2c3d4e5f6"
    assert captured_cmd[0] == gateway._resolve_docker_binary()
    assert captured_cmd[1] == "exec"


