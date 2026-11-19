"""
Unit Tests: Synthetic Medical Record Fixture Validation & PHI Guardrails.
"""

import pytest
from fixtures.synthetic_records import (
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    get_synthetic_radiology_report,
    validate_no_real_phi,
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID
)


@pytest.mark.unit
def test_synthetic_lab_report_phi_compliance():
    """Verify synthetic lab report contains no real PHI and satisfies schema."""
    record = get_synthetic_lab_report(PATIENT_ALICE_ID)
    assert validate_no_real_phi(record) is True
    assert record["patient_id"] == PATIENT_ALICE_ID
    assert record["record_type"] == "LAB_REPORT"
    assert "synthetic_notice" in record
    assert len(record["sha256_checksum"]) == 64
    assert record["ipfs_cid"].startswith("bafybeimdt")


@pytest.mark.unit
def test_synthetic_cardiology_phi_compliance():
    """Verify cardiology encounter is compliant and structured."""
    record = get_synthetic_cardiology_encounter(PATIENT_ALICE_ID)
    assert validate_no_real_phi(record) is True
    assert record["record_type"] == "CARDIOLOGY_VISIT"
    assert "vitals" in record["clinical_data"]
    assert record["clinical_data"]["vitals"]["blood_pressure_systolic"] == 118


@pytest.mark.unit
def test_synthetic_radiology_phi_compliance():
    """Verify radiology encounter is compliant."""
    record = get_synthetic_radiology_report(PATIENT_BOB_ID)
    assert validate_no_real_phi(record) is True
    assert record["patient_id"] == PATIENT_BOB_ID
    assert record["clinical_data"]["modality"] == "MRI"


@pytest.mark.unit
def test_phi_guardrail_detects_real_ssn_pattern():
    """Ensure the guardrail raises ValueError if a real SSN format is introduced."""
    leak_record = {
        "patient_id": "SYNTH-PAT-001",
        "ssn": "123-45-6789",  # Valid format SSN
        "synthetic_notice": "SYNTHETIC"
    }
    with pytest.raises(ValueError, match="Security Violation: Record contains patterns matching real SSN"):
        validate_no_real_phi(leak_record)


@pytest.mark.unit
def test_phi_guardrail_enforces_synthetic_identifier_prefix():
    """Ensure identifiers without SYNTH- prefix fail compliance check."""
    invalid_record = {
        "patient_id": "REAL-PATIENT-9999",
        "synthetic_notice": "SYNTHETIC"
    }
    with pytest.raises(ValueError, match="Compliance Violation: patient_id"):
        validate_no_real_phi(invalid_record)
