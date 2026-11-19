"""
Unit Tests: Automated Zero-PHI Compliance Scanner Verification.
"""

import pytest
from fixtures.phi_scanner import (
    PHIComplianceScanner,
    PHIComplianceViolationError,
    ScanReport
)
from fixtures.synthetic_records import (
    get_synthetic_ehr_encounter,
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    get_synthetic_radiology_report,
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID
)


@pytest.fixture
def scanner():
    return PHIComplianceScanner()


@pytest.mark.unit
def test_scanner_clean_synthetic_records_pass(scanner):
    """Verify that all four synthetic clinical record fixtures pass scanner with 0 violations."""
    records = [
        get_synthetic_ehr_encounter(PATIENT_ALICE_ID),
        get_synthetic_lab_report(PATIENT_ALICE_ID),
        get_synthetic_cardiology_encounter(PATIENT_ALICE_ID),
        get_synthetic_radiology_report(PATIENT_BOB_ID)
    ]
    for rec in records:
        report = scanner.scan_record(rec)
        assert report.is_compliant is True
        assert len(report.violations) == 0
        assert report.scanned_fields_count > 0


@pytest.mark.unit
def test_scanner_detects_ssn_variations(scanner):
    """Verify scanner catches SSNs in dashed or spaced format."""
    ssn_samples = ["123-45-6789", "987 65 4321"]
    for ssn in ssn_samples:
        bad_rec = {
            "patient_id": "SYNTH-PAT-001",
            "notes": f"Patient SSN is {ssn}",
            "synthetic_notice": "SYNTHETIC"
        }
        report = scanner.scan_record(bad_rec)
        assert report.is_compliant is False
        assert any("Social Security Number" in v for v in report.violations)


@pytest.mark.unit
def test_scanner_detects_real_external_email(scanner):
    """Verify scanner flags external commercial or personal email domains."""
    bad_rec = {
        "patient_id": "SYNTH-PAT-001",
        "contact_email": "real.patient.john@gmail.com",
        "synthetic_notice": "SYNTHETIC"
    }
    report = scanner.scan_record(bad_rec)
    assert report.is_compliant is False
    assert any("external email address" in v for v in report.violations)


@pytest.mark.unit
def test_scanner_allows_synthetic_domain_emails(scanner):
    """Verify scanner permits synthetic test email domains."""
    good_rec = {
        "patient_id": "SYNTH-PAT-001",
        "contact_email": "alice@synthetic.health",
        "synthetic_notice": "SYNTHETIC"
    }
    report = scanner.scan_record(good_rec)
    assert report.is_compliant is True


@pytest.mark.unit
def test_scanner_detects_real_telephone_pattern(scanner):
    """Verify scanner catches standard US telephone formats with non-555 area code."""
    bad_rec = {
        "patient_id": "SYNTH-PAT-001",
        "phone": "415-891-2345",
        "synthetic_notice": "SYNTHETIC"
    }
    report = scanner.scan_record(bad_rec)
    assert report.is_compliant is False
    assert any("real telephone number" in v for v in report.violations)


@pytest.mark.unit
def test_scanner_flags_missing_synthetic_notice(scanner):
    """Verify scanner requires the mandatory synthetic notice tag."""
    bad_rec = {
        "patient_id": "SYNTH-PAT-001",
        "diagnosis": "Healthy"
    }
    report = scanner.scan_record(bad_rec)
    assert report.is_compliant is False
    assert any("synthetic_notice" in v for v in report.violations)


@pytest.mark.unit
def test_scanner_assert_zero_phi_raises_exception(scanner):
    """Verify assert_zero_phi raises PHIComplianceViolationError on violation."""
    bad_rec = {
        "patient_id": "SYNTH-PAT-001",
        "ssn": "123-45-6789"
    }
    with pytest.raises(PHIComplianceViolationError) as exc_info:
        scanner.assert_zero_phi(bad_rec)
    assert len(exc_info.value.violations) > 0
