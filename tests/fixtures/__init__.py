"""QA Fixtures package for MedTrust test harness."""

from .synthetic_records import (
    get_synthetic_ehr_encounter,
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    get_synthetic_radiology_report,
    validate_no_real_phi,
    to_canonical_json_bytes,
    compute_sha256,
    compute_payload_cid,
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID,
    PATIENT_CHARLIE_ID,
    DOCTOR_DR_SMITH_ID,
    DOCTOR_DR_JONES_ID,
    ATTACKER_EVE_ID
)
from .phi_scanner import (
    PHIComplianceScanner,
    PHIComplianceViolationError,
    ScanReport
)
from .golden_vectors import (
    GOLDEN_VECTORS,
    get_golden_vector,
    verify_golden_digest,
    export_golden_vectors_as_json
)
