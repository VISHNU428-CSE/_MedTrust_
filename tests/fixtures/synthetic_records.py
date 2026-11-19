"""
Synthetic Medical Record Fixtures for MedTrust QA Suite.

COMPLIANCE NOTICE:
All records in this module are strictly synthetic and generated for automated
testing purposes. NO REAL PROTECTED HEALTH INFORMATION (PHI) IS INCLUDED.
All names, dates of birth, MRNs, and clinical data are artificial.
"""

import hashlib
import json
import re
from typing import Dict, Any, List

from .phi_scanner import PHIComplianceScanner, PHIComplianceViolationError


# Guardrail regex to detect real SSNs or suspicious real patterns
SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")


def compute_sha256(content: bytes) -> str:
    """Compute hex SHA-256 digest for payload integrity verification."""
    return hashlib.sha256(content).hexdigest()


def compute_payload_cid(content: bytes) -> str:
    """
    Generate a deterministic mock IPFS CIDv1 (base32-style) from content SHA-256.
    In live IPFS/Kubo this corresponds to a multihash-derived CID.
    """
    digest = hashlib.sha256(content).hexdigest()
    return f"bafybeimdt{digest[:26]}medtrust"


def to_canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """
    Serializes dictionary into deterministic, canonical bytes (sorted keys, compact separators).
    Guarantees cross-language and cross-platform SHA-256 digest stability.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Pre-defined Synthetic Patient Identifiers
PATIENT_ALICE_ID = "SYNTH-PAT-001"
PATIENT_BOB_ID = "SYNTH-PAT-002"
PATIENT_CHARLIE_ID = "SYNTH-PAT-003"

# Pre-defined Synthetic Doctor Identifiers
DOCTOR_DR_SMITH_ID = "SYNTH-DOC-101"
DOCTOR_DR_JONES_ID = "SYNTH-DOC-102"
ATTACKER_EVE_ID = "SYNTH-MAL-999"


def get_synthetic_ehr_encounter(patient_id: str = PATIENT_ALICE_ID) -> Dict[str, Any]:
    """Generates a synthetic Comprehensive Electronic Health Record (EHR) encounter."""
    data = {
        "record_id": f"REC-EHR-{patient_id}-000",
        "record_type": "EHR_GENERAL",
        "patient_id": patient_id,
        "facility": "Synthetic Health System - Primary Care Clinic",
        "encounter_date": "2026-08-10T10:00:00Z",
        "chief_complaint": "Annual wellness examination and preventive health counseling.",
        "clinical_data": {
            "history_of_present_illness": "Synthetic patient presents for routine preventive health assessment. No acute complaints.",
            "allergies": [
                {"substance": "Synthetic Amoxicillin", "reaction": "Mild skin rash", "severity": "MODERATE"}
            ],
            "medications": [
                {"name": "Synthetic Lisinopril", "dosage": "10mg daily", "route": "Oral"}
            ],
            "immunizations": [
                {"vaccine": "Synthetic Influenza Vaccine", "date": "2025-10-15"}
            ],
            "assessment_and_plan": "Well-managed baseline health. Routine laboratory screening ordered."
        },
        "synthetic_notice": "SYNTHETIC TEST RECORD - STRICTLY NO REAL PHI"
    }
    raw_bytes = to_canonical_json_bytes(data)
    data["sha256_checksum"] = compute_sha256(raw_bytes)
    data["ipfs_cid"] = compute_payload_cid(raw_bytes)
    return data


def get_synthetic_lab_report(patient_id: str = PATIENT_ALICE_ID) -> Dict[str, Any]:
    """Generates a synthetic Comprehensive Metabolic Panel (CMP) medical record."""
    data = {
        "record_id": f"REC-LAB-{patient_id}-001",
        "record_type": "LAB_REPORT",
        "patient_id": patient_id,
        "facility": "Synthetic General Hospital - Lab Division",
        "encounter_date": "2026-09-15T09:30:00Z",
        "clinical_data": {
            "panel": "Comprehensive Metabolic Panel (Synthetic)",
            "results": [
                {"test": "Glucose", "value": 92, "unit": "mg/dL", "reference_range": "70-99", "status": "NORMAL"},
                {"test": "Blood Urea Nitrogen (BUN)", "value": 14, "unit": "mg/dL", "reference_range": "7-20", "status": "NORMAL"},
                {"test": "Creatinine", "value": 0.9, "unit": "mg/dL", "reference_range": "0.6-1.2", "status": "NORMAL"},
                {"test": "Sodium", "value": 139, "unit": "mmol/L", "reference_range": "135-145", "status": "NORMAL"},
                {"test": "Potassium", "value": 4.1, "unit": "mmol/L", "reference_range": "3.5-5.0", "status": "NORMAL"},
            ]
        },
        "synthetic_notice": "SYNTHETIC TEST RECORD - NOT REAL MEDICAL DATA"
    }
    raw_bytes = to_canonical_json_bytes(data)
    data["sha256_checksum"] = compute_sha256(raw_bytes)
    data["ipfs_cid"] = compute_payload_cid(raw_bytes)
    return data


def get_synthetic_cardiology_encounter(patient_id: str = PATIENT_ALICE_ID) -> Dict[str, Any]:
    """Generates a synthetic Cardiology encounter and vital signs record."""
    data = {
        "record_id": f"REC-CARD-{patient_id}-002",
        "record_type": "CARDIOLOGY_VISIT",
        "patient_id": patient_id,
        "facility": "Synthetic Heart Institute",
        "encounter_date": "2026-09-20T14:15:00Z",
        "clinical_data": {
            "vitals": {
                "blood_pressure_systolic": 118,
                "blood_pressure_diastolic": 76,
                "heart_rate_bpm": 68,
                "respiratory_rate": 16,
                "oxygen_saturation_pct": 99
            },
            "assessment": "Routine outpatient follow-up. Normal sinus rhythm on synthetic ECG.",
            "plan": "Continue current lifestyle recommendations. Annual review in 12 months."
        },
        "synthetic_notice": "SYNTHETIC TEST RECORD - NOT REAL MEDICAL DATA"
    }
    raw_bytes = to_canonical_json_bytes(data)
    data["sha256_checksum"] = compute_sha256(raw_bytes)
    data["ipfs_cid"] = compute_payload_cid(raw_bytes)
    return data


def get_synthetic_radiology_report(patient_id: str = PATIENT_BOB_ID) -> Dict[str, Any]:
    """Generates a synthetic MRI Lumbar Spine report metadata."""
    data = {
        "record_id": f"REC-RAD-{patient_id}-003",
        "record_type": "RADIOLOGY_REPORT",
        "patient_id": patient_id,
        "facility": "Synthetic Imaging Diagnostic Center",
        "encounter_date": "2026-10-01T11:00:00Z",
        "clinical_data": {
            "modality": "MRI",
            "body_part": "Lumbar Spine",
            "findings": "Synthetic imaging findings show normal alignment, no disk herniation or stenosis.",
            "impression": "Normal synthetic lumbar spine study."
        },
        "synthetic_notice": "SYNTHETIC TEST RECORD - NOT REAL MEDICAL DATA"
    }
    raw_bytes = to_canonical_json_bytes(data)
    data["sha256_checksum"] = compute_sha256(raw_bytes)
    data["ipfs_cid"] = compute_payload_cid(raw_bytes)
    return data


def validate_no_real_phi(record: Dict[str, Any]) -> bool:
    """
    Validates that the record contains no identifiable real PHI patterns.
    Returns True if clean, raises ValueError / PHIComplianceViolationError if suspicious real data found.
    """
    scanner = PHIComplianceScanner()
    report = scanner.scan_record(record)
    if not report.is_compliant:
        for v in report.violations:
            if "Social Security Number" in v:
                raise ValueError("Security Violation: Record contains patterns matching real SSN!")
            if "violates synthetic prefix" in v:
                raise ValueError(f"Compliance Violation: patient_id '{record.get('patient_id')}' does not follow synthetic schema 'SYNTH-PAT-*'!")
            if "Missing mandatory 'synthetic_notice'" in v:
                raise ValueError("Compliance Violation: Record is missing 'synthetic_notice' tag!")
        raise ValueError(f"Security Violation: Record contains patterns matching real SSN / PHI: {report.violations}")
    return True
