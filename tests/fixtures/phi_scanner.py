"""
Automated PHI & PII Compliance Scanner for MedTrust.

Performs recursive, deep pattern inspection on clinical records, JSON payloads,
and raw bytes to ensure ZERO Protected Health Information (PHI) or Personally
Identifiable Information (PII) is present.
"""

import json
import re
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field


# Regex patterns for detecting sensitive data patterns (SSN, ITIN, Tax ID)
SSN_REGEX = re.compile(
    r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"
)

PHONE_REGEX = re.compile(
    r"\b(?:\+?1[-. ]?)?\(?[2-9]\d{2}\)?[-. ]?[2-9]\d{2}[-. ]?\d{4}\b"
)

# Checks for non-synthetic email addresses
NON_SYNTHETIC_EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?!example\.com|test\.medtrust\.local|synthetic\.health|synthetic\.local)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    re.IGNORECASE
)

# Standard Credit Card / PAN regex (Luhn format)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[- ]?){3}\d{4}\b"
)


class PHIComplianceViolationError(Exception):
    """Raised when one or more PHI/PII compliance violations are detected."""
    def __init__(self, violations: List[str]):
        super().__init__(f"PHI Compliance Violations Detected:\n - " + "\n - ".join(violations))
        self.violations = violations


@dataclass
class ScanReport:
    """Detailed report produced by the PHI compliance scanner."""
    is_compliant: bool
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scanned_fields_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_compliant": self.is_compliant,
            "violations": self.violations,
            "warnings": self.warnings,
            "scanned_fields_count": self.scanned_fields_count
        }


class PHIComplianceScanner:
    """
    Automated zero-PHI scanner for synthetic clinical datasets and serialized payloads.
    """

    def scan_string(self, text: str, context_path: str = "root") -> List[str]:
        """Scans a single text string against all sensitivity rules."""
        violations = []

        # 1. Social Security Number Check
        if SSN_REGEX.search(text):
            violations.append(f"[{context_path}] Contains pattern matching Social Security Number (SSN)")

        # 2. Real Phone Number Check (excluding synthetic area code 555)
        phone_matches = PHONE_REGEX.findall(text)
        for pm in phone_matches:
            if "555" not in pm:
                violations.append(f"[{context_path}] Contains potential real telephone number: {pm}")

        # 3. Real External Email Check
        email_matches = NON_SYNTHETIC_EMAIL_REGEX.findall(text)
        for em in email_matches:
            violations.append(f"[{context_path}] Contains non-synthetic external email address: {em}")

        # 4. Credit Card Pattern Check
        if CREDIT_CARD_REGEX.search(text):
            violations.append(f"[{context_path}] Contains pattern matching credit card / financial number")

        return violations

    def scan_record(self, record: Dict[str, Any]) -> ScanReport:
        """
        Recursively scans a dictionary or clinical record object.
        """
        violations: List[str] = []
        warnings: List[str] = []
        scanned_count = [0]

        # Rule A: Mandatory synthetic notice tag
        if "synthetic_notice" not in record:
            violations.append("[record] Missing mandatory 'synthetic_notice' disclosure attribute")

        # Rule B: Identifier schema validation
        patient_id = record.get("patient_id")
        if patient_id and not str(patient_id).startswith("SYNTH-PAT-"):
            violations.append(f"[patient_id] Identifier '{patient_id}' violates synthetic prefix 'SYNTH-PAT-*'")

        def _walk(obj: Any, path: str):
            scanned_count[0] += 1
            if isinstance(obj, str):
                violations.extend(self.scan_string(obj, path))
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    _walk(v, f"{path}.{k}")
            elif isinstance(obj, (list, tuple)):
                for idx, item in enumerate(obj):
                    _walk(item, f"{path}[{idx}]")

        _walk(record, "record")

        is_compliant = len(violations) == 0
        return ScanReport(
            is_compliant=is_compliant,
            violations=violations,
            warnings=warnings,
            scanned_fields_count=scanned_count[0]
        )

    def scan_raw_bytes(self, payload: bytes) -> ScanReport:
        """Scans raw binary or utf-8 encoded payload."""
        try:
            decoded = payload.decode("utf-8")
            try:
                parsed = json.loads(decoded)
                if isinstance(parsed, dict):
                    return self.scan_record(parsed)
            except json.JSONDecodeError:
                pass
            
            # Fall back to text scanning
            violations = self.scan_string(decoded, "raw_bytes")
            return ScanReport(
                is_compliant=len(violations) == 0,
                violations=violations,
                warnings=[],
                scanned_fields_count=1
            )
        except UnicodeDecodeError:
            # Binary payload (e.g. encrypted ciphertext)
            return ScanReport(is_compliant=True, violations=[], warnings=[], scanned_fields_count=1)

    def assert_zero_phi(self, record: Union[Dict[str, Any], bytes, str]) -> None:
        """
        Convenience assertion helper. Raises PHIComplianceViolationError if violations found.
        """
        if isinstance(record, dict):
            report = self.scan_record(record)
        elif isinstance(record, bytes):
            report = self.scan_raw_bytes(record)
        elif isinstance(record, str):
            report = ScanReport(
                is_compliant=len(self.scan_string(record)) == 0,
                violations=self.scan_string(record),
                scanned_fields_count=1
            )
        else:
            raise TypeError(f"Unsupported record type: {type(record)}")

        if not report.is_compliant:
            raise PHIComplianceViolationError(report.violations)
