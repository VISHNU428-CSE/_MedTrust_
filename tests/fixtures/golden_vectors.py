"""
Golden Test Vectors for MedTrust IPFS Storage & Encryption Verification.

Precalculated, deterministic golden digests for synthetic clinical records.
Provides importable test vectors for backend encryption tests, IPFS upload/retrieval,
and tamper detection.
"""

import hashlib
import json
from typing import Dict, Any, Optional

from .synthetic_records import (
    get_synthetic_ehr_encounter,
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    get_synthetic_radiology_report,
    to_canonical_json_bytes,
    compute_sha256,
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID
)


# Precalculated Golden SHA-256 Digests (Immutable Invariant)
GOLDEN_VECTORS: Dict[str, Dict[str, Any]] = {
    "EHR": {
        "record_type": "EHR_GENERAL",
        "record_id": f"REC-EHR-{PATIENT_ALICE_ID}-000",
        "patient_id": PATIENT_ALICE_ID,
        "sha256_digest": "fd8dd8bb9f533caa14c2e9cef0ae672ae4be99b3e66607d7f06e3e57dd88cdef",
        "ipfs_cid": "bafybeimdtfd8dd8bb9f533caa14c2e9cef0medtrust",
        "byte_length": 819,
        "sample_record": get_synthetic_ehr_encounter(PATIENT_ALICE_ID)
    },
    "LAB_REPORT": {
        "record_type": "LAB_REPORT",
        "record_id": f"REC-LAB-{PATIENT_ALICE_ID}-001",
        "patient_id": PATIENT_ALICE_ID,
        "sha256_digest": "c1a9163840a3685b46ee0f1cd9ecf9731bdf2fbc8ecb33a4ec3c135b031cc29c",
        "ipfs_cid": "bafybeimdtc1a9163840a3685b46ee0f1cd9medtrust",
        "byte_length": 794,
        "sample_record": get_synthetic_lab_report(PATIENT_ALICE_ID)
    },
    "CARDIOLOGY": {
        "record_type": "CARDIOLOGY_VISIT",
        "record_id": f"REC-CARD-{PATIENT_ALICE_ID}-002",
        "patient_id": PATIENT_ALICE_ID,
        "sha256_digest": "18a685c4ef09649cbd61d083e70a0c78cdeb83d806b22fc83c7df9296b29b48a",
        "ipfs_cid": "bafybeimdt18a685c4ef09649cbd61d083e7medtrust",
        "byte_length": 548,
        "sample_record": get_synthetic_cardiology_encounter(PATIENT_ALICE_ID)
    },
    "RADIOLOGY": {
        "record_type": "RADIOLOGY_REPORT",
        "record_id": f"REC-RAD-{PATIENT_BOB_ID}-003",
        "patient_id": PATIENT_BOB_ID,
        "sha256_digest": "ddf24c12968d2ffade1d7cd3d4cbbef743b83754e1b67f396e645c191ba80d49",
        "ipfs_cid": "bafybeimdtddf24c12968d2ffade1d7cd3d4medtrust",
        "byte_length": 444,
        "sample_record": get_synthetic_radiology_report(PATIENT_BOB_ID)
    }
}


def get_golden_vector(key: str) -> Dict[str, Any]:
    """Retrieve precalculated golden vector by key (EHR, LAB_REPORT, CARDIOLOGY, RADIOLOGY)."""
    norm_key = key.upper()
    if norm_key not in GOLDEN_VECTORS:
        raise KeyError(f"Unknown golden vector key '{key}'. Available: {list(GOLDEN_VECTORS.keys())}")
    return GOLDEN_VECTORS[norm_key]


def verify_golden_digest(record: Dict[str, Any]) -> bool:
    """
    Verifies if a generated record's sha256_checksum matches its precalculated golden vector.
    """
    record_type = record.get("record_type")
    # Map record_type to key
    mapping = {
        "EHR_GENERAL": "EHR",
        "LAB_REPORT": "LAB_REPORT",
        "CARDIOLOGY_VISIT": "CARDIOLOGY",
        "RADIOLOGY_REPORT": "RADIOLOGY"
    }
    key = mapping.get(record_type)
    if not key or key not in GOLDEN_VECTORS:
        return False

    golden = GOLDEN_VECTORS[key]
    return (
        record.get("sha256_checksum") == golden["sha256_digest"] and
        record.get("ipfs_cid") == golden["ipfs_cid"]
    )


def export_golden_vectors_as_json() -> str:
    """Exports all golden vectors into a portable JSON string."""
    exportable = {}
    for k, v in GOLDEN_VECTORS.items():
        exportable[k] = {
            "record_type": v["record_type"],
            "record_id": v["record_id"],
            "patient_id": v["patient_id"],
            "sha256_digest": v["sha256_digest"],
            "ipfs_cid": v["ipfs_cid"],
            "byte_length": v["byte_length"],
            "sample_record": v["sample_record"]
        }
    return json.dumps(exportable, indent=2, sort_keys=True)
