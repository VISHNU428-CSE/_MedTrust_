"""
Unit Tests: Golden SHA-256 Vector Stability & Digest Verification.
"""

import json
import os
import pytest
from fixtures.golden_vectors import (
    GOLDEN_VECTORS,
    get_golden_vector,
    verify_golden_digest,
    export_golden_vectors_as_json
)
from fixtures.synthetic_records import (
    get_synthetic_ehr_encounter,
    get_synthetic_lab_report,
    get_synthetic_cardiology_encounter,
    get_synthetic_radiology_report,
    PATIENT_ALICE_ID,
    PATIENT_BOB_ID
)


@pytest.mark.unit
def test_all_golden_vectors_present():
    """Verify all 4 core clinical categories have defined golden vectors."""
    assert "EHR" in GOLDEN_VECTORS
    assert "LAB_REPORT" in GOLDEN_VECTORS
    assert "CARDIOLOGY" in GOLDEN_VECTORS
    assert "RADIOLOGY" in GOLDEN_VECTORS


@pytest.mark.unit
def test_golden_vector_retrieval_and_fields():
    """Verify get_golden_vector retrieves well-structured vector entries."""
    vec = get_golden_vector("LAB_REPORT")
    assert vec["record_type"] == "LAB_REPORT"
    assert len(vec["sha256_digest"]) == 64
    assert vec["ipfs_cid"].startswith("bafybeimdt")
    assert vec["byte_length"] > 0


@pytest.mark.unit
def test_golden_digests_match_freshly_generated_fixtures():
    """
    CRITICAL REGRESSION INVARIANT:
    Ensures that freshly generated synthetic records produce identical, non-drifting
    SHA-256 digests matching precalculated golden test vectors.
    """
    ehr = get_synthetic_ehr_encounter(PATIENT_ALICE_ID)
    lab = get_synthetic_lab_report(PATIENT_ALICE_ID)
    card = get_synthetic_cardiology_encounter(PATIENT_ALICE_ID)
    rad = get_synthetic_radiology_report(PATIENT_BOB_ID)

    assert verify_golden_digest(ehr) is True
    assert verify_golden_digest(lab) is True
    assert verify_golden_digest(card) is True
    assert verify_golden_digest(rad) is True


@pytest.mark.unit
def test_verify_golden_digest_rejects_tampered_record():
    """Verify that tampering with any field in a record causes golden verification to fail."""
    lab = get_synthetic_lab_report(PATIENT_ALICE_ID)
    # Alter the sha256_checksum field or content
    lab["sha256_checksum"] = "0000000000000000000000000000000000000000000000000000000000000000"
    assert verify_golden_digest(lab) is False


@pytest.mark.unit
def test_exported_golden_vectors_json_file_validity():
    """Verify that the generated golden_test_vectors.json file exists and is valid."""
    json_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "golden_test_vectors.json")
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "EHR" in data
    assert "LAB_REPORT" in data
    assert "CARDIOLOGY" in data
    assert "RADIOLOGY" in data
    assert data["LAB_REPORT"]["sha256_digest"] == GOLDEN_VECTORS["LAB_REPORT"]["sha256_digest"]
