"""
Unit Tests: Phase 6 Clinical Detail Pydantic Schemas & CamelModel Serializers.

Verifies:
- RecordDetailResponse fields, default values, and camelCase aliases.
- from_orm_model factory handling datetime vs string created_at.
- RecordDetailCreate validation.
- RecordUploadResponse composite serialization.
"""

from datetime import datetime, timezone
import pytest
from app.models.schemas import (
    RecordDetailResponse,
    RecordDetailCreate,
    RecordUploadResponse,
    MedicalRecord,
    RecordType
)


class MockRecordDetailORM:
    """Simulates SQLAlchemy RecordDetailModel for unit testing."""
    def __init__(
        self,
        id="det-test-123",
        record_id="rec-test-123",
        patient_id="pat-984210",
        description="Test symptom description",
        prescription_cid="bafkreitestcid12345",
        prescription_filename="test_prescription.pdf",
        prescription_checksum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        has_document=True,
        created_at=None
    ):
        self.id = id
        self.record_id = record_id
        self.patient_id = patient_id
        self.description = description
        self.prescription_cid = prescription_cid
        self.prescription_filename = prescription_filename
        self.prescription_checksum = prescription_checksum
        self.has_document = has_document
        self.created_at = created_at or datetime.now(timezone.utc)


@pytest.mark.unit
def test_record_detail_response_from_orm_with_datetime():
    """Verify RecordDetailResponse accurately converts ORM model with datetime."""
    orm_model = MockRecordDetailORM(
        created_at=datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
    )
    dto = RecordDetailResponse.from_orm_model(orm_model)

    assert dto.id == "det-test-123"
    assert dto.record_id == "rec-test-123"
    assert dto.patient_id == "pat-984210"
    assert dto.description == "Test symptom description"
    assert dto.prescription_cid == "bafkreitestcid12345"
    assert dto.prescription_filename == "test_prescription.pdf"
    assert dto.has_document is True
    assert dto.created_at.startswith("2026-10-22T12:00:00")


@pytest.mark.unit
def test_record_detail_response_camel_case_serialization():
    """Verify JSON dump uses camelCase keys expected by frontend components."""
    dto = RecordDetailResponse(
        id="det-1",
        record_id="rec-1",
        patient_id="pat-1",
        description="Persistent cough",
        prescription_cid="bafk123",
        prescription_filename="cough_syrup.pdf",
        prescription_checksum="abc1234",
        has_document=False,
        created_at="2026-10-22T10:00:00Z"
    )
    dumped = dto.model_dump(by_alias=True)

    assert "recordId" in dumped
    assert "patientId" in dumped
    assert "prescriptionCid" in dumped
    assert "prescriptionFilename" in dumped
    assert "prescriptionChecksum" in dumped
    assert "hasDocument" in dumped
    assert dumped["hasDocument"] is False


@pytest.mark.unit
def test_record_detail_create_validation():
    """Verify RecordDetailCreate validates required vs optional attributes."""
    create_dto = RecordDetailCreate(
        record_id="rec-abc",
        patient_id="pat-xyz",
        description="Mild allergic rhinitis",
        has_document=False
    )
    assert create_dto.record_id == "rec-abc"
    assert create_dto.patient_id == "pat-xyz"
    assert create_dto.prescription_cid is None
    assert create_dto.prescription_filename is None


@pytest.mark.unit
def test_record_upload_response_composite():
    """Verify RecordUploadResponse contains both MedicalRecord and RecordDetailResponse."""
    med_rec = MedicalRecord(
        id="rec-99",
        patient_id="pat-99",
        patient_name="John Doe",
        title="Checkup Summary",
        record_type=RecordType.CLINICAL_SUMMARY,
        ipfs_cid="bafk999",
        file_size="10 KB",
        mime_type="application/pdf",
        created_at="2026-10-22T10:00:00Z",
        hospital="City Clinic",
        key_fingerprint="SHA256:abc"
    )
    detail_dto = RecordDetailResponse(
        id="det-99",
        record_id="rec-99",
        patient_id="pat-99",
        description="Self-reported fever",
        has_document=True,
        created_at="2026-10-22T10:00:00Z"
    )

    upload_res = RecordUploadResponse(
        success=True,
        record=med_rec,
        details=detail_dto
    )
    dumped = upload_res.model_dump(by_alias=True)

    assert dumped["success"] is True
    assert dumped["record"]["id"] == "rec-99"
    assert dumped["details"]["description"] == "Self-reported fever"
    assert dumped["details"]["hasDocument"] is True
