"""
Pydantic schemas for MedTrust API.
Maintains camelCase serialization compatibility with Frontend and strict validation.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Union, Any
from pydantic import BaseModel, ConfigDict, field_validator
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )

    def __getitem__(self, item: str) -> Any:
        if hasattr(self, item):
            return getattr(self, item)
        import re
        snake = re.sub(r'(?<!^)(?=[A-Z])', '_', item).lower()
        if hasattr(self, snake):
            return getattr(self, snake)
        raise KeyError(item)

    def __contains__(self, item: str) -> bool:
        if hasattr(self, item):
            return True
        import re
        snake = re.sub(r'(?<!^)(?=[A-Z])', '_', item).lower()
        return hasattr(self, snake)

    def get(self, item: str, default: Any = None) -> Any:
        try:
            return self[item]
        except KeyError:
            return default


class UserRole(str, Enum):
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


class RecordType(str, Enum):
    LAB_REPORT = "LAB_REPORT"
    PRESCRIPTION = "PRESCRIPTION"
    IMAGING_MRI = "IMAGING_MRI"
    IMAGING_XRAY = "IMAGING_XRAY"
    CLINICAL_SUMMARY = "CLINICAL_SUMMARY"
    GENOMIC_DATA = "GENOMIC_DATA"


class ConsentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    APPROVED = "APPROVED"
    PENDING = "PENDING"
    REVOKED = "REVOKED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class DoctorApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AccessAction(str, Enum):
    VIEW = "VIEW"
    DOWNLOAD = "DOWNLOAD"
    REQUEST_CONSENT = "REQUEST_CONSENT"
    REVOKE_CONSENT = "REVOKE_CONSENT"
    GRANT_CONSENT = "GRANT_CONSENT"
    UPLOAD_RECORD = "UPLOAD_RECORD"
    UPDATE_USER_STATUS = "UPDATE_USER_STATUS"
    VERIFY_RECORD = "VERIFY_RECORD"


# --- User & Auth Models ---

class UserProfile(CamelModel):
    id: str
    name: str
    role: UserRole
    email: str
    hospital: Optional[str] = None
    specialty: Optional[str] = None
    license_number: Optional[str] = None
    approval_status: Optional[str] = None


class UserLoginRequest(CamelModel):
    email: str
    password: str


class UserRegisterRequest(CamelModel):
    id: Optional[str] = None
    name: str
    email: str
    password: str
    role: UserRole = UserRole.PATIENT
    hospital: Optional[str] = None
    specialty: Optional[str] = None


class DoctorApplicationCreate(CamelModel):
    name: str
    email: str
    password: str
    hospital: str
    specialty: str
    license_number: str


class DoctorApplicationResponse(CamelModel):
    id: str
    name: str
    email: str
    role: UserRole = UserRole.DOCTOR
    hospital: Optional[str] = None
    specialty: Optional[str] = None
    license_number: str
    approval_status: DoctorApprovalStatus
    applied_at: Optional[str] = None
    message: str = "Doctor application submitted successfully. Your credentials are under administrative review."


class DoctorApplicationSummary(CamelModel):
    id: str
    name: str
    email: str
    role: UserRole = UserRole.DOCTOR
    hospital: Optional[str] = None
    specialty: Optional[str] = None
    license_number: Optional[str] = None
    approval_status: str
    is_active: bool
    applied_at: Optional[str] = None
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    rejection_reason: Optional[str] = None


class DoctorApplicationRejectRequest(CamelModel):
    reason: str


class DoctorApplicationActionResponse(CamelModel):
    success: bool
    id: str
    name: str
    email: str
    approval_status: str
    is_active: bool
    reviewed_by: str
    reviewed_at: str
    rejection_reason: Optional[str] = None
    message: str


class TokenResponse(CamelModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile


class UserSummary(CamelModel):
    id: str
    name: str
    email: str
    role: UserRole
    hospital: Optional[str] = None
    specialty: Optional[str] = None
    license_number: Optional[str] = None
    approval_status: Optional[str] = None
    is_active: bool
    created_at: Optional[str] = None


class UserStatusUpdate(CamelModel):
    is_active: Optional[bool] = None
    status: Optional[str] = None

    @property
    def active_value(self) -> bool:
        if self.is_active is not None:
            return bool(self.is_active)
        if self.status is not None:
            return self.status.upper() in ("ACTIVE", "ENABLED", "TRUE")
        return True


class PasswordRecoveryRequest(CamelModel):
    email: str


class PasswordRecoveryResponse(CamelModel):
    success: bool
    message: str


# --- Medical Record Models ---

class MedicalRecord(CamelModel):
    id: str
    patient_id: str
    patient_name: str = "Patient"
    title: str = "Medical Record"
    record_type: Union[RecordType, str] = "CLINICAL_SUMMARY"
    ipfs_cid: str
    file_size: str = "1.0 MB"
    mime_type: str = "application/pdf"
    created_at: str = ""
    created_by_doctor: Optional[str] = None
    hospital: str = "Metro General Hospital"
    encryption_algorithm: str = "AES-256-GCM"
    key_fingerprint: str = "SHA256:UNKNOWN"
    checksum_sha256: Optional[str] = None
    is_quarantined: Optional[bool] = False
    quarantine_reason: Optional[str] = None


class RecordDetailResponse(CamelModel):
    id: str
    record_id: str
    patient_id: str
    description: Optional[str] = None
    prescription_cid: Optional[str] = None
    prescription_filename: Optional[str] = None
    prescription_checksum: Optional[str] = None
    has_document: bool = False
    document_filename: Optional[str] = None
    document_mime_type: Optional[str] = None
    created_at: str

    @field_validator("created_at", mode="before")
    @classmethod
    def serialize_created_at(cls, v: Any) -> str:
        if hasattr(v, "isoformat"):
            return v.isoformat()
        return str(v)

    @classmethod
    def from_orm_model(cls, model: Any) -> "RecordDetailResponse":
        created = getattr(model, "created_at", None)
        if hasattr(created, "isoformat"):
            created_str = created.isoformat()
        elif created is not None:
            created_str = str(created)
        else:
            created_str = datetime.now(timezone.utc).isoformat()

        return cls(
            id=model.id,
            record_id=model.record_id,
            patient_id=model.patient_id,
            description=model.description,
            prescription_cid=model.prescription_cid,
            prescription_filename=model.prescription_filename,
            prescription_checksum=model.prescription_checksum,
            has_document=bool(model.has_document),
            document_filename=getattr(model, "document_filename", None),
            document_mime_type=getattr(model, "document_mime_type", None),
            created_at=created_str
        )


class RecordDetailCreate(CamelModel):
    record_id: str
    patient_id: str
    description: Optional[str] = None
    prescription_cid: Optional[str] = None
    prescription_filename: Optional[str] = None
    prescription_checksum: Optional[str] = None
    has_document: bool = False
    document_filename: Optional[str] = None
    document_mime_type: Optional[str] = None


class RecordUploadResponse(CamelModel):
    success: bool
    record: Optional[MedicalRecord] = None
    details: Optional[RecordDetailResponse] = None
    error: Optional[str] = None


class RecordVerifyResponse(CamelModel):
    record_id: str
    ipfs_cid: str
    checksum_matches: bool
    ledger_checksum: str
    computed_sha256: str
    status: str
    detail: str
    is_quarantined: Optional[bool] = False
    quarantine_reason: Optional[str] = None


# --- Consent Models ---

class ConsentRecord(CamelModel):
    id: str
    patient_id: str
    doctor_id: str
    doctor_name: str = "Doctor"
    hospital: str = "Metro General Hospital"
    specialty: str = "General Practice"
    purpose: str = ""
    status: ConsentStatus
    allowed_record_types: Union[List[Union[RecordType, str]], str] = ["ALL"]
    granted_at: str
    expires_at: str
    tx_hash: str = ""


class ConsentRequestPayload(CamelModel):
    patient_id: str
    doctor_id: Optional[str] = None
    purpose: str
    duration_days: int = 30
    allowed_record_types: List[Union[RecordType, str]]
    consent_id: Optional[str] = None


class ConsentActionResponse(CamelModel):
    success: bool
    tx_hash: Optional[str] = None
    id: Optional[str] = None
    error: Optional[str] = None


class ConsentVerifyResponse(CamelModel):
    allowed: bool
    reason: str
    consent_id: Optional[str] = None


# --- Audit Models ---

class AccessLog(CamelModel):
    id: str
    timestamp: str
    actor_id: str
    actor_name: str
    actor_role: Union[UserRole, str]
    action: Union[AccessAction, str]
    record_id: Optional[str] = None
    record_title: Optional[str] = None
    purpose: str
    tx_hash: str
    status: str  # SUCCESS | DENIED
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None
    detail: Optional[str] = None
    target_patient_id: Optional[str] = None


# --- Health & Diagnostic Models ---

class HealthResponse(CamelModel):
    online: bool = True
    version: str
    status: str = "healthy"
    ipfs_status: str
    fabric_status: str
