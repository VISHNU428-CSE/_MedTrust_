"""
SQLAlchemy ORM models for MedTrust Authentication and Sessions.
Persistent storage: SQLite (medtrust.db).
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text, UniqueConstraint, Index
from sqlalchemy.orm import relationship

from app.db.session import Base


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False)  # PATIENT, DOCTOR, AUDITOR, ADMIN
    password_hash = Column(String(512), nullable=False)
    hospital = Column(String(255), nullable=True)
    specialty = Column(String(255), nullable=True)
    license_number = Column(String(128), nullable=True)
    approval_status = Column(String(32), default="PENDING", nullable=False)  # PENDING, APPROVED, REJECTED
    applied_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by = Column(String(64), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    sessions = relationship("UserSessionModel", back_populates="user", cascade="all, delete-orphan")


class UserSessionModel(Base):
    __tablename__ = "user_sessions"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_jti = Column(String(128), unique=True, index=True, nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)

    user = relationship("UserModel", back_populates="sessions")


class RecordDetailModel(Base):
    """
    Protected persistent storage for sensitive patient clinical submissions:
    - Symptom / health concern descriptions (off-chain, patient-scoped)
    - Prescription attachment references (IPFS CID, checksum, filename)
    Strictly isolated from public blockchain and public IPFS metadata.
    """
    __tablename__ = "record_details"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    record_id = Column(String(64), unique=True, index=True, nullable=False)
    patient_id = Column(String(64), index=True, nullable=False)
    description = Column(Text, nullable=True)
    prescription_cid = Column(String(128), nullable=True)
    prescription_filename = Column(String(255), nullable=True)
    prescription_checksum = Column(String(64), nullable=True)
    has_document = Column(Boolean, default=False, nullable=False)
    document_filename = Column(String(255), nullable=True)
    document_mime_type = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class RecordKeyModel(Base):
    """
    Persistent key store for enveloped Data Encryption Keys (DEKs).
    Stores DEKs wrapped by the Master Key Encryption Key (KEK) using AES-256-GCM.
    
    Composite uniqueness: (record_id, purpose) and (record_id, target_type) ensures distinct key
    management for primary document versus prescription attachments.
    Anti-cascade retention: Independent lifecycle prevents accidental cryptographic destruction.
    Strict Zero-PHI: Plaintext DEKs are NEVER persisted.
    """
    __tablename__ = "record_keys"

    id = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    record_id = Column(String(64), index=True, nullable=False)
    patient_id = Column(String(64), index=True, nullable=False)
    purpose = Column(String(32), nullable=False, default="PRIMARY_DOCUMENT")  # PRIMARY_DOCUMENT | PRESCRIPTION
    target_type = Column(String(32), nullable=False, default="record")  # 'record' | 'prescription'
    encrypted_dek = Column(Text, nullable=False)  # Hex or base64 wrapped DEK ciphertext
    dek_nonce = Column(String(64), nullable=False)  # 96-bit CSPRNG nonce
    dek_tag = Column(String(64), nullable=False)  # 128-bit authentication tag
    kek_version = Column(String(32), nullable=False, default="v1")  # Master KEK version identifier
    key_fingerprint = Column(String(128), nullable=True)  # SHA-256 fingerprint for verification/audit
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        UniqueConstraint("record_id", "purpose", name="uq_record_keys_record_purpose"),
        UniqueConstraint("record_id", "target_type", name="uq_record_keys_record_target"),
        Index("ix_record_keys_record_target", "record_id", "target_type"),
        Index("ix_record_keys_patient_record", "patient_id", "record_id"),
    )

    def __init__(self, **kwargs):
        p = kwargs.get("purpose")
        t = kwargs.get("target_type")
        if p is not None and t is None:
            kwargs["target_type"] = "prescription" if str(p).upper() == "PRESCRIPTION" else "record"
        elif t is not None and p is None:
            kwargs["purpose"] = "PRESCRIPTION" if str(t).upper() == "PRESCRIPTION" else "PRIMARY_DOCUMENT"
        elif p is None and t is None:
            kwargs["purpose"] = "PRIMARY_DOCUMENT"
            kwargs["target_type"] = "record"
        super().__init__(**kwargs)


class RecordQuarantineModel(Base):
    """
    Persistent quarantine registry for records that suffered dual-write failure:
    - Fabric ledger committed the immutable record
    - Local key or clinical detail persistence failed
    Quarantined records are locked from download/decryption and flagged in listing/verification.
    Zero-PHI: Never stores plain health records or unencrypted DEKs.
    """
    __tablename__ = "record_quarantines"

    record_id = Column(String(64), primary_key=True)
    patient_id = Column(String(64), index=True, nullable=False)
    quarantine_reason = Column(Text, nullable=False)
    ipfs_cid = Column(String(128), nullable=True)
    prescription_cid = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)



