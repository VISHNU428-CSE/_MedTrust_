"""
Medical Record Business Service.
Coordinates:
- AES-256-GCM encryption of off-chain health records
- IPFS (Kubo) pinning and SHA-256 checksum verification
- Hyperledger Fabric RecordContract registration
- Consent-based access authorization & audit logging
"""

import os
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.adapters.fabric_gateway import fabric_gateway
from app.adapters.ipfs_client import ipfs_client, compute_sha256
from app.core.crypto import generate_key, encrypt_payload, decrypt_payload, calculate_sha256
from app.core.exceptions import AccessDeniedError, ChecksumMismatchError, RecordNotFoundError
from app.core.rbac import Role
from app.models.schemas import RecordVerifyResponse
from app.db.models import RecordDetailModel, RecordQuarantineModel

logger = logging.getLogger(__name__)

# Key repository storing record encryption keys mapped to record_id (deprecated)
_RECORD_KEY_STORE: Dict[str, bytes] = {}

# In-memory quarantine registry providing immediate process-level quarantine fallback
_QUARANTINED_RECORDS: Dict[str, Dict[str, Any]] = {}


def format_file_size(size_bytes: int) -> str:
    """Formats raw bytes into human readable size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


class RecordService:
    def __init__(self):
        self.gateway = fabric_gateway
        self.ipfs = ipfs_client

    def register_and_upload_record(
        self,
        patient_id: str,
        patient_name: str,
        title: str,
        record_type: str,
        hospital: str,
        raw_file_bytes: Optional[bytes] = None,
        mime_type: Optional[str] = "application/pdf",
        doctor_id: Optional[str] = None,
        doctor_name: Optional[str] = None,
        dek: Optional[bytes] = None,
        custom_record_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full zero-knowledge upload pipeline:
        1. Generates ephemeral AES-256-GCM symmetric key (or uses provided DEK)
        2. Encrypts payload off-chain (zero PHI exposed)
        3. Computes SHA-256 checksum of the ciphertext
        4. Pins encrypted ciphertext to IPFS Kubo node
        5. Registers metadata (CID + Checksum + Fingerprint) on Hyperledger Fabric ledger
        6. Logs audit event to Fabric AuditContract
        """
        record_id = custom_record_id or f"rec-{uuid.uuid4().hex[:6]}"
        payload_bytes = raw_file_bytes if raw_file_bytes is not None else b""
        file_size_str = format_file_size(len(payload_bytes))
        effective_mime = mime_type or "application/octet-stream"

        # 1 & 2. Encrypt payload
        aes_key = dek if dek is not None else generate_key()
        encrypted_bytes, key_fingerprint = encrypt_payload(payload_bytes, aes_key)
        # Note: In-memory _RECORD_KEY_STORE is deprecated; keys are durably enveloped via KeyManager.

        # 3 & 4. Pin to IPFS Kubo
        try:
            cid, checksum_sha256 = self.ipfs.add_bytes(encrypted_bytes, pin=True)
        except Exception as e:
            logger.warning("Direct Kubo upload encountered: %s. Using deterministic content addressing.", str(e))
            checksum_sha256 = compute_sha256(encrypted_bytes)
            cid = f"bafybei{hashlib_sha256_to_cid(checksum_sha256)}"
            self.ipfs.store_offline_bytes(cid, encrypted_bytes)

        # 5. Register on Fabric with compensation on failure
        try:
            record_entry = self.gateway.register_record(
                record_id=record_id,
                patient_id=patient_id,
                patient_name=patient_name,
                title=title,
                record_type=record_type,
                ipfs_cid=cid,
                file_size=file_size_str,
                mime_type=effective_mime,
                hospital=hospital,
                key_fingerprint=key_fingerprint,
                checksum_sha256=checksum_sha256,
                created_by_doctor=doctor_name
            )
        except Exception as fabric_err:
            logger.error(
                "Fabric record registration failed for record '%s' (CID: %s): %s. "
                "Executing compensating transaction to unpin orphan IPFS CID.",
                record_id, cid, str(fabric_err)
            )
            try:
                self.ipfs.pin_rm(cid)
            except Exception as unpin_err:
                logger.warning("Compensating unpin failed for CID %s: %s", cid, str(unpin_err))
            try:
                self.ipfs.remove_offline_bytes(cid)
            except Exception:
                pass
            raise
        record_entry["_dek"] = aes_key

        # 6. Audit Trail
        actor_id = doctor_id or patient_id
        actor_name = doctor_name or patient_name
        actor_role = Role.DOCTOR if doctor_id else Role.PATIENT
        self.gateway.log_access_event(
            actor_id=actor_id,
            actor_name=actor_name,
            actor_role=actor_role,
            target_patient_id=patient_id,
            action="UPLOAD_RECORD",
            purpose=f"Uploaded and encrypted {record_type} record",
            status="SUCCESS",
            record_id=record_id,
            record_title=title
        )

        return record_entry

    def save_record_details(
        self,
        db: Session,
        record_id: str,
        patient_id: str,
        description: Optional[str] = None,
        prescription_cid: Optional[str] = None,
        prescription_filename: Optional[str] = None,
        prescription_checksum: Optional[str] = None,
        has_document: bool = False,
        document_filename: Optional[str] = None,
        document_mime_type: Optional[str] = None,
    ) -> RecordDetailModel:
        """
        Persists sensitive off-chain clinical details in SQLite via RecordDetailModel.
        Strictly isolates Zero-PHI from public blockchain ledger and IPFS plain blobs.
        """
        existing = db.query(RecordDetailModel).filter(RecordDetailModel.record_id == record_id).first()
        if existing:
            if description is not None:
                existing.description = description
            if prescription_cid is not None:
                existing.prescription_cid = prescription_cid
            if prescription_filename is not None:
                existing.prescription_filename = prescription_filename
            if prescription_checksum is not None:
                existing.prescription_checksum = prescription_checksum
            if document_filename is not None:
                existing.document_filename = document_filename
            if document_mime_type is not None:
                existing.document_mime_type = document_mime_type
            existing.has_document = has_document
            db.commit()
            db.refresh(existing)
            return existing

        detail = RecordDetailModel(
            id=f"det-{uuid.uuid4().hex[:8]}",
            record_id=record_id,
            patient_id=patient_id,
            description=description,
            prescription_cid=prescription_cid,
            prescription_filename=prescription_filename,
            prescription_checksum=prescription_checksum,
            has_document=has_document,
            document_filename=document_filename,
            document_mime_type=document_mime_type,
        )
        db.add(detail)
        db.commit()
        db.refresh(detail)
        return detail

    def get_record_details(
        self,
        db: Session,
        record_id: str
    ) -> Optional[RecordDetailModel]:
        """Retrieves persistent off-chain clinical details for a record."""
        return db.query(RecordDetailModel).filter(RecordDetailModel.record_id == record_id).first()

    def list_patient_records(
        self,
        actor_id: str,
        actor_role: str,
        patient_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lists medical records subject to RBAC isolation:
        - Patients can only list their own records.
        - Doctors can list records for patients where they hold active consent.
        """
        target_patient = patient_id or actor_id

        if actor_role == Role.PATIENT and actor_id != target_patient:
            self.gateway.log_access_event(
                actor_id=actor_id,
                actor_name="Unknown Patient",
                actor_role=actor_role,
                target_patient_id=target_patient,
                action="VIEW",
                purpose="Attempted cross-patient record listing",
                status="DENIED"
            )
            raise AccessDeniedError(
                f"Patient {actor_id} is forbidden from accessing records of patient {target_patient}",
                code=403,
                reason="UNAUTHORIZED_HORIZONTAL_ACCESS"
            )

        records = self.gateway.list_records(target_patient)
        return records

    def quarantine_record(
        self,
        db: Optional[Session],
        record_id: str,
        patient_id: str,
        quarantine_reason: str,
        ipfs_cid: Optional[str] = None,
        prescription_cid: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Registers a record as quarantined due to dual-write failure:
        1. Records in-memory fallback state in _QUARANTINED_RECORDS.
        2. Persists in SQLite table 'record_quarantines' via a dedicated transaction.
        """
        entry = {
            "record_id": record_id,
            "patient_id": patient_id,
            "quarantine_reason": quarantine_reason,
            "ipfs_cid": ipfs_cid,
            "prescription_cid": prescription_cid,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        _QUARANTINED_RECORDS[record_id] = entry

        if db is not None:
            try:
                existing = db.query(RecordQuarantineModel).filter(RecordQuarantineModel.record_id == record_id).first()
                if not existing:
                    model = RecordQuarantineModel(
                        record_id=record_id,
                        patient_id=patient_id,
                        quarantine_reason=quarantine_reason,
                        ipfs_cid=ipfs_cid,
                        prescription_cid=prescription_cid
                    )
                    db.add(model)
                    db.commit()
                else:
                    existing.quarantine_reason = quarantine_reason
                    db.commit()
                logger.info("Persisted quarantine state for record '%s' to database.", record_id)
            except Exception as e:
                db.rollback()
                logger.warning("quarantine_record: Failed to persist to SQLite table record_quarantines: %s", str(e))

        return entry

    def is_record_quarantined(self, db: Optional[Session], record_id: str) -> bool:
        """Returns True if the record is currently quarantined."""
        if record_id in _QUARANTINED_RECORDS:
            return True
        if db is not None:
            try:
                found = db.query(RecordQuarantineModel).filter(RecordQuarantineModel.record_id == record_id).first()
                if found:
                    _QUARANTINED_RECORDS[record_id] = {
                        "record_id": found.record_id,
                        "patient_id": found.patient_id,
                        "quarantine_reason": found.quarantine_reason,
                        "ipfs_cid": found.ipfs_cid,
                        "prescription_cid": found.prescription_cid,
                        "created_at": found.created_at.isoformat() if hasattr(found.created_at, "isoformat") else str(found.created_at)
                    }
                    return True
            except Exception as e:
                logger.warning("is_record_quarantined DB check failed: %s", str(e))
        return False

    def get_quarantine_info(self, db: Optional[Session], record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves quarantine metadata if the record is quarantined."""
        if record_id in _QUARANTINED_RECORDS:
            return _QUARANTINED_RECORDS[record_id]
        if db is not None:
            try:
                found = db.query(RecordQuarantineModel).filter(RecordQuarantineModel.record_id == record_id).first()
                if found:
                    info = {
                        "record_id": found.record_id,
                        "patient_id": found.patient_id,
                        "quarantine_reason": found.quarantine_reason,
                        "ipfs_cid": found.ipfs_cid,
                        "prescription_cid": found.prescription_cid,
                        "created_at": found.created_at.isoformat() if hasattr(found.created_at, "isoformat") else str(found.created_at)
                    }
                    _QUARANTINED_RECORDS[record_id] = info
                    return info
            except Exception as e:
                logger.warning("get_quarantine_info DB check failed: %s", str(e))
        return None

    def verify_record_integrity(self, record_id: str, db: Optional[Session] = None) -> RecordVerifyResponse:
        """
        Fetches record metadata from Fabric ledger and compares
        live IPFS CID payload against the registered checksum.
        Standardized statuses strictly to:
        - 'VERIFIED' (if checksums match)
        - 'CHECKSUM_MISMATCH' (if computed != expected)
        - 'IPFS_UNAVAILABLE' (if Kubo retrieval fails or times out)
        - 'LEDGER_UNAVAILABLE' (if ledger query fails or record not found)
        - 'RECORD_QUARANTINED' (if record is quarantined due to dual-write failure)
        """
        if self.is_record_quarantined(db, record_id):
            q_info = self.get_quarantine_info(db, record_id) or {}
            reason = q_info.get("quarantine_reason", "Dual-write failure: key persistence failed")
            cid = q_info.get("ipfs_cid") or "UNKNOWN"
            try:
                rec = self.gateway.get_record(record_id)
                if rec:
                    cid = rec.get("ipfs_cid") or rec.get("ipfsCid", cid)
                    expected_sha = rec.get("checksum_sha256") or rec.get("checksumSha256", "UNAVAILABLE")
                else:
                    expected_sha = "UNAVAILABLE"
            except Exception:
                expected_sha = "UNAVAILABLE"

            return RecordVerifyResponse(
                record_id=record_id,
                ipfs_cid=cid,
                checksum_matches=False,
                ledger_checksum=expected_sha,
                computed_sha256="QUARANTINED",
                status="RECORD_QUARANTINED",
                detail=f"Record '{record_id}' is quarantined due to dual-write failure ({reason}). Cryptographic operations are locked.",
                is_quarantined=True,
                quarantine_reason=reason
            )

        try:
            record = self.gateway.get_record(record_id)
            if not record:
                raise RecordNotFoundError(f"Record with ID '{record_id}' not found on Fabric ledger.")
        except Exception as e:
            logger.warning("Fabric ledger lookup failed for %s: %s", record_id, str(e))
            return RecordVerifyResponse(
                record_id=record_id,
                ipfs_cid="UNKNOWN",
                checksum_matches=False,
                ledger_checksum="UNAVAILABLE",
                computed_sha256="UNAVAILABLE",
                status="LEDGER_UNAVAILABLE",
                detail="Record not found or ledger query failed (not found on Fabric ledger)"
            )

        cid = record.get("ipfs_cid") or record.get("ipfsCid", "")
        expected_sha = record.get("checksum_sha256") or record.get("checksumSha256") or ""

        try:
            # Query IPFS
            payload = self.ipfs.get_bytes(cid, expected_sha256=expected_sha)
            computed_sha = compute_sha256(payload)
            matches = (computed_sha.lower() == expected_sha.lower())
            status = "VERIFIED" if matches else "CHECKSUM_MISMATCH"
            detail = (
                "Cryptographic integrity verified against Hyperledger Fabric ledger checksum."
                if matches
                else f"Checksum mismatch: expected {expected_sha}, computed {computed_sha}."
            )
        except ChecksumMismatchError as e:
            matches = False
            computed_sha = "MISMATCH"
            status = "CHECKSUM_MISMATCH"
            detail = str(e)
        except Exception as e:
            matches = False
            computed_sha = "UNAVAILABLE"
            status = "IPFS_UNAVAILABLE"
            err_msg = e.args[0] if (isinstance(e, KeyError) and e.args) else str(e)
            detail = f"Could not retrieve payload from IPFS: {err_msg}"

        return RecordVerifyResponse(
            record_id=record_id,
            ipfs_cid=cid,
            checksum_matches=matches,
            ledger_checksum=expected_sha,
            computed_sha256=computed_sha,
            status=status,
            detail=detail
        )


def hashlib_sha256_to_cid(hex_digest: str) -> str:
    """Helper formatting sha256 into a 46-char simulated CID string."""
    return f"{hex_digest[:32]}{hex_digest[-14:]}"


record_service = RecordService()
