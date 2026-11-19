"""
Medical Record Endpoints.
Handles encrypted document ingestion, IPFS pinning,
ledger registration, and record queries with strict RBAC enforcement.
"""

import logging
import mimetypes
import os
import re
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import quote
from fastapi import APIRouter, HTTPException, Depends, Query, Form, UploadFile, File, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.models.schemas import MedicalRecord, RecordVerifyResponse, RecordDetailResponse, UserProfile, UserRole
from app.services.record_service import record_service, hashlib_sha256_to_cid
from app.adapters.fabric_gateway import fabric_gateway
from app.adapters.ipfs_client import ipfs_client, compute_sha256
from app.core.crypto import generate_key, encrypt_payload, decrypt_payload, wrap_dek, unwrap_dek, get_master_kek
from app.core.exceptions import AccessDeniedError, RecordNotFoundError, EncryptionError, ChecksumMismatchError, IPFSConnectionError, FabricGatewayError
from app.services.key_service import KeyManager, KeyPurpose, KeyConflictError, KeyConfigurationError, KeyNotFoundError, KeyUnwrapError, KeyManagementError
from app.api.deps import get_current_user
from app.db.session import get_db
from app.db.models import UserModel, RecordDetailModel, RecordKeyModel

logger = logging.getLogger(__name__)

router = APIRouter()


def _safe_log_access_event(**kwargs):
    """Logs an access or audit event to Fabric without letting audit infrastructure failures mask denials."""
    try:
        fabric_gateway.log_access_event(**kwargs)
    except Exception as log_err:
        logger.warning("Failed to record access audit event to Fabric ledger: %s", str(log_err))


def _annotate_quarantine_info(records: List[Dict[str, Any]], db: Session) -> List[Dict[str, Any]]:
    """Annotates record dictionaries with quarantine status and diagnostic reason."""
    for rec in records:
        rec_id = rec.get("id")
        if rec_id and record_service.is_record_quarantined(db, rec_id):
            rec["is_quarantined"] = True
            q_info = record_service.get_quarantine_info(db, rec_id) or {}
            rec["quarantine_reason"] = q_info.get("quarantine_reason")
        else:
            rec["is_quarantined"] = False
            rec["quarantine_reason"] = None
    return records


MIME_TO_EXTENSION = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "application/pdf": ".pdf",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "application/dicom": ".dcm",
    "application/zip": ".zip",
    "text/plain": ".txt",
    "application/json": ".json",
}


def _detect_magic_mime_and_ext(data: bytes) -> tuple[Optional[str], Optional[str]]:
    """Detect MIME type and file extension directly from binary magic bytes."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", ".png"
    if data.startswith(b"%PDF-"):
        return "application/pdf", ".pdf"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", ".jpg"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "image/webp", ".webp"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif", ".gif"
    if len(data) > 132 and data[128:132] == b"DICM":
        return "application/dicom", ".dcm"
    if data.startswith(b"PK\x03\x04"):
        return "application/zip", ".zip"
    return None, None


def _build_download_response(
    data: bytes,
    record_id: str,
    default_prefix: str,
    declared_filename: Optional[str] = None,
    declared_mime: Optional[str] = None
) -> Response:
    """
    Constructs a standards-compliant file download response.
    Preserves exact original filename and MIME type where available.
    Falls back to binary magic byte inspection and RFC 5987 / RFC 6266 Content-Disposition headers.
    """
    magic_mime, magic_ext = _detect_magic_mime_and_ext(data)

    # 1. Determine effective MIME type
    if magic_mime:
        effective_mime = magic_mime
    elif declared_mime and declared_mime != "application/octet-stream":
        effective_mime = declared_mime
    elif declared_filename:
        guessed_type, _ = mimetypes.guess_type(declared_filename)
        effective_mime = guessed_type or "application/octet-stream"
    else:
        effective_mime = "application/octet-stream"

    # 2. Determine resolved filename
    if declared_filename and declared_filename.strip():
        clean_name = os.path.basename(declared_filename).strip()
        clean_name = re.sub(r'[\r\n"\\/*?:"<>|]', '_', clean_name)
        root, ext = os.path.splitext(clean_name)
        expected_ext = magic_ext or MIME_TO_EXTENSION.get(effective_mime.lower())
        if not ext and expected_ext:
            clean_name = f"{root}{expected_ext}"
        filename = clean_name
    else:
        ext = magic_ext or MIME_TO_EXTENSION.get(effective_mime.lower(), ".bin")
        filename = f"{record_id}_{default_prefix}{ext}"

    # 3. Build RFC 5987 / RFC 6266 Content-Disposition header
    safe_ascii_name = re.sub(r'[^\w\.\-]', '_', filename)
    if not safe_ascii_name:
        safe_ascii_name = f"{record_id}_{default_prefix}.bin"
    encoded_utf8_name = quote(filename, safe='')
    content_disposition = f'attachment; filename="{safe_ascii_name}"; filename*=UTF-8\'\'{encoded_utf8_name}'

    return Response(
        content=data,
        media_type=effective_mime,
        headers={
            "Content-Disposition": content_disposition,
            "Content-Length": str(len(data)),
            "Content-Type": effective_mime
        }
    )


@router.get("", response_model=List[MedicalRecord])
def get_records(
    patient_id: Optional[str] = Query(None),
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves medical records.
    - Patient: only allowed to view their own records (horizontal isolation).
    - Doctor: allowed to view patient records subject to consent.
    - Admin: STRICT PRIVACY BOUNDARY. Administrators are strictly prohibited from viewing medical records.
    - Auditor: allowed to query for compliance auditing.
    """
    if current_user.role == UserRole.ADMIN:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value,
            action="VIEW",
            purpose="Administrative attempt to access confidential medical records blocked",
            status="DENIED",
            target_patient_id=patient_id or "ALL"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators are strictly prohibited from viewing patient medical records."
        )

    # Enforce doctor authorization and consent scoping
    if current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VIEW",
                purpose=f"Unapproved doctor attempt to query clinical records blocked (status: {status_val})",
                status="DENIED",
                target_patient_id=patient_id or "ALL"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )

        if patient_id:
            consents = [
                c for c in fabric_gateway.list_consents(patient_id)
                if c.get("doctor_id") == current_user.id and c.get("status") == "ACTIVE"
            ]
            if not consents:
                fabric_gateway.log_access_event(
                    actor_id=current_user.id,
                    actor_name=current_user.name,
                    actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                    action="VIEW",
                    purpose=f"Doctor attempt to list records of patient {patient_id} denied: no active consent",
                    status="DENIED",
                    target_patient_id=patient_id
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access denied: Doctor does not have active consent to access records for patient '{patient_id}'."
                )

            raw_records = fabric_gateway.list_records(patient_id)
            allowed_records = []
            for rec in raw_records:
                rec_type = rec.get("record_type") or rec.get("recordType", "CLINICAL_SUMMARY")
                res = fabric_gateway.verify_consent(
                    doctor_id=current_user.id,
                    patient_id=patient_id,
                    record_type=rec_type
                )
                if res.get("allowed", False):
                    allowed_records.append(rec)
            return _annotate_quarantine_info(allowed_records, db)
        else:
            # Doctor omitted patient_id: prevent global listing of unconsented patient records
            all_consents = fabric_gateway.list_consents()
            active_patient_ids = set(
                c.get("patient_id") for c in all_consents
                if c.get("doctor_id") == current_user.id and c.get("status") == "ACTIVE"
            )
            allowed_records = []
            for pid in active_patient_ids:
                for rec in fabric_gateway.list_records(pid):
                    rec_type = rec.get("record_type") or rec.get("recordType", "CLINICAL_SUMMARY")
                    res = fabric_gateway.verify_consent(
                        doctor_id=current_user.id,
                        patient_id=pid,
                        record_type=rec_type
                    )
                    if res.get("allowed", False):
                        allowed_records.append(rec)
            return _annotate_quarantine_info(allowed_records, db)

    target_patient = patient_id or (current_user.id if current_user.role == UserRole.PATIENT else None)

    # Enforce horizontal RBAC for patients
    if current_user.role == UserRole.PATIENT and target_patient and current_user.id != target_patient:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value,
            action="VIEW",
            purpose=f"Unauthorized horizontal attempt to list records of {target_patient}",
            status="DENIED",
            target_patient_id=target_patient
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Horizontal Access Denied: Patient '{current_user.id}' cannot access records belonging to '{target_patient}'."
        )

    records = fabric_gateway.list_records(target_patient)
    return _annotate_quarantine_info(records, db)


@router.post("/upload", response_model=MedicalRecord)
async def upload_record(
    patient_id: str = Form(...),
    patient_name: Optional[str] = Form(None),
    title: str = Form(...),
    record_type: str = Form(...),
    hospital: str = Form(...),
    file: Optional[UploadFile] = File(None),
    description: Optional[str] = Form(None),
    prescription_file: Optional[UploadFile] = File(None),
    record_id: Optional[str] = Form(None),
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Ingests and securely uploads a medical record with multi-input support:
    - Accepts optional document file, optional clinical description, and optional prescription attachment
    - Validates that at least one of (file, description, prescription_file) is provided
    - Encrypts payloads with AES-256-GCM (Zero-PHI on storage & ledger)
    - Pins ciphertext to IPFS Kubo
    - Records metadata & SHA-256 integrity checksum on Hyperledger Fabric ledger
    - Persists protected clinical details off-chain in SQLite via RecordDetailModel
    """
    if current_user.role == UserRole.ADMIN:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="UPLOAD_RECORD",
            purpose="Administrative attempt to upload medical record blocked (Healthcare Privacy Boundary)",
            status="DENIED",
            target_patient_id=patient_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators cannot upload confidential patient medical records."
        )

    # 1. Validate target patient exists in platform records
    db_patient = db.query(UserModel).filter(UserModel.id == patient_id).first()
    if not db_patient or (db_patient.role != "PATIENT" and db_patient.role != UserRole.PATIENT.value):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target patient '{patient_id}' not found in platform records."
        )

    # 2. Prevent patients from uploading under another patient's ID
    if current_user.role == UserRole.PATIENT:
        if current_user.id != patient_id:
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="UPLOAD_RECORD",
                purpose=f"Horizontal upload violation: Patient {current_user.id} attempted to upload record for {patient_id}",
                status="DENIED",
                target_patient_id=patient_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Horizontal Access Denied: Patient '{current_user.id}' cannot upload records for patient '{patient_id}'."
            )

    # 3. Validate authorized clinical relationship and active consent for doctor uploads
    if current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical upload denied. Doctor approval status is '{status_val}'."
            )

        consent_res = fabric_gateway.verify_consent(
            doctor_id=current_user.id,
            patient_id=patient_id,
            record_type=record_type
        )
        if not consent_res.get("allowed", False):
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="UPLOAD_RECORD",
                purpose=f"Doctor upload for patient {patient_id} denied: no active consent ({consent_res.get('reason')})",
                status="DENIED",
                target_patient_id=patient_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical upload denied: Doctor does not have active consent for patient '{patient_id}' ({consent_res.get('reason')})."
            )

    # Multi-input validation: at least one of (file, description, prescription_file) must be provided
    has_file = file is not None and bool(getattr(file, "filename", None)) and getattr(file, "filename", "").strip() != ""
    has_prescription = prescription_file is not None and bool(getattr(prescription_file, "filename", None)) and getattr(prescription_file, "filename", "").strip() != ""
    has_description = description is not None and bool(description.strip())

    if not (has_file or has_prescription or has_description):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one clinical input must be provided: document file, clinical description, or prescription attachment."
        )

    # Initialize and validate KeyManager up front (fail closed before IPFS pinning or Fabric registration)
    try:
        key_manager = KeyManager()
    except KeyConfigurationError as e:
        logger.error("Upload rejected: KeyManager configuration failure: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Master key configuration error: {str(e)}"
        )

    try:
        # Resolve patient name dynamically from authenticated caller, parameter, or persistent database
        if current_user.id == patient_id and current_user.name:
            resolved_patient_name = current_user.name
        elif patient_name and patient_name.strip():
            resolved_patient_name = patient_name.strip()
        else:
            db_patient = db.query(UserModel).filter(UserModel.id == patient_id).first()
            resolved_patient_name = db_patient.name if db_patient else f"Patient {patient_id}"

        doctor_id = current_user.id if current_user.role == UserRole.DOCTOR else None
        doctor_name = current_user.name if current_user.role == UserRole.DOCTOR else None

        # Process prescription_file if provided
        rx_cid = None
        rx_filename = None
        rx_checksum = None

        rx_key = None
        if has_prescription:
            rx_content = await prescription_file.read()
            rx_filename = prescription_file.filename
            rx_key = generate_key()
            rx_encrypted, rx_fingerprint = encrypt_payload(rx_content, rx_key)
            try:
                rx_cid, rx_checksum = ipfs_client.add_bytes(rx_encrypted, pin=True)
            except Exception as e:
                logger.warning("IPFS Kubo pinning for prescription encountered: %s. Using deterministic content addressing.", str(e))
                rx_checksum = compute_sha256(rx_encrypted)
                rx_cid = f"bafybei{hashlib_sha256_to_cid(rx_checksum)}"
                ipfs_client.store_offline_bytes(rx_cid, rx_encrypted)

        # Process main document file if provided
        doc_filename = None
        if has_file:
            file_content = await file.read()
            doc_filename = file.filename
            # Determine mime_type safely: prioritize file.content_type, or guess from filename
            mime_type = file.content_type
            if not mime_type or mime_type == "application/octet-stream":
                import mimetypes
                guessed, _ = mimetypes.guess_type(file.filename or "")
                mime_type = guessed or "application/octet-stream"
            has_document = True
        else:
            file_content = b""
            mime_type = "application/octet-stream"
            has_document = False

        doc_dek = generate_key()
        try:
            record_entry = record_service.register_and_upload_record(
                patient_id=patient_id,
                patient_name=resolved_patient_name,
                title=title,
                record_type=record_type,
                hospital=hospital,
                raw_file_bytes=file_content,
                mime_type=mime_type,
                doctor_id=doctor_id,
                doctor_name=doctor_name,
                dek=doc_dek,
                custom_record_id=record_id
            )
        except Exception as reg_err:
            if rx_cid is not None:
                logger.error(
                    "Upload failed during record registration; unpinning orphan prescription CID: %s",
                    rx_cid
                )
                try:
                    ipfs_client.pin_rm(rx_cid)
                except Exception as rx_unpin_err:
                    logger.warning("Compensating unpin failed for rx CID %s: %s", rx_cid, str(rx_unpin_err))
                try:
                    ipfs_client.remove_offline_bytes(rx_cid)
                except Exception:
                    pass
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Record registration failed on ledger: {str(reg_err)}. Compensating transaction executed: unpinned IPFS ciphertext."
            )

        record_id = record_entry.get("id")

        # Persist envelope encryption keys and clinical details within SQLite transaction
        try:
            # 1. Wrap and persist primary document key using canonical KeyPurpose.PRIMARY_DOCUMENT
            wrapped_doc = key_manager.wrap_dek(
                dek=doc_dek,
                record_id=record_id,
                patient_id=patient_id,
                purpose=KeyPurpose.PRIMARY_DOCUMENT
            )
            key_manager.save_record_key(
                db=db,
                record_id=record_id,
                patient_id=patient_id,
                purpose=KeyPurpose.PRIMARY_DOCUMENT,
                wrapped=wrapped_doc
            )

            # 2. Wrap and persist prescription key using canonical KeyPurpose.PRESCRIPTION (if provided)
            if has_prescription and rx_key is not None:
                wrapped_rx = key_manager.wrap_dek(
                    dek=rx_key,
                    record_id=record_id,
                    patient_id=patient_id,
                    purpose=KeyPurpose.PRESCRIPTION
                )
                key_manager.save_record_key(
                    db=db,
                    record_id=record_id,
                    patient_id=patient_id,
                    purpose=KeyPurpose.PRESCRIPTION,
                    wrapped=wrapped_rx
                )

            # 3. Persist off-chain clinical details in SQLite via RecordDetailModel
            clean_description = description.strip() if (description and description.strip()) else None
            record_service.save_record_details(
                db=db,
                record_id=record_id,
                patient_id=patient_id,
                description=clean_description,
                prescription_cid=rx_cid,
                prescription_filename=rx_filename,
                prescription_checksum=rx_checksum,
                has_document=has_document,
                document_filename=doc_filename,
                document_mime_type=mime_type if has_document else None
            )

            db.commit()
        except KeyConflictError as e:
            db.rollback()
            record_service.quarantine_record(
                db=db,
                record_id=record_id,
                patient_id=patient_id,
                quarantine_reason=f"KeyConflictError: {str(e)}",
                ipfs_cid=record_entry.get("ipfs_cid"),
                prescription_cid=rx_cid
            )
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="RECORD_QUARANTINED",
                purpose=f"Dual-write key conflict for record {record_id}: {str(e)}. Record quarantined to prevent split-brain access.",
                status="QUARANTINED",
                target_patient_id=patient_id,
                record_id=record_id,
                record_title=title
            )
            logger.critical(
                "KeyConflictError on upload key persistence for record '%s': %s. "
                "Record registered on Fabric but QUARANTINED in off-chain state. "
                "IPFS CIDs (%s, %s) will NOT be unpinned.",
                record_id, str(e), record_entry.get("ipfs_cid"), rx_cid
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cryptographic key conflict: {str(e)}. Record '{record_id}' was registered on ledger but has been quarantined due to key persistence conflict."
            )
        except Exception as e:
            db.rollback()
            record_service.quarantine_record(
                db=db,
                record_id=record_id,
                patient_id=patient_id,
                quarantine_reason=f"Dual-write key persistence failure: {str(e)}",
                ipfs_cid=record_entry.get("ipfs_cid"),
                prescription_cid=rx_cid
            )
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="RECORD_QUARANTINED",
                purpose=f"Dual-write key persistence failure for record {record_id}: {str(e)}. Record quarantined to prevent split-brain access.",
                status="QUARANTINED",
                target_patient_id=patient_id,
                record_id=record_id,
                record_title=title
            )
            logger.critical(
                "Failed to persist encryption keys for record '%s': %s. "
                "Record registered on Fabric but QUARANTINED in off-chain state. "
                "IPFS CIDs (%s, %s) will NOT be unpinned.",
                record_id, str(e), record_entry.get("ipfs_cid"), rx_cid
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Record key persistence failed: {str(e)}. Record '{record_id}' was registered on ledger but has been quarantined to prevent split-brain access."
            )

        # Sanitize internal key attribute from output dictionary (Zero-PHI boundary)
        record_entry.pop("_dek", None)
        return record_entry
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Record registration failed: {str(e)}")


@router.get("/{record_id}/details", response_model=RecordDetailResponse)
def get_record_details(
    record_id: str,
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retrieves off-chain sensitive clinical details for a record:
    - Admin: strictly denied (HTTP 403 Healthcare Privacy Boundary)
    - Patient: only allowed to view their own record details
    - Doctor: only allowed if holding active Fabric consent
    - Auditor: allowed for compliance review
    """
    # 1. Admin Privacy Boundary
    if current_user.role == UserRole.ADMIN:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VIEW",
            purpose=f"Administrative attempt to view confidential clinical details for record {record_id} blocked (Healthcare Privacy Boundary)",
            status="DENIED",
            target_patient_id="UNKNOWN",
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators are strictly prohibited from viewing patient clinical details."
        )

    # 2. Retrieve record metadata from Fabric ledger
    try:
        fabric_record = fabric_gateway.get_record(record_id)
        if not fabric_record:
            raise RecordNotFoundError(f"Record '{record_id}' not found.")
    except RecordNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Record '{record_id}' not found."
        )
    except Exception as e:
        logger.error("Failed to query ledger for record '%s': %s", record_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ledger service unavailable: unable to retrieve record metadata."
        )

    patient_id = fabric_record.get("patient_id") or fabric_record.get("patientId")
    record_type = fabric_record.get("record_type") or fabric_record.get("recordType", "CLINICAL_SUMMARY")

    # 3. RBAC Enforcement
    if current_user.role == UserRole.PATIENT:
        if current_user.id != patient_id:
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VIEW",
                purpose=f"Unauthorized patient attempt to view clinical details belonging to {patient_id}",
                status="DENIED",
                target_patient_id=patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Patient '{current_user.id}' cannot access clinical details belonging to patient '{patient_id}'."
            )

        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VIEW",
            purpose=f"Patient viewed own clinical details for {record_id}",
            status="SUCCESS",
            target_patient_id=patient_id,
            record_id=record_id
        )

    elif current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VIEW",
                purpose=f"Unapproved doctor attempt to view clinical details for {record_id} blocked (status: {status_val})",
                status="DENIED",
                target_patient_id=patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )

        consent_res = fabric_gateway.verify_consent(
            doctor_id=current_user.id,
            patient_id=patient_id,
            record_type=record_type
        )
        allowed = consent_res.get("allowed", False)
        reason = consent_res.get("reason", "NO_CONSENT_FOUND")
        if not allowed:
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VIEW",
                purpose=f"Doctor attempt to view clinical details for {record_id} denied: {reason}",
                status="DENIED",
                target_patient_id=patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Doctor does not have active consent to access patient '{patient_id}' clinical details ({reason})."
            )

        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VIEW",
            purpose=f"Doctor accessed clinical details for {record_id} under active consent {consent_res.get('consentId')}",
            status="SUCCESS",
            target_patient_id=patient_id,
            record_id=record_id
        )

    elif current_user.role == UserRole.AUDITOR:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VIEW",
            purpose=f"Auditor accessed clinical details for compliance review of {record_id}",
            status="SUCCESS",
            target_patient_id=patient_id,
            record_id=record_id
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied."
        )

    # 4. Check quarantine gate
    if record_service.is_record_quarantined(db, record_id):
        q_info = record_service.get_quarantine_info(db, record_id) or {}
        q_reason = q_info.get("quarantine_reason", "Dual-write failure: record quarantined")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Clinical details unavailable: Record '{record_id}' is quarantined due to dual-write failure ({q_reason})."
        )

    # 5. Retrieve detail from SQLite
    detail = record_service.get_record_details(db, record_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Clinical details for record '{record_id}' not found."
        )

    return RecordDetailResponse.from_orm_model(detail)


@router.get("/{record_id}/download")
def download_record_file(
    record_id: str,
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Secure authenticated download and client decryption route for medical record documents.
    Enforces strict Zero-PHI boundaries, canonical KeyManager AAD, and consent authorization:
    - Early fail-closed KeyManager KEK validation
    - Admin: strictly denied (HTTP 403 Healthcare Privacy Boundary)
    - Auditor: strictly denied (HTTP 403, verification only)
    - Patient: own records only (HTTP 403 on horizontal breach)
    - Doctor: requires approval and active unrevoked Fabric consent covering record category
    - Description-only submissions: HTTP 404
    - Missing keys & legacy records (rec-001..rec-003): HTTP 404 (verification-only mode)
    - Checksum mismatch on IPFS ciphertext: HTTP 409 Conflict + TAMPER_DETECTED audit
    - DEK unwrap or AES-GCM decryption failure: HTTP 500 + TAMPER_DETECTED audit
    """
    # 0. Initialize and validate KeyManager up front (fail closed on missing/malformed master KEK)
    try:
        key_manager = KeyManager()
    except KeyConfigurationError as e:
        logger.error("Download rejected: Master KEK configuration error: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Master key configuration error."
        )

    # 1. Admin Privacy Boundary
    if current_user.role == UserRole.ADMIN:
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_RECORD",
            purpose=f"Administrative attempt to download confidential medical record {record_id} blocked (Healthcare Privacy Boundary)",
            status="DENIED",
            target_patient_id="UNKNOWN",
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators are strictly prohibited from downloading patient medical records."
        )

    # 2. Auditor Access Restriction
    if current_user.role == UserRole.AUDITOR:
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_RECORD",
            purpose=f"Auditor attempt to download record {record_id} blocked (Auditors limited to ledger verification)",
            status="DENIED",
            target_patient_id="UNKNOWN",
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Compliance auditors are restricted to ledger verification and cannot download decrypted medical files."
        )

    # 3. Retrieve record metadata from Fabric ledger
    try:
        record = fabric_gateway.get_record(record_id)
    except RecordNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Medical record '{record_id}' not found."
        )
    except Exception as e:
        logger.error("Failed to query ledger for record '%s': %s", record_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ledger service unavailable: unable to retrieve record metadata."
        )

    target_patient_id = record.get("patient_id") or record.get("patientId")
    record_type = record.get("record_type") or record.get("recordType", "CLINICAL_SUMMARY")
    title = record.get("title", f"Record {record_id}")
    ipfs_cid = record.get("ipfs_cid") or record.get("ipfsCid")
    expected_sha256 = record.get("checksum_sha256") or record.get("checksumSha256")

    # 4. Patient horizontal isolation check
    if current_user.role == UserRole.PATIENT:
        if current_user.id != target_patient_id:
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="DOWNLOAD_RECORD",
                purpose=f"Horizontal download violation: Patient {current_user.id} attempted to download record {record_id} of patient {target_patient_id}",
                status="DENIED",
                target_patient_id=target_patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Horizontal Access Denied: Patient '{current_user.id}' cannot download records for patient '{target_patient_id}'."
            )

    # 5. Doctor authorization and active consent verification
    if current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="DOWNLOAD_RECORD",
                purpose=f"Unapproved doctor attempt to download clinical record {record_id} blocked (status: {status_val})",
                status="DENIED",
                target_patient_id=target_patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )

        consent_res = fabric_gateway.verify_consent(
            doctor_id=current_user.id,
            patient_id=target_patient_id,
            record_type=record_type
        )
        if not consent_res.get("allowed", False):
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="DOWNLOAD_RECORD",
                purpose=f"Doctor download attempt for record {record_id} denied: no active consent ({consent_res.get('reason')})",
                status="DENIED",
                target_patient_id=target_patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical download denied: Doctor does not have active consent for patient '{target_patient_id}' ({consent_res.get('reason')})."
            )

    # 5.5. Check quarantine gate
    if record_service.is_record_quarantined(db, record_id):
        q_info = record_service.get_quarantine_info(db, record_id) or {}
        q_reason = q_info.get("quarantine_reason", "Dual-write key persistence failure")
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_RECORD",
            purpose=f"Download blocked: Record {record_id} is quarantined ({q_reason})",
            status="LOCKED",
            target_patient_id=target_patient_id,
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Record '{record_id}' is quarantined due to dual-write key persistence failure ({q_reason}). Document cannot be downloaded."
        )

    # 6. Check if record has document attachment (or is description-only)
    detail_row = db.query(RecordDetailModel).filter(RecordDetailModel.record_id == record_id).first()
    if detail_row and not detail_row.has_document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Record '{record_id}' does not have an attached document file (description-only submission)."
        )

    # 7. Persistent key lookup in RecordKeyModel via KeyManager
    key_row = key_manager.get_record_key(db, record_id, purpose=KeyPurpose.PRIMARY_DOCUMENT)
    if not key_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Encryption key for record '{record_id}' not found. Legacy records operate in ledger-verification-only mode."
        )

    # 8. Fetch ciphertext from IPFS and verify SHA-256 integrity against Fabric ledger
    try:
        ciphertext_bytes = ipfs_client.get_bytes(ipfs_cid, expected_sha256=expected_sha256)
    except ChecksumMismatchError as e:
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_RECORD",
            purpose=f"Cryptographic integrity alert on IPFS retrieval for record {record_id}: {str(e)}",
            status="TAMPER_DETECTED",
            target_patient_id=target_patient_id,
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cryptographic integrity failure: IPFS ciphertext checksum mismatch against Fabric ledger."
        )
    except Exception as e:
        logger.error("Failed to retrieve record content from IPFS for record '%s': %s", record_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to retrieve record content from IPFS storage."
        )

    # 9. Unwrap DEK using KeyManager with canonical PRIMARY_DOCUMENT AAD & decrypt payload
    try:
        dek = key_manager.unwrap_dek(
            wrapped=key_row,
            record_id=record_id,
            patient_id=target_patient_id,
            purpose=KeyPurpose.PRIMARY_DOCUMENT
        )
        decrypted_bytes = decrypt_payload(ciphertext_bytes, dek)
    except (KeyUnwrapError, KeyManagementError, EncryptionError) as e:
        logger.error("DEK unwrapping or decryption failure for record '%s': %s", record_id, str(e))
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_RECORD",
            purpose=f"DEK unwrapping or decryption failure for record {record_id}: {str(e)}",
            status="TAMPER_DETECTED",
            target_patient_id=target_patient_id,
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed: cryptographic verification error."
        )

    # 10. Audit Log on Fabric
    _safe_log_access_event(
        actor_id=current_user.id,
        actor_name=current_user.name,
        actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
        action="DOWNLOAD_RECORD",
        purpose=f"Successfully downloaded and decrypted medical record {record_id}",
        status="SUCCESS",
        target_patient_id=target_patient_id,
        record_id=record_id,
        record_title=title
    )

    detail_row = db.query(RecordDetailModel).filter(RecordDetailModel.record_id == record_id).first()
    declared_name = detail_row.document_filename if detail_row else None
    declared_mime = (detail_row.document_mime_type if detail_row else None) or record.get("mime_type") or record.get("mimeType")

    return _build_download_response(
        data=decrypted_bytes,
        record_id=record_id,
        default_prefix="document",
        declared_filename=declared_name,
        declared_mime=declared_mime
    )


@router.get("/{record_id}/prescription/download")
def download_prescription_file(
    record_id: str,
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Secure authenticated download and client decryption route for record prescription attachments.
    Enforces strict Zero-PHI boundaries, canonical KeyManager AAD, and consent authorization:
    - Early fail-closed KeyManager KEK validation
    - Admin: strictly denied (HTTP 403 Healthcare Privacy Boundary)
    - Auditor: strictly denied (HTTP 403, verification only)
    - Patient: own records only (HTTP 403 on horizontal breach)
    - Doctor: requires approval and active unrevoked Fabric consent covering record category
    - Missing prescription / legacy records: HTTP 404
    - Checksum mismatch on IPFS ciphertext: HTTP 409 Conflict + TAMPER_DETECTED audit
    - DEK unwrap or AES-GCM decryption failure: HTTP 500 + TAMPER_DETECTED audit
    """
    # 0. Initialize and validate KeyManager up front (fail closed on missing/malformed master KEK)
    try:
        key_manager = KeyManager()
    except KeyConfigurationError as e:
        logger.error("Download rejected: Master KEK configuration error: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Master key configuration error."
        )

    # 1. Admin Privacy Boundary
    if current_user.role == UserRole.ADMIN:
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_PRESCRIPTION",
            purpose=f"Administrative attempt to download confidential prescription for record {record_id} blocked (Healthcare Privacy Boundary)",
            status="DENIED",
            target_patient_id="UNKNOWN",
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators are strictly prohibited from downloading patient prescriptions."
        )

    # 2. Auditor Access Restriction
    if current_user.role == UserRole.AUDITOR:
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_PRESCRIPTION",
            purpose=f"Auditor attempt to download prescription for record {record_id} blocked (Auditors limited to ledger verification)",
            status="DENIED",
            target_patient_id="UNKNOWN",
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Compliance auditors are restricted to ledger verification and cannot download decrypted prescription files."
        )

    # 3. Retrieve record metadata from Fabric ledger
    try:
        record = fabric_gateway.get_record(record_id)
    except RecordNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Medical record '{record_id}' not found."
        )
    except Exception as e:
        logger.error("Failed to query ledger for record '%s': %s", record_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ledger service unavailable: unable to retrieve record metadata."
        )

    target_patient_id = record.get("patient_id") or record.get("patientId")
    record_type = record.get("record_type") or record.get("recordType", "CLINICAL_SUMMARY")

    # 4. Patient horizontal isolation check
    if current_user.role == UserRole.PATIENT:
        if current_user.id != target_patient_id:
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="DOWNLOAD_PRESCRIPTION",
                purpose=f"Horizontal download violation: Patient {current_user.id} attempted to download prescription for record {record_id} of patient {target_patient_id}",
                status="DENIED",
                target_patient_id=target_patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Horizontal Access Denied: Patient '{current_user.id}' cannot download prescriptions for patient '{target_patient_id}'."
            )

    # 5. Doctor authorization and active consent verification
    if current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="DOWNLOAD_PRESCRIPTION",
                purpose=f"Unapproved doctor attempt to download clinical prescription for record {record_id} blocked (status: {status_val})",
                status="DENIED",
                target_patient_id=target_patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )

        consent_res = fabric_gateway.verify_consent(
            doctor_id=current_user.id,
            patient_id=target_patient_id,
            record_type=record_type
        )
        if not consent_res.get("allowed", False):
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="DOWNLOAD_PRESCRIPTION",
                purpose=f"Doctor prescription download attempt for record {record_id} denied: no active consent ({consent_res.get('reason')})",
                status="DENIED",
                target_patient_id=target_patient_id,
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical download denied: Doctor does not have active consent for patient '{target_patient_id}' ({consent_res.get('reason')})."
            )

    # 5.5. Check quarantine gate
    if record_service.is_record_quarantined(db, record_id):
        q_info = record_service.get_quarantine_info(db, record_id) or {}
        q_reason = q_info.get("quarantine_reason", "Dual-write key persistence failure")
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_PRESCRIPTION",
            purpose=f"Prescription download blocked: Record {record_id} is quarantined ({q_reason})",
            status="LOCKED",
            target_patient_id=target_patient_id,
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Record '{record_id}' is quarantined due to dual-write key persistence failure ({q_reason}). Prescription cannot be downloaded."
        )

    # 6. Check prescription existence in RecordDetailModel
    detail_row = db.query(RecordDetailModel).filter(RecordDetailModel.record_id == record_id).first()
    if not detail_row or not detail_row.prescription_cid:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No prescription attachment found for record '{record_id}'."
        )

    # 7. Persistent key lookup in RecordKeyModel via KeyManager
    key_row = key_manager.get_record_key(db, record_id, purpose=KeyPurpose.PRESCRIPTION)
    if not key_row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Encryption key for prescription in record '{record_id}' not found. Legacy records operate in ledger-verification-only mode."
        )

    # 8. Fetch ciphertext from IPFS and verify SHA-256 integrity
    try:
        ciphertext_bytes = ipfs_client.get_bytes(
            detail_row.prescription_cid,
            expected_sha256=detail_row.prescription_checksum
        )
    except ChecksumMismatchError as e:
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_PRESCRIPTION",
            purpose=f"Cryptographic integrity alert on IPFS retrieval for prescription of record {record_id}: {str(e)}",
            status="TAMPER_DETECTED",
            target_patient_id=target_patient_id,
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cryptographic integrity failure: IPFS prescription ciphertext checksum mismatch."
        )
    except Exception as e:
        logger.error("Failed to retrieve prescription content from IPFS for record '%s': %s", record_id, str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to retrieve prescription content from IPFS storage."
        )

    # 9. Unwrap DEK using KeyManager with canonical PRESCRIPTION AAD & decrypt payload
    try:
        dek = key_manager.unwrap_dek(
            wrapped=key_row,
            record_id=record_id,
            patient_id=target_patient_id,
            purpose=KeyPurpose.PRESCRIPTION
        )
        decrypted_bytes = decrypt_payload(ciphertext_bytes, dek)
    except (KeyUnwrapError, KeyManagementError, EncryptionError) as e:
        logger.error("Prescription DEK unwrapping or decryption failure for record '%s': %s", record_id, str(e))
        _safe_log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="DOWNLOAD_PRESCRIPTION",
            purpose=f"Prescription DEK unwrapping or decryption failure for record {record_id}: {str(e)}",
            status="TAMPER_DETECTED",
            target_patient_id=target_patient_id,
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Decryption failed: cryptographic verification error."
        )

    # 10. Audit Log on Fabric
    _safe_log_access_event(
        actor_id=current_user.id,
        actor_name=current_user.name,
        actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
        action="DOWNLOAD_PRESCRIPTION",
        purpose=f"Successfully downloaded and decrypted prescription for medical record {record_id}",
        status="SUCCESS",
        target_patient_id=target_patient_id,
        record_id=record_id
    )

    declared_name = detail_row.prescription_filename if detail_row else None
    declared_mime = "application/pdf" if (declared_name and declared_name.lower().endswith(".pdf")) else None

    return _build_download_response(
        data=decrypted_bytes,
        record_id=record_id,
        default_prefix="prescription",
        declared_filename=declared_name,
        declared_mime=declared_mime
    )


@router.get("/{record_id}", response_model=MedicalRecord)
def get_record_by_id(
    record_id: str,
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Fetches single record metadata by record_id."""
    if current_user.role == UserRole.ADMIN:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VIEW",
            purpose=f"Administrative attempt to view record {record_id} blocked (Healthcare Privacy Boundary)",
            status="DENIED",
            target_patient_id="UNKNOWN"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators cannot view confidential medical record details."
        )
    try:
        record = fabric_gateway.get_record(record_id)
    except RecordNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    if current_user.role == UserRole.PATIENT and record["patient_id"] != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cannot view another patient's record."
        )

    if current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )

        rec_type = record.get("record_type") or record.get("recordType", "CLINICAL_SUMMARY")
        consent_res = fabric_gateway.verify_consent(
            doctor_id=current_user.id,
            patient_id=record["patient_id"],
            record_type=rec_type
        )
        allowed = consent_res.get("allowed", False)
        reason = consent_res.get("reason", "NO_CONSENT_FOUND")
        if not allowed:
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VIEW",
                purpose=f"Doctor attempt to view record {record_id} metadata denied: {reason}",
                status="DENIED",
                target_patient_id=record["patient_id"],
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Doctor does not have active consent to access record '{record_id}' ({reason})."
            )

        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VIEW",
            purpose=f"Doctor accessed record metadata for {record_id} under active consent {consent_res.get('consentId')}",
            status="SUCCESS",
            target_patient_id=record["patient_id"],
            record_id=record_id
        )

    rec_id = record.get("id") or record_id
    if record_service.is_record_quarantined(db, rec_id):
        record["is_quarantined"] = True
        q_info = record_service.get_quarantine_info(db, rec_id) or {}
        record["quarantine_reason"] = q_info.get("quarantine_reason")
    else:
        record["is_quarantined"] = False
        record["quarantine_reason"] = None

    return record


@router.post("/{record_id}/verify", response_model=RecordVerifyResponse)
@router.get("/{record_id}/verify", response_model=RecordVerifyResponse)
def verify_record_integrity(
    record_id: str,
    current_user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verifies IPFS content integrity against the tamper-proof ledger checksum.
    Returns structured status: VERIFIED, CHECKSUM_MISMATCH, IPFS_UNAVAILABLE, or LEDGER_UNAVAILABLE.
    Returns structured response directly without raising HTTP 404 so client receives full diagnostic fields.
    Enforces RBAC:
    - Admin: Forbidden (Zero-PHI boundary).
    - Patient: Allowed only for own records; cross-patient queries return non-revealing 200 LEDGER_UNAVAILABLE
      identical to nonexistent records to eliminate existence oracle.
    - Doctor: Allowed only with active, unrevoked consent for record category.
    - Auditor: Allowed for compliance verification.
    """
    if current_user.role == UserRole.ADMIN:
        fabric_gateway.log_access_event(
            actor_id=current_user.id,
            actor_name=current_user.name,
            actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
            action="VERIFY",
            purpose=f"Administrative attempt to verify record {record_id} blocked (Healthcare Privacy Boundary)",
            status="DENIED",
            target_patient_id="UNKNOWN",
            record_id=record_id
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators cannot verify confidential medical records."
        )

    try:
        record = fabric_gateway.get_record(record_id)
        if not record:
            return RecordVerifyResponse(
                record_id=record_id,
                ipfs_cid="UNKNOWN",
                checksum_matches=False,
                ledger_checksum="UNAVAILABLE",
                computed_sha256="UNAVAILABLE",
                status="LEDGER_UNAVAILABLE",
                detail=f"Record '{record_id}' not found on Fabric ledger."
            )
    except RecordNotFoundError:
        return RecordVerifyResponse(
            record_id=record_id,
            ipfs_cid="UNKNOWN",
            checksum_matches=False,
            ledger_checksum="UNAVAILABLE",
            computed_sha256="UNAVAILABLE",
            status="LEDGER_UNAVAILABLE",
            detail=f"Record '{record_id}' not found on Fabric ledger."
        )
    except Exception as e:
        return RecordVerifyResponse(
            record_id=record_id,
            ipfs_cid="UNKNOWN",
            checksum_matches=False,
            ledger_checksum="UNAVAILABLE",
            computed_sha256="UNAVAILABLE",
            status="LEDGER_UNAVAILABLE",
            detail=f"Record query failed: {str(e)}"
        )

    if current_user.role == UserRole.PATIENT:
        if record["patient_id"] != current_user.id:
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VERIFY",
                purpose=f"Patient attempt to verify another patient's record {record_id} denied",
                status="DENIED",
                target_patient_id=record["patient_id"],
                record_id=record_id
            )
            return RecordVerifyResponse(
                record_id=record_id,
                ipfs_cid="UNKNOWN",
                checksum_matches=False,
                ledger_checksum="UNAVAILABLE",
                computed_sha256="UNAVAILABLE",
                status="LEDGER_UNAVAILABLE",
                detail=f"Record '{record_id}' not found on Fabric ledger."
            )

    elif current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )

        rec_type = record.get("record_type") or record.get("recordType", "CLINICAL_SUMMARY")
        consent_res = fabric_gateway.verify_consent(
            doctor_id=current_user.id,
            patient_id=record["patient_id"],
            record_type=rec_type
        )
        allowed = consent_res.get("allowed", False)
        reason = consent_res.get("reason", "NO_CONSENT_FOUND")
        if not allowed:
            fabric_gateway.log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VERIFY",
                purpose=f"Doctor attempt to verify record {record_id} denied: {reason}",
                status="DENIED",
                target_patient_id=record["patient_id"],
                record_id=record_id
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Doctor does not have active consent to verify record '{record_id}' ({reason})."
            )

    elif current_user.role != UserRole.AUDITOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied."
        )

    try:
        verify_result = record_service.verify_record_integrity(record_id, db=db)
        if verify_result.status == "RECORD_QUARANTINED":
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VERIFY",
                purpose=f"Verification query on quarantined record {record_id} flagged as RECORD_QUARANTINED",
                status="QUARANTINED",
                target_patient_id=record["patient_id"],
                record_id=record_id
            )
        elif current_user.role in (UserRole.DOCTOR, UserRole.AUDITOR):
            _safe_log_access_event(
                actor_id=current_user.id,
                actor_name=current_user.name,
                actor_role=current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role),
                action="VERIFY",
                purpose=f"{current_user.role.value.capitalize()} verified cryptographic integrity for record {record_id}",
                status="SUCCESS",
                target_patient_id=record["patient_id"],
                record_id=record_id
            )
        return verify_result
    except Exception as e:
        return RecordVerifyResponse(
            record_id=record_id,
            ipfs_cid="UNKNOWN",
            checksum_matches=False,
            ledger_checksum="UNAVAILABLE",
            computed_sha256="UNAVAILABLE",
            status="LEDGER_UNAVAILABLE",
            detail=f"Record not found or ledger query failed: {str(e)}"
        )
