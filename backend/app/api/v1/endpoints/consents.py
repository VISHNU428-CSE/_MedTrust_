"""
Consent Management Endpoints.
Implements the decentralized consent workflow:
- Request consent (Doctor -> Patient)
- Grant consent (Patient activation)
- Revoke consent (Immediate patient termination)
- Verify consent status (Smart contract rule evaluation)
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, status
from sqlalchemy.orm import Session

from app.models.schemas import (
    ConsentRecord,
    ConsentRequestPayload,
    ConsentActionResponse,
    ConsentVerifyResponse,
    UserProfile,
    UserRole
)
from app.services.consent_service import consent_service
from app.core.exceptions import AccessDeniedError, ConsentNotFoundError
from app.api.deps import get_current_user, require_doctor
from app.db.session import get_db
from app.db.models import UserModel

router = APIRouter()


@router.get("", response_model=List[ConsentRecord])
def get_consents(
    patient_id: Optional[str] = Query(None),
    current_user: UserProfile = Depends(get_current_user)
):
    """
    Retrieves consent records filtered by role authorization and least-privilege scoping:
    - Patient: strictly isolated to consents where they are the patient.
    - Doctor: strictly isolated to consents where they are the attending clinician.
    - Auditor/Admin: platform governance and compliance review.
    """
    if current_user.role == UserRole.PATIENT:
        if patient_id and patient_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Horizontal Access Denied: Patients cannot query consent records of other patients."
            )
        return consent_service.list_consents(current_user.id)

    elif current_user.role == UserRole.DOCTOR:
        all_consents = consent_service.list_consents(patient_id)
        return [
            c for c in all_consents
            if c.get("doctor_id") == current_user.id or c.get("doctorId") == current_user.id
        ]

    elif current_user.role in (UserRole.AUDITOR, UserRole.ADMIN):
        return consent_service.list_consents(patient_id)

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied."
        )


@router.post("/request", response_model=ConsentActionResponse)
def request_consent(
    payload: ConsentRequestPayload,
    current_user: UserProfile = Depends(require_doctor),
    db: Session = Depends(get_db)
):
    """
    Submits a consent request from doctor to patient.
    Healthcare Invariant: Restricted strictly to approved, active clinicians.
    Enforces doctor identity binding: doctors can only request consent under their own authenticated identity.
    Validates target patient exists and has role PATIENT in platform records.
    """
    # 1. Enforce doctor identity binding: reject attempts to request consent under another doctor's ID
    if payload.doctor_id and payload.doctor_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Horizontal Access Denied: Doctor '{current_user.id}' cannot submit consent requests on behalf of doctor '{payload.doctor_id}'."
        )

    # 2. Validate target patient exists in platform records with role PATIENT
    db_patient = db.query(UserModel).filter(UserModel.id == payload.patient_id).first()
    if not db_patient or (db_patient.role != "PATIENT" and db_patient.role != UserRole.PATIENT.value):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target patient '{payload.patient_id}' not found in platform records."
        )

    doctor_id = current_user.id
    doctor_name = current_user.name
    hospital = current_user.hospital or "Metro General Hospital"
    specialty = current_user.specialty or "Clinical Consultation"

    allowed_types = [t.value if hasattr(t, "value") else str(t) for t in payload.allowed_record_types]

    consent = consent_service.request_access(
        doctor_id=doctor_id,
        doctor_name=doctor_name,
        hospital=hospital,
        specialty=specialty,
        patient_id=payload.patient_id,
        purpose=payload.purpose,
        allowed_record_types=allowed_types,
        duration_days=payload.duration_days,
        consent_id=payload.consent_id
    )
    return ConsentActionResponse(
        success=True,
        id=consent["id"],
        tx_hash=consent.get("tx_hash")
    )


@router.post("/{consent_id}/grant", response_model=ConsentActionResponse)
def grant_consent(
    consent_id: str,
    current_user: UserProfile = Depends(get_current_user)
):
    """Patient approves and activates the consent on the ledger."""
    try:
        consent = consent_service.grant_consent(
            consent_id=consent_id,
            patient_id=current_user.id,
            patient_name=current_user.name
        )
        return ConsentActionResponse(
            success=True,
            id=consent["id"],
            tx_hash=consent.get("tx_hash")
        )
    except ConsentNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except AccessDeniedError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.post("/{consent_id}/revoke", response_model=ConsentActionResponse)
def revoke_consent(
    consent_id: str,
    current_user: UserProfile = Depends(get_current_user)
):
    """Patient immediately revokes access, blocking subsequent doctor queries."""
    try:
        consent = consent_service.revoke_consent(
            consent_id=consent_id,
            patient_id=current_user.id,
            patient_name=current_user.name
        )
        return ConsentActionResponse(
            success=True,
            id=consent["id"],
            tx_hash=consent.get("tx_hash")
        )
    except ConsentNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except AccessDeniedError as e:
        raise HTTPException(status_code=e.code, detail=e.message)


@router.get("/verify", response_model=ConsentVerifyResponse)
def verify_consent(
    doctor_id: str = Query(...),
    patient_id: str = Query(...),
    record_type: str = Query(...),
    current_user: UserProfile = Depends(get_current_user)
):
    """
    Smart contract rule evaluation: verifies if active consent authorizes clinical access.
    Enforces authorization:
    - Admin: Forbidden (Zero-PHI boundary).
    - Doctor: Must be APPROVED and can only verify consent issued to themselves (doctor_id == current_user.id).
    - Patient: Can only verify consent regarding their own records (patient_id == current_user.id).
    - Auditor: Permitted for cross-patient compliance verification.
    """
    if current_user.role == UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative Privacy Boundary: Administrators cannot evaluate or verify clinical consent relationships."
        )

    if current_user.role == UserRole.DOCTOR:
        status_val = getattr(current_user, "approval_status", "PENDING") or "PENDING"
        if status_val != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Clinical access denied. Doctor approval status is '{status_val}'."
            )
        if current_user.id != doctor_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Horizontal Access Denied: Doctor '{current_user.id}' cannot verify consent issued to doctor '{doctor_id}'."
            )

    elif current_user.role == UserRole.PATIENT:
        if current_user.id != patient_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Horizontal Access Denied: Patient '{current_user.id}' cannot verify consent relationships of patient '{patient_id}'."
            )

    elif current_user.role == UserRole.AUDITOR:
        pass  # Auditors may perform cross-patient compliance verification

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied."
        )

    allowed, reason, consent_id = consent_service.verify_access(
        doctor_id=doctor_id,
        patient_id=patient_id,
        record_type=record_type
    )
    return ConsentVerifyResponse(
        allowed=allowed,
        reason=reason,
        consent_id=consent_id
    )
