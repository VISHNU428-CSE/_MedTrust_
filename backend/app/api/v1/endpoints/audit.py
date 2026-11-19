"""
Audit Trail Endpoints.
Provides queries for immutable access logs and cryptographic verification
of the SHA-256 hash-chained ledger.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Query, Depends, HTTPException, status

from app.models.schemas import AccessLog, UserProfile, UserRole
from app.services.audit_service import audit_service
from app.api.deps import get_current_user

router = APIRouter()


@router.get("", response_model=List[AccessLog])
def get_audit_logs(
    patient_id: Optional[str] = Query(None),
    current_user: UserProfile = Depends(get_current_user)
):
    """
    Returns audit trail entries subject to role-based least-privilege scoping:
    - Patient: strictly isolated to events concerning their own identity.
    - Doctor: strictly isolated to events where the doctor was the actor.
    - Auditor/Admin: allowed for platform governance and regulatory review.
    """
    if current_user.role == UserRole.PATIENT:
        if patient_id and patient_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Horizontal Access Denied: Patients cannot query audit history of other patients."
            )
        return audit_service.get_logs(current_user.id)

    elif current_user.role == UserRole.DOCTOR:
        logs = audit_service.get_logs(patient_id)
        return [
            l for l in logs
            if l.get("actor_id") == current_user.id or l.get("actorId") == current_user.id
        ]

    elif current_user.role in (UserRole.AUDITOR, UserRole.ADMIN):
        return audit_service.get_logs(patient_id)

    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied."
        )


@router.get("/verify")
def verify_audit_chain_integrity(
    current_user: UserProfile = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Cryptographically verifies the SHA-256 hash chain of the entire audit trail.
    Ensures that no log entry has been inserted, mutated, or deleted.
    Available to all authenticated roles (PATIENT, DOCTOR, AUDITOR, ADMIN).
    Rejects unauthenticated requests with HTTP 401.
    """
    is_intact, message = audit_service.verify_integrity()
    return {
        "chainIntact": is_intact,
        "message": message
    }
