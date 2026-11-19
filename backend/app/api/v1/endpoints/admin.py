"""
Admin Management Endpoints.
Provides user management, status toggling, security events,
and platform telemetry for Platform Administrators.
Healthcare Least-Privilege Invariant: Administrators are strictly isolated from clinical medical records.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Depends, status, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import UserModel, UserSessionModel
from app.models.schemas import (
    UserSummary,
    UserStatusUpdate,
    UserProfile,
    UserRole,
    AccessLog,
    DoctorApplicationSummary,
    DoctorApplicationRejectRequest,
    DoctorApplicationActionResponse,
    DoctorApprovalStatus
)
from app.api.deps import require_admin
from app.services.audit_service import audit_service
from app.adapters.fabric_gateway import fabric_gateway

router = APIRouter()


@router.get("/users", response_model=List[UserSummary])
def list_users(
    admin: UserProfile = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Lists all registered platform users with account status. Passwords strictly omitted."""
    users = db.query(UserModel).order_by(UserModel.created_at.desc()).all()
    result = []
    for u in users:
        role_enum = UserRole(u.role) if u.role in [r.value for r in UserRole] else UserRole.PATIENT
        result.append(
            UserSummary(
                id=u.id,
                name=u.name,
                email=u.email,
                role=role_enum,
                hospital=u.hospital,
                specialty=u.specialty,
                license_number=getattr(u, "license_number", None),
                approval_status=getattr(u, "approval_status", None),
                is_active=u.is_active,
                created_at=u.created_at.isoformat() if u.created_at else None
            )
        )
    return result


@router.patch("/users/{user_id}/status", response_model=UserSummary)
def update_user_status(
    user_id: str,
    payload: UserStatusUpdate,
    admin: UserProfile = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Enables or suspends a user account."""
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{user_id}' not found."
        )

    target_active = payload.active_value

    # Protect against self-suspension by admin
    if user.id == admin.id and not target_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot suspend their own account."
        )

    user.is_active = target_active

    if not target_active:
        # Revoke all active sessions for this user
        sessions = db.query(UserSessionModel).filter(
            UserSessionModel.user_id == user.id,
            UserSessionModel.is_revoked == False
        ).all()
        for s in sessions:
            s.is_revoked = True

    from app.adapters.fabric_gateway import fabric_gateway
    fabric_gateway.log_access_event(
        actor_id=admin.id,
        actor_name=admin.name,
        actor_role=admin.role.value if hasattr(admin.role, "value") else str(admin.role),
        action="UPDATE_USER_STATUS",
        purpose=f"Admin {admin.name} updated user {user.id} status to is_active={target_active}",
        status="ALLOWED",
        target_patient_id=user.id
    )

    db.commit()
    db.refresh(user)

    role_enum = UserRole(user.role) if user.role in [r.value for r in UserRole] else UserRole.PATIENT
    return UserSummary(
        id=user.id,
        name=user.name,
        email=user.email,
        role=role_enum,
        hospital=user.hospital,
        specialty=user.specialty,
        license_number=getattr(user, "license_number", None),
        approval_status=getattr(user, "approval_status", None),
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else None
    )


@router.get("/security-events", response_model=List[AccessLog])
def get_security_events(
    admin: UserProfile = Depends(require_admin)
):
    """
    Returns security events: access denials, horizontal escalation attempts,
    consent revocations, and administrative governance actions.
    """
    all_logs = audit_service.get_logs()
    # Filter for security-significant events or return comprehensive audit feed
    security_events = []
    for log in all_logs:
        log_status = log.get("status") if isinstance(log, dict) else getattr(log, "status", None)
        log_action = log.get("action") if isinstance(log, dict) else getattr(log, "action", None)
        if log_status == "DENIED" or log_action in [
            "REVOKE_CONSENT", "REQUEST_CONSENT", "UPDATE_USER_STATUS", "ACCESS_DENIED"
        ]:
            security_events.append(log)

    return security_events if security_events else all_logs


@router.get("/telemetry")
def get_admin_telemetry(
    admin: UserProfile = Depends(require_admin),
    db: Session = Depends(get_db)
) -> Dict[str, Any]:
    """Returns platform administrative metrics."""
    total_users = db.query(UserModel).count()
    active_users = db.query(UserModel).filter(UserModel.is_active == True).count()
    patient_count = db.query(UserModel).filter(UserModel.role == "PATIENT").count()
    doctor_count = db.query(UserModel).filter(UserModel.role == "DOCTOR").count()
    auditor_count = db.query(UserModel).filter(UserModel.role == "AUDITOR").count()
    admin_count = db.query(UserModel).filter(UserModel.role == "ADMIN").count()
    active_sessions = db.query(UserSessionModel).filter(UserSessionModel.is_revoked == False).count()

    return {
        "totalUsers": total_users,
        "activeUsers": active_users,
        "activeSessions": active_sessions,
        "roleCounts": {
            "patient": patient_count,
            "doctor": doctor_count,
            "auditor": auditor_count,
            "admin": admin_count
        },
        "privacyBoundaryEnforced": True,
        "adminClinicalAccessBanned": True
    }


# --- Doctor Application Review Workflow ---

@router.get("/doctor-applications", response_model=List[DoctorApplicationSummary])
def list_doctor_applications(
    status_filter: Optional[str] = Query("PENDING", alias="status"),
    admin: UserProfile = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Lists doctor applications for administrative review.
    Filter by status: PENDING (default), APPROVED, REJECTED, or ALL.
    Strictly excludes passwords, tokens, and sensitive credentials.
    """
    query = db.query(UserModel).filter(UserModel.role == "DOCTOR")
    if status_filter and status_filter.upper() != "ALL":
        query = query.filter(UserModel.approval_status == status_filter.upper())

    doctors = query.order_by(UserModel.created_at.desc()).all()
    results = []
    for doc in doctors:
        results.append(
            DoctorApplicationSummary(
                id=doc.id,
                name=doc.name,
                email=doc.email,
                role=UserRole.DOCTOR,
                hospital=doc.hospital,
                specialty=doc.specialty,
                license_number=getattr(doc, "license_number", None),
                approval_status=getattr(doc, "approval_status", "PENDING"),
                is_active=doc.is_active,
                applied_at=doc.applied_at.isoformat() if getattr(doc, "applied_at", None) else None,
                reviewed_at=doc.reviewed_at.isoformat() if getattr(doc, "reviewed_at", None) else None,
                reviewed_by=getattr(doc, "reviewed_by", None),
                rejection_reason=getattr(doc, "rejection_reason", None),
            )
        )
    return results


@router.post("/doctor-applications/{doctor_id}/approve", response_model=DoctorApplicationActionResponse)
def approve_doctor_application(
    doctor_id: str,
    admin: UserProfile = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Approves a pending doctor application.
    Promotes status to APPROVED, activates account (is_active=True),
    records administrative reviewer audit metadata, and logs access event to Fabric.
    Takes effect immediately for all live database authorization checks.
    """
    doctor = db.query(UserModel).filter(UserModel.id == doctor_id).first()
    if not doctor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Doctor application '{doctor_id}' not found."
        )

    if doctor.role != "DOCTOR":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User '{doctor_id}' has role '{doctor.role}'. Only doctor applications can be approved."
        )

    if doctor.approval_status == "APPROVED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Doctor application '{doctor_id}' is already approved."
        )

    now = datetime.now(timezone.utc)
    doctor.approval_status = "APPROVED"
    doctor.is_active = True
    doctor.reviewed_by = admin.id
    doctor.reviewed_at = now
    doctor.rejection_reason = None

    fabric_gateway.log_access_event(
        actor_id=admin.id,
        actor_name=admin.name,
        actor_role=admin.role.value if hasattr(admin.role, "value") else str(admin.role),
        action="APPROVE_DOCTOR",
        purpose=f"Admin {admin.name} ({admin.id}) approved doctor application for {doctor.name} ({doctor.id})",
        status="ALLOWED",
        target_patient_id=doctor.id
    )

    db.commit()
    db.refresh(doctor)

    return DoctorApplicationActionResponse(
        success=True,
        id=doctor.id,
        name=doctor.name,
        email=doctor.email,
        approval_status=doctor.approval_status,
        is_active=doctor.is_active,
        reviewed_by=doctor.reviewed_by or admin.id,
        reviewed_at=doctor.reviewed_at.isoformat() if doctor.reviewed_at else now.isoformat(),
        rejection_reason=None,
        message=f"Doctor application for {doctor.name} ({doctor.id}) has been approved."
    )


@router.post("/doctor-applications/{doctor_id}/reject", response_model=DoctorApplicationActionResponse)
def reject_doctor_application(
    doctor_id: str,
    payload: DoctorApplicationRejectRequest,
    admin: UserProfile = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Rejects a doctor application.
    Requires a meaningful rejection reason (>= 5 chars).
    Sets status to REJECTED, deactivates account (is_active=False),
    revokes any existing sessions, and logs access event to Fabric.
    """
    if not payload or not payload.reason or len(payload.reason.strip()) < 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A meaningful rejection reason of at least 5 characters is required."
        )

    reason = payload.reason.strip()

    doctor = db.query(UserModel).filter(UserModel.id == doctor_id).first()
    if not doctor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Doctor application '{doctor_id}' not found."
        )

    if doctor.role != "DOCTOR":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User '{doctor_id}' has role '{doctor.role}'. Only doctor applications can be rejected."
        )

    if doctor.approval_status == "REJECTED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Doctor application '{doctor_id}' is already rejected."
        )

    now = datetime.now(timezone.utc)
    doctor.approval_status = "REJECTED"
    doctor.is_active = False
    doctor.reviewed_by = admin.id
    doctor.reviewed_at = now
    doctor.rejection_reason = reason

    # Revoke any active sessions
    active_sessions = db.query(UserSessionModel).filter(
        UserSessionModel.user_id == doctor.id,
        UserSessionModel.is_revoked == False
    ).all()
    for s in active_sessions:
        s.is_revoked = True

    fabric_gateway.log_access_event(
        actor_id=admin.id,
        actor_name=admin.name,
        actor_role=admin.role.value if hasattr(admin.role, "value") else str(admin.role),
        action="REJECT_DOCTOR",
        purpose=f"Admin {admin.name} ({admin.id}) rejected doctor application for {doctor.name} ({doctor.id}). Reason: {reason}",
        status="ALLOWED",
        target_patient_id=doctor.id
    )

    db.commit()
    db.refresh(doctor)

    return DoctorApplicationActionResponse(
        success=True,
        id=doctor.id,
        name=doctor.name,
        email=doctor.email,
        approval_status=doctor.approval_status,
        is_active=doctor.is_active,
        reviewed_by=doctor.reviewed_by or admin.id,
        reviewed_at=doctor.reviewed_at.isoformat() if doctor.reviewed_at else now.isoformat(),
        rejection_reason=doctor.rejection_reason,
        message=f"Doctor application for {doctor.name} ({doctor.id}) has been rejected."
    )

