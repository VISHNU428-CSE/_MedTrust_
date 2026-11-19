"""
FastAPI Dependency Injection Providers.
Handles JWT authentication parsing, user resolution, RBAC validation,
and adapter lifecycle injection.
"""

from typing import Dict, Any, Optional
from fastapi import Header, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.security import verify_and_decode_token
from app.core.exceptions import AccessDeniedError
from app.models.schemas import UserProfile, UserRole
from app.adapters.ipfs_client import ipfs_client, IPFSClient
from app.adapters.fabric_gateway import fabric_gateway, FabricGatewayAdapter
from app.services.record_service import record_service, RecordService
from app.services.consent_service import consent_service, ConsentService
from app.services.audit_service import audit_service, AuditService

security_bearer = HTTPBearer(auto_error=False)


def get_token_payload(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    authorization: Optional[str] = Header(None)
) -> Dict[str, Any]:
    """
    Extracts and cryptographically validates Bearer JWT token.
    Supports both Authorization header formats.
    """
    token = None
    if credentials:
        token = credentials.credentials
    elif authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please provide a valid Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = verify_and_decode_token(token)
        return payload
    except AccessDeniedError as e:
        raise HTTPException(
            status_code=e.code if hasattr(e, "code") else status.HTTP_401_UNAUTHORIZED,
            detail=e.message,
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(payload: Dict[str, Any] = Depends(get_token_payload)) -> UserProfile:
    """Resolves authenticated UserProfile from JWT claims and validates account & session validity."""
    user_id = payload.get("sub") or payload.get("id", "anonymous")
    name = payload.get("name", "User")
    role_str = payload.get("role", "PATIENT")
    email = payload.get("email", f"{user_id}@medtrust.local")
    hospital = payload.get("hospital")
    specialty = payload.get("specialty")
    session_id = payload.get("session_id")
    token_jti = payload.get("jti")

    approval_status = payload.get("approval_status")
    license_number = payload.get("license_number")

    # If database is accessible, verify user account is active and session is not revoked
    try:
        from app.db.session import SessionLocal
        from app.db.models import UserModel, UserSessionModel
        from sqlalchemy import or_

        db = SessionLocal()
        try:
            db_user = db.query(UserModel).filter(UserModel.id == user_id).first()
            if db_user:
                approval_status = getattr(db_user, "approval_status", approval_status)
                license_number = getattr(db_user, "license_number", license_number)
                if db_user.role == "DOCTOR" and approval_status != "APPROVED":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Clinical access denied. Doctor approval status is '{approval_status}'."
                    )
                if not db_user.is_active:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="User account is inactive or suspended. Contact platform administrator."
                    )

            if session_id or token_jti:
                conds = []
                if session_id:
                    conds.append(UserSessionModel.id == session_id)
                if token_jti:
                    conds.append(UserSessionModel.token_jti == token_jti)
                revoked = db.query(UserSessionModel).filter(
                    or_(*conds),
                    UserSessionModel.is_revoked == True
                ).first()
                if revoked:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session has been revoked. Please log in again.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception:
        pass

    try:
        role = UserRole(role_str)
    except ValueError:
        role = UserRole.PATIENT

    return UserProfile(
        id=user_id,
        name=name,
        role=role,
        email=email,
        hospital=hospital,
        specialty=specialty,
        license_number=license_number,
        approval_status=approval_status
    )


# --- Role-Based Dependency Checkers ---

def require_patient(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Restricts access strictly to Patients. Healthcare boundary: Admins cannot access patient vaults."""
    if user.role != UserRole.PATIENT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Endpoint restricted to Patients. Current role: {user.role}"
        )
    return user


def require_doctor(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """
    Restricts access strictly to Doctors who are verified & approved in SQLite database.
    Checks live database approval status on every request, even if incoming JWT claims DOCTOR role.
    """
    if user.role != UserRole.DOCTOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Endpoint restricted to Doctors. Current role: {user.role}"
        )

    from app.db.session import SessionLocal
    from app.db.models import UserModel

    db = SessionLocal()
    try:
        db_user = db.query(UserModel).filter(UserModel.id == user.id).first()
        if not db_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account not found in platform database."
            )
        status_val = getattr(db_user, "approval_status", "PENDING") or "PENDING"
        if status_val == "PENDING":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account is pending administrator approval. Clinical endpoints blocked."
            )
        elif status_val == "REJECTED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account was rejected by platform administration."
            )
        elif status_val != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account is not approved for clinical access."
            )
        if not db_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account is inactive or suspended."
            )
    finally:
        db.close()

    return user


def require_admin(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Restricts access strictly to Platform Administrators."""
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Endpoint restricted to Platform Administrators. Current role: {user.role}"
        )
    return user


def require_auditor(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Restricts access strictly to Compliance Auditors."""
    if user.role != UserRole.AUDITOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Endpoint restricted to Compliance Auditors. Current role: {user.role}"
        )
    return user


def require_auditor_or_admin(user: UserProfile = Depends(get_current_user)) -> UserProfile:
    """Permits access to Auditors or Admins for platform governance and audit queries."""
    if user.role not in (UserRole.AUDITOR, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Endpoint restricted to Auditors or Admins. Current role: {user.role}"
        )
    return user


# --- Adapter & Service Injectors ---

def get_ipfs() -> IPFSClient:
    return ipfs_client


def get_fabric() -> FabricGatewayAdapter:
    return fabric_gateway


def get_records_svc() -> RecordService:
    return record_service


def get_consents_svc() -> ConsentService:
    return consent_service


def get_audits_svc() -> AuditService:
    return audit_service
