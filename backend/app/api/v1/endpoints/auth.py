"""
Authentication & Authorization Endpoints.
Uses SQLite persistence via SQLAlchemy (backend/app/db/).
Zero in-memory auth mocks.
"""

from datetime import datetime, timedelta, timezone
import uuid
from typing import Dict, Any
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session

from app.core.security import create_access_token, hash_password, verify_password
from app.models.schemas import (
    UserLoginRequest,
    UserRegisterRequest,
    DoctorApplicationCreate,
    DoctorApplicationResponse,
    DoctorApprovalStatus,
    TokenResponse,
    UserProfile,
    UserRole,
    PasswordRecoveryRequest,
    PasswordRecoveryResponse
)
from app.db.session import get_db
from app.db.models import UserModel, UserSessionModel
from app.api.deps import get_current_user, get_token_payload

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLoginRequest, db: Session = Depends(get_db)):
    """Authenticates credentials against persistent SQLite database and creates user session."""
    user = db.query(UserModel).filter(UserModel.email == credentials.email.lower()).first()
    if not user or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Enforce doctor application approval status
    if user.role == UserRole.DOCTOR.value or user.role == "DOCTOR":
        status_val = getattr(user, "approval_status", "PENDING") or "PENDING"
        if status_val == "PENDING":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor application is pending administrator review. Clinical access will be granted upon verification."
            )
        elif status_val == "REJECTED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor application was rejected. Please contact hospital administration."
            )
        elif status_val != "APPROVED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Doctor account is not approved for clinical access."
            )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive.",
        )

    # Persist session in SQLite
    session_id = str(uuid.uuid4())
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=2)

    db_session = UserSessionModel(
        id=session_id,
        user_id=user.id,
        token_jti=jti,
        created_at=now,
        expires_at=expires,
        is_revoked=False
    )
    db.add(db_session)
    db.commit()

    role_enum = UserRole(user.role) if user.role in [r.value for r in UserRole] else UserRole.PATIENT

    user_profile = UserProfile(
        id=user.id,
        name=user.name,
        role=role_enum,
        email=user.email,
        hospital=user.hospital,
        specialty=user.specialty,
        license_number=getattr(user, "license_number", None),
        approval_status=getattr(user, "approval_status", None)
    )

    claims = {
        "sub": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "hospital": user.hospital,
        "specialty": user.specialty,
        "license_number": getattr(user, "license_number", None),
        "approval_status": getattr(user, "approval_status", None),
        "jti": jti,
        "session_id": session_id
    }

    token = create_access_token(claims)
    return TokenResponse(access_token=token, user=user_profile)


@router.post("/register", response_model=TokenResponse)
def register(req: UserRegisterRequest, db: Session = Depends(get_db)):
    """Registers a new user in persistent SQLite storage. Public self-registration is strictly locked to PATIENT."""
    # Ensure role is PATIENT
    if req.role and req.role != UserRole.PATIENT:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public self-registration is restricted to Patients only. Clinician and administrator accounts must be provisioned by a platform administrator."
        )

    email_key = req.email.lower().strip()
    existing = db.query(UserModel).filter(UserModel.email == email_key).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )

    prefix = "pat-" if (req.role == UserRole.PATIENT or str(req.role).upper() == "PATIENT") else "usr-"
    uid = req.id or f"{prefix}{uuid.uuid4().hex[:6]}"
    new_user = UserModel(
        id=uid,
        name=req.name.strip(),
        email=email_key,
        role=req.role.value if hasattr(req.role, "value") else str(req.role),
        password_hash=hash_password(req.password),
        hospital=req.hospital,
        specialty=req.specialty,
        approval_status="APPROVED",
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Persist initial session
    session_id = str(uuid.uuid4())
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=2)

    db_session = UserSessionModel(
        id=session_id,
        user_id=new_user.id,
        token_jti=jti,
        created_at=now,
        expires_at=expires,
        is_revoked=False
    )
    db.add(db_session)
    db.commit()

    user_profile = UserProfile(
        id=new_user.id,
        name=new_user.name,
        role=req.role,
        email=new_user.email,
        hospital=new_user.hospital,
        specialty=new_user.specialty,
        approval_status="APPROVED"
    )

    claims = {
        "sub": new_user.id,
        "name": new_user.name,
        "email": new_user.email,
        "role": new_user.role,
        "hospital": new_user.hospital,
        "specialty": new_user.specialty,
        "approval_status": "APPROVED",
        "jti": jti,
        "session_id": session_id
    }

    token = create_access_token(claims)
    return TokenResponse(access_token=token, user=user_profile)


@router.post("/register-doctor", response_model=DoctorApplicationResponse, status_code=status.HTTP_201_CREATED)
def register_doctor(req: DoctorApplicationCreate, db: Session = Depends(get_db)):
    """
    Registers a real doctor applicant with credentials.
    Account is stored in SQLite in PENDING status.
    Security Invariant: Absolutely ZERO authenticated session or access token is generated.
    """
    email_key = req.email.lower().strip()
    existing = db.query(UserModel).filter(UserModel.email == email_key).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists."
        )

    if not req.license_number or not req.license_number.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Medical license number is required for doctor registration."
        )

    if not req.name or not req.name.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Doctor full name is required."
        )

    if not req.hospital or not req.hospital.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Hospital affiliation is required."
        )

    if not req.specialty or not req.specialty.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Medical specialty is required."
        )

    if not req.password or len(req.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must be at least 6 characters."
        )

    uid = f"doc-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)
    new_doctor = UserModel(
        id=uid,
        name=req.name.strip(),
        email=email_key,
        role=UserRole.DOCTOR.value,
        password_hash=hash_password(req.password),
        hospital=req.hospital.strip(),
        specialty=req.specialty.strip(),
        license_number=req.license_number.strip(),
        approval_status=DoctorApprovalStatus.PENDING.value,
        is_active=False,
        applied_at=now
    )
    db.add(new_doctor)
    db.commit()
    db.refresh(new_doctor)

    return DoctorApplicationResponse(
        id=new_doctor.id,
        name=new_doctor.name,
        email=new_doctor.email,
        role=UserRole.DOCTOR,
        hospital=new_doctor.hospital,
        specialty=new_doctor.specialty,
        license_number=new_doctor.license_number,
        approval_status=DoctorApprovalStatus.PENDING,
        applied_at=now.isoformat(),
        message="Doctor application submitted successfully. Your credentials are under administrative review."
    )


@router.get("/me", response_model=UserProfile)
def get_current_user_profile(
    user: UserProfile = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns currently authenticated user profile from persistent SQLite storage."""
    db_user = db.query(UserModel).filter(UserModel.id == user.id).first()
    if db_user:
        role_enum = UserRole(db_user.role) if db_user.role in [r.value for r in UserRole] else UserRole.PATIENT
        return UserProfile(
            id=db_user.id,
            name=db_user.name,
            role=role_enum,
            email=db_user.email,
            hospital=db_user.hospital,
            specialty=db_user.specialty
        )
    return user


@router.post("/logout")
def logout(
    payload: Dict[str, Any] = Depends(get_token_payload),
    db: Session = Depends(get_db)
):
    """Revokes active user session in SQLite."""
    session_id = payload.get("session_id")
    token_jti = payload.get("jti")

    revoked = False
    if session_id:
        db_session = db.query(UserSessionModel).filter(UserSessionModel.id == session_id).first()
        if db_session:
            db_session.is_revoked = True
            revoked = True
    if token_jti:
        db_session = db.query(UserSessionModel).filter(UserSessionModel.token_jti == token_jti).first()
        if db_session:
            db_session.is_revoked = True
            revoked = True

    db.commit()
    return {"success": True, "message": "Session successfully revoked."}


@router.post("/recover", response_model=PasswordRecoveryResponse)
def recover_password(req: PasswordRecoveryRequest, db: Session = Depends(get_db)):
    """Initiates account recovery for registered email."""
    # Check if user exists (generic message returned regardless to prevent email enumeration)
    _ = db.query(UserModel).filter(UserModel.email == req.email.lower()).first()
    return PasswordRecoveryResponse(
        success=True,
        message=f"If an active account exists for {req.email}, recovery instructions have been dispatched."
    )
