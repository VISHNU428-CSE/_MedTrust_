"""
Role-Based Access Control (RBAC) definitions and policy enforcement.
Supports: PATIENT, DOCTOR, ADMIN, AUDITOR.
"""

from typing import List, Dict, Any, Callable
from fastapi import HTTPException, status
from app.core.exceptions import AccessDeniedError


class Role:
    PATIENT = "PATIENT"
    DOCTOR = "DOCTOR"
    ADMIN = "ADMIN"
    AUDITOR = "AUDITOR"


ALL_ROLES = [Role.PATIENT, Role.DOCTOR, Role.ADMIN, Role.AUDITOR]


def require_role_in(allowed_roles: List[str]) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Factory creating an RBAC role checker dependency."""
    def role_checker(token_payload: Dict[str, Any]) -> Dict[str, Any]:
        user_role = token_payload.get("role")
        if not user_role or user_role not in allowed_roles:
            raise AccessDeniedError(
                f"Role '{user_role}' does not have sufficient permissions. Allowed: {allowed_roles}",
                code=status.HTTP_403_FORBIDDEN,
                reason="ROLE_NOT_AUTHORIZED"
            )
        return token_payload
    return role_checker


def check_patient_horizontal_isolation(actor_id: str, actor_role: str, target_patient_id: str) -> None:
    """
    Prevents horizontal privilege escalation where Patient A accesses Patient B's data.
    """
    if actor_role == Role.PATIENT and actor_id != target_patient_id:
        raise AccessDeniedError(
            f"Horizontal access violation: Patient '{actor_id}' cannot access records belonging to Patient '{target_patient_id}'.",
            code=status.HTTP_403_FORBIDDEN,
            reason="UNAUTHORIZED_HORIZONTAL_ACCESS"
        )
