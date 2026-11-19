"""
Immutable Audit Trail Service.
Handles audit log queries and cryptographic verification of the SHA-256 hash chain.
"""

from typing import List, Dict, Any, Optional, Tuple
from app.adapters.fabric_gateway import fabric_gateway


class AuditService:
    def __init__(self):
        self.gateway = fabric_gateway

    def get_logs(self, patient_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves audit trail entries."""
        return self.gateway.list_audit_logs(patient_id)

    def verify_integrity(self) -> Tuple[bool, str]:
        """Mathematically verifies cryptographic hash chain."""
        return self.gateway.verify_audit_chain_integrity()

    def log_event(
        self,
        actor_id: str,
        actor_name: str,
        actor_role: str,
        action: str,
        purpose: str,
        status: str,
        record_id: Optional[str] = None,
        record_title: Optional[str] = None
    ) -> Dict[str, Any]:
        """Appends an immutable audit log entry."""
        return self.gateway.log_access_event(
            actor_id=actor_id,
            actor_name=actor_name,
            actor_role=actor_role,
            action=action,
            purpose=purpose,
            status=status,
            record_id=record_id,
            record_title=record_title
        )


audit_service = AuditService()
