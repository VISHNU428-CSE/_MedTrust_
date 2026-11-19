"""
Consent Management Service.
Coordinates consent lifecycle (REQUEST -> GRANT -> REVOKE)
and verifies access authorization against on-chain Fabric state.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple

from app.adapters.fabric_gateway import fabric_gateway
from app.core.exceptions import AccessDeniedError, ConsentNotFoundError

logger = logging.getLogger(__name__)


class ConsentService:
    def __init__(self):
        self.gateway = fabric_gateway

    def request_access(
        self,
        doctor_id: str,
        doctor_name: str,
        hospital: str,
        specialty: str,
        patient_id: str,
        purpose: str,
        allowed_record_types: List[str],
        duration_days: int = 30,
        consent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Doctor requests consent from a patient."""
        consent = self.gateway.request_consent(
            consent_id=consent_id,
            patient_id=patient_id,
            doctor_id=doctor_id,
            doctor_name=doctor_name,
            hospital=hospital,
            specialty=specialty,
            purpose=purpose,
            allowed_record_types=allowed_record_types,
            duration_days=duration_days
        )
        # Log to audit trail
        self.gateway.log_access_event(
            actor_id=doctor_id,
            actor_name=doctor_name,
            actor_role="DOCTOR",
            action="REQUEST_CONSENT",
            purpose=purpose,
            status="SUCCESS"
        )
        return consent

    def grant_consent(self, consent_id: str, patient_id: str, patient_name: str = "Patient") -> Dict[str, Any]:
        """Patient approves and activates consent."""
        consent = self.gateway.grant_consent(consent_id, requesting_patient_id=patient_id)
        self.gateway.log_access_event(
            actor_id=patient_id,
            actor_name=patient_name,
            actor_role="PATIENT",
            action="GRANT_CONSENT",
            purpose=f"Approved consent {consent_id}",
            status="SUCCESS"
        )
        return consent

    def revoke_consent(self, consent_id: str, patient_id: str, patient_name: str = "Patient") -> Dict[str, Any]:
        """Patient immediately revokes consent."""
        consent = self.gateway.revoke_consent(consent_id, requesting_patient_id=patient_id)
        self.gateway.log_access_event(
            actor_id=patient_id,
            actor_name=patient_name,
            actor_role="PATIENT",
            action="REVOKE_CONSENT",
            purpose=f"Revoked consent {consent_id}",
            status="SUCCESS"
        )
        return consent

    def verify_access(
        self,
        doctor_id: str,
        patient_id: str,
        record_type: str
    ) -> Tuple[bool, str, Optional[str]]:
        """Verifies if a doctor has valid, non-expired, non-revoked consent."""
        return self.gateway.verify_consent(doctor_id, patient_id, record_type)

    def list_consents(self, patient_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Queries active and historical consents."""
        return self.gateway.list_consents(patient_id)


consent_service = ConsentService()
