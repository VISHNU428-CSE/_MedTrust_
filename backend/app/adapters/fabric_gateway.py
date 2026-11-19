"""
MedTrust Hyperledger Fabric Gateway Client Adapter.
Interfaces with chaincode contracts designed by Kelly:
- ConsentContract (RequestConsent, GrantConsent, RejectConsent, RevokeConsent, VerifyConsent, GetConsent, GetConsentsByPatient)
- MedicalRecordContract (RegisterRecord, GetRecord, GetRecordsByPatient, VerifyRecordChecksum)
- AuditTrailContract (LogAccessEvent, GetAuditLogsByPatient, GetAuditLogsByActor, VerifyAuditChain)

Strictly enforces:
1. Zero-PHI on ledger (no SSNs, plain medical records, private keys, passwords)
2. Immediate atomic consent revocation
3. Cryptographic SHA-256 hash chaining with GENESIS_BLOCK_HASH anchor
4. Live gRPC connectivity inspection and standby readiness
"""

import hashlib
import json
import logging
import os
import socket
import time
import uuid
from typing import Dict, Any, List, Optional, Tuple, Union

from app.config import settings
from app.core.exceptions import (
    AccessDeniedError,
    FabricGatewayError,
    RecordNotFoundError,
    ConsentNotFoundError,
    PHIViolationError,
)
from app.adapters.real_fabric_gateway import (
    RealFabricGatewayAdapter,
    RealFabricGatewayClient,
    real_fabric_gateway,
    assert_zero_phi_payload,
    assert_zero_phi,
    canonical_json_dumps,
    generate_tx_hash,
    SSN_PATTERN,
    CREDIT_CARD_PATTERN,
    FORBIDDEN_SECRET_TERMS,
)

logger = logging.getLogger(__name__)


class VerifyConsentResult(dict):
    """
    Dictionary representing VerifyConsent evaluation result.
    Supports both dict access (e.g. res['allowed'], res['reason']) according to
    GATEWAY_ADAPTER_SPEC.md, and tuple unpacking (e.g. allowed, reason, consent_id = res)
    for FastAPI endpoint compatibility.
    """
    def __iter__(self):
        yield self["allowed"]
        yield self["reason"]
        yield self.get("consentId")


class VerifyAuditChainResult(dict):
    """
    Dictionary representing VerifyAuditChain evaluation result.
    Supports both dict access (e.g. res['isIntact'], res['message']) according to
    GATEWAY_ADAPTER_SPEC.md, and 2-tuple unpacking (is_intact, message = res).
    """
    def __iter__(self):
        yield self["isIntact"]
        yield self["message"]


class FabricGatewayAdapter(RealFabricGatewayAdapter):
    """
    Production-grade Hyperledger Fabric Gateway client adapter.
    Inherits full GATEWAY_ADAPTER_SPEC.md compliance from RealFabricGatewayAdapter,
    with dual-signature overloads for seamless compatibility with both internal
    FastAPI endpoints and external QA test harnesses.
    """
    def __init__(
        self,
        connection_profile_path: Optional[str] = None,
        channel_name: Optional[str] = None,
        chaincode_name: Optional[str] = None,
        contract_name: Optional[str] = None,
        msp_id: Optional[str] = None,
        peer_endpoint: Optional[str] = None,
    ):
        super().__init__(
            connection_profile_path=connection_profile_path,
            channel_name=channel_name,
            chaincode_name=chaincode_name,
            contract_name=contract_name,
            msp_id=msp_id,
            peer_endpoint=peer_endpoint,
        )
        self._fallback_adapter = self

    def get_status(self) -> Dict[str, Any]:
        """Returns Fabric channel, peer endpoint, and ledger state health."""
        conn_info = self.check_peer_connectivity()
        return {
            "status": "connected",
            "channel": self.channel_name,
            "chaincode": self.chaincode_name,
            "contract": self.contract_name,
            "msp_id": self.msp_id,
            "peer_endpoint": self.peer_endpoint,
            "mode": conn_info.get("mode", "standby"),
            "records_count": len(self._records),
            "consents_count": len(self._consents),
            "audit_blocks_count": len(self._audit_chain)
        }

    def register_record(
        self,
        record_id: str,
        patient_id: str,
        *args,
        ipfs_cid: Optional[str] = None,
        checksum: Optional[str] = None,
        checksum_sha256: Optional[str] = None,
        record_type: Optional[str] = None,
        facility: Optional[str] = None,
        hospital: Optional[str] = None,
        registered_by: Optional[str] = None,
        patient_name: Optional[str] = None,
        title: Optional[str] = None,
        file_size: Optional[str] = None,
        mime_type: Optional[str] = None,
        key_fingerprint: Optional[str] = None,
        created_by_doctor: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Dual-signature record registration.
        Accepts both GATEWAY_ADAPTER_SPEC.md arguments and FastAPI record_service arguments.
        """
        # Parse positional args if supplied
        if args:
            if len(args) >= 1 and (args[0].startswith("bafy") or args[0].startswith("bafk") or args[0].startswith("Qm")):
                # Spec positional: (ipfs_cid, checksum, record_type, facility, registered_by)
                ipfs_cid = args[0]
                if len(args) > 1:
                    checksum = args[1]
                if len(args) > 2:
                    record_type = args[2]
                if len(args) > 3:
                    facility = args[3]
                if len(args) > 4:
                    registered_by = args[4]
            else:
                # Legacy positional: (patient_name, title, record_type, ipfs_cid, file_size, mime_type, hospital, key_fingerprint, checksum_sha256)
                patient_name = args[0]
                if len(args) > 1:
                    title = args[1]
                if len(args) > 2:
                    record_type = args[2]
                if len(args) > 3:
                    ipfs_cid = args[3]
                if len(args) > 4:
                    file_size = args[4]
                if len(args) > 5:
                    mime_type = args[5]
                if len(args) > 6:
                    hospital = args[6]
                if len(args) > 7:
                    key_fingerprint = args[7]
                if len(args) > 8:
                    checksum_sha256 = args[8]

        final_cid = ipfs_cid or kwargs.get("ipfs_cid", "")
        final_checksum = checksum or checksum_sha256 or kwargs.get("checksum_sha256", "")
        final_type = record_type or kwargs.get("record_type", "EHR_GENERAL")
        final_facility = facility or hospital or kwargs.get("hospital", "Metro General Hospital")
        final_doctor = registered_by or created_by_doctor or kwargs.get("created_by_doctor", "")
        final_patient_name = patient_name or kwargs.get("patient_name") or f"Patient {patient_id}"
        final_title = title or kwargs.get("title") or f"Record {record_id}"
        final_size = file_size or kwargs.get("file_size") or "1.0 MB"
        final_mime = mime_type or kwargs.get("mime_type") or "application/pdf"
        final_fingerprint = key_fingerprint or kwargs.get("key_fingerprint") or f"SHA256:{final_checksum[:16]}"

        return self.register_record_metadata(
            record_id=record_id,
            patient_id=patient_id,
            ipfs_cid=final_cid,
            checksum=final_checksum,
            record_type=final_type,
            facility=final_facility,
            registered_by=final_doctor,
            patient_name=final_patient_name,
            title=final_title,
            file_size=final_size,
            mime_type=final_mime,
            key_fingerprint=final_fingerprint,
        )

    def list_records(self, patient_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists records for a given patient, or all records if patient_id is None."""
        if patient_id:
            return self.get_records_by_patient(patient_id)
        return list(self._records.values())

    def request_consent(
        self,
        consent_id: Optional[str] = None,
        patient_id: Optional[str] = None,
        doctor_id: Optional[str] = None,
        allowed_record_types: Optional[Union[List[str], str]] = None,
        valid_until_epoch: Optional[int] = None,
        purpose: str = "",
        doctor_name: Optional[str] = None,
        hospital: Optional[str] = None,
        specialty: Optional[str] = None,
        duration_days: int = 30,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Dual-signature consent request.
        Supports both spec signature (consent_id, patient_id, doctor_id, ...) and
        FastAPI service signature (patient_id, doctor_id, doctor_name, ...).
        """
        cid = consent_id or kwargs.get("consent_id") or f"cst-{uuid.uuid4().hex[:6]}"
        pid = patient_id or kwargs.get("patient_id", "")
        did = doctor_id or kwargs.get("doctor_id", "")
        rec_types = allowed_record_types if allowed_record_types is not None else kwargs.get("allowed_record_types", ["ALL"])
        purp = purpose or kwargs.get("purpose", "")
        dname = doctor_name or kwargs.get("doctor_name", "Doctor")
        hosp = hospital or kwargs.get("hospital", "Metro General Hospital")
        spec = specialty or kwargs.get("specialty", "General Practice")

        if valid_until_epoch is None:
            now = time.time()
            days = duration_days or kwargs.get("duration_days", 30)
            valid_until_epoch = int(now + (days * 86400))

        return super().request_consent(
            consent_id=cid,
            patient_id=pid,
            doctor_id=did,
            allowed_record_types=rec_types,
            valid_until_epoch=valid_until_epoch,
            purpose=purp,
            doctor_name=dname,
            hospital=hosp,
            specialty=spec,
        )

    def grant_consent(
        self,
        consent_id: str,
        patient_id: Optional[str] = None,
        requesting_patient_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Approves consent with ownership enforcement."""
        pid = patient_id or requesting_patient_id or kwargs.get("patient_id", "")
        return super().grant_consent(
            consent_id=consent_id,
            patient_id=pid,
            doctor_id=kwargs.get("doctor_id", ""),
            allowed_record_types=kwargs.get("allowed_record_types", '["ALL"]'),
            valid_until_epoch=kwargs.get("valid_until_epoch", 0),
            purpose=kwargs.get("purpose", ""),
        )

    def revoke_consent(
        self,
        consent_id: str,
        requesting_patient_id: Optional[str] = None,
        patient_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Revokes consent immediately with ownership enforcement."""
        pid = requesting_patient_id or patient_id or ""
        return super().revoke_consent(
            consent_id=consent_id,
            requesting_patient_id=pid,
        )

    def list_consents(self, patient_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Queries consents for a patient or all consents."""
        if patient_id:
            return self.get_consents_by_patient(patient_id)
        return list(self._consents.values())

    def verify_consent(
        self,
        doctor_id: str,
        patient_id: str,
        record_type: str
    ) -> VerifyConsentResult:
        """
        Verifies consent status returning a result that is both dict-accessible
        and tuple-unpackable.
        """
        raw_result = super().verify_consent(
            doctor_id=doctor_id,
            patient_id=patient_id,
            record_type=record_type
        )
        return VerifyConsentResult(raw_result)

    def log_access_event(
        self,
        *args,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Dual-signature audit logging.
        Handles both:
        - Spec signature: (event_type, actor_id, actor_role, target_patient_id, ...)
        - Service signature: (actor_id, actor_name, actor_role, action, purpose, status, ...)
        """
        event_type = kwargs.get("event_type") or kwargs.get("action")
        actor_id = kwargs.get("actor_id")
        actor_name = kwargs.get("actor_name")
        actor_role = kwargs.get("actor_role")
        target_patient_id = kwargs.get("target_patient_id")
        action = kwargs.get("action")
        purpose = kwargs.get("purpose")
        detail = kwargs.get("detail")
        status = kwargs.get("status", "SUCCESS")
        record_id = kwargs.get("record_id")
        record_title = kwargs.get("record_title")
        consent_id = kwargs.get("consent_id")

        if args:
            # Disambiguate positional arguments
            if len(args) >= 3 and args[2] in ("PATIENT", "DOCTOR", "ADMIN", "AUDITOR", "SYSTEM"):
                # Spec positional: event_type, actor_id, actor_role, target_patient_id
                event_type = args[0]
                actor_id = args[1]
                actor_role = args[2]
                if len(args) > 3:
                    target_patient_id = args[3]
            else:
                # Service positional: actor_id, actor_name, actor_role, action, purpose, status
                actor_id = args[0]
                if len(args) > 1:
                    actor_name = args[1]
                if len(args) > 2:
                    actor_role = args[2]
                if len(args) > 3:
                    action = args[3]
                    event_type = action
                if len(args) > 4:
                    purpose = args[4]
                if len(args) > 5:
                    status = args[5]

        return super().log_access_event(
            event_type=event_type or action or "ACCESS_EVENT",
            actor_id=actor_id or "SYSTEM",
            actor_role=actor_role or "SYSTEM",
            target_patient_id=target_patient_id or actor_id or "",
            record_id=record_id,
            consent_id=consent_id,
            status=status,
            detail=detail or purpose or "",
            actor_name=actor_name,
            record_title=record_title,
            purpose=purpose,
        )

    def list_audit_logs(self, patient_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns audit entries matching patient or all audit entries."""
        if patient_id:
            return self.get_audit_logs_by_patient(patient_id)
        return list(self._audit_chain)

    def verify_audit_chain(self) -> VerifyAuditChainResult:
        """Evaluates MedTrustContract:VerifyAuditChain query."""
        return VerifyAuditChainResult(super().verify_audit_chain())

    def verify_audit_chain_integrity(self) -> Tuple[bool, str]:
        """Compatibility method returning (is_intact, message)."""
        res = self.verify_audit_chain()
        return res["isIntact"], res["message"]


# Global singleton instance
fabric_gateway = FabricGatewayAdapter()


def get_active_gateway() -> FabricGatewayAdapter:
    """Returns the active gateway adapter."""
    return fabric_gateway
