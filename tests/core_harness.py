"""
Core Test Harness & Verification Engines for MedTrust QA.

Implements the contract models, verification rules, tamper-detection logic,
consent state machine, and cryptographic audit log chain.
"""

import hashlib
import json
import time
from typing import Dict, Any, List, Optional, Tuple


class ChecksumMismatchError(Exception):
    """Raised when IPFS content digest does not match the ledger registered checksum."""
    pass


class AccessDeniedError(Exception):
    """Raised when RBAC or Consent authorization check fails."""
    def __init__(self, message: str, code: int = 403, reason: str = "FORBIDDEN"):
        super().__init__(message)
        self.code = code
        self.reason = reason


class MockIPFSNode:
    """
    Simulates IPFS (Kubo) storage and retrieval behavior.
    Enforces CID addressing and enables simulating tampering / bit flips.
    """
    def __init__(self):
        self._storage: Dict[str, bytes] = {}

    def pin_content(self, cid: str, content: bytes) -> str:
        """Stores content under CID."""
        self._storage[cid] = content
        return cid

    def retrieve_content(self, cid: str) -> bytes:
        """Retrieves raw content by CID."""
        if cid not in self._storage:
            raise KeyError(f"IPFS CID not found: {cid}")
        return self._storage[cid]

    def simulate_tampering(self, cid: str, tampered_content: bytes) -> None:
        """Simulates MITM corruption or storage bit rot/tampering."""
        self._storage[cid] = tampered_content


class IPFSVerifier:
    """
    Verifies IPFS retrieved content against the tamper-proof ledger checksum.
    """
    def __init__(self, ipfs_node: MockIPFSNode):
        self.ipfs_node = ipfs_node

    def fetch_and_verify(self, cid: str, expected_sha256: str) -> bytes:
        """
        Retrieves payload from IPFS and rigorously verifies SHA-256 integrity.
        Raises ChecksumMismatchError on tampering.
        """
        raw_bytes = self.ipfs_node.retrieve_content(cid)
        actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        if actual_sha256.lower() != expected_sha256.lower():
            raise ChecksumMismatchError(
                f"CRITICAL SECURITY ALERT: Checksum mismatch for CID {cid}! "
                f"Expected {expected_sha256}, calculated {actual_sha256}. "
                "Data has been tampered with or corrupted in transit!"
            )
        return raw_bytes


class ConsentEngine:
    """
    Simulates the Hyperledger Fabric Consent Management Smart Contract.
    Enforces atomic transitions: ACTIVE -> REVOKED.
    """
    def __init__(self):
        # Key: consent_id -> Consent Dict
        self._consents: Dict[str, Dict[str, Any]] = {}

    def grant_consent(
        self,
        consent_id: str,
        patient_id: str,
        doctor_id: str,
        allowed_record_types: List[str],
        valid_until_epoch: int
    ) -> Dict[str, Any]:
        """Patient grants time-bound, scoped access to a doctor."""
        consent = {
            "consent_id": consent_id,
            "patient_id": patient_id,
            "doctor_id": doctor_id,
            "allowed_record_types": allowed_record_types,  # e.g. ["LAB_REPORT"] or ["ALL"]
            "valid_until": valid_until_epoch,
            "status": "ACTIVE",
            "created_at": int(time.time()),
            "revoked_at": None
        }
        self._consents[consent_id] = consent
        return consent

    def revoke_consent(self, consent_id: str, requesting_patient_id: str) -> Dict[str, Any]:
        """Patient revokes active consent with immediate effect."""
        if consent_id not in self._consents:
            raise KeyError(f"Consent record {consent_id} not found")

        consent = self._consents[consent_id]
        if consent["patient_id"] != requesting_patient_id:
            raise AccessDeniedError(
                f"Patient {requesting_patient_id} is not authorized to revoke consent {consent_id} owned by {consent['patient_id']}",
                code=403,
                reason="REVOCATION_OWNERSHIP_VIOLATION"
            )

        consent["status"] = "REVOKED"
        consent["revoked_at"] = int(time.time())
        return consent

    def check_access_permission(
        self,
        doctor_id: str,
        patient_id: str,
        record_type: str
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Evaluates whether a doctor has legitimate, active consent to access patient's record.
        Returns: (is_allowed, reason, consent_id)
        """
        matching_consents = [
            c for c in self._consents.values()
            if c["patient_id"] == patient_id and c["doctor_id"] == doctor_id
        ]

        if not matching_consents:
            return False, "NO_CONSENT_FOUND", None

        # Check latest relevant consent
        for consent in reversed(matching_consents):
            if consent["status"] == "REVOKED":
                return False, "CONSENT_REVOKED", consent["consent_id"]

            if time.time() > consent["valid_until"]:
                return False, "CONSENT_EXPIRED", consent["consent_id"]

            if "ALL" in consent["allowed_record_types"] or record_type in consent["allowed_record_types"]:
                return True, "CONSENT_ACTIVE", consent["consent_id"]
            else:
                return False, "CONSENT_SCOPE_EXCLUDED", consent["consent_id"]

        return False, "NO_ACTIVE_CONSENT", None


class AuditTrailLedger:
    """
    Implements a tamper-evident, cryptographic hash-chained audit trail.
    Every read, grant, revocation, or denied access attempt is recorded.
    """
    def __init__(self):
        self.entries: List[Dict[str, Any]] = []
        self._prev_hash: str = "GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000"

    def log_event(
        self,
        event_type: str,
        actor_id: str,
        actor_role: str,
        target_patient_id: str,
        record_id: Optional[str],
        consent_id: Optional[str],
        status: str,  # ALLOWED | DENIED
        detail: str
    ) -> Dict[str, Any]:
        """Appends an immutable audit log entry."""
        entry_data = {
            "seq": len(self.entries) + 1,
            "timestamp": time.time(),
            "event_type": event_type,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "target_patient_id": target_patient_id,
            "record_id": record_id,
            "consent_id": consent_id,
            "status": status,
            "detail": detail,
            "prev_hash": self._prev_hash
        }
        # Compute SHA-256 hash of this entry
        serialized = json.dumps(entry_data, sort_keys=True).encode("utf-8")
        entry_hash = hashlib.sha256(serialized).hexdigest()
        entry_data["entry_hash"] = entry_hash

        self.entries.append(entry_data)
        self._prev_hash = entry_hash
        return entry_data

    def verify_chain_integrity(self) -> Tuple[bool, str]:
        """
        Mathematically verifies the integrity of the audit hash chain.
        Returns: (is_intact, error_message)
        """
        expected_prev = "GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000"
        for i, entry in enumerate(self.entries):
            if entry["prev_hash"] != expected_prev:
                return False, f"Broken chain link at index {i}: expected prev_hash {expected_prev}, found {entry['prev_hash']}"

            # Recompute entry hash
            payload_to_verify = dict(entry)
            stored_hash = payload_to_verify.pop("entry_hash")
            recomputed = hashlib.sha256(json.dumps(payload_to_verify, sort_keys=True).encode("utf-8")).hexdigest()
            if stored_hash != recomputed:
                return False, f"Corrupted entry hash at index {i}: stored {stored_hash}, computed {recomputed}"

            expected_prev = stored_hash

        return True, "Chain is cryptographically intact and unbroken."


class RBACAuthorizer:
    """
    Enforces MedTrust endpoint authorization and access rules.
    """
    def __init__(self, consent_engine: ConsentEngine, audit_ledger: AuditTrailLedger):
        self.consent_engine = consent_engine
        self.audit = audit_ledger

    def authorize_record_access(
        self,
        token_payload: Dict[str, Any],
        target_patient_id: str,
        record_id: str,
        record_type: str
    ) -> bool:
        """
        Evaluates token claims and consent to determine if access is permitted.
        Logs every attempt to the audit ledger.
        """
        actor_id = token_payload.get("sub", "UNKNOWN")
        actor_role = token_payload.get("role", "ANONYMOUS")

        # 1. Patient self-access
        if actor_role == "PATIENT":
            if actor_id == target_patient_id:
                self.audit.log_event(
                    event_type="PATIENT_SELF_READ",
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_patient_id=target_patient_id,
                    record_id=record_id,
                    consent_id=None,
                    status="ALLOWED",
                    detail="Patient accessed their own medical record"
                )
                return True
            else:
                self.audit.log_event(
                    event_type="HORIZONTAL_ACCESS_ATTEMPT",
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_patient_id=target_patient_id,
                    record_id=record_id,
                    consent_id=None,
                    status="DENIED",
                    detail="Unauthorized horizontal access: Patient attempted to access another patient's record"
                )
                raise AccessDeniedError(
                    f"Access Denied: Patient {actor_id} cannot access records of patient {target_patient_id}",
                    code=403,
                    reason="UNAUTHORIZED_HORIZONTAL_ACCESS"
                )

        # 2. Doctor access requires active consent
        elif actor_role == "DOCTOR":
            allowed, reason, consent_id = self.consent_engine.check_access_permission(
                doctor_id=actor_id,
                patient_id=target_patient_id,
                record_type=record_type
            )
            if allowed:
                self.audit.log_event(
                    event_type="DOCTOR_RECORD_READ",
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_patient_id=target_patient_id,
                    record_id=record_id,
                    consent_id=consent_id,
                    status="ALLOWED",
                    detail=f"Doctor accessed record under active consent {consent_id}"
                )
                return True
            else:
                self.audit.log_event(
                    event_type="DOCTOR_UNAUTHORIZED_READ",
                    actor_id=actor_id,
                    actor_role=actor_role,
                    target_patient_id=target_patient_id,
                    record_id=record_id,
                    consent_id=consent_id,
                    status="DENIED",
                    detail=f"Access denied to doctor {actor_id}: {reason}"
                )
                raise AccessDeniedError(
                    f"Access Denied: Doctor {actor_id} has no valid consent for patient {target_patient_id} ({reason})",
                    code=403,
                    reason=reason
                )

        # 3. Any other role
        else:
            self.audit.log_event(
                event_type="UNAUTHORIZED_ROLE_ACCESS",
                actor_id=actor_id,
                actor_role=actor_role,
                target_patient_id=target_patient_id,
                record_id=record_id,
                consent_id=None,
                status="DENIED",
                detail=f"Role {actor_role} is not permitted to access patient clinical records"
            )
            raise AccessDeniedError(
                f"Access Denied: Role {actor_role} is not authorized to read medical records",
                code=403,
                reason="INVALID_ROLE"
            )
