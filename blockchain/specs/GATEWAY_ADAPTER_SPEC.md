# MedTrust Hyperledger Fabric Chaincode & Gateway Adapter Specification
**Author:** Kelly (`kelly-mv4swsb3`) — MedTrust Blockchain Developer  
**Target:** Pramod (`backend-pramod-mv4st3jp`) — FastAPI Backend Developer & Surya (`qa-surya-mv4szm5i`) — QA & Security  
**Network Channel:** `medtrust-channel`  
**Chaincode Name:** `medtrust-contract`  
**Primary Contract:** `MedTrustContract`  

---

## 1. Architecture Overview

MedTrust uses Hyperledger Fabric v2.5 to provide an immutable, decentralized ledger for:
1. **Patient Consent Management:** Fine-grained, time-bound, scoped patient permissions with immediate atomic revocation.
2. **Medical Record Metadata:** Anchors encrypted IPFS content CIDs and SHA-256 integrity digests with **ZERO PHI** on-chain.
3. **Access Audit Trail:** Append-only cryptographic hash chain (`prevHash` -> `entryHash`) recording all read attempts, grants, and revocations for non-repudiation.

```
+-----------------------------------------------------------------------------------+
|                            MedTrust Backend (FastAPI)                             |
|                           [Pramod - Gateway Adapter]                              |
+-----------------------------------------------------------------------------------+
                                    |
                gRPC / Fabric Gateway Connection Profile
                                    v
+-----------------------------------------------------------------------------------+
|                  Hyperledger Fabric Channel: medtrust-channel                     |
|                      Chaincode: medtrust-contract                                 |
+-----------------------------------------------------------------------------------+
|  1. Patient Consent       |  2. Record Metadata        |  3. Audit Trail Ledger   |
|  - RequestConsent         |  - RegisterRecord          |  - LogAccessEvent        |
|  - GrantConsent           |  - GetRecord               |  - GetAuditLogsByPatient |
|  - RejectConsent          |  - GetRecordsByPatient     |  - GetAuditLogsByActor   |
|  - RevokeConsent          |  - VerifyRecordChecksum    |  - VerifyAuditChain      |
|  - VerifyConsent          |                            |                          |
|  - GetConsent / Patient   |                            |                          |
+-----------------------------------------------------------------------------------+
```

---

## 2. Smart Contract Interface Definitions

All methods are exposed via contract `MedTrustContract` (or their individual contracts).

### 2.1 Consent Management (`ConsentContract` / `MedTrustContract`)

#### A. `RequestConsent`
Clinician or doctor requests access to specific categories of records from a patient.
- **Type:** Transaction (Invoke)
- **Method:** `MedTrustContract:RequestConsent`
- **Arguments:**
  | Argument | Type | Description | Example |
  | :--- | :--- | :--- | :--- |
  | `consentId` | string | Unique consent identifier | `"CONSENT-ALICE-SMITH-001"` |
  | `patientId` | string | Pseudonymous patient ID | `"SYNTH-PAT-001"` |
  | `doctorId` | string | Clinician / Doctor ID | `"SYNTH-DOC-101"` |
  | `allowedRecordTypesJson` | string (JSON array) | Allowed record types | `'["LAB_REPORT"]'` or `'["ALL"]'` |
  | `validUntilEpoch` | string / number | Expiration timestamp in seconds | `"1760336400"` |
  | `purpose` | string | Reason for request | `"Annual physical and metabolic review"` |
- **Initial State:** `PENDING`
- **Response:** JSON string of `ConsentRecord`

#### B. `GrantConsent`
Patient approves a pending request, or directly grants new scoped access.
- **Type:** Transaction (Invoke)
- **Method:** `MedTrustContract:GrantConsent`
- **Arguments:**
  | Argument | Type | Description | Example |
  | :--- | :--- | :--- | :--- |
  | `consentId` | string | Target consent identifier | `"CONSENT-ALICE-SMITH-001"` |
  | `patientId` | string | Patient granting consent (must match owner) | `"SYNTH-PAT-001"` |
  | `doctorId` | string | (Optional if approving pending) Doctor ID | `"SYNTH-DOC-101"` |
  | `allowedRecordTypesJson` | string | (Optional if approving pending) Record types | `'["LAB_REPORT"]'` |
  | `validUntilEpoch` | string / number | (Optional if approving pending) Expiration | `"1760336400"` |
  | `purpose` | string | (Optional) Notes | `""` |
- **State Transition:** `PENDING` -> `APPROVED`
- **Response:** JSON string of `ConsentRecord` (Status: `APPROVED`)

#### C. `RejectConsent`
Patient declines a pending consent request.
- **Type:** Transaction (Invoke)
- **Method:** `MedTrustContract:RejectConsent`
- **Arguments:** `consentId`, `patientId`, `reason`
- **State Transition:** `PENDING` -> `REJECTED`

#### D. `RevokeConsent`
Patient immediately revokes an active consent. Takes effect instantly with zero delay.
- **Type:** Transaction (Invoke)
- **Method:** `MedTrustContract:RevokeConsent`
- **Arguments:**
  | Argument | Type | Description |
  | :--- | :--- | :--- |
  | `consentId` | string | Consent identifier |
  | `requestingPatientId` | string | Caller patient ID (Enforces ownership) |
- **Security Check:** If `consent.patientId != requestingPatientId`, throws `REVOCATION_OWNERSHIP_VIOLATION`.
- **State Transition:** `APPROVED` -> `REVOKED`
- **Response:** JSON string of `ConsentRecord` (Status: `REVOKED`, `revokedAt`: timestamp)

#### E. `VerifyConsent`
Real-time authorization check used by backend gateway before fetching encrypted IPFS files.
- **Type:** Query (Evaluate)
- **Method:** `MedTrustContract:VerifyConsent`
- **Arguments:**
  | Argument | Type | Description | Example |
  | :--- | :--- | :--- | :--- |
  | `doctorId` | string | Doctor requesting access | `"SYNTH-DOC-101"` |
  | `patientId` | string | Target patient | `"SYNTH-PAT-001"` |
  | `recordType` | string | Record category requested | `"LAB_REPORT"` |
- **Response JSON:**
  ```json
  {
    "allowed": true,
    "reason": "CONSENT_ACTIVE",
    "consentId": "CONSENT-ALICE-SMITH-001",
    "validUntil": 1760336400,
    "allowedRecordTypes": ["LAB_REPORT"]
  }
  ```
  Possible reasons:
  - `CONSENT_ACTIVE`: Access permitted.
  - `NO_CONSENT_FOUND`: No record found between doctor and patient.
  - `CONSENT_REVOKED`: Access revoked by patient.
  - `CONSENT_EXPIRED`: Current time exceeds `validUntil`.
  - `CONSENT_SCOPE_EXCLUDED`: Doctor granted other types, but not this `recordType`.
  - `CONSENT_PENDING`: Consent requested but patient has not approved yet.
  - `CONSENT_REJECTED`: Consent was rejected by patient.

---

### 2.2 Medical Record Metadata (`MedicalRecordContract` / `MedTrustContract`)

#### A. `RegisterRecord`
Registers cryptographic metadata after backend pins encrypted payload to IPFS.
- **Type:** Transaction (Invoke)
- **Method:** `MedTrustContract:RegisterRecord`
- **Arguments:**
  | Argument | Type | Description | Example |
  | :--- | :--- | :--- | :--- |
  | `recordId` | string | Record identifier | `"REC-LAB-ALICE-001"` |
  | `patientId` | string | Patient owner | `"SYNTH-PAT-001"` |
  | `ipfsCid` | string | IPFS multihash CID | `"bafybeimdt7318a47402636a2829210medtrust"` |
  | `checksum` | string | SHA-256 hex digest (64 chars) | `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"` |
  | `recordType` | string | Category | `"LAB_REPORT"` |
  | `facility` | string | Originating institution | `"Synthetic General Hospital"` |
  | `registeredBy` | string | Submitting actor/doctor | `"SYNTH-DOC-101"` |
- **Compliance Enforcement:** Validates `assertZeroPHI` (no SSNs, no raw notes, no passwords).
- **Response:** JSON string of `MedicalRecordMetadata`.

#### B. `GetRecord`
- **Type:** Query
- **Method:** `MedTrustContract:GetRecord`
- **Arguments:** `recordId`
- **Response:** `MedicalRecordMetadata` JSON.

#### C. `GetRecordsByPatient`
- **Type:** Query
- **Method:** `MedTrustContract:GetRecordsByPatient`
- **Arguments:** `patientId`
- **Response:** JSON array of `MedicalRecordMetadata` objects.

#### D. `VerifyRecordChecksum`
- **Type:** Query
- **Method:** `MedTrustContract:VerifyRecordChecksum`
- **Arguments:** `recordId`, `calculatedChecksum`
- **Response JSON:**
  ```json
  {
    "verified": true,
    "recordId": "REC-LAB-ALICE-001",
    "expectedChecksum": "e3b0c442...",
    "calculatedChecksum": "e3b0c442...",
    "ipfsCid": "bafybeimdt...",
    "status": "VERIFIED_INTACT" // or "CHECKSUM_MISMATCH"
  }
  ```

---

### 2.3 Access Audit Trail (`AuditTrailContract` / `MedTrustContract`)

#### A. `LogAccessEvent`
Appends a tamper-evident audit record cryptographically linked to the previous entry hash.
- **Type:** Transaction (Invoke)
- **Method:** `MedTrustContract:LogAccessEvent`
- **Arguments:**
  - `eventType`: string (e.g. `"DOCTOR_RECORD_READ"`, `"CONSENT_REVOCATION"`, `"HORIZONTAL_ACCESS_ATTEMPT"`)
  - `actorId`: string
  - `actorRole`: string (`"PATIENT"` | `"DOCTOR"` | `"AUDITOR"` | `"SYSTEM"`)
  - `targetPatientId`: string
  - `recordId`: string (optional)
  - `consentId`: string (optional)
  - `status`: string (`"ALLOWED"` | `"DENIED"` | `"RECORDED"`)
  - `detail`: string
- **Hash Chaining:**
  - `entry[0].prevHash` = `"GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000"`
  - `entry[i].prevHash` = `entry[i-1].entryHash`
  - `entryHash` = `SHA-256(canonicalJson(entryWithoutHash))`

#### B. `GetAuditLogsByPatient`
- **Type:** Query
- **Arguments:** `patientId`
- **Response:** Array of audit events for patient compliance review.

#### C. `VerifyAuditChain`
- **Type:** Query
- **Arguments:** None
- **Response:**
  ```json
  {
    "isIntact": true,
    "entryCount": 14,
    "lastHash": "73e9...",
    "message": "Chain is cryptographically intact and unbroken."
  }
  ```

---

## 3. FastAPI Gateway Integration Example (Python)

Pramod can adapt this snippet in `backend/app/services/fabric_gateway.py`:

```python
import json
from typing import Dict, Any

class FabricGatewayAdapter:
    """
    Connects FastAPI backend to Hyperledger Fabric chaincode via connection profile.
    """
    def __init__(self, connection_profile_path: str, channel_name: str = "medtrust-channel", contract_name: str = "medtrust-contract"):
        self.connection_profile_path = connection_profile_path
        self.channel_name = channel_name
        self.contract_name = contract_name

    async def verify_consent(self, doctor_id: str, patient_id: str, record_type: str) -> Dict[str, Any]:
        """
        Queries Fabric chaincode to verify access authorization.
        """
        # Call fabric-gateway evaluateTransaction("MedTrustContract:VerifyConsent", doctor_id, patient_id, record_type)
        raw_result = await self._evaluate_tx("MedTrustContract:VerifyConsent", doctor_id, patient_id, record_type)
        return json.loads(raw_result)

    async def register_record_metadata(self, record_id: str, patient_id: str, ipfs_cid: str, checksum: str, record_type: str, facility: str, registered_by: str) -> Dict[str, Any]:
        """
        Submits transaction to register metadata on-chain.
        """
        raw_result = await self._submit_tx(
            "MedTrustContract:RegisterRecord",
            record_id, patient_id, ipfs_cid, checksum, record_type, facility, registered_by
        )
        return json.loads(raw_result)

    async def revoke_consent(self, consent_id: str, requesting_patient_id: str) -> Dict[str, Any]:
        """
        Submits revocation transaction on-chain with immediate atomic effect.
        """
        raw_result = await self._submit_tx("MedTrustContract:RevokeConsent", consent_id, requesting_patient_id)
        return json.loads(raw_result)

    async def log_audit_event(self, event_type: str, actor_id: str, actor_role: str, target_patient_id: str, record_id: str, consent_id: str, status: str, detail: str) -> Dict[str, Any]:
        """
        Appends entry to on-chain cryptographic audit trail.
        """
        raw_result = await self._submit_tx(
            "MedTrustContract:LogAccessEvent",
            event_type, actor_id, actor_role, target_patient_id, record_id or "", consent_id or "", status, detail
        )
        return json.loads(raw_result)
```

---

## 4. Security & Compliance Invariants
1. **Zero PHI On Ledger:** No patient names, dates of birth, plain clinical notes, raw scans, private keys, or credentials exist in state database. Only cryptographically verified CIDs and SHA-256 hashes.
2. **Immediate Revocation:** Once `RevokeConsent` is submitted, world state immediately marks the consent `REVOKED`. Subsequent calls to `VerifyConsent` fail with `CONSENT_REVOKED` without latency.
3. **Cross-Patient Isolation:** Only the owning patient (`consent.patientId`) can approve, reject, or revoke consent.
4. **Audit Immutability:** Audit trail uses deterministic SHA-256 hashing. Modifying or deleting any historical log entry breaks the cryptographic chain.
