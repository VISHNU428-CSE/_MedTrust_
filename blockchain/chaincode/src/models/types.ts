/**
 * MedTrust Hyperledger Fabric Domain Models & State Types
 * Enforces Zero PHI, deterministic state representations, and tamper-evident auditing.
 */

export enum ConsentStatus {
  PENDING = 'PENDING',
  APPROVED = 'APPROVED',
  REJECTED = 'REJECTED',
  REVOKED = 'REVOKED',
  EXPIRED = 'EXPIRED'
}

export type ActorRole = 'PATIENT' | 'DOCTOR' | 'AUDITOR' | 'SYSTEM' | 'ADMIN';

export type AccessStatus = 'ALLOWED' | 'DENIED' | 'RECORDED';

export interface ConsentRecord {
  docType: 'consent';
  consentId: string;
  patientId: string;
  doctorId: string;
  allowedRecordTypes: string[]; // e.g. ["LAB_REPORT", "CARDIOLOGY_VISIT"] or ["ALL"]
  status: ConsentStatus;
  validUntil: number; // Unix timestamp in seconds
  createdAt: number;
  updatedAt: number;
  approvedAt?: number;
  revokedAt?: number;
  rejectedAt?: number;
  purpose?: string;
}

export interface MedicalRecordMetadata {
  docType: 'record_metadata';
  recordId: string;
  patientId: string;
  ipfsCid: string; // Multihash/CIDv1 string pointing to encrypted IPFS storage
  checksum: string; // Hexadecimal SHA-256 cryptographic digest of raw record bytes
  recordType: string; // e.g. "LAB_REPORT", "CARDIOLOGY_VISIT", "RADIOLOGY_REPORT"
  facility: string; // Originating clinic / hospital / lab name
  timestamp: number; // Registration unix timestamp in seconds
  registeredBy: string; // Actor ID or client certificate subject
  metadataVersion: number;
}

export interface AuditLogEntry {
  docType: 'audit_entry';
  seq: number;
  timestamp: number;
  eventType: string; // e.g. "DOCTOR_RECORD_READ", "CONSENT_REVOKED", "RECORD_REGISTERED"
  actorId: string;
  actorRole: ActorRole | string;
  targetPatientId: string;
  recordId?: string;
  consentId?: string;
  status: AccessStatus;
  detail: string;
  prevHash: string;
  entryHash: string;
}

export interface VerifyConsentResult {
  allowed: boolean;
  reason:
    | 'CONSENT_ACTIVE'
    | 'NO_CONSENT_FOUND'
    | 'CONSENT_REVOKED'
    | 'CONSENT_EXPIRED'
    | 'CONSENT_SCOPE_EXCLUDED'
    | 'CONSENT_PENDING'
    | 'CONSENT_REJECTED';
  consentId?: string;
  validUntil?: number;
  allowedRecordTypes?: string[];
}

export interface AuditChainVerificationResult {
  isIntact: boolean;
  entryCount: number;
  lastHash: string;
  message: string;
  brokenIndex?: number;
}
