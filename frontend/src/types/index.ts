export type UserRole = 'PATIENT' | 'DOCTOR' | 'AUDITOR' | 'ADMIN';
export type AppView = 'LANDING' | 'LOGIN' | 'PATIENT' | 'DOCTOR' | 'AUDITOR' | 'ADMIN';
export type ActiveView = 'LANDING' | 'LOGIN' | UserRole;

export interface UserProfile {
  id: string;
  name: string;
  role: UserRole;
  email: string;
  hospital?: string;
  specialty?: string;
}

export interface UserSummary {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  hospital?: string;
  specialty?: string;
  licenseNumber?: string;
  approvalStatus?: string;
  isActive: boolean;
  createdAt?: string;
}

export interface AdminTelemetry {
  totalUsers: number;
  activeUsers: number;
  activeSessions: number;
  roleCounts: {
    patient: number;
    doctor: number;
    auditor: number;
    admin: number;
  };
  privacyBoundaryEnforced: boolean;
  adminClinicalAccessBanned: boolean;
}

export type RecordType = 
  | 'LAB_REPORT' 
  | 'PRESCRIPTION' 
  | 'IMAGING_MRI' 
  | 'IMAGING_XRAY' 
  | 'CLINICAL_SUMMARY' 
  | 'GENOMIC_DATA'
  | (string & {});

export interface MedicalRecord {
  id: string;
  patientId: string;
  patientName: string;
  title: string;
  recordType: RecordType;
  ipfsCid: string; // Real IPFS Kubo CID hash
  fileSize: string;
  mimeType: string;
  createdAt: string;
  createdByDoctor?: string;
  hospital: string;
  encryptionAlgorithm: 'AES-256-GCM';
  keyFingerprint: string;
  checksumSha256?: string;
  txHash?: string;
}

export type ConsentStatus = 'ACTIVE' | 'PENDING' | 'REVOKED' | 'EXPIRED';

export interface ConsentRecord {
  id: string;
  patientId: string;
  doctorId: string;
  doctorName: string;
  hospital: string;
  specialty: string;
  purpose: string;
  status: ConsentStatus;
  allowedRecordTypes: RecordType[] | 'ALL';
  grantedAt: string;
  expiresAt: string;
  txHash: string; // Fabric transaction ID
}

export interface AccessLog {
  id: string;
  timestamp: string;
  actorId: string;
  actorName: string;
  actorRole: UserRole;
  action: 'VIEW' | 'DOWNLOAD' | 'REQUEST_CONSENT' | 'REVOKE_CONSENT' | 'GRANT_CONSENT' | 'UPLOAD_RECORD';
  recordId?: string;
  recordTitle?: string;
  purpose: string;
  txHash: string; // Hyperledger Fabric TxID
  status: 'SUCCESS' | 'DENIED';
  prevHash?: string;
  entryHash?: string;
}

export interface ConsentRequestPayload {
  patientId: string;
  doctorId: string;
  purpose: string;
  durationDays: number;
  allowedRecordTypes: RecordType[];
}

export type RecordVerifyStatus =
  | 'VERIFIED'
  | 'CHECKSUM_MISMATCH'
  | 'IPFS_UNAVAILABLE'
  | 'LEDGER_UNAVAILABLE'
  | string;

export interface RecordVerifyResponse {
  recordId: string;
  ipfsCid: string;
  checksumMatches: boolean;
  ledgerChecksum: string;
  computedSha256: string;
  status: RecordVerifyStatus;
  detail: string;
}

export interface RecordDetailResponse {
  id: string;
  recordId: string;
  patientId: string;
  description?: string | null;
  prescriptionCid?: string | null;
  prescriptionFilename?: string | null;
  prescriptionChecksum?: string | null;
  hasDocument: boolean;
  documentFilename?: string | null;
  documentMimeType?: string | null;
  createdAt: string;
}

export interface RecordUploadPayload {
  patientId: string;
  patientName?: string;
  title: string;
  recordType: RecordType;
  hospital: string;
  file?: File | null;
  description?: string | null;
  prescriptionFile?: File | null;
}

export interface ConsentVerifyResponse {
  allowed: boolean;
  reason: string;
  consentId?: string | null;
}

export interface AuditIntegrityResponse {
  chainIntact: boolean;
  message: string;
}

export interface HealthCheckResponse {
  online: boolean;
  version?: string;
  status?: string;
  ipfsStatus?: string;
  fabricStatus?: string;
}

// --- Doctor Application & Review Types ---

export interface DoctorApplicationRequest {
  name: string;
  email: string;
  password: string;
  hospital: string;
  specialty: string;
  licenseNumber: string;
}

export interface DoctorApplicationResponse {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  hospital?: string;
  specialty?: string;
  licenseNumber: string;
  approvalStatus: 'PENDING' | 'APPROVED' | 'REJECTED' | string;
  appliedAt?: string;
  message: string;
}

export interface DoctorApplicationSummary {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  hospital?: string;
  specialty?: string;
  licenseNumber?: string;
  approvalStatus: 'PENDING' | 'APPROVED' | 'REJECTED' | string;
  isActive: boolean;
  appliedAt?: string | null;
  reviewedAt?: string | null;
  reviewedBy?: string | null;
  rejectionReason?: string | null;
}

export interface DoctorApplicationActionResponse {
  success: boolean;
  id: string;
  name: string;
  email: string;
  approvalStatus: string;
  isActive: boolean;
  reviewedBy: string;
  reviewedAt: string;
  rejectionReason?: string | null;
  message: string;
}

