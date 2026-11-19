import type { 
  MedicalRecord, 
  ConsentRecord, 
  AccessLog, 
  ConsentRequestPayload,
  UserProfile,
  UserRole,
  RecordVerifyResponse,
  RecordVerifyStatus,
  ConsentVerifyResponse,
  AuditIntegrityResponse,
  HealthCheckResponse,
  UserSummary,
  AdminTelemetry,
  RecordDetailResponse,
  RecordUploadPayload,
  DoctorApplicationRequest,
  DoctorApplicationResponse,
  DoctorApplicationSummary,
  DoctorApplicationActionResponse
} from '../types';

const API_BASE_URL = (import.meta as { env?: { VITE_API_BASE_URL?: string } })?.env?.VITE_API_BASE_URL || 'http://localhost:8001/api/v1';

export const DEMO_PATIENT: UserProfile = {
  id: 'pat-984210',
  name: 'Eleanor Vance',
  role: 'PATIENT',
  email: 'e.vance@example.med',
};

export const DEMO_DOCTOR: UserProfile = {
  id: 'doc-331902',
  name: 'Dr. Marcus Sterling, MD',
  role: 'DOCTOR',
  email: 'm.sterling@metrohealth.org',
  hospital: 'Metro General Hospital',
  specialty: 'Cardiovascular Surgery',
};

export const DEMO_AUDITOR: UserProfile = {
  id: 'aud-001001',
  name: 'Federal Compliance Auditor',
  role: 'AUDITOR',
  email: 'auditor@medtrust.gov',
  hospital: 'Office of the National Coordinator',
  specialty: 'HIPAA & Consent Oversight',
};

export const DEMO_ADMIN: UserProfile = {
  id: 'adm-999999',
  name: 'Platform Administrator',
  role: 'ADMIN',
  email: 'admin@medtrust.org',
  hospital: 'MedTrust Governance HQ',
  specialty: 'Infrastructure & Security Oversight',
};

export const DEMO_CREDENTIALS: Record<UserRole, { email: string; password: string; name: string; label: string }> = {
  PATIENT: { email: 'e.vance@example.med', password: 'password123', name: 'Eleanor Vance', label: 'Patient Vault' },
  DOCTOR: { email: 'm.sterling@metrohealth.org', password: 'password123', name: 'Dr. Marcus Sterling, MD', label: 'Doctor Clinical Portal' },
  ADMIN: { email: 'admin@medtrust.org', password: 'admin123', name: 'Platform Administrator', label: 'Administrator Console' },
  AUDITOR: { email: 'auditor@medtrust.gov', password: 'password123', name: 'Federal Compliance Auditor', label: 'Compliance Audit Ledger' },
};

export const INITIAL_RECORDS: MedicalRecord[] = [
  {
    id: 'rec-001',
    patientId: 'pat-984210',
    patientName: 'Eleanor Vance',
    title: 'Echocardiogram Comprehensive Diagnostic Report',
    recordType: 'IMAGING_MRI',
    ipfsCid: 'bafkreiajkhnxasfkrk67gw3duvtupx2gbc7b5kfs52vhgrgo3adbk5rm54',
    fileSize: '4.8 MB',
    mimeType: 'application/pdf',
    createdAt: '2026-09-28T14:32:00Z',
    createdByDoctor: 'Dr. Marcus Sterling, MD',
    hospital: 'Metro General Hospital',
    encryptionAlgorithm: 'AES-256-GCM',
    keyFingerprint: 'SHA256:20e9c1985f3becb5...3cba',
    checksumSha256: '0951db7048aa8abdf35b63a56747df4608be1ea8b2eeaa7344ced80615762cef',
    txHash: '0x334901ba7162e91024b819203a7491bb4029183746112a9bc8301726a992014b',
  },
  {
    id: 'rec-002',
    patientId: 'pat-984210',
    patientName: 'Eleanor Vance',
    title: 'Comprehensive Lipid & Metabolic Panel (Lab Results)',
    recordType: 'LAB_REPORT',
    ipfsCid: 'bafkreictuhch5gilp2jxajuaapi65hmeh4tqs5swvdjnkvk74esryocdqq',
    fileSize: '1.2 MB',
    mimeType: 'application/pdf',
    createdAt: '2026-10-04T09:15:00Z',
    createdByDoctor: 'Dr. Sarah Lin, MD',
    hospital: 'Metro Labs & Diagnostics',
    encryptionAlgorithm: 'AES-256-GCM',
    keyFingerprint: 'SHA256:e7ec067240f521b0...dd24',
    checksumSha256: '53a1c47e990b7e9370268003d1ee9d843f27097656a8d2d5555fe1251c384384',
    txHash: '0x4f82bc7190de1249fa6b2194c730e1bb45920b784a9382fec32104d49a712c98',
  },
  {
    id: 'rec-003',
    patientId: 'pat-984210',
    patientName: 'Eleanor Vance',
    title: 'Cardiac Post-Operative Treatment & Prescription Regimen',
    recordType: 'PRESCRIPTION',
    ipfsCid: 'bafkreia3ptjqohjrgx7vxpefcr56dlgudoohqfgqzqu7w4lo3w4ycjriny',
    fileSize: '420 KB',
    mimeType: 'application/pdf',
    createdAt: '2026-10-08T11:45:00Z',
    createdByDoctor: 'Dr. Marcus Sterling, MD',
    hospital: 'Metro General Hospital',
    encryptionAlgorithm: 'AES-256-GCM',
    keyFingerprint: 'SHA256:58560c63e1ae1b55...db2c',
    checksumSha256: '1b7cd3071d3135ff5bbc85147be1acd41b9c7814d0cc29fb716eddb98126286e',
    txHash: '0x81ca293b6e8201fa84c98230bc7102ad99321481e839201fcbb9401726a831b1',
  },
];

export const INITIAL_CONSENTS: ConsentRecord[] = [
  {
    id: 'cst-8801',
    patientId: 'pat-984210',
    doctorId: 'doc-331902',
    doctorName: 'Dr. Marcus Sterling, MD',
    hospital: 'Metro General Hospital',
    specialty: 'Cardiovascular Surgery',
    purpose: 'Ongoing cardiovascular post-op observation & diagnostic follow-up',
    status: 'ACTIVE',
    allowedRecordTypes: 'ALL',
    grantedAt: '2026-09-29T10:00:00Z',
    expiresAt: '2026-12-31T23:59:59Z',
    txHash: '0x4f82bc7190de1249fa6b2194c730e1bb45920b784a9382fec32104d49a712c98',
  },
  {
    id: 'cst-8802',
    patientId: 'pat-984210',
    doctorId: 'doc-441209',
    doctorName: 'Dr. Nathan Drake, MD',
    hospital: 'St. Jude Neurology Center',
    specialty: 'Neurology Consultation',
    purpose: 'Elective migraine diagnostic assessment & historical MRI review',
    status: 'PENDING',
    allowedRecordTypes: ['IMAGING_MRI', 'CLINICAL_SUMMARY'],
    grantedAt: '2026-10-11T16:20:00Z',
    expiresAt: '2026-11-11T23:59:59Z',
    txHash: '0x81ca293b6e8201fa84c98230bc7102ad99321481e839201fcbb9401726a831b1',
  },
  {
    id: 'cst-8790',
    patientId: 'pat-984210',
    doctorId: 'doc-119283',
    doctorName: 'Dr. Clara Oswald, DDS',
    hospital: 'Apex Dental & Maxillofacial',
    specialty: 'Oral Surgery',
    purpose: 'Dental surgery pre-clearance consultation',
    status: 'REVOKED',
    allowedRecordTypes: ['LAB_REPORT'],
    grantedAt: '2026-08-10T08:00:00Z',
    expiresAt: '2026-09-10T23:59:59Z',
    txHash: '0x99281741bb82910fc38201948ba29031ca7192830491823abcbfa98210492104',
  },
];

export const INITIAL_AUDIT_LOGS: AccessLog[] = [
  {
    id: 'aud-9901',
    timestamp: '2026-10-12T06:14:22Z',
    actorId: 'doc-331902',
    actorName: 'Dr. Marcus Sterling, MD',
    actorRole: 'DOCTOR',
    action: 'VIEW',
    recordId: 'rec-001',
    recordTitle: 'Echocardiogram Comprehensive Diagnostic Report',
    purpose: 'Review of ejection fraction before medication titration',
    txHash: '0x12a9bc8301726a992014bca81923049182bbaf49201948271039840291837461',
    status: 'SUCCESS',
    prevHash: '7dfc7f2bf6757841a63d5e79f601182cc0d973d435e012971b06c572126b391a',
    entryHash: '2384aeb92a4e9c77b08355922554981b9d702e1a8d1e6518230dd30ef7e3ea2b',
  },
  {
    id: 'aud-9902',
    timestamp: '2026-10-11T16:20:00Z',
    actorId: 'doc-441209',
    actorName: 'Dr. Nathan Drake, MD',
    actorRole: 'DOCTOR',
    action: 'REQUEST_CONSENT',
    purpose: 'Elective migraine diagnostic assessment & historical MRI review',
    txHash: '0x81ca293b6e8201fa84c98230bc7102ad99321481e839201fcbb9401726a831b1',
    status: 'SUCCESS',
    prevHash: '5a95c2554af75672ab31441935fb2d8ca0bc5287de85d661600727c038ca17f4',
    entryHash: '7dfc7f2bf6757841a63d5e79f601182cc0d973d435e012971b06c572126b391a',
  },
  {
    id: 'aud-9903',
    timestamp: '2026-10-09T18:40:11Z',
    actorId: 'pat-984210',
    actorName: 'Eleanor Vance',
    actorRole: 'PATIENT',
    action: 'REVOKE_CONSENT',
    purpose: 'Revoked access for Dr. Clara Oswald after treatment completion',
    txHash: '0x99281741bb82910fc38201948ba29031ca7192830491823abcbfa98210492104',
    status: 'SUCCESS',
    prevHash: '4b39d4908ad36585f134730bbe92c353ba76263d1bb193835d9465d6e61ed5de',
    entryHash: '5a95c2554af75672ab31441935fb2d8ca0bc5287de85d661600727c038ca17f4',
  },
  {
    id: 'aud-9904',
    timestamp: '2026-10-08T11:45:00Z',
    actorId: 'doc-331902',
    actorName: 'Dr. Marcus Sterling, MD',
    actorRole: 'DOCTOR',
    action: 'UPLOAD_RECORD',
    recordId: 'rec-003',
    recordTitle: 'Cardiac Post-Operative Treatment & Prescription Regimen',
    purpose: 'Upload encrypted clinical discharge prescription',
    txHash: '0x334901ba7162e91024b819203a7491bb4029183746112a9bc8301726a992014b',
    status: 'SUCCESS',
    prevHash: 'GENESIS_BLOCK_HASH_0000000000000000000000000000000000000000',
    entryHash: '4b39d4908ad36585f134730bbe92c353ba76263d1bb193835d9465d6e61ed5de',
  },
];

class MedTrustApiService {
  private baseUrl = API_BASE_URL;
  private currentRole: UserRole = 'PATIENT';
  private tokens: Partial<Record<UserRole, string>> = {};
  private activeToken: string | null = null;
  private currentUser: UserProfile | null = null;

  setToken(token: string | null) {
    this.activeToken = token;
    if (typeof sessionStorage !== 'undefined') {
      if (token) {
        sessionStorage.setItem('medtrust_jwt', token);
      } else {
        sessionStorage.removeItem('medtrust_jwt');
      }
    }
  }

  getToken(): string | null {
    if (!this.activeToken && typeof sessionStorage !== 'undefined') {
      this.activeToken = sessionStorage.getItem('medtrust_jwt');
    }
    return this.activeToken;
  }

  setCurrentUser(user: UserProfile | null) {
    this.currentUser = user;
    if (typeof sessionStorage !== 'undefined') {
      if (user) {
        this.currentRole = user.role;
        sessionStorage.setItem('medtrust_user', JSON.stringify(user));
      } else {
        sessionStorage.removeItem('medtrust_user');
      }
    }
  }

  getSavedUser(): UserProfile | null {
    if (this.currentUser) return this.currentUser;
    if (typeof sessionStorage !== 'undefined') {
      const raw = sessionStorage.getItem('medtrust_user');
      if (raw) {
        try {
          this.currentUser = JSON.parse(raw);
          if (this.currentUser) this.currentRole = this.currentUser.role;
          return this.currentUser;
        } catch {
          return null;
        }
      }
    }
    return null;
  }

  // Unified production authentication
  async login(credentials: { email: string; password: string }): Promise<{ accessToken: string; user: UserProfile }> {
    const res = await fetch(`${this.baseUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Sign in failed with status ${res.status}`);
    }

    const data = await res.json();
    const token = data.accessToken || data.access_token;
    this.setToken(token);
    this.setCurrentUser(data.user);
    this.tokens[data.user.role as UserRole] = token;
    return { accessToken: token, user: data.user };
  }

  // Patient Self-Registration
  async register(payload: {
    name: string;
    email: string;
    password: string;
    hospital?: string;
    specialty?: string;
  }): Promise<{ accessToken: string; user: UserProfile }> {
    const res = await fetch(`${this.baseUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...payload,
        role: 'PATIENT',
      }),
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Registration failed with status ${res.status}`);
    }

    const data = await res.json();
    const token = data.accessToken || data.access_token;
    this.setToken(token);
    this.setCurrentUser(data.user);
    this.tokens[data.user.role as UserRole] = token;
    return { accessToken: token, user: data.user };
  }

  // Doctor Registration / Credential Application (ZERO token issued, PENDING state)
  async registerDoctor(payload: DoctorApplicationRequest): Promise<DoctorApplicationResponse> {
    const res = await fetch(`${this.baseUrl}/auth/register-doctor`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Doctor application failed with status ${res.status}`);
    }

    return await res.json();
  }

  async logout(): Promise<void> {
    const token = this.getToken();
    if (token) {
      try {
        await fetch(`${this.baseUrl}/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(3000),
        });
      } catch {
        // Safe client teardown regardless
      }
    }
    this.setToken(null);
    this.setCurrentUser(null);
    this.tokens = {};
  }

  async recoverPassword(email: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch(`${this.baseUrl}/auth/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || 'Recovery request rejected');
    }
    return await res.json();
  }

  async getMe(): Promise<UserProfile> {
    const token = this.getToken();
    if (!token) throw new Error('Unauthenticated');
    const res = await fetch(`${this.baseUrl}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) {
      this.logout();
      throw new Error('Session invalid or expired');
    }
    const user = await res.json();
    this.setCurrentUser(user);
    return user;
  }

  // Dynamic role authentication fallback for legacy demo modes
  async authenticateForRole(role: UserRole): Promise<string | null> {
    this.currentRole = role;
    if (this.tokens[role]) {
      return this.tokens[role]!;
    }
    const creds = DEMO_CREDENTIALS[role];
    if (!creds) return null;
    try {
      const res = await fetch(`${this.baseUrl}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(creds),
        signal: AbortSignal.timeout(2500),
      });
      if (res.ok) {
        const data = await res.json();
        this.tokens[role] = data.accessToken;
        this.setToken(data.accessToken);
        this.setCurrentUser(data.user);
        return data.accessToken;
      }
    } catch {
      // In offline / fallback mode
    }
    return null;
  }

  private getAuthHeaders(role?: UserRole): Record<string, string> {
    const active = this.getToken();
    if (active) {
      return { Authorization: `Bearer ${active}` };
    }
    const targetRole = role || this.currentRole;
    const token = this.tokens[targetRole];
    if (token) {
      return { Authorization: `Bearer ${token}` };
    }
    return {};
  }

  // Real backend health inspection
  async checkHealth(): Promise<HealthCheckResponse> {
    try {
      const res = await fetch(`${this.baseUrl}/health`, { method: 'GET', signal: AbortSignal.timeout(5000) });
      if (res.ok) {
        const data = await res.json();
        return { 
          online: true, 
          version: data.version || 'v1.0.0',
          status: data.status || 'healthy',
          ipfsStatus: data.ipfsStatus,
          fabricStatus: data.fabricStatus,
        };
      }
      return { online: false };
    } catch {
      return { online: false };
    }
  }

  // Fetch patient medical records
  async getRecords(patientId?: string): Promise<MedicalRecord[]> {
    try {
      const url = patientId ? `${this.baseUrl}/records?patient_id=${patientId}` : `${this.baseUrl}/records`;
      const res = await fetch(url, { 
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(3000) 
      });
      if (res.ok) {
        return await res.json();
      }
      throw new Error(`Server returned ${res.status}`);
    } catch {
      return INITIAL_RECORDS.filter(r => !patientId || r.patientId === patientId);
    }
  }

  // Upload record with multi-input support (document, clinical description, prescription attachment)
  async uploadRecord(payload: RecordUploadPayload): Promise<{ success: boolean; record?: MedicalRecord; details?: RecordDetailResponse; error?: string }> {
    try {
      const formData = new FormData();
      formData.append('patient_id', payload.patientId);
      if (payload.patientName) {
        formData.append('patient_name', payload.patientName);
      }
      formData.append('title', payload.title);
      formData.append('record_type', payload.recordType);
      formData.append('hospital', payload.hospital);
      if (payload.file) {
        formData.append('file', payload.file);
      }
      if (payload.description && payload.description.trim()) {
        formData.append('description', payload.description.trim());
      }
      if (payload.prescriptionFile) {
        formData.append('prescription_file', payload.prescriptionFile);
      }

      const res = await fetch(`${this.baseUrl}/records/upload`, {
        method: 'POST',
        headers: {
          ...this.getAuthHeaders(),
        },
        body: formData,
        signal: AbortSignal.timeout(10000),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => null);
        throw new Error(errJson?.detail || `Upload failed with status ${res.status}`);
      }
      const record = await res.json();
      return { success: true, record };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Upload connection failed';
      return { 
        success: false, 
        error: `Backend API error (${message}). Cannot commit IPFS CID or Fabric ledger entry without live backend.` 
      };
    }
  }

  // Retrieve off-chain sensitive clinical details for a record
  async getRecordDetails(recordId: string): Promise<RecordDetailResponse | null> {
    try {
      const res = await fetch(`${this.baseUrl}/records/${recordId}/details`, {
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch {
      return null;
    }
  }

  // Verify record integrity against ledger
  async verifyRecordIntegrity(recordId: string): Promise<RecordVerifyResponse> {
    try {
      const res = await fetch(`${this.baseUrl}/records/${recordId}/verify`, {
        method: 'POST',
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(10000),
      });

      if (res.ok) {
        const data = await res.json();
        return data as RecordVerifyResponse;
      }

      // Handle HTTP non-200 responses gracefully
      const err = await res.json().catch(() => null);
      const detail = err?.detail || `Record verification returned HTTP status ${res.status}`;
      const isIpfs = /ipfs/i.test(detail) || err?.status === 'IPFS_UNAVAILABLE';
      const fallbackStatus: RecordVerifyStatus = isIpfs ? 'IPFS_UNAVAILABLE' : 'LEDGER_UNAVAILABLE';

      return {
        recordId,
        ipfsCid: err?.ipfsCid || 'UNKNOWN',
        checksumMatches: false,
        ledgerChecksum: err?.ledgerChecksum || 'UNAVAILABLE',
        computedSha256: err?.computedSha256 || 'UNAVAILABLE',
        status: (err?.status as RecordVerifyStatus) || fallbackStatus,
        detail,
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Network error';
      const isIpfs = /ipfs/i.test(msg);
      const fallbackStatus: RecordVerifyStatus = isIpfs ? 'IPFS_UNAVAILABLE' : 'LEDGER_UNAVAILABLE';
      return {
        recordId,
        ipfsCid: 'UNKNOWN',
        checksumMatches: false,
        ledgerChecksum: 'UNAVAILABLE',
        computedSha256: 'UNAVAILABLE',
        status: fallbackStatus,
        detail: `Verification service unavailable: ${msg}. Check FastAPI backend on port 8001.`,
      };
    }
  }

  // Fetch consents
  async getConsents(patientId?: string): Promise<ConsentRecord[]> {
    const activeToken = this.getToken();
    try {
      const url = patientId ? `${this.baseUrl}/consents?patient_id=${patientId}` : `${this.baseUrl}/consents`;
      const res = await fetch(url, { 
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(5000) 
      });
      if (res.ok) {
        return await res.json();
      }
      const errJson = await res.json().catch(() => null);
      throw new Error(errJson?.detail || `Server error ${res.status}`);
    } catch (err: unknown) {
      if (activeToken) {
        throw err;
      }
      return INITIAL_CONSENTS;
    }
  }

  // Update consent status (Grant / Revoke)
  async updateConsentStatus(
    consentId: string, 
    action: 'GRANT' | 'REVOKE'
  ): Promise<{ success: boolean; txHash?: string; error?: string }> {
    try {
      const res = await fetch(`${this.baseUrl}/consents/${consentId}/${action.toLowerCase()}`, {
        method: 'POST',
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(20000),
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, txHash: data.txHash };
      }
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.detail || `Consent update rejected with status ${res.status}`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Network error';
      return { 
        success: false, 
        error: `Cannot complete Fabric ledger consensus: ${message}. Real blockchain verification requires live backend & chaincode gateway.` 
      };
    }
  }

  // Request Consent
  async requestConsent(payload: ConsentRequestPayload): Promise<{ success: boolean; consentId?: string; txHash?: string; error?: string }> {
    try {
      const res = await fetch(`${this.baseUrl}/consents/request`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          ...this.getAuthHeaders(),
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(20000),
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, consentId: data.id, txHash: data.txHash };
      }
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.detail || `Failed with status ${res.status}`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Network error';
      return { 
        success: false, 
        error: `Access request failed: ${message}. Requires active connection to backend Fabric adapter.` 
      };
    }
  }

  // Verify Consent rule against Fabric smart contract
  async verifyConsent(doctorId: string, patientId: string, recordType: string): Promise<ConsentVerifyResponse> {
    try {
      const res = await fetch(
        `${this.baseUrl}/consents/verify?doctor_id=${doctorId}&patient_id=${patientId}&record_type=${recordType}`,
        {
          headers: {
            ...this.getAuthHeaders(),
          },
          signal: AbortSignal.timeout(3000),
        }
      );
      if (res.ok) {
        return await res.json();
      }
      throw new Error(`Verification query error ${res.status}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Offline';
      return { allowed: false, reason: `OFFLINE_OR_UNAVAILABLE (${msg})` };
    }
  }

  // Fetch access audit logs
  async getAuditLogs(patientId?: string): Promise<AccessLog[]> {
    try {
      const url = patientId ? `${this.baseUrl}/audit?patient_id=${patientId}` : `${this.baseUrl}/audit`;
      const res = await fetch(url, { 
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(3000) 
      });
      if (res.ok) {
        return await res.json();
      }
      throw new Error(`Server error ${res.status}`);
    } catch {
      return INITIAL_AUDIT_LOGS;
    }
  }

  // Verify entire audit chain integrity
  async verifyAuditChain(): Promise<AuditIntegrityResponse> {
    try {
      const res = await fetch(`${this.baseUrl}/audit/verify`, {
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        return await res.json();
      }
      throw new Error(`Failed with status ${res.status}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification error';
      return { chainIntact: false, message: `Could not verify chain: ${msg}` };
    }
  }

  // Administrative portal queries
  async getAdminUsers(): Promise<UserSummary[]> {
    const res = await fetch(`${this.baseUrl}/admin/users`, {
      headers: this.getAuthHeaders(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to fetch users: status ${res.status}`);
    }
    return await res.json();
  }

  async updateUserStatus(userId: string, isActive: boolean): Promise<UserSummary> {
    const res = await fetch(`${this.baseUrl}/admin/users/${userId}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      body: JSON.stringify({ isActive }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to update user status: status ${res.status}`);
    }
    return await res.json();
  }

  async getAdminSecurityEvents(): Promise<AccessLog[]> {
    const res = await fetch(`${this.baseUrl}/admin/security-events`, {
      headers: this.getAuthHeaders(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to fetch security events: status ${res.status}`);
    }
    return await res.json();
  }

  async getAdminTelemetry(): Promise<AdminTelemetry> {
    const res = await fetch(`${this.baseUrl}/admin/telemetry`, {
      headers: this.getAuthHeaders(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to fetch admin telemetry: status ${res.status}`);
    }
    return await res.json();
  }

  // Doctor Application Review Workflow (Admin Only)
  async getDoctorApplications(status: string = 'PENDING'): Promise<DoctorApplicationSummary[]> {
    const res = await fetch(`${this.baseUrl}/admin/doctor-applications?status=${encodeURIComponent(status)}`, {
      headers: this.getAuthHeaders(),
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to fetch doctor applications: status ${res.status}`);
    }
    return await res.json();
  }

  async approveDoctorApplication(doctorId: string): Promise<DoctorApplicationActionResponse> {
    const res = await fetch(`${this.baseUrl}/admin/doctor-applications/${encodeURIComponent(doctorId)}/approve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to approve doctor application: status ${res.status}`);
    }
    return await res.json();
  }

  async rejectDoctorApplication(doctorId: string, reason: string): Promise<DoctorApplicationActionResponse> {
    const res = await fetch(`${this.baseUrl}/admin/doctor-applications/${encodeURIComponent(doctorId)}/reject`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      body: JSON.stringify({ reason }),
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.detail || `Failed to reject doctor application: status ${res.status}`);
    }
    return await res.json();
  }

  // Download decrypted primary medical document
  async downloadRecordDocument(recordId: string): Promise<DownloadFileResult> {
    const res = await fetch(`${this.baseUrl}/records/${encodeURIComponent(recordId)}/download`, {
      headers: {
        ...this.getAuthHeaders(),
      },
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => null);
      const detail = errJson?.detail || `Document download failed with status ${res.status}`;
      throw new ApiDownloadError(res.status, detail);
    }

    const blob = await res.blob();
    const disposition = res.headers.get('Content-Disposition');
    const contentType = res.headers.get('Content-Type') || blob.type;
    const fallbackExt = inferExtensionFromMime(contentType);
    const fallback = `${recordId}_document${fallbackExt}`;
    const filename = extractFilenameFromHeader(disposition, fallback);
    return { blob, filename };
  }

  // Download decrypted clinical prescription attachment
  async downloadRecordPrescription(recordId: string): Promise<DownloadFileResult> {
    const res = await fetch(`${this.baseUrl}/records/${encodeURIComponent(recordId)}/prescription/download`, {
      headers: {
        ...this.getAuthHeaders(),
      },
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => null);
      const detail = errJson?.detail || `Prescription download failed with status ${res.status}`;
      throw new ApiDownloadError(res.status, detail);
    }

    const blob = await res.blob();
    const disposition = res.headers.get('Content-Disposition');
    const contentType = res.headers.get('Content-Type') || blob.type;
    const fallbackExt = inferExtensionFromMime(contentType);
    const fallback = `${recordId}_prescription${fallbackExt}`;
    const filename = extractFilenameFromHeader(disposition, fallback);
    return { blob, filename };
  }
}

export interface DownloadFileResult {
  blob: Blob;
  filename: string;
}

export class ApiDownloadError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail);
    this.name = 'ApiDownloadError';
    this.status = status;
    this.detail = detail;
  }
}

export function inferExtensionFromMime(mime: string | null): string {
  if (!mime) return '.bin';
  const clean = mime.split(';')[0].trim().toLowerCase();
  switch (clean) {
    case 'image/png': return '.png';
    case 'image/jpeg':
    case 'image/jpg': return '.jpg';
    case 'application/pdf': return '.pdf';
    case 'image/webp': return '.webp';
    case 'image/gif': return '.gif';
    case 'application/dicom': return '.dcm';
    case 'application/zip': return '.zip';
    case 'text/plain': return '.txt';
    case 'application/json': return '.json';
    default: return '.bin';
  }
}

export function extractFilenameFromHeader(header: string | null, fallback: string): string {
  if (!header) return fallback;
  // RFC 5987 / RFC 6266 filename*
  const utf8Match = header.match(/filename\*=utf-8''([^;]+)/i);
  if (utf8Match && utf8Match[1]) {
    try {
      return decodeURIComponent(utf8Match[1].trim().replace(/['"]/g, ''));
    } catch {
      return utf8Match[1].trim().replace(/['"]/g, '');
    }
  }
  // Standard filename="..." or filename=...
  const regularMatch = header.match(/filename="?([^";]+)"?/i);
  if (regularMatch && regularMatch[1]) {
    return regularMatch[1].trim().replace(/['"]/g, '');
  }
  return fallback;
}

export function formatDownloadErrorMessage(err: unknown, defaultMessage = 'Download failed'): string {
  if (typeof err === 'string' && err.trim()) {
    return err;
  }
  if (err && typeof err === 'object') {
    const anyErr = err as { status?: number; detail?: string; message?: string };
    const status = anyErr.status;
    const detail = anyErr.detail || anyErr.message;

    if (status === 403) {
      return detail || 'Access denied: You do not have authorization or an active consent grant to download this clinical file.';
    }
    if (status === 404) {
      if (detail && /legacy/i.test(detail)) {
        return 'Legacy record: This record was anchored before envelope encryption key persistence and operates in verification-only mode.';
      }
      return detail || 'File not found: The requested document or prescription attachment is not available for this record.';
    }
    if (status === 409) {
      return 'Cryptographic integrity alert: Ciphertext checksum mismatch against the on-chain Fabric ledger. File transfer blocked for patient safety.';
    }
    if (status === 503) {
      return 'Service unavailable: Unable to communicate with IPFS storage or the Fabric ledger. Please check network connectivity and retry.';
    }
    if (status === 500) {
      return detail || 'Decryption failed: A cryptographic verification error occurred while decrypting the record.';
    }
    if (detail) {
      return detail;
    }
  }
  return defaultMessage;
}

export function triggerFileDownload(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  try {
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  } finally {
    setTimeout(() => {
      window.URL.revokeObjectURL(url);
    }, 1000);
  }
}

export const apiService = new MedTrustApiService();
