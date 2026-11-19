# MedTrust: Decentralized Healthcare Data & Consent Management Platform

**MedTrust** is an enterprise-grade, privacy-first healthcare data sharing and sovereign consent governance platform designed for HIPAA/GDPR compliance. It integrates **FastAPI**, **React + TypeScript + Vite**, **AES-256-GCM Zero-Knowledge Encryption**, **IPFS (Kubo)** decentralized content-addressed storage, and **Hyperledger Fabric v2.5** smart contracts.

---

## 🏛️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MEDTRUST BROWSER APPLICATION                          │
│     React 19 • TypeScript • Vite • Tailwind CSS (Port 5174)                 │
│                                                                             │
│  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────────┐  │
│  │   Patient Dashboard   │ │   Doctor Dashboard   │ │ Auditor Dashboard  │  │
│  │ (Records, Consent,    │ │ (Patient Directory,  │ │ (Tamper-Evident    │  │
│  │  Verify Ledger Modal) │ │  Authorized Access)  │ │  Audit Hash Chain) │  │
│  └───────────┬───────────┘ └──────────┬───────────┘ └─────────┬──────────┘  │
└──────────────┼────────────────────────┼───────────────────────┼─────────────┘
               │ (Bearer JWT / RBAC)    │                       │
               ▼                        ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FASTAPI BACKEND SERVICE                            │
│                  Python 3.14 • REST APIs (Port 8001)                        │
│                                                                             │
│  ┌───────────────────────┐ ┌──────────────────────┐ ┌────────────────────┐  │
│  │  Auth & RBAC Service  │ │ Record Crypto Engine │ │   Consent Service  │  │
│  │  (SQLite medtrust.db) │ │ (AES-256-GCM/SHA-256)│ │ (Rules & Lifecycle)│  │
│  └───────────────────────┘ └──────────┬───────────┘ └─────────┬──────────┘  │
└───────────────────────────────────────┼───────────────────────┼─────────────┘
                                        │                       │
                 ┌──────────────────────┴───────┐               │
                 ▼                              ▼               ▼
┌────────────────────────────────┐ ┌──────────────────────────────────────────┐
│      IPFS KUBO STORAGE         │ │        HYPERLEDGER FABRIC v2.5           │
│   (Port 5001 RPC / 8080 GW)    │ │   (Raft Orderer 7050, Peer 7051, CouchDB)│
│                                │ │                                          │
│ • Content-Addressed CIDv1      │ │ • Zero-PHI Metadata (CIDs, SHA-256)      │
│ • AES-256-GCM Ciphertext only  │ │ • Instant Atomic Consent Revocation      │
│ • Zero Plaintext PHI           │ │ • Chained Audit Hash Ledger (prev->entry)│
└────────────────────────────────┘ └──────────────────────────────────────────┘
```

---

## 🛡️ Core Cryptographic & Security Invariants

1. **Zero-PHI On-Ledger & IPFS**: Neither patient names, plaintext health records, nor decryption keys ever touch the Hyperledger Fabric ledger or IPFS storage. Only encrypted blobs are pinned to IPFS, and only content-addressed CIDs and SHA-256 integrity digests are registered to the ledger.
2. **Deterministic Integrity Verification**: Every retrieved record undergoes SHA-256 calculation and is asserted against the immutable Fabric ledger digest before decryption.
3. **Explicit Revocation Invariant**: Consent revocation takes effect immediately with zero lag on the ledger, blocking subsequent authorizations. (Mathematically, revocation blocks future platform retrievals but cannot alter previously saved local offline files).
4. **Horizontal Privilege Escalation Prevention**: Patients are strictly restricted to their own records. Cross-patient consent grant, rejection, or revocation tampering is rejected by smart contract rules.
5. **Tamper-Evident Merkle Audit Trail**: Every access event is appended with a cryptographic SHA-256 link (`prevHash` -> `entryHash`) starting from `GENESIS_BLOCK_HASH`. Any deletion or modification is immediately detected.

---

## 🔍 Verify Ledger: 4 Standardized States

Per `design.md` Section 8, the **Verify Ledger** subsystem validates record integrity and reports four distinct states:

| Status | Badge Color | Description | Diagnostic Output |
| :--- | :--- | :--- | :--- |
| **`VERIFIED`** | Emerald | IPFS payload retrieved and SHA-256 hash matches the on-chain ledger digest. | `checksumMatches: true`, `computedSha256: <hash>`, `ledgerChecksum: <hash>` |
| **`CHECKSUM_MISMATCH`** | Rose | IPFS payload has been tampered with or corrupted; computed hash does not match expected digest. | `checksumMatches: false`, `computedSha256: MISMATCH`, alert details |
| **`IPFS_UNAVAILABLE`** | Amber | Kubo daemon connection timed out, is offline, or the specific CID block is missing on node storage. | `checksumMatches: false`, `computedSha256: UNAVAILABLE`, connection diagnosis |
| **`LEDGER_UNAVAILABLE`** | Slate/Rose | Record ID is missing on the Hyperledger Fabric ledger or ledger query failed. | `checksumMatches: false`, `ledgerChecksum: UNAVAILABLE`, ledger query details |

---

## 🚀 Setup & Execution Guide

### Prerequisites
- **Node.js**: v18+ (verified on v24.16.0)
- **Python**: 3.10+ (verified on 3.14.0)
- **Docker Desktop** (optional for live Fabric/IPFS containers; platform includes verified synchronized standby adapters)

### 1. Backend Service
```bash
cd "My Team Project/backend"
pip install -r requirements.txt
python run.py
```
- API Server: `http://localhost:8001`
- Swagger OpenAPI Docs: `http://localhost:8001/docs`
- Health Inspection: `http://localhost:8001/api/v1/health`

### 2. Frontend Application
```bash
cd "My Team Project/frontend"
npm install
npm run dev
```
- Web Application: `http://localhost:5174` (strictly configured to port 5174)

### 3. Automated Test Suites
```bash
# Core QA Integration & Security Suite (59 tests)
python -m pytest "My Team Project/tests" -v

# Backend API & Gateway Suite (55 tests)
python -m pytest "My Team Project/backend/tests" -v --ignore="My Team Project/backend/tests/test_e2e_ipfs_crypto.py"

# Smart Contracts Jest Suite (29 tests across 5 suites, 92.69% line coverage)
cd "My Team Project/blockchain/chaincode"
npm test

# Frontend Linting & Production Build
cd "My Team Project/frontend"
npm run lint    # 0 warnings, 0 errors
npm run build   # tsc -b && vite build clean in <600ms
```

---

## 🎓 Viva Demonstration Script (6 Critical Workflows)

This concise script walks examiners through the end-to-end MedTrust unified production platform per `design.md` Sections 3, 5, 8, 9, and 12:

### Step 1: Public Landing Page & Unified Production Authentication
1. Open browser to `http://localhost:5174/`.
2. Notice the Public Landing Page featuring MedTrust sovereign branding, privacy/security explanation, live backend/Fabric consensus indicators, and a single **"Sign In to Sovereign Portal"** CTA (no separate role-selection buttons).
3. Click **"Sign In"** to open the Unified Login experience:
   - Single authentication entry point for all user types.
   - Show toggleable password visibility and demo credential quick-fill pills (Eleanor Vance - Patient, Dr. Marcus Sterling - Doctor, Admin - Platform Admin, Federal Auditor - Auditor).
   - Backend authoritatively verifies credentials and resolves the user's role—the browser role is never trusted.
4. Sign in with Patient credentials: `e.vance@example.med` / `password123`.
5. Observe dynamic backend routing: the user is immediately routed to the Sovereign Patient Vault with user badge in the navigation bar.

### Step 2: Patient Vault, Verify Ledger & Synthetic Record Upload
1. Point out the Patient Vault showing 3 encrypted records (`rec-001`, `rec-002`, `rec-003`).
2. Highlight zero-secret metadata: real IPFS CID hashes, AES-256-GCM cipher tags, and safe key fingerprints.
3. Click the **"Verify Ledger"** button on `rec-001`:
   - Cryptographic verification modal opens and queries the live backend `/api/v1/records/rec-001/verify`.
   - Displays emerald **`VERIFIED`** badge with matching ledger SHA-256 digest (`0951db7...`) and live IPFS computed digest.
   - Resiliently handles and distinguishes all 4 states (`VERIFIED`, `CHECKSUM_MISMATCH`, `IPFS_UNAVAILABLE`, `LEDGER_UNAVAILABLE`).
4. Click **"Upload Medical Record"** in the top navigation banner.
5. Ingest a synthetic document (e.g., `LAB_REPORT`), title `"Cardiovascular Metabolic Profile"`, and submit.
6. The backend computes AES-256-GCM ciphertext off-chain, calculates SHA-256 checksum, pins to IPFS Kubo CID, and registers metadata to the Fabric ledger with a transaction hash.

### Step 3: Doctor Access Request & Patient Consent Governance
1. Click **"Sign Out"** in the navigation bar (revokes active session in backend SQLite `user_sessions`).
2. Log in through the unified portal with Doctor credentials: `m.sterling@metrohealth.org` / `password123`.
3. Backend authoritatively routes Dr. Sterling to the **Doctor Clinical Portal**.
4. Search for patient `pat-984210` and submit an access request specifying medical justification (`"Review of coronary ejection fraction"`) and requested scope (`IMAGING_MRI`, `LAB_REPORT`).
5. Sign out and log back in as Eleanor Vance (`e.vance@example.med`).
6. Navigate to **"Consent Management"** tab: show the pending request under **"Pending Access Requests Requiring Patient Approval"**.
7. Click **"Grant Consent"**: Fabric smart contract commits the approval transaction.

### Step 4: Authorized Doctor Retrieval & Revocation Enforcement
1. Log in again as Dr. Sterling (`m.sterling@metrohealth.org`).
2. Refresh authorized patient records: notice Eleanor's records are now unlocked and readable according to the granted scope.
3. Log back in as Eleanor and click **"Revoke Access"**.
4. Fabric smart contract atomically executes `RevokeConsent` on-chain.
5. In the Doctor Portal, attempt to fetch the record again: the backend smart contract rule evaluator (`/api/v1/consents/verify`) returns `allowed: false, reason: "CONSENT_REVOKED"`. Retrieval is strictly blocked.

### Step 5: Administrator Console & Zero-PHI Privacy Boundary
1. Sign in through the unified portal with Admin credentials: `admin@medtrust.org` / `admin123`.
2. Backend authoritatively routes to the **Administrator Console**.
3. Inspect the Zero-PHI banner: confirms Platform Administrators are strictly isolated from clinical medical records.
4. Demonstrate RBAC privacy boundary: attempts by Admin to query `/api/v1/records` return HTTP 403 Forbidden with `"Administrative Privacy Boundary: Administrators are strictly prohibited from viewing patient medical records"` and record a `DENIED` access event on the Fabric ledger.
5. Review user and role management (active/suspended account controls), security audit event feed, and real-time microservices telemetry (Active Users, Total Records, Active Sessions).

### Step 6: Non-Repudiation Audit Trail & System Health Verification
1. Sign in as Federal Compliance Auditor: `auditor@medtrust.gov` / `password123`.
2. View the append-only audit trail: every login, upload, consent request, grant, revocation, and view event is listed with its actor, role, purpose, and Fabric transaction ID.
3. Inspect the cryptographic hash chain: `prevHash` -> `entryHash` chained back to `GENESIS_BLOCK_HASH`.
4. Click **"Verify Audit Chain Integrity"**: the auditor service cryptographically walks the entire chain from genesis, asserting 100% unbroken chain integrity.

