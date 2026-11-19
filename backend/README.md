# MedTrust Decentralized Healthcare Backend API

FastAPI backend service for MedTrust: Decentralized Healthcare Data and Consent Management platform.

---

## 🎯 Architecture & Features

1. **FastAPI Application & Dependency Injection**:
   - High-performance asynchronous API with OpenAPI 3.0 interactive docs at `/docs` and `/redoc`.
   - Modularity across core configuration, schemas, security, adapters, and business services.

2. **Zero-Knowledge Encryption & Key Management**:
   - Patient health records are encrypted off-chain using **AES-256-GCM** before persistence.
   - Deterministic SHA-256 integrity checksums calculated on ciphertext.
   - **Zero-PHI Guarantee**: Neither raw health data nor symmetric keys ever touch the Hyperledger Fabric ledger or IPFS storage.

3. **Real IPFS (Kubo) Client Adapter**:
   - Communicates with IPFS Kubo RPC API (`http://127.0.0.1:5001/api/v0`).
   - Pins encrypted document payloads with content-addressed CIDv1.
   - Rigorously evaluates SHA-256 integrity against the on-chain ledger digest upon retrieval, raising `ChecksumMismatchError` on tampered payloads.

4. **Hyperledger Fabric Gateway Adapter**:
   - Interfaces directly with smart contracts designed by Kelly:
     - `RecordContract`: `RegisterRecord`, `GetRecord`, `ListPatientRecords`.
     - `ConsentContract`: `RequestConsent`, `GrantConsent`, `RevokeConsent`, `VerifyConsent`.
     - `AuditContract`: `LogEvent`, `GetAuditLogs`, `VerifyAuditChain`.
   - Generates deterministic 64-char transaction receipts (`0x...`).
   - Maintains cryptographic SHA-256 hash chaining across all access logs for non-repudiation.

5. **JWT Authentication & Role-Based Access Control (RBAC)**:
   - HS256 JWT tokens with expiration, signature tamper checks, and roles: `PATIENT`, `DOCTOR`, `ADMIN`, `AUDITOR`.
   - Horizontal privilege escalation protection: Patients are strictly isolated to their own records.
   - Clinical access requires active, non-expired, and non-revoked consent with scope isolation (`ALL` or specific record types).

---

## 📁 Project Structure

```
backend/
├── app/
│   ├── config.py             # Pydantic Settings & environment variables
│   ├── main.py               # FastAPI application factory & exception handlers
│   ├── core/
│   │   ├── crypto.py         # AES-256-GCM encryption & SHA-256 checksumming
│   │   ├── exceptions.py     # Domain exceptions (AccessDeniedError, ChecksumMismatchError)
│   │   ├── rbac.py           # Role definition & horizontal isolation policies
│   │   └── security.py       # JWT creation, decoding & PBKDF2 password hashing
│   ├── models/
│   │   └── schemas.py        # Pydantic models with camelCase frontend serialization
│   ├── adapters/
│   │   ├── ipfs_client.py    # IPFS Kubo client with SHA-256 tamper verification
│   │   └── fabric_gateway.py # Hyperledger Fabric Gateway client adapter
│   ├── services/
│   │   ├── record_service.py # Encryption, IPFS upload & Fabric record registration
│   │   ├── consent_service.py# Consent request, grant, revoke & verification
│   │   └── audit_service.py  # Cryptographic audit logging & hash chain validation
│   └── api/
│       ├── deps.py           # Dependency injection for auth & adapters
│       └── v1/
│           ├── api_router.py # V1 API router aggregator
│           └── endpoints/
│               ├── health.py # /api/v1/health diagnostic endpoint
│               ├── auth.py   # /api/v1/auth (login, register, me)
│               ├── records.py# /api/v1/records (upload, list, verify)
│               ├── consents.py# /api/v1/consents (request, grant, revoke, verify)
│               └── audit.py  # /api/v1/audit (logs & chain integrity)
├── tests/                    # Comprehensive unit, integration, and security tests
├── requirements.txt          # Python package dependencies
├── run.py                    # Server runner script
└── README.md
```

---

## 🚀 Running the Backend

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI server
```bash
python run.py
```
Server runs on `http://127.0.0.1:8000` with Swagger documentation at `http://127.0.0.1:8000/docs`.

### 3. Run the Test Suite
```bash
python -m pytest backend/tests -v
```
