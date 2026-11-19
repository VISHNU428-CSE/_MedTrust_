# MedTrust Frontend Client

Decentralized healthcare data and consent management frontend built with **React**, **TypeScript**, **Vite**, and **Tailwind CSS**.

---

## 🏗️ Architecture Overview

The MedTrust frontend provides role-based interfaces for patients, doctors, and compliance auditors interacting with:
- **Decentralized Storage**: Encrypted medical documents stored on IPFS (Kubo) identified by real Content Identifiers (CIDs).
- **Consent Governance**: Granular, time-bound consent contracts immutably anchored and enforced on **Hyperledger Fabric**.
- **Secure Backend Integration**: Direct communication with FastAPI REST endpoints (`/api/v1/...`).

---

## 🛡️ Core Views & Capabilities

### 1. Patient Portal
- **Medical Records Vault**: View encrypted records with verification of IPFS CID hashes, AES-256-GCM cipher standards, and key fingerprints.
- **Upload Record Flow**: Client-side encryption envelope and metadata tagging before dispatching to the storage node.
- **Consent Management**: Review, grant, and revoke doctor access permissions.
- **Access Audit Logs**: Real-time view of who accessed records, for what clinical purpose, and the corresponding Hyperledger Fabric transaction ID (`txHash`).

### 2. Doctor Portal
- **Patient Directory & Search**: Query registered patients by ID, name, or clinical condition.
- **Access Requests**: Transmit consent requests with explicit medical justification, expiration duration, and requested record categories.
- **Authorized Records**: Inspect and decrypt authorized records once consent is confirmed on-chain.

### 3. Compliance & Audit Ledger
- Real-time audit trail of all data transactions, consent grants, and revocations for HIPAA/GDPR regulatory compliance.

---

## 🔒 Security Principles

1. **Zero Secret Storage**: Never store private keys, secrets, or passwords in local storage or client bundles.
2. **No Mock Consensus Fallbacks**: The client does not fabricate successful blockchain consensus; all cryptographic proofs and ledger updates must originate from authenticated backend endpoints.

---

## 🚀 Getting Started

### Development
```bash
npm install
npm run dev
```

### Production Build & Linting
```bash
npm run lint
npm run build
```
