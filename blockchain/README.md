# MedTrust Blockchain Subsystem
**Decentralized Consent Management, Medical Record Metadata Anchoring & Audit Trail Ledger**

## Overview
This directory contains the Hyperledger Fabric blockchain implementation for the **MedTrust** healthcare platform.
It provides:
- **TypeScript Smart Contracts (`chaincode/`)**: Patient Consent lifecycle, Zero PHI Medical Record Metadata Registration, and Cryptographic Audit Trail Hash Chain.
- **Fabric Network Configuration (`network/`)**: Docker Compose topologies, channel definitions (`configtx.yaml`), crypto definitions (`crypto-config.yaml`), and connection profiles.
- **Interface Specifications (`specs/`)**: API documentation for integration with FastAPI Backend Gateway Adapter and QA Verification Suites.

## Directory Layout
```
blockchain/
├── chaincode/                     # TypeScript Fabric chaincode
│   ├── src/
│   │   ├── contracts/             # Smart contracts
│   │   │   ├── ConsentContract.ts       # Grant, revoke, verify patient consent
│   │   │   ├── MedicalRecordContract.ts # Register & verify IPFS record metadata
│   │   │   ├── AuditTrailContract.ts    # Tamper-evident hash-chained audit logging
│   │   │   └── MedTrustContract.ts      # Unified primary contract interface
│   │   ├── models/                # Domain types and state enums
│   │   │   └── types.ts
│   │   ├── utils/                 # Canonical hashing & Zero PHI validation
│   │   │   └── cryptoUtils.ts
│   │   └── index.ts               # Chaincode package entrypoint
│   ├── test/                      # Comprehensive unit & integration tests
│   │   ├── mockContext.ts         # ChaincodeStub and MockContext engine
│   │   ├── ConsentContract.test.ts
│   │   ├── MedicalRecordContract.test.ts
│   │   ├── AuditTrailContract.test.ts
│   │   └── MedTrustContract.test.ts
│   ├── package.json
│   ├── tsconfig.json
│   └── jest.config.js
├── network/                       # Hyperledger Fabric v2.5 Network Config
│   ├── connection-profiles/       # Client Gateway Connection Profiles
│   │   ├── connection-org1.json
│   │   └── connection-org2.json
│   ├── scripts/                   # Deployment and lifecycle scripts
│   │   ├── deployChaincode.sh
│   │   ├── startNetwork.sh
│   │   └── stopNetwork.sh
│   ├── configtx.yaml              # Genesis block and channel definitions
│   ├── crypto-config.yaml        # Cryptographic material generation
│   └── docker-compose-test-net.yaml
├── specs/
│   └── GATEWAY_ADAPTER_SPEC.md    # FastAPI Gateway Adapter Interface Specification
└── README.md
```

## Security & Compliance Invariants
1. **Zero PHI Guarantee:** No patient names, plain text medical records, clinical observations, or private credentials are stored on-ledger. Only content-addressed IPFS CIDs and SHA-256 integrity digests are anchored.
2. **Immediate Revocation:** Once a patient executes `RevokeConsent`, the ledger immediately marks the state as `REVOKED`. Any subsequent access check fails with `CONSENT_REVOKED` with zero propagation lag.
3. **Cross-Patient Isolation:** Only the owning patient can approve, reject, or revoke consent. Third-party manipulation is blocked by contract ownership checks.
4. **Non-Repudiation & Audit Integrity:** Every read, consent grant, and revocation is recorded in an append-only ledger chained to the previous entry hash (`prevHash` -> `entryHash`).

## Testing & Verification
To run tests locally:
```bash
cd blockchain/chaincode
npm test
```
All unit tests and end-to-end multi-contract flows execute against the in-memory mock Fabric stub.
