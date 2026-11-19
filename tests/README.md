# MedTrust QA & Security Review Suite

Automated verification harness, synthetic clinical fixtures, Zero-PHI compliance scanner, Hyperledger Fabric ledger transaction suites, and security audit suites for the MedTrust platform.

---

## 🎯 Scope & Objectives
1. **Automated Test Architecture**: Modular structure covering Unit, Integration, and Security verification suites.
2. **Synthetic Medical Fixtures**: High-fidelity EHR, CMP Lab, Cardiology encounters, and Radiology reports with strict **Zero-PHI** compliance guardrails.
3. **Automated Zero-PHI Compliance Scanner**: Deep recursive scanner detecting SSNs, phone numbers, real emails, unencrypted financial tokens, and non-synthetic identifiers.
4. **Precalculated SHA-256 Golden Digests**: Deterministic, language-agnostic test vectors for backend encryption tests and IPFS upload/retrieval verification.
5. **Fabric On-Chain Transaction & Ledger State Verification**:
   - Transaction submission (`RegisterRecord`), block commit validation, and ledger queries.
   - On-chain checksum validation (`VERIFIED_INTACT` vs `CHECKSUM_MISMATCH`).
   - Full decentralized consent lifecycle (`PENDING` -> `ACTIVE` -> `REVOKED` with zero-latency enforcement).
   - Ledger state persistence across simulated node / container restarts.
6. **Fabric Security Invariants & Attack Resistance**:
   - Zero-PHI on-chain enforcement (rejection of SSNs, private keys, plaintext passwords).
   - Cross-patient horizontal privilege escalation denial (`UNAUTHORIZED_GRANT`, `REVOCATION_OWNERSHIP_VIOLATION`).
   - Consent scope confinement (`CONSENT_SCOPE_EXCLUDED`).
   - Cryptographic audit trail non-repudiation and tamper resistance.
7. **RBAC & JWT Security Audit**: Thorough penetration tests for token tampering, expiration, horizontal privilege escalation, and vertical role escalation.
8. **IPFS Tamper Detection**: Retrieval of content by CID and cryptographic SHA-256 verification against the ledger-registered checksum to detect storage corruption or MITM modification.

---

## 📂 Test Architecture Layout

```
tests/
├── pytest.ini                            # Pytest configuration & markers
├── conftest.py                           # Pytest fixtures (IPFS node, verifier, consent engine, Fabric adapter)
├── core_harness.py                       # Test harness engines, exception hierarchy, and contracts
├── fixtures/
│   ├── __init__.py
│   ├── synthetic_records.py             # Synthetic EHR, Lab, Cardio, Radio fixtures & zero-PHI validator
│   ├── phi_scanner.py                   # Automated zero-PHI & PII recursive compliance scanner
│   ├── golden_vectors.py                # Precalculated golden SHA-256 digests and IPFS CID vectors
│   ├── golden_test_vectors.json         # Static JSON export of golden test vectors
│   └── auth_tokens.py                   # Pure-Python JWT encoder, decoders, and tampering generators
├── unit/
│   ├── __init__.py
│   ├── test_synthetic_fixtures.py       # Fixture schema & PHI compliance verification
│   ├── test_checksum_integrity.py       # Deterministic hashing & avalanche bit-flip sensitivity
│   ├── test_phi_compliance_scanner.py   # Multi-vector scanner verification tests
│   ├── test_golden_vectors.py           # Golden vector stability and non-drifting digest checks
│   └── test_clinical_detail_schemas.py  # Phase 6 RecordDetail schemas & CamelModel serialization
├── security/
│   ├── __init__.py
│   ├── test_rbac_jwt_security.py        # RBAC, token tampering, and unauthorized access tests
│   ├── test_consent_revocation.py       # Consent granting, expiration, and immediate revocation tests
│   ├── test_fabric_security_invariants.py # Fabric Zero-PHI, cross-patient isolation, and audit tamper resistance
│   └── test_clinical_detail_security_gates.py # Phase 6 Clinical details RBAC, isolation & privacy boundary
└── integration/
    ├── __init__.py
    ├── test_ipfs_checksum_tampering.py  # IPFS CID retrieval & tampering alert tests
    ├── test_audit_trail_completeness.py # Audit logging completeness & cryptographic hash chain verification
    ├── test_fabric_ledger_transactions.py # Fabric transaction submission, consent lifecycle & persistence
    └── test_phase6_clinical_upload_and_details.py # Phase 6 Multi-input upload & SQLite persistence
```

---

## 💎 Precalculated Golden Test Vectors (Phase 1 & 2)

| Category | Record ID | Canonical SHA-256 Golden Digest | IPFS CIDv1 |
| :--- | :--- | :--- | :--- |
| **EHR** | `REC-EHR-SYNTH-PAT-001-000` | `fd8dd8bb9f533caa14c2e9cef0ae672ae4be99b3e66607d7f06e3e57dd88cdef` | `bafybeimdtfd8dd8bb9f533caa14c2e9cef0medtrust` |
| **LAB_REPORT** | `REC-LAB-SYNTH-PAT-001-001` | `c1a9163840a3685b46ee0f1cd9ecf9731bdf2fbc8ecb33a4ec3c135b031cc29c` | `bafybeimdtc1a9163840a3685b46ee0f1cd9medtrust` |
| **CARDIOLOGY** | `REC-CARD-SYNTH-PAT-001-002` | `18a685c4ef09649cbd61d083e70a0c78cdeb83d806b22fc83c7df9296b29b48a` | `bafybeimdt18a685c4ef09649cbd61d083e7medtrust` |
| **RADIOLOGY** | `REC-RAD-SYNTH-PAT-002-003` | `ddf24c12968d2ffade1d7cd3d4cbbef743b83754e1b67f396e645c191ba80d49` | `bafybeimdtddf24c12968d2ffade1d7cd3d4medtrust` |

---

## 📊 QA Test Matrix (80 Tests Total)

| Category | Suite | Test Name | Invariant / Objective | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Unit** | `synthetic_fixtures` | `test_synthetic_lab_report_phi_compliance` | No real PHI, valid schema, valid SHA-256 & CID | ✅ PASS |
| **Unit** | `synthetic_fixtures` | `test_synthetic_cardiology_phi_compliance` | Valid cardiology encounter & vitals schema | ✅ PASS |
| **Unit** | `synthetic_fixtures` | `test_synthetic_radiology_phi_compliance` | Valid radiology imaging metadata | ✅ PASS |
| **Unit** | `synthetic_fixtures` | `test_phi_guardrail_detects_real_ssn_pattern` | Rejects real SSN format | ✅ PASS |
| **Unit** | `synthetic_fixtures` | `test_phi_guardrail_enforces_synthetic_identifier_prefix` | Enforces `SYNTH-PAT-*` prefix | ✅ PASS |
| **Unit** | `checksum_integrity` | `test_checksum_deterministic` | SHA-256 is deterministic across identical bytes | ✅ PASS |
| **Unit** | `checksum_integrity` | `test_checksum_avalanche_effect_single_byte_flip` | Single byte change alters hash completely | ✅ PASS |
| **Unit** | `checksum_integrity` | `test_checksum_handles_empty_payload` | Correct standard SHA-256 on empty string | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_clean_synthetic_records_pass` | All 4 clean synthetic records pass with 0 errors | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_detects_ssn_variations` | Catches SSN variations (dashed and spaced) | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_detects_real_external_email` | Catches non-synthetic external email domains | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_allows_synthetic_domain_emails` | Permits synthetic test email domains | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_detects_real_telephone_pattern` | Catches real telephone number patterns | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_flags_missing_synthetic_notice` | Rejects records missing synthetic notice tag | ✅ PASS |
| **Unit** | `phi_scanner` | `test_scanner_assert_zero_phi_raises_exception` | Raises PHIComplianceViolationError | ✅ PASS |
| **Unit** | `golden_vectors` | `test_all_golden_vectors_present` | All 4 clinical categories have golden vectors | ✅ PASS |
| **Unit** | `golden_vectors` | `test_golden_vector_retrieval_and_fields` | Vector fields and types verified | ✅ PASS |
| **Unit** | `golden_vectors` | `test_golden_digests_match_freshly_generated_fixtures` | No digest drift on newly generated records | ✅ PASS |
| **Unit** | `golden_vectors` | `test_verify_golden_digest_rejects_tampered_record` | Detects modification in digest or payload | ✅ PASS |
| **Unit** | `golden_vectors` | `test_exported_golden_vectors_json_file_validity` | golden_test_vectors.json exists and is valid | ✅ PASS |
| **Unit** | `clinical_detail_schemas` | `test_record_detail_response_from_orm_with_datetime` | Verifies ORM conversion and datetime serialization | ✅ PASS |
| **Unit** | `clinical_detail_schemas` | `test_record_detail_response_camel_case_serialization` | Verifies camelCase output matching frontend types | ✅ PASS |
| **Unit** | `clinical_detail_schemas` | `test_record_detail_create_validation` | Verifies Pydantic creation validation | ✅ PASS |
| **Unit** | `clinical_detail_schemas` | `test_record_upload_response_composite` | Verifies composite record + details response | ✅ PASS |
| **Security** | `rbac_jwt` | `test_valid_patient_jwt_verification` | Legitimate patient JWT verified successfully | ✅ PASS |
| **Security** | `rbac_jwt` | `test_tampered_jwt_signature_rejected` | Forged/tampered secret key signature rejected | ✅ PASS |
| **Security** | `rbac_jwt` | `test_tampered_payload_content_rejected` | Modified payload rejected | ✅ PASS |
| **Security** | `rbac_jwt` | `test_expired_jwt_token_rejected` | Expired timestamp rejected | ✅ PASS |
| **Security** | `rbac_jwt` | `test_malformed_token_structure_rejected` | Non-JWT strings safely rejected | ✅ PASS |
| **Security** | `rbac_jwt` | `test_patient_self_access_allowed` | Patient can read own records | ✅ PASS |
| **Security** | `rbac_jwt` | `test_horizontal_privilege_escalation_blocked` | Patient A cannot read Patient B's records | ✅ PASS |
| **Security** | `rbac_jwt` | `test_doctor_access_without_active_consent_denied` | Doctor without consent rejected (403 Forbidden) | ✅ PASS |
| **Security** | `rbac_jwt` | `test_unauthorized_role_denied` | Untrusted external role rejected | ✅ PASS |
| **Security** | `rbac_jwt` | `test_admin_clinical_records_access_denied_zero_phi_boundary` | Admin denied access to clinical records (403) | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_unauthenticated_rejected_401` | Protected details reject unauthenticated access | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_patient_self_access_allowed_200` | Patient self-access granted for details | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_patient_horizontal_isolation_blocked_403` | Cross-patient access to details blocked (403) | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_doctor_active_consent_allowed_200` | Doctor with active consent accesses details | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_doctor_revoked_consent_denied_403` | Doctor with revoked consent denied details (403) | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_doctor_without_consent_denied_403` | Doctor without consent denied details (403) | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_admin_zero_phi_privacy_boundary_denied_403` | Admin strictly blocked by Zero-PHI boundary (403) | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_auditor_compliance_access_allowed_200` | Auditor allowed oversight access to details | ✅ PASS |
| **Security** | `clinical_security_gates` | `test_clinical_details_nonexistent_record_returns_404` | Unknown record ID returns 404 Not Found | ✅ PASS |
| **Security** | `consent_revocation`| `test_active_consent_permits_doctor_access` | Active consent grants clinical access | ✅ PASS |
| **Security** | `consent_revocation`| `test_immediate_access_block_upon_consent_revocation` | Revoked consent blocks doctor instantly | ✅ PASS |
| **Security** | `consent_revocation`| `test_expired_consent_blocks_access` | Past `valid_until` timestamp blocks doctor | ✅ PASS |
| **Security** | `consent_revocation`| `test_consent_scope_isolation_enforced` | Scoped consent limits record types | ✅ PASS |
| **Security** | `consent_revocation`| `test_unauthorized_patient_cannot_revoke_third_party_consent` | Cross-patient consent revocation rejected | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_zero_phi_rejection_ssn` | Submitting SSN in chaincode raises ValueError | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_zero_phi_rejection_private_key` | Submitting private key raises ValueError | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_zero_phi_rejection_plaintext_password`| Submitting password raises ValueError | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_cross_patient_consent_grant_denied` | Unauthorized patient grant rejected (403) | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_cross_patient_consent_revocation_denied` | Unauthorized patient revocation rejected (403)| ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_consent_scope_confinement` | Doctor out-of-scope query rejected | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_unregistered_doctor_access_denied` | Unknown actor returns NO_CONSENT_FOUND | ✅ PASS |
| **Security** | `fabric_invariants`| `test_fabric_on_chain_audit_tamper_resistance` | Historical block tampering caught by hash chain | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_clinical_upload_description_only_success` | Text symptoms upload without files succeeds | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_clinical_upload_document_file_only_success` | Document upload without description succeeds | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_clinical_upload_prescription_only_success` | Prescription attachment only upload succeeds | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_clinical_upload_multi_input_combined_success` | Multi-input combined upload succeeds | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_clinical_upload_empty_submission_rejected_422` | Empty upload rejected with HTTP 422 | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_clinical_upload_whitespace_description_rejected_422` | Whitespace-only description rejected (422) | ✅ PASS |
| **Integration** | `phase6_upload_details` | `test_baseline_seeded_record_details` | rec-001, rec-002, rec-003 persistent details intact | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_valid_ipfs_retrieval_and_checksum_verification` | CID fetch matches ledger hash | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_ipfs_tampered_payload_triggers_critical_alert` | Altered IPFS content raises ChecksumMismatchError | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_ipfs_truncated_payload_detected` | Truncated payload detected | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_ipfs_cid_not_found` | Nonexistent CID raises KeyError | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_verify_ledger_state_verified` | Verify ledger returns VERIFIED on match | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_verify_ledger_state_checksum_mismatch` | Verify ledger returns CHECKSUM_MISMATCH on tamper | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_verify_ledger_state_ipfs_unavailable` | Verify ledger returns IPFS_UNAVAILABLE on timeout | ✅ PASS |
| **Integration** | `ipfs_tampering` | `test_verify_ledger_state_ledger_unavailable` | Verify ledger returns LEDGER_UNAVAILABLE on missing | ✅ PASS |
| **Integration** | `audit_trail` | `test_audit_event_logged_on_authorized_read` | Emits ALLOWED audit entry with actor/record | ✅ PASS |
| **Integration** | `audit_trail` | `test_audit_event_logged_on_denied_attempt` | Emits DENIED audit entry on horizontal attack | ✅ PASS |
| **Integration** | `audit_trail` | `test_audit_hash_chain_integrity` | Multi-step lifecycle produces intact hash chain | ✅ PASS |
| **Integration** | `audit_trail` | `test_audit_tamper_detection_on_modified_log` | Detects mutation in past audit log entries | ✅ PASS |
| **Integration** | `audit_trail` | `test_audit_tamper_detection_on_deleted_entry` | Detects deleted audit entry in log history | ✅ PASS |
| **Integration** | `fabric_transactions` | `test_fabric_register_record_transaction_and_query` | Tx submission, 64-hex hash, block commit | ✅ PASS |
| **Integration** | `fabric_transactions` | `test_fabric_verify_record_checksum_on_ledger` | Verified intact vs checksum mismatch query | ✅ PASS |
| **Integration** | `fabric_transactions` | `test_fabric_consent_full_lifecycle` | PENDING -> ACTIVE -> REVOKED with zero lag | ✅ PASS |
| **Integration** | `fabric_transactions` | `test_fabric_ledger_state_persistence_across_restarts` | State checkpoint & reload across node restart | ✅ PASS |

---

## 🚀 Running the Tests

To run the complete QA suite:
```bash
python -m pytest tests -v
```

To run only Fabric integration and security suites:
```bash
python -m pytest tests -k "fabric" -v
```
