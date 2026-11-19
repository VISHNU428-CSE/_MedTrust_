#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo " MEDTRUST QA HYPERLEDGER FABRIC LIVE VERIFICATION SUITE"
echo "=========================================================="

echo "=== TEST 1: LEDGER STATE PERSISTENCE AFTER RESTART ==="
RECORD_RESULT=$(peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c '{"function":"MedTrustContract:GetRecord","Args":["REC-SYNTH-1791802553"]}')
echo "Queried Record: ${RECORD_RESULT}"
if echo "${RECORD_RESULT}" | grep -q "REC-SYNTH-1791802553"; then
  echo ">>> [PASS] Record REC-SYNTH-1791802553 persisted across container restart!"
else
  echo ">>> [FAIL] Record not found after restart!"
  exit 1
fi

echo "=== TEST 2: CONSENT REVOCATION STATUS PERSISTENCE ==="
REVOKED_STATUS=$(peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c '{"function":"MedTrustContract:VerifyConsent","Args":["doc-331902","SYNTH-PAT-001","CARDIOLOGY_REPORT"]}')
echo "VerifyConsent Response: ${REVOKED_STATUS}"
if echo "${REVOKED_STATUS}" | grep -q "CONSENT_REVOKED"; then
  echo ">>> [PASS] Consent revocation state accurately persisted!"
else
  echo ">>> [FAIL] Consent revocation state incorrect!"
  exit 1
fi

echo "=== TEST 3: UNAUTHORIZED ACCESS DENIAL (NO CONSENT) ==="
DENIED_STATUS=$(peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c '{"function":"MedTrustContract:VerifyConsent","Args":["doc-unknown-999","SYNTH-PAT-001","CARDIOLOGY_REPORT"]}')
echo "Unauthorized Check Response: ${DENIED_STATUS}"
if echo "${DENIED_STATUS}" | grep -q "NO_CONSENT_FOUND"; then
  echo ">>> [PASS] Unauthorized doctor access blocked with NO_CONSENT_FOUND!"
else
  echo ">>> [FAIL] Unauthorized access was not rejected!"
  exit 1
fi

echo "=== TEST 4: AUDIT TRAIL CRYPTOGRAPHIC HASH CHAIN INTEGRITY ==="
AUDIT_VERIFY=$(peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c '{"function":"MedTrustContract:VerifyAuditChain","Args":[]}')
echo "Audit Trail Verification: ${AUDIT_VERIFY}"
if echo "${AUDIT_VERIFY}" | grep -q '"isIntact":true'; then
  echo ">>> [PASS] Cryptographic audit hash chain is intact and unbroken!"
else
  echo ">>> [FAIL] Audit chain verification failed!"
  exit 1
fi

echo "=========================================================="
echo " ALL LIVE FABRIC LEDGER VERIFICATIONS PASSED (4/4)"
echo "=========================================================="
