#!/usr/bin/env bash
set -euo pipefail

RUN_ID=$(date +%s)
RECORD_ID="REC-SYNTH-${RUN_ID}"
CONSENT_ID="CONSENT-SYNTH-${RUN_ID}"

echo "=== 1. Registering Record (${RECORD_ID}) on Hyperledger Fabric Ledger ==="
peer chaincode invoke \
  -o orderer.medtrust.com:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --tls \
  --cafile /network/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt \
  -C medtrust-channel \
  -n medtrust-contract \
  --peerAddresses peer0.org1.medtrust.com:7051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt \
  --peerAddresses peer0.org2.medtrust.com:9051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org2.medtrust.com/peers/peer0.org2.medtrust.com/tls/ca.crt \
  -c "{\"function\":\"MedTrustContract:RegisterRecord\",\"Args\":[\"${RECORD_ID}\",\"SYNTH-PAT-001\",\"bafkreiahwbxcorp2i3ezl5bpv5i7zebfp3dhkrlng32zl6kmvsl3ysl2ai\",\"07b06e2745fa46c995f42faf51fc90257ec675456d36f595f94cac97bc497a02\",\"CARDIOLOGY_REPORT\",\"Metro General Hospital\",\"doc-331902\"]}"

sleep 2

echo "=== 2. Querying Record Back from Ledger State ==="
peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c "{\"function\":\"MedTrustContract:GetRecord\",\"Args\":[\"${RECORD_ID}\"]}"

echo "=== 3. Testing Consent Lifecycle: RequestConsent ==="
peer chaincode invoke \
  -o orderer.medtrust.com:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --tls \
  --cafile /network/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt \
  -C medtrust-channel \
  -n medtrust-contract \
  --peerAddresses peer0.org1.medtrust.com:7051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt \
  --peerAddresses peer0.org2.medtrust.com:9051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org2.medtrust.com/peers/peer0.org2.medtrust.com/tls/ca.crt \
  -c "{\"function\":\"MedTrustContract:RequestConsent\",\"Args\":[\"${CONSENT_ID}\",\"SYNTH-PAT-001\",\"doc-331902\",\"[\\\"CARDIOLOGY_REPORT\\\"]\",\"1893456000\",\"Cardiac evaluation\"]}"

sleep 2

echo "=== 4. Testing Consent Lifecycle: GrantConsent ==="
peer chaincode invoke \
  -o orderer.medtrust.com:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --tls \
  --cafile /network/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt \
  -C medtrust-channel \
  -n medtrust-contract \
  --peerAddresses peer0.org1.medtrust.com:7051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt \
  --peerAddresses peer0.org2.medtrust.com:9051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org2.medtrust.com/peers/peer0.org2.medtrust.com/tls/ca.crt \
  -c "{\"function\":\"MedTrustContract:GrantConsent\",\"Args\":[\"${CONSENT_ID}\",\"SYNTH-PAT-001\",\"doc-331902\",\"[\\\"CARDIOLOGY_REPORT\\\"]\",\"1893456000\",\"Approved by patient\"]}"

sleep 2

echo "=== 5. Querying VerifyConsent (Should Be Allowed) ==="
peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c '{"function":"MedTrustContract:VerifyConsent","Args":["doc-331902","SYNTH-PAT-001","CARDIOLOGY_REPORT"]}'

echo "=== 6. Testing Consent Revocation ==="
peer chaincode invoke \
  -o orderer.medtrust.com:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --tls \
  --cafile /network/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt \
  -C medtrust-channel \
  -n medtrust-contract \
  --peerAddresses peer0.org1.medtrust.com:7051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt \
  --peerAddresses peer0.org2.medtrust.com:9051 \
  --tlsRootCertFiles /network/crypto-config/peerOrganizations/org2.medtrust.com/peers/peer0.org2.medtrust.com/tls/ca.crt \
  -c "{\"function\":\"MedTrustContract:RevokeConsent\",\"Args\":[\"${CONSENT_ID}\",\"SYNTH-PAT-001\"]}"

sleep 2

echo "=== 7. Querying VerifyConsent After Revocation (Should Be Denied) ==="
peer chaincode query \
  -C medtrust-channel \
  -n medtrust-contract \
  -c '{"function":"MedTrustContract:VerifyConsent","Args":["doc-331902","SYNTH-PAT-001","CARDIOLOGY_REPORT"]}'
