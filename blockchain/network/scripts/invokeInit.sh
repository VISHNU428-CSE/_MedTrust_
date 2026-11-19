#!/usr/bin/env bash
set -euo pipefail

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
  -c '{"function":"MedTrustContract:InitLedger","Args":[]}'
