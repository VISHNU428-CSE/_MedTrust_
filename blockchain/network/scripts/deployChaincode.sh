#!/usr/bin/env bash
# Deploy MedTrust Chaincode (Packaging, Installation, Approval, and Commit)
set -euo pipefail

CHANNEL_NAME=${1:-"medtrust-channel"}
CC_NAME=${2:-"medtrust-contract"}
CC_VERSION=${3:-"1.0"}
CC_SEQUENCE=${4:-"1"}
CC_SRC_PATH="../chaincode"

echo "=== 1. Packaging Chaincode (${CC_NAME} v${CC_VERSION}) ==="
peer lifecycle chaincode package "${CC_NAME}.tar.gz" \
  --path "${CC_SRC_PATH}" \
  --lang node \
  --label "${CC_NAME}_${CC_VERSION}"

echo "=== 2. Installing Chaincode on Org1 Peer ==="
export CORE_PEER_LOCALMSPID="Org1MSP"
export CORE_PEER_TLS_ROOTCERT_FILE="$(pwd)/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt"
export CORE_PEER_MSPCONFIGPATH="$(pwd)/crypto-config/peerOrganizations/org1.medtrust.com/users/Admin@org1.medtrust.com/msp"
export CORE_PEER_ADDRESS="localhost:7051"

peer lifecycle chaincode install "${CC_NAME}.tar.gz"

echo "=== 3. Querying Installed Package ID ==="
CC_PACKAGE_ID=$(peer lifecycle chaincode calculatepackageid "${CC_NAME}.tar.gz")
echo "Package ID: ${CC_PACKAGE_ID}"

echo "=== 4. Approving Chaincode Definition for Org1 ==="
peer lifecycle chaincode approveformyorg -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --package-id "${CC_PACKAGE_ID}" \
  --sequence "${CC_SEQUENCE}" \
  --tls \
  --cafile "$(pwd)/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt"

echo "=== 5. Committing Chaincode Definition to Channel ==="
peer lifecycle chaincode commit -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --channelID "${CHANNEL_NAME}" \
  --name "${CC_NAME}" \
  --version "${CC_VERSION}" \
  --sequence "${CC_SEQUENCE}" \
  --tls \
  --cafile "$(pwd)/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "$(pwd)/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt"

echo "=== 6. Initializing Ledger ==="
peer chaincode invoke -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.medtrust.com \
  --tls \
  --cafile "$(pwd)/crypto-config/ordererOrganizations/medtrust.com/orderers/orderer.medtrust.com/tls/ca.crt" \
  -C "${CHANNEL_NAME}" \
  -n "${CC_NAME}" \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles "$(pwd)/crypto-config/peerOrganizations/org1.medtrust.com/peers/peer0.org1.medtrust.com/tls/ca.crt" \
  -c '{"function":"MedTrustContract:InitLedger","Args":[]}'

echo "=== MedTrust Chaincode Successfully Deployed! ==="
