#!/usr/bin/env bash
# Start MedTrust Hyperledger Fabric local network
set -euo pipefail

echo "=== Starting MedTrust Fabric Network (Orderer + Peers + CouchDB) ==="
docker compose -f docker-compose-test-net.yaml up -d

echo "=== Verifying running containers ==="
docker ps --filter "name=medtrust" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
