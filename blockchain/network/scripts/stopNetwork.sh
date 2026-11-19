#!/usr/bin/env bash
# Tear down MedTrust Hyperledger Fabric network
set -euo pipefail

echo "=== Tearing down MedTrust Fabric Network ==="
docker compose -f docker-compose-test-net.yaml down -v --remove-orphans

echo "=== Cleaned up ==="
