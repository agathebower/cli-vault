#!/usr/bin/env bash
# Builds vault + vaultd for the host (./vault-system/{vault,vaultd})
# and for linux amd64/arm64 (./vault-system/dist/).
set -euo pipefail
cd "$(dirname "$0")/vault-system"
echo "[*] Building vault + vaultd..."
make build release
echo "[*] Done"
ls -la vault vaultd dist/*/
