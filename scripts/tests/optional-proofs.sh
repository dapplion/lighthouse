#!/usr/bin/env bash
#
# Bring up a local devnet that gates payload import on EIP-8025 execution proofs.
#
# See scripts/tests/optional-proofs.md. Build the two images first, Lighthouse needs `spec-minimal`
# because the config runs the minimal preset:
#
#   docker build --build-arg FEATURES=portable,spec-minimal -t lighthouse:local .
#   docker build -t mock-proof-engine:local -f testing/mock_proof_engine/Dockerfile .
set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=${1:-optional-proofs}
CONFIG=${2:-$SCRIPT_DIR/optional-proofs-config.yaml}

kurtosis run --enclave "$ENCLAVE_NAME" "$SCRIPT_DIR/optional-proofs.star" --args-file "$CONFIG"
