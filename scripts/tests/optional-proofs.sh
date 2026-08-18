#!/usr/bin/env bash
#
# Bring up a local devnet that gates payload import on EIP-8025 execution proofs.
set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=${1:-optional-proofs}
CONFIG=${2:-$SCRIPT_DIR/optional-proofs-config.yaml}

kurtosis run --enclave "$ENCLAVE_NAME" "$SCRIPT_DIR/optional-proofs.star" --args-file "$CONFIG"
