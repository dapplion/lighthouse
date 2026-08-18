#!/usr/bin/env bash
#
# Bring up a local devnet that gates payload import on EIP-8025 execution proofs.
#
# The proof engine is a plain docker container attached to the enclave network under the name
# the beacon nodes are pointed at, so its address is known before the enclave exists.
set -Eeuo pipefail

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
ENCLAVE_NAME=${1:-optional-proofs}
CONFIG=${2:-$SCRIPT_DIR/optional-proofs-config.yaml}
ETHEREUM_PKG_VERSION=main

# The beacon nodes resolve the engine by this name on the enclave network.
ENGINE_NAME=mock-proof-engine
NETWORK_NAME=kt-$ENCLAVE_NAME

attach_proof_engine() {
  echo "Waiting for enclave network $NETWORK_NAME"
  until docker network inspect "$NETWORK_NAME" &>/dev/null; do sleep 1; done

  docker rm -f "$ENGINE_NAME" &>/dev/null || true
  docker run -d --name "$ENGINE_NAME" --network "$NETWORK_NAME" \
    "$ENGINE_NAME:local" --listen-address 0.0.0.0:8025
  echo "Proof engine attached to $NETWORK_NAME"
}

attach_proof_engine &
ATTACH_PID=$!

kurtosis run --enclave "$ENCLAVE_NAME" \
  "github.com/ethpandaops/ethereum-package@$ETHEREUM_PKG_VERSION" \
  --args-file "$CONFIG" \
  --image-download always

wait $ATTACH_PID
