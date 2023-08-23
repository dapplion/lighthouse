#!/usr/bin/env bash

#
# Starts a validator client based upon a genesis state created by
# `./setup.sh`.
#
# Usage: ./validator_client.sh <DATADIR> <BEACON-NODE-HTTP> <OPTIONAL-DEBUG-LEVEL>

set -Eeuo pipefail

source ./vars.env

DEBUG_LEVEL=info

BUILDER_PROPOSALS=

# Get options
while getopts "pd:" flag; do
  case "${flag}" in
    p) BUILDER_PROPOSALS="--builder-proposals";;
    d) DEBUG_LEVEL=${OPTARG};;
  esac
done

data_dir=${@:OPTIND+0:1}
beacon_node_url=${@:OPTIND+1:1}
metrics_port=${@:OPTIND+2:1}

exec lighthouse \
	--debug-level $DEBUG_LEVEL \
	vc \
	$BUILDER_PROPOSALS \
	--datadir $data_dir \
	--testnet-dir $TESTNET_DIR \
	--init-slashing-protection \
	--beacon-nodes $beacon_node_url \
    --metrics \
    --metrics-port $metrics_port \
    --metrics-address 0.0.0.0 \
	--suggested-fee-recipient 0x690B9A9E9aa1C9dB991C7721a92d351Db4FaC990 \
	$VC_ARGS
