# Optional execution proofs devnet

Five Lighthouse nodes, Gloas from genesis, minimal preset, each paired with geth. `cl-1`/`cl-2` have no proof engine and import payloads unconditionally, so a stalled consumer is distinguishable from a broken devnet. `cl-3`/`cl-4` have a verify-only relay and hold a payload optimistic until proofs from two systems arrive. `cl-5`'s relay holds a key, so it signs proofs and submits them to that node, which gossips them.

## Run it

```
docker build --build-arg FEATURES=portable,spec-minimal -t lighthouse:local .
docker build -t proof-seeder:local -f proof_seeder/Dockerfile .
./scripts/tests/optional-proofs.sh
./scripts/tests/optional-proofs-status.sh
kurtosis enclave rm -f optional-proofs
```

A healthy run has the consumers at the same head **and the same finalized epoch** as the controls, with `VALIDATED_VIA_PROOF` climbing — equal heads alone only show the consumer is following, equal finality shows it is attesting on time.

## Gotchas

Kurtosis must be **1.20 or newer**; the `apt.fury.io` repository in the older install instructions stops at 1.15.2, which cannot parse the current `ethereum-package`:

```
echo "deb [trusted=yes] https://sdk.kurtosis.com/kurtosis-cli-release-artifacts/ /" \
  | sudo tee /etc/apt/sources.list.d/kurtosis.list
sudo apt update && sudo apt install -y kurtosis-cli
kurtosis engine restart
```

Lighthouse must be built with `spec-minimal`, or the nodes exit with `Eth spec 'minimal' is not supported by this build of Lighthouse`.

The relays are Kurtosis services, not containers attached to the enclave network afterwards — Kurtosis allocates enclave IPs itself, and an outside container takes an address it had reserved, failing the enclave with `Address already in use`. They start after the package, because a relay reads the spec from its beacon node before it can sign.

The seeding relay signs with validator 0 of the `ethereum-package` mnemonic, set in `optional-proofs.star`. Consumers reject proofs from validators that are not in the registry, so it has to be a real key; `python3 scripts/tests/derive_validator_key.py "<mnemonic>" 0` regenerates it.

`--source fixture` downloads real zkEVM artifacts from Ethproofs, which needs outbound network access from the enclave. `--source synthetic` runs offline.
