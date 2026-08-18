# Optional execution proofs devnet

Runs a local network where some nodes gate payload import on EIP-8025 execution proofs, and one
node produces and gossips those proofs. Use it to check that a gated node keeps up with an ungated
one, which is the question the optional-proof rollout turns on.

## What the network looks like

Five Lighthouse nodes, Gloas from genesis, minimal preset, all paired with geth.

| Nodes | Engine | Behaviour |
| --- | --- | --- |
| `cl-1`, `cl-2` | none | Control. Imports payloads unconditionally. |
| `cl-3`, `cl-4` | `mock-proof-engine` | Consumer. Verify-only engine, so it gates payload import on proofs from two distinct proof systems. |
| `cl-5` | `mock-proof-seeder` | Seeder. Its engine holds a validator key, so it produces signed proofs and gossips them. |

The controls exist so a stalled consumer is distinguishable from a broken devnet. Without them, a
chain that stops moving tells you nothing about why.

Every node using proofs is given the same `--proof-engine-endpoint` flag. Whether a node seeds is
decided by the engine behind that flag, not by the node's configuration: an engine with a key
returns signed proofs, one without returns nothing. The beacon node never holds a validator key,
and both the proving and the signing stay inside the engine binary.

A seeder imports the proofs it was handed as well as gossiping them, so it satisfies its own gate
and does not stall waiting on a proof it is already holding.

Proving is mocked by `mock_proof_engine`, which mints a proof deterministically from the payload's
request root and the proof type. It is not an always-`VALID` stub: bytes it did not mint verify as
`INVALID`, so the consumer's reject path stays reachable. The BLS signature over each proof is
real, because consumers check it.

## Prerequisites

- Docker.
- Kurtosis **1.20 or newer**. The `apt.fury.io` repository in the older install instructions stops
  at 1.15.2, which cannot parse the current `ethereum-package`:

  ```
  echo "deb [trusted=yes] https://sdk.kurtosis.com/kurtosis-cli-release-artifacts/ /" \
    | sudo tee /etc/apt/sources.list.d/kurtosis.list
  sudo apt update && sudo apt install -y kurtosis-cli
  kurtosis engine restart
  ```

## Build the images

Lighthouse **must** be built with `spec-minimal`. Without it the nodes exit at startup with
`Eth spec 'minimal' is not supported by this build of Lighthouse`.

```
docker build --build-arg FEATURES=portable,spec-minimal -t lighthouse:local .
docker build -t mock-proof-engine:local -f testing/mock_proof_engine/Dockerfile .
```

## Run it

```
./scripts/tests/optional-proofs.sh
```

The engines are Kurtosis services, not containers attached to the enclave network afterwards.
Kurtosis allocates enclave IPs itself, and an outside container joining that network takes an
address it had reserved, which fails the enclave with `Address already in use`. Being services
also means they are reachable before the first Gloas payload, which matters: see below.

## Check it

```
./scripts/tests/optional-proofs-status.sh
```

```
NODE   ROLE      HEAD   JUST/FINAL  PUBLISHED  VERIFIED  IMPORTED_VIA_PROOF
cl-1   control   54     5/4         0          0         0
cl-2   control   54     5/4         0          0         0
cl-3   consumer  54     5/4         0          106       51
cl-4   consumer  54     5/4         0          106       52
cl-5   seeder    55     5/4         108        0         0
```

What to look for:

- Consumers at the same head **and the same finalized epoch** as the controls. Equal heads alone
  only show the consumer is following the chain; equal finality shows it is attesting on time, so
  proofs are arriving inside the attestation deadline.
- `IMPORTED_VIA_PROOF` climbing. These are envelopes that became importable only once a proof
  arrived, so the gate is real rather than passing everything through.
- `PUBLISHED` at twice the number of payloads, since the seeder covers both proof types itself.

## Tear it down

```
kurtosis enclave rm -f optional-proofs
```

## Notes

The seeding engine signs with validator 0's key, derived from the `ethereum-package` mnemonic, set
in `optional-proofs.star`. Consumers reject proofs from validators that are not in the active set,
so this has to be a real key. To regenerate it, or to use a different mnemonic or index:

```
python3 scripts/tests/derive_validator_key.py "<mnemonic>" 0
```

A consumer that misses a proof never imports that payload. Proofs have no RPC or sync path, on the
assumption that they are recursive, and an unreachable proof engine is ignored without penalty, so
a node whose engine is down during a payload's slot stalls on that payload silently. This is why
the engine has to be up before the first Gloas payload rather than attached later.
