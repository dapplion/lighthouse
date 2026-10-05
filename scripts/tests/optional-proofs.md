# Optional execution proofs devnet

Runs a local network where some nodes take EIP-8025 execution proofs as a payload's validity and
never send payloads to their execution layer, and one node has proofs submitted to it and gossips them. Use it
to check that a gated node keeps up with an ungated one, which is the question the optional-proof
rollout turns on.

## What the network looks like

Five Lighthouse nodes, Gloas from genesis, minimal preset, all paired with geth.

| Nodes | Engine | Behaviour |
| --- | --- | --- |
| `cl-1`, `cl-2` | none | Control. Imports payloads unconditionally. |
| `cl-3`, `cl-4` | `proof-verifier` | Consumer. Verify-only engine, so a payload stays optimistic until proofs from two distinct proof systems arrive. |
| `cl-5` | `proof-seeder` | Seeder. Its relay holds a validator key, so it signs proofs and submits them to this node, which gossips them. |

The controls exist so a stalled consumer is distinguishable from a broken devnet. Without them, a
chain that stops moving tells you nothing about why.

Every node using proofs is given the same `--proof-engine-endpoint` flag, which is what verifies
incoming proofs. Seeding is separate and goes the other way: a relay signs proofs and submits them
to `POST /eth/v1/beacon/pool/execution_proofs`, so a node seeds because something is submitting to
it, not because of how it is configured. The beacon node never holds a validator key.

A seeder verifies and counts the proofs it publishes, so it satisfies its own gate and does not
stall waiting on a proof it is already holding.

Proving is mocked by `proof_seeder`, but the proofs are not: it runs with `--source fixture`, which
downloads real zkEVM artifacts from the Ethproofs public API, one per proof type from a pinned
mainnet block. Those run from roughly 250 KB to 2.1 MB against the 1 KB a synthetic proof costs, so
proof propagation is exercised at something like true size. The BLS signature over each proof is
real too, because consumers check it.

It is not an always-`VALID` stub either: bytes the relay does not hold verify as `INVALID`, so the
consumer's reject path stays reachable. The artifacts are not derived from the payload, but the
public inputs are: the relay stamps the payload's block hash and parent hash into every proof it
signs, and a consumer rejects one that names another payload.

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
docker build -t proof-seeder:local -f proof_seeder/Dockerfile .
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
NODE   ROLE      HEAD   JUST/FINAL  PUBLISHED  VERIFIED  VALIDATED_VIA_PROOF
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
- `VALIDATED_VIA_PROOF` climbing. These are payloads fork choice called valid only once their
  proofs arrived, so the gate is real rather than passing everything through.
- `PUBLISHED` at twice the number of payloads, since the seeder covers both proof types itself.

## Tear it down

```
kurtosis enclave rm -f optional-proofs
```

## Notes

The seeding relay signs with validator 0's key, derived from the `ethereum-package` mnemonic, set
in `optional-proofs.star`. Consumers reject proofs from validators that are not in the active set,
so this has to be a real key. To regenerate it, or to use a different mnemonic or index:

```
python3 scripts/tests/derive_validator_key.py "<mnemonic>" 0
```

Both relays fetch from Ethproofs on startup, which needs outbound network access from the enclave
and adds a few seconds to it. Use `--source synthetic` in `optional-proofs.star` to run offline on
synthetic proofs instead.

A consumer that misses a proof holds that payload as optimistic for good, since nothing else can
validate it: the payload is never sent to an execution layer. Proofs have no RPC or sync path, on the
assumption that they are recursive, and an unreachable proof engine is ignored without penalty, so a
node whose engine is down during a payload's slot stalls on that payload silently.

The relays start after the package rather than before it, because a relay reads the spec from its
beacon node before it can sign. A consumer's verification engine only has to be up before the first
Gloas payload it needs to verify.
