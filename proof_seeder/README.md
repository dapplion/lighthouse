# Proof seeder

A relay that signs EIP-8025 execution proofs and submits them to a beacon node.

A proving service knows one thing about a proof: which execution block it is of. Getting it onto
the network takes a beacon block root, a fork's signing domain and a validator key, none of which a
prover should have to hold. This relay holds all three, so the integration for a proving team is one
HTTP POST:

```
POST /proofs?block_hash=0x…&proof_type=3
body: the raw proof
```

The prover decides when. Neither this relay nor the beacon node drives the timing — proofs arrive
when they arrive, and a payload proven twenty minutes late is submitted twenty minutes late.

It can also fetch from [Ethproofs](https://ethproofs.org) itself, for seeding a network nobody is
submitting to yet.

## Run it

Live on a network whose execution blocks are mainnet blocks:

```
cargo run --release -p proof_seeder -- \
  --beacon-node http://127.0.0.1:5052 \
  --keystore /path/to/keystore.json \
  --keystore-password-file /path/to/password \
  --validator-index <index>
```

Verify only, which is what a node that consumes proofs without seeding them runs. No key, so
nothing is signed or submitted:

```
cargo run --release -p proof_seeder -- --beacon-node http://127.0.0.1:5052
```

| Flag | Meaning |
| --- | --- |
| `--listen-address` | Address to bind. Default `127.0.0.1:8025`. |
| `--beacon-node` | Node to read the chain from and submit proofs to. Default `http://127.0.0.1:5052`. |
| `--source` | Where proofs come from besides submissions: `live`, `fixture`, `synthetic` or `none`. Default `live`. |
| `--fixture-block` | Mainnet block whose proofs are served for every payload, in fixture mode. |
| `--keystore`, `--keystore-password-file` | EIP-2335 keystore holding the signing key. |
| `--secret-key` | Hex BLS key instead of a keystore. For devnets. |
| `--validator-index` | Index of the signing validator. Must be in the registry. |
| `--max-proofs-per-payload` | Proofs submitted per payload. Default `4`. |
| `--cache-payloads` | Payloads tracked, and the slot window read on startup. Default `64`. |
| `--requests-per-minute` | Ethproofs request budget. Default `8`, against their quota of ten. |
| `--first-poll-after-minutes` | Delay before asking Ethproofs about a payload. Default `5`. |
| `--give-up-after-minutes` | How long to keep asking. Default `45`. |
| `--proof-size` | Bytes per synthetic proof. Default `1024`. |
| `--reject-all` | Answer `INVALID` to everything, to test a consumer's reject path. |

The spec comes from the beacon node, so there is no `--network` to get wrong, and a relay cannot
disagree with its node about fork versions. It waits for the node rather than exiting if the node
is not up yet.

## What it does with a proof

1. **Resolves the payload.** It reads blocks forward from the head and keeps a window of
   `block_hash → (beacon block root, parent hash, slot)` taken from each block's payload bid. A
   proof of a block hash it has never seen is refused with 404, since there is nothing to sign
   against.
2. **Signs.** `ExecutionProof { beacon_root, zk_proof { proof_data, proof_type, public_inputs
   { block_hash, parent_hash } }, validator_index }`, over `DOMAIN_EXECUTION_PROOF` for the fork at
   that slot.
3. **Submits** to `POST /eth/v1/beacon/pool/execution_proofs`, which verifies and gossips.

Every proof carries this relay's validator index, whoever proved it. Running it for a proving team
means vouching for that team: it holds no verification keys, so it cannot check what it signs.
Proofs it fetched from Ethproofs itself are different — there it knows what the bytes are.

## Sources

`live` asks Ethproofs for proofs of the payloads it is tracking. A payload's `block_hash` on a
network following mainnet execution is the hash Ethproofs indexes, so no block numbers and no chain
walking are involved.

`fixture` serves the proofs of one pinned mainnet block for every payload. A devnet's payloads are
not mainnet blocks, so Ethproofs has nothing for them; this is how a devnet carries proofs of
realistic size and encoding anyway. Every relay on the network needs the same `--fixture-block`, or
their bytes disagree and nothing verifies.

`synthetic` expands bytes from the payload hash. No network, and two relays agree.

`none` relays only what is submitted to it.

## Ethproofs

Two unauthenticated routes carry everything:

```
GET https://ethproofs.org/api/v0/blocks/{number}                -> block metadata, incl. hash
GET https://ethproofs.org/api/v0/proofs/download/block/{hash}   -> zip of every team's proof
```

An API key would also open `GET /proofs?block=` for cheap discovery and `GET /proofs/download/{id}`
for single proofs, instead of a multi-megabyte archive per payload. Nothing here needs one yet.

There is no feed and no webhook, so a payload nobody has proven yet goes on a queue, polled on a
backoff under a request budget until the proofs appear or it ages out.

Measured on 2026-10-05:

| Block age | Proofs | Proving systems |
| --- | --- | --- |
| at the tip | not indexed | — |
| 5 min | 5 | 4 |
| 10 min | 10 | 7 |
| 20–60 min | 10 | 7 |

So seeding from Ethproofs is always retroactive: a payload is proven minutes after it stopped being
the head, and no consumer will attest to it on the strength of a proof. Every block carries at least
four distinct systems, including blocks the whole cohort skips, so a requirement of two is
satisfiable everywhere.

Artifacts run from 250 KB to 2.1 MB, above the spec's 300 KiB `MAX_PROOF_SIZE`. Ours is 4 MiB
deliberately; at the spec's bound most real proofs would not fit.

Proof types are assigned per proving team by a fixed table, so two relays agree on which system is
which. The four teams that prove every block take types 0 to 3.

## Routes

| Route | Behaviour |
| --- | --- |
| `POST /proofs?block_hash&proof_type` | Takes raw proof bytes. `202` once signed and submitted, `404` if the payload is unknown, `503` if this relay holds no key. |
| `POST /v1/execution_proof_verifications` | `{"status":"VALID"}` if the body is an artifact this relay holds for that payload and system. Takes `block_hash` and `proof_type`. |

Verification is not a zkEVM verification: this relay holds no verification keys. A consumer that
wants proofs actually checked needs an engine that can check them.
