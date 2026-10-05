# Proof seeder

An EIP-8025 proof engine that seeds a network with execution proofs from
[Ethproofs](https://ethproofs.org). Point a beacon node at it with
`--proof-engine-endpoint` and, if it has a key, the node gossips the proofs it hands back.

The beacon node holds no validator key and does no proving: it asks this for proofs of a payload
and relays what it gets. Whether a node seeds is therefore a property of its engine. An engine
with a key produces; an engine without one only verifies.

## Run it

Live on a network whose execution blocks are mainnet blocks:

```
cargo run --release -p proof_seeder -- \
  --listen-address 127.0.0.1:8025 \
  --keystore /path/to/keystore.json \
  --keystore-password-file /path/to/password \
  --validator-index <index>
```

Verify only, which is what a node that consumes proofs without seeding them runs:

```
cargo run --release -p proof_seeder -- --listen-address 127.0.0.1:8025
```

| Flag | Meaning |
| --- | --- |
| `--listen-address` | Address to bind. Default `127.0.0.1:8025`. |
| `--source` | `live`, `fixture` or `synthetic`. Default `live`. |
| `--fixture-block` | Mainnet block whose proofs are served for every payload, in fixture mode. |
| `--keystore`, `--keystore-password-file` | EIP-2335 keystore holding the signing key. |
| `--secret-key` | Hex BLS key instead of a keystore. For devnets. |
| `--validator-index` | Index of the signing validator. Must be in the registry. |
| `--max-proofs-per-payload` | Proofs served per payload. Default `4`. |
| `--cache-payloads` | Payloads to keep proofs for. Default `16`, and each can be megabytes. |
| `--requests-per-minute` | Ethproofs request budget. Default `8`, against their quota of ten. |
| `--first-poll-after-minutes` | Delay before the first poll for a payload. Default `5`. |
| `--give-up-after-minutes` | How long to keep polling a payload. Default `45`. |
| `--proof-size` | Bytes per synthetic proof. Default `1024`. |
| `--reject-all` | Answer `INVALID` to everything, to test a consumer's reject path. |

## Sources

`live` asks Ethproofs for proofs of the payload the beacon node asked about. A payload's
`block_hash` on a network following mainnet execution is the hash Ethproofs indexes, so no block
numbers and no chain walking are involved.

`fixture` serves the proofs of one pinned mainnet block for every payload. A devnet's payloads are
not mainnet blocks, so Ethproofs has nothing for them; this is how a devnet carries proofs of
realistic size and encoding anyway. Every engine on the network needs the same `--fixture-block`,
or their bytes disagree and nothing verifies.

`synthetic` expands bytes from the payload hash. No network, and two engines agree.

## Ethproofs

Two unauthenticated routes carry everything:

```
GET https://ethproofs.org/api/v0/blocks/{number}                -> block metadata, incl. hash
GET https://ethproofs.org/api/v0/proofs/download/block/{hash}   -> zip of every team's proof
```

An API key would also open `GET /proofs?block=` for cheap discovery and `GET /proofs/download/{id}`
for single proofs, instead of a multi-megabyte archive per payload. Nothing here needs one yet.

There is no feed and no webhook, so this emulates one. A payload nobody has proven yet goes on a
queue, polled on a backoff under a request budget until the proofs appear or it ages out.

Measured on 2026-10-05:

| Block age | Proofs | Proving systems |
| --- | --- | --- |
| at the tip | not indexed | — |
| 5 min | 5 | 4 |
| 10 min | 10 | 7 |
| 20–60 min | 10 | 7 |

So seeding is always retroactive: a payload is proven minutes after it stopped being the head, and
no consumer will attest to it on the strength of a proof. Every block carries at least four
distinct systems, including blocks the whole cohort skips, so a requirement of two is satisfiable
everywhere.

Artifacts run from 250 KB to 2.1 MB, above the spec's 300 KiB `MAX_PROOF_SIZE`. Ours is 4 MiB
deliberately; at the spec's bound most real proofs would not fit.

Proof types are assigned per proving team by a fixed table, so two seeders agree on which system is
which. The four teams that prove every block take types 0 to 3.

## Routes

| Route | Behaviour |
| --- | --- |
| `GET /v1/execution_proofs` | SSZ list of `SignedExecutionProof` for a payload. Empty without a key, and empty until Ethproofs has the payload. Takes `beacon_block_root`, `block_hash`, `parent_hash` and `domain`. |
| `POST /v1/execution_proof_verifications` | `{"status":"VALID"}` if the body is a proof Ethproofs serves for that payload and system. Takes `block_hash` and `proof_type`. |

`domain` is supplied by the caller, so this needs no chain configuration to sign — the arrangement
a remote signer has with a validator client.

Verification is not a zkEVM verification: this engine holds no verification keys, and answers
whether the bytes are the artifact Ethproofs serves. A consumer that wants proofs actually checked
needs an engine that can check them.
