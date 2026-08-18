# Mock proof engine

A stand-in for an EIP-8025 proving service, so a devnet can run the proof producer and the proof
consumer end to end without any real proving.

There is no cryptography here. A proof is `sha256` expanded from the payload's request root and the
proof type. Producer and consumer therefore agree, distinct proof types give distinct proofs, and
bytes this engine did not mint are rejected, which keeps the consumer's REJECT path reachable.

## Run it

Verify only:

```
cargo run --release -p mock_proof_engine -- --listen-address 127.0.0.1:8025
```

Verify and produce, by giving it a validator key to sign with:

```
cargo run --release -p mock_proof_engine -- \
  --listen-address 127.0.0.1:8025 \
  --secret-key <bls-secret-key> \
  --validator-index <index> \
  --proof-types 0,1
```

| Flag | Meaning |
| --- | --- |
| `--listen-address` | Address to bind. Default `127.0.0.1:8025`. |
| `--proof-size` | Bytes per proof. Default `1024`. |
| `--reject-all` | Answer `INVALID` to everything, to test the consumer's reject path. |
| `--secret-key` | Hex BLS key to sign produced proofs with. Without it this engine only verifies. |
| `--validator-index` | Index of the signing validator. Default `0`. |
| `--proof-types` | Proof types to produce per payload. Default `0,1`. |
| `--ethproofs` | Serve real zkEVM proofs downloaded from Ethproofs instead of synthetic ones. |
| `--ethproofs-block` | Mainnet block to take those artifacts from. Pinned by default. |

## Real proofs

`--ethproofs` downloads one real proof per proof type at startup, from the Ethproofs public API:

```
GET https://ethproofs.org/api/v0/blocks/{number}                -> block metadata, incl. hash
GET https://ethproofs.org/api/v0/proofs/download/block/{hash}   -> zip of every team's proof
```

Neither endpoint needs a key. The whole prover cohort proves every hundredth mainnet block, so
the default block is pinned to one that carries proofs from nine teams; engines started at
different times therefore agree on the bytes, which they must, since a verifier compares against
what a producer signed. Proofs are taken smallest first.

Artifacts run from about 96 KB to 2.6 MB depending on the proving system, against the 2 KB a
synthetic proof costs. Feeding real ones through gossip is the point: it is the only way the
devnet says anything about how proof propagation behaves at true size.

Every engine on a network needs the same `--ethproofs` and `--ethproofs-block` settings. Mixed
settings mean the bytes disagree and nothing verifies.

## Routes

| Route | Behaviour |
| --- | --- |
| `GET /v1/execution_proofs` | SSZ list of `SignedExecutionProof` for a payload. Empty without a key. Takes `beacon_block_root`, `new_payload_request_root` and `domain` as query parameters. |
| `POST /v1/execution_proof_verifications` | `{"status":"VALID"}` if the body is the proof this engine would mint. |

`domain` is supplied by the caller so this engine needs no chain configuration to sign, the same
arrangement a remote signer has with a validator client.

## Devnet wiring

Every node using proofs gets the same flag:

```
lighthouse bn --proof-engine-endpoint http://127.0.0.1:8025 ...
```

Whether that node seeds proofs onto the network is decided here, not there. An engine started with
`--secret-key` hands back signed proofs and its node gossips them; an engine started without one
hands back nothing and its node only gates. The beacon node holds no validator key.

The key must belong to a validator that is active at the block's epoch, or consumers reject the
proofs and their payloads never import. `--proof-types` must cover at least as many distinct types
as consumers require, since one seeder supplies all of them.

Real proofs are not derived from the payload being proved, so with `--ethproofs` a proof no longer
binds to a particular request root. The reject path still holds for corrupt or mistyped bytes.

EIP-8025 expects a validator or the builder to sign, so a single engine signing for a devnet
validator is a shortcut. Keeping the key here rather than in the beacon node at least puts it in
the same binary as the proving.
