# Mock proof engine

A stand-in for an EIP-8025 proving service, so a devnet can run the proof producer and the proof
consumer end to end without any real proving.

There is no cryptography here. A proof is `sha256` expanded from the payload's request root and the
proof type. Producer and consumer therefore agree, distinct proof types give distinct proofs, and
bytes this engine did not mint are rejected, which keeps the consumer's REJECT path reachable.

## Run it

```
cargo run --release -p mock_proof_engine -- --listen-address 127.0.0.1:8025
```

| Flag | Meaning |
| --- | --- |
| `--listen-address` | Address to bind. Default `127.0.0.1:8025`. |
| `--proof-size` | Bytes per proof. Default `1024`. |
| `--reject-all` | Answer `INVALID` to everything, to test the consumer's reject path. |

## Routes

| Route | Used by | Behaviour |
| --- | --- | --- |
| `GET /v1/execution_proofs/{new_payload_request_root}/{proof_type}` | producer | Mints the proof bytes to sign and gossip. |
| `POST /v1/execution_proof_verifications` | consumer | `{"status":"VALID"}` if the body is the proof this engine would mint. |

## Devnet wiring

Every node needs an engine to verify against, and one node seeds the proofs.

Consumer, which gates payload import on proofs:

```
lighthouse bn --proof-engine-endpoint http://127.0.0.1:8025 ...
```

Producer, which does the same and additionally signs and gossips a proof for every payload it
imports:

```
lighthouse bn \
  --proof-engine-endpoint http://127.0.0.1:8025 \
  --proof-producer-secret-key 0x<bls-secret-key> \
  --proof-producer-validator-index <index> \
  --proof-producer-types 0,1
```

The key must belong to an active validator at the block's epoch, or consumers reject the proofs and
their payloads never import. `--proof-producer-types` must cover at least as many distinct types as
consumers require, since one seeder supplies all of them.

The beacon node signs with the key given on the command line. EIP-8025 expects the validator client
to hold that key, so this is a devnet shortcut and nothing else.
