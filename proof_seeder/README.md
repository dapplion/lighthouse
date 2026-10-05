# Proof seeder

Signs EIP-8025 execution proofs and submits them to a beacon node, so a proving service needs no validator key and speaks no SSZ. It posts the proof and the facts that say what the proof is of:

```
POST /proofs?beacon_root=0x…&slot=1234&block_hash=0x…&parent_hash=0x…&proof_type=1
body: the raw proof
```

`202` once the beacon node has it, `400` if the parameters are malformed, `413` if the proof is over `MAX_PROOF_SIZE`, `502` with the node's reason if it refused.

```
cargo run --release -p proof_seeder -- --beacon-node http://127.0.0.1:5052 \
  --keystore keystore.json --keystore-password-file password --validator-index 7
```

The prover supplies the chain facts, so the relay holds no cache and follows nothing — the only state is the key. It authenticates nobody, so do not expose the socket: the beacon node binds this validator to a block's proof type on signature validity alone, before its engine has said anything, so whoever can post can burn every proof type of a block for this validator and get the real prover's proofs rejected as duplicates. Every proof carries this relay's validator index whoever proved it, and nothing here checks a proof, so running it for a proving service means vouching for that service.

`ethproofs_bridge` is one such service: it follows the chain, asks [Ethproofs](https://ethproofs.org) for proofs of the blocks it sees, and posts them here over this same route.
