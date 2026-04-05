# Checkpoint Sync Progress — epbs-devnet-1

## Goal
Make Lighthouse checkpoint sync against epbs-devnet-1 and follow head.

## Status: CHECKPOINT SYNC WORKS + ENVELOPE LOOKUP WIRED
- Checkpoint sync initializes correctly, zero block rejections, finalized root matches devnet
- Cannot test full sync-to-head: Prysm collocation limit blocks our IP
- Root cause: 22 peer IDs stored from our IP 85.10.201.236, exceeds Prysm's CollocationLimit=5
- Not an IP ban — it's an anti-Sybil measure in `beacon-chain/p2p/peers/status.go:isfromBadIP`
- Need: fresh IP, Prysm restart (clear peer store), or different machine

## Devnet State (checked 2026-04-04)
- Devnet alive, head slot ~25232, synced, not optimistic
- Checkpoint sync URL: `https://beacon.epbs-devnet-1.ethpandaops.io/`

## Pre-existing Bugs (from DEVNET_SYNC_STATUS.md)

### Bug 1: MissingHotStateSummary — FIXED (prior work)
- **File**: `beacon_node/store/src/hot_cold_store.rs`
- **Fix**: Fall back to Pending when previous state summary missing during checkpoint sync

### Bug 2: Missing Envelope for Parent Block — WORKAROUND ONLY
- **File**: `beacon_node/beacon_chain/src/block_verification.rs`
- **Symptom**: `DBInconsistent("Missing envelope for parent block")`
- **Current workaround**: Falls back to Pending state, causes state root mismatches → validation fails → peers drop → stall
- **This is the blocking issue**

---

## My Attempts

### Attempt 1: Download envelope during checkpoint sync
- Downloaded envelope from checkpoint server HTTP API (works, Prysm serves it)
- Stored envelope in DB for invariant 5 compliance
- **Problem**: fork choice set `payload_received=true` for anchor (genesis logic), returned `Full` status
- `get_advanced_hot_state` couldn't find Full state (only Pending stored)
- **Fix**: Changed `is_genesis` in proto_array to check `slot == 0` not just `parent.is_none()`

### Attempt 2: Snapshot with envelope=None, fallback in load_parent  
- Snapshot without envelope → fork choice returns Pending → head loads correctly
- Envelope stored in DB only
- `load_parent` falls back from Full→Pending when Full state not found
- **Problem**: Pending state has wrong `latest_block_hash` — hasn't been updated by envelope
- Child block's `ExecutionPayloadBid.parent_block_hash` doesn't match `state.latest_block_hash`
- Error: `ExecutionPayloadBidInvalid: ParentBlockHashMismatch`

### Attempt 3: Mutate `latest_block_hash` on Pending state + recompute root
- Applied minimal mutation: set `state.latest_block_hash = envelope.payload.block_hash`
- Recomputed state root after mutation and updated split point
- Stored envelope in DB for invariant 5 compliance
- Snapshot uses `execution_envelope: None` so fork choice computes correct block root
- Proto_array fix: `is_genesis = parent_index.is_none() && block.slot == 0` (not just no parent)
- `load_parent` falls back from Full→Pending when Full state not found (for first child block)
- **Result**: Zero block rejections, head advances from checkpoint slot to slot+~65
- **Remaining issue**: Prysm peers rate-limit `data_columns_by_range` requests → peers disconnect → sync stalls
- This is a networking issue, not a checkpoint sync bug

### Bug 3: Peers disconnect with "Fault" — wrong finalized_root (CRITICAL)
- Prysm peers send `Goodbye: Fault` immediately after status exchange
- Our `finalized_root` doesn't match theirs for the same finalized epoch
- Root cause: mutating `latest_block_hash` on the checkpoint state changes the state root
- The changed state root cascades: `get_forkchoice_store` computes block header root using
  the mutated state root → different block root → different finalized_root in status messages
- Blocks DO import correctly (head advances ~100 slots) but peers disconnect during status
- **The state mutation approach is fundamentally broken** — can't change state without
  changing roots, which makes status messages incompatible

### Key insight: Can't mutate the Pending state
The downloaded Pending state has a specific root that matches what the network expects.
Mutating it changes the root, making our node incompatible. Need a different approach.

### Attempt 4: Patch in-memory state only, don't mutate stored state (CURRENT)
- Reverted all stored-state mutations (keeps correct roots for status messages)
- In `load_parent`, when falling back from Full→Pending, load the envelope from DB and
  apply `latest_block_hash = envelope.payload.block_hash` on the IN-MEMORY state only
- The on-disk state retains its original root → correct fork choice and status messages
- **Result**: Zero block rejections, head advances ~100+ slots from checkpoint
- **finalized_root matches devnet** — our status messages have correct finalized data

### Bug 4: Range sync doesn't download envelopes (CRITICAL for Gloas)
- `block_components_by_range_request` sends: BlocksByRange + DataColumnsByRange
- No `PayloadEnvelopesByRange` requests are made
- Blocks import successfully as Pending (beacon block processing succeeds without envelope)
- The chain operates in Pending-only mode — no Full states, no execution payload validation
- Eventually, child blocks whose parents were Full will fail bid validation:
  `ExecutionPayloadBidInvalid: ParentBlockHashMismatch`
- Our `load_parent` in-memory patch covers the checkpoint block's children, but NOT
  subsequent full blocks whose envelopes were never downloaded
- **Fix needed**: Add `PayloadEnvelopesByRange` to `block_components_by_range_request`,
  similar to how `DataColumnsByRange` was integrated. This is a significant change to the
  range sync pipeline and coupling logic.

### Bug 5: Prysm peers IP-banned from previous broken sessions (NETWORKING)
- Prysm sends `Goodbye: Fault` immediately after status exchange
- Happens BEFORE any data requests — not caused by rate limiting
- Our finalized_root and epoch match the devnet's canonical chain
- Likely a Prysm interop issue with StatusMessageV2 or some field mismatch
- Lodestar peers at epoch 3/206 are far behind and correctly disconnected
- Blocks import correctly when peers are connected (zero rejections)
- **This is a separate P2P interop issue, not related to checkpoint sync**

### Changes Made (files modified)
1. `beacon_node/client/src/builder.rs` — Download envelope during Gloas checkpoint sync
2. `beacon_node/beacon_chain/src/builder.rs` — Accept envelope param, store in DB, no state mutation
3. `beacon_node/beacon_chain/src/block_verification.rs` — Fallback Full→Pending + in-memory block_hash patch
4. `beacon_node/beacon_chain/tests/store_tests.rs` — Updated call sites for new signature
5. `beacon_node/store/src/hot_cold_store.rs` — Bug 1 fix (handle missing previous_state_root)
6. `consensus/proto_array/src/proto_array.rs` — Fix `is_genesis` for checkpoint sync anchors
7. `.cargo/config.toml` — Build target dir

### Changes Made (files modified)
1. `beacon_node/client/src/builder.rs` — Download envelope during Gloas checkpoint sync
2. `beacon_node/beacon_chain/src/builder.rs` — Accept envelope, mutate `latest_block_hash`, store envelope in DB, recompute state root
3. `beacon_node/beacon_chain/src/block_verification.rs` — Fallback from Full→Pending in load_parent
4. `beacon_node/beacon_chain/tests/store_tests.rs` — Updated call sites for new signature
5. `beacon_node/store/src/hot_cold_store.rs` — Bug 1 fix (handle missing previous_state_root)
6. `consensus/proto_array/src/proto_array.rs` — Fix `is_genesis` for checkpoint sync anchors
7. `.cargo/config.toml` — Build target dir
