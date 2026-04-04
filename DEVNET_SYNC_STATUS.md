# Lighthouse ePBS Devnet-1 Checkpoint Sync — Status & Handoff

## Goal
Get Lighthouse to checkpoint sync against epbs-devnet-1 and follow head.

## Branch
- **Location**: `/root/.openclaw/workspace/lighthouse-devnet-test`
- **Branch**: `devnet-test-combined` (local only, not pushed)
- **Base**: `sigp/unstable` @ `99f5a92b9`
- **Merged in**: sigp/lighthouse PR #9025 (Gloas fork choice redux, commit `68f18efbe`)
- **Merged in**: dapplion/lighthouse PR #68 (gloas-lookup-sync-fixes, branch `gloas-lookup-sync-fixes` @ `8f4a5f0a4`)
- **Local fixes**: 2 patches applied on top (see below)
- **Cargo target-dir**: `/mnt/ssd/builds/lighthouse-devnet-test`

## Devnet Config
- **Network**: epbs-devnet-1
- **Config files**: `/tmp/epbs-devnet-1/` (config.yaml, genesis.ssz, jwt.hex, boot_enrs.txt, el_bootnodes.txt, genesis.json)
- **Checkpoint sync URL**: `https://beacon.epbs-devnet-1.ethpandaops.io/`
- **Beacon API**: `https://beacon.epbs-devnet-1.ethpandaops.io/`
- **Ports used**: CL 9200/udp+tcp, HTTP 5053, EL authrpc 18551
- **Data dirs**: CL `/mnt/ssd/lighthouse-devnet-1`, EL `/mnt/ssd/geth-devnet-1`

## EL Setup
- **Image**: `ethpandaops/geth:epbs-devnet-0` (Docker)
- **Container name**: `geth-devnet-1`
- **Network ID**: 7070339337
- **Start command**:
```bash
EL_BOOTNODES=$(cat /tmp/epbs-devnet-1/el_bootnodes.txt | tr '\n' ',' | sed 's/,$//')
docker run -d --name geth-devnet-1 --network host \
  -v /mnt/ssd/geth-devnet-1:/data -v /tmp/epbs-devnet-1/jwt.hex:/jwt.hex \
  ethpandaops/geth:epbs-devnet-0 \
  --datadir /data --networkid 7070339337 --bootnodes "$EL_BOOTNODES" \
  --port 30304 --discovery.port 30304 \
  --http --http.port 8546 --http.api eth,net,web3,txpool \
  --authrpc.port 18551 --authrpc.jwtsecret /jwt.hex \
  --syncmode full --verbosity 3
```
- **Init**: Must run `docker run --rm ... geth init --datadir /data /genesis.json` first with the EL genesis

## CL Start Command
Script at `/tmp/start-lh-devnet.sh`:
```bash
BOOT_ENRS=$(cat /tmp/epbs-devnet-1/boot_enrs.txt | paste -sd,)
exec /mnt/ssd/builds/lighthouse-devnet-test/release/lighthouse bn \
  --testnet-dir /tmp/epbs-devnet-1 \
  --datadir /mnt/ssd/lighthouse-devnet-1 \
  --checkpoint-sync-url https://beacon.epbs-devnet-1.ethpandaops.io \
  --boot-nodes "$BOOT_ENRS" \
  --target-peers 50 --port 9200 --discovery-port 9200 \
  --http --http-port 5053 \
  --execution-endpoint http://localhost:18551 \
  --execution-jwt /tmp/epbs-devnet-1/jwt.hex \
  --subscribe-all-subnets --import-all-attestations
```

## Bugs Found & Fixed

### Bug 1: MissingHotStateSummary (FIXED)
- **File**: `beacon_node/store/src/hot_cold_store.rs` ~line 1897
- **Symptom**: `CRIT Failed to start beacon node: MissingHotStateSummary(0xe8ee...)`
- **Root cause**: During checkpoint sync, only ONE state is stored (the checkpoint state). `HotStateSummary::new` computes a `previous_state_root` pointing to slot-1's state root, but that state was never stored. When `get_hot_state_summary_payload_status()` tries to load it, it fails.
- **Fix applied**: In `get_hot_state_summary_payload_status()`, when `load_hot_state_summary(&previous_state_root)` returns `None`, instead of erroring, fall back to determining payload status from the current summary alone:
  - If `summary.slot == summary.latest_block_slot` → Pending (block state)
  - Otherwise → Pending (safe default for checkpoint boundary states)
- **This is a correct fix** — checkpoint states at epoch boundaries are always Pending.

### Bug 2: Missing Envelope for Parent Block (PARTIALLY FIXED — NEEDS PROPER FIX)
- **File**: `beacon_node/beacon_chain/src/block_verification.rs` ~line 1976
- **Symptom**: `BlockProcessingFailure: DBInconsistent("Missing envelope for parent block 0xfd97...")`
- **Root cause**: During checkpoint sync, only the block and state are downloaded — NOT the execution payload envelope. When child blocks arrive and reference the checkpoint block as parent with `is_parent_block_full()=true`, the code needs the parent's envelope to get the Full state root. The envelope isn't in the DB.
- **Current workaround**: Falls back to `(Pending, parent_block.state_root())` when envelope is missing. This allows processing to proceed but **causes state root mismatches** → block validation fails → peers disconnect.
- **Result**: Node starts, briefly connects to peers, fails to validate blocks, loses all peers, stalls.

## What Needs to Happen (Priority Order)

### 1. Fix the envelope problem (BLOCKING)
The core issue: checkpoint sync doesn't download/store the execution payload envelope for the checkpoint block. Three approaches:

**Option A — Download envelope during checkpoint sync (RECOMMENDED)**
- Extend `weak_subjectivity_state()` in `beacon_node/beacon_chain/src/builder.rs` (~line 425) to also download and store the checkpoint block's envelope
- The checkpoint sync server at `https://beacon.epbs-devnet-1.ethpandaops.io/` serves blocks via `/eth/v2/beacon/blocks/{slot}` which contains `signed_execution_payload_bid`
- BUT the envelope itself may need a separate endpoint. Check if `/eth/v1/beacon/execution_payload_envelopes/{block_root}` exists (it 404'd when I tried)
- If the envelope isn't available via HTTP, you'd need to either:
  - Add envelope support to the checkpoint sync protocol
  - Or compute it: fetch the execution payload from geth for that block hash and construct the envelope

**Option B — Trigger P2P envelope lookup when missing**
- When `get_payload_envelope(&root)` returns `None`, instead of erroring or falling back, queue an envelope lookup via P2P (similar to how block lookups work)
- PR #68's lookup sync code may already have infrastructure for this — check `single_block_lookup.rs` and `network_context.rs` for envelope request methods
- `request_single_envelope()` exists at `network_context.rs` — this may be usable

**Option C — Compute Full state from Pending state + payload**
- Load the Pending state, execute the payload against it to produce the Full state
- This requires having the execution payload data and running a state transition
- Complex and not ideal for the sync hot path

### 2. Peer connectivity issues
- Node connects to 2-7 peers initially but drops to 0 quickly
- This happens even before block processing (the checkpoint sync instance lost peers before any blocks were processed)
- Might be related to: fork digest mismatch, status message incompatibility, or rate limiting
- The genesis sync test (with vibehouse) maintained peers better — investigate why checkpoint sync loses them
- Could also be a gossip subnet issue — the devnet only has ~10 nodes total

### 3. EL sync coordination
- Geth starts and imports ~157 blocks but then stalls waiting for forkchoice updates from the CL
- Once the CL can process blocks, it will send forkchoice updates and geth will follow
- This is expected and not a bug — it's just downstream of fixing the envelope issue

## Key Code Locations

| What | File | Line |
|------|------|------|
| Checkpoint sync init | `beacon_node/beacon_chain/src/builder.rs` | ~425 (`weak_subjectivity_state`) |
| State storage | `beacon_node/store/src/hot_cold_store.rs` | ~1077 (`put_state`) |
| Hot state summary | `beacon_node/store/src/hot_cold_store.rs` | ~4220 (`HotStateSummary::new`) |
| Payload status check | `beacon_node/store/src/hot_cold_store.rs` | ~1864 (`get_hot_state_summary_payload_status`) |
| Parent state loading | `beacon_node/beacon_chain/src/block_verification.rs` | ~1960 (`load_parent`) |
| Envelope storage | `beacon_node/store/src/hot_cold_store.rs` | ~1064 (`put_payload_envelope`) |
| Envelope retrieval | `beacon_node/store/src/hot_cold_store.rs` | ~741 (`get_payload_envelope`) |
| Envelope P2P request | `beacon_node/network/src/sync/network_context.rs` | search for `request_single_envelope` |

## Files Modified (uncommitted)

1. **`beacon_node/store/src/hot_cold_store.rs`** — Bug 1 fix: handle missing previous_state_root summary in `get_hot_state_summary_payload_status`
2. **`beacon_node/beacon_chain/src/block_verification.rs`** — Bug 2 workaround: fallback to Pending when envelope missing + added `warn` to tracing imports

## What's NOT the Problem
- Build: compiles fine in release (~2-4 min incremental)
- EL: geth syncs and connects, authrpc works
- P2P boot ENRs: correct, 11 entries, work for genesis sync
- Checkpoint sync download: block and state download fine
- Config: correct network config, fork schedule, genesis state

## Useful Commands
```bash
# Check sync status
curl -s http://127.0.0.1:5053/eth/v1/node/syncing | jq .

# Check devnet head
curl -s "https://beacon.epbs-devnet-1.ethpandaops.io/eth/v1/beacon/headers/head" | jq '.data.header.message.slot'

# Check geth
docker logs geth-devnet-1 2>&1 | tail -20

# Check CL logs
tail -50 /tmp/lh-devnet.log

# Rebuild after changes
export PATH="$HOME/.cargo/bin:$PATH"
cd /root/.openclaw/workspace/lighthouse-devnet-test
cargo build --release --bin lighthouse

# Restart clean
pkill -f "lighthouse-devnet-test" 2>/dev/null; sleep 2
rm -rf /mnt/ssd/lighthouse-devnet-1
nohup /tmp/start-lh-devnet.sh > /tmp/lh-devnet.log 2>&1 &
```
