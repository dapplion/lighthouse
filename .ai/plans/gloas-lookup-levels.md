# Gloas block lookup: three-stream model

Design for handling block lookups across forks with independent block, data,
and payload streams. Avoids state machine mutation — streams are additive only.

## Problem

In Gloas, a block has three independent components: **block**, **data**
(blobs/columns), and **payload** (execution payload envelope). Different
triggers need different subsets:

- **Unknown root** (attestation reference): only need the block
- **Unknown parent, child is empty**: need block + data
- **Unknown parent, child is full**: need block + data + payload

A lookup's completeness requirement can increase over time as children arrive.
Mutating a live state machine is error-prone, so the design uses additive-only
independent streams.

## Design: three independent streams

Each lookup contains three independent streams with their own lifecycle:

```
BLOCK stream:
  1. download block (has peers from lookup creation)
  2. wait for parent ready:
     - Pre-Gloas: parent block is in fork choice (block_is_known_to_fork_choice)
     - Gloas: parent block is in fork choice AND (parent is empty OR parent envelope imported)
  3. send block for processing
  4. block processing done

DATA stream (created after block downloaded, if block has blobs):
  preconditions: block downloaded + parent processed
  starts with: 0 peers (Gloas) or lookup peers (pre-Gloas)
  1. wait for preconditions + peers > 0
  2. download data
  3. wait for block processing done
  4. import data (send_blobs_for_processing / send_custody_columns_for_processing)
  5. data imported → continue empty children

PAYLOAD stream (created after block downloaded, if block is full, Gloas only):
  preconditions: block downloaded + parent processed
  starts with: 0 peers
  1. wait for preconditions + peers > 0
  2. download payload
  3. wait for block processing done
  4. import payload
  5. payload imported → continue full children
```

### Key properties

- **Additive only**: streams are created, never mutated or removed.
- **0-peers gating**: streams exist proactively but can't download without
  peers. Children arriving add peers to the right stream.
- **No upgrade logic**: no levels, no replacement. Just add peers.
- **Independent lifecycles**: each stream has its own download + processing
  state.

## When streams are created

### Block stream

Always created on lookup creation. Has the lookup's initial peers.

### Data stream

Created after block is downloaded, if `block.num_expected_blobs() > 0`.
Fork-dependent type:
- Deneb/Electra: blob request
- Fulu/Gloas: custody column request

Initial peers:
- Pre-Gloas forks: same peers as block stream (always need data)
- Gloas: 0 peers (data only needed when a child arrives)

### Payload stream

Created after block is downloaded, if block is "full" (Gloas only).
Initial peers: 0 (payload only needed when a full child arrives).

## What children do

When child Y arrives with unknown parent X and lookup for X exists:

1. Determine if parent X is full or empty using `parent_hash` from Y
2. Add Y's peers to X's **data** stream (if data stream exists)
3. If X is full: also add Y's peers to X's **payload** stream

The child sets `awaiting_parent` with enough info to know what it waits for.

## AwaitingParent enum

```rust
enum AwaitingParent {
    /// Pre-Gloas: wait for parent lookup to fully complete (block + data)
    PreGloas { parent_root: Hash256 },
    /// Post-Gloas: track parent_hash to determine full/empty dependency
    PostGloas {
        parent_root: Hash256,
        parent_hash: ExecutionBlockHash,
    },
}
```

For PostGloas children:
- If parent is empty → child waits for parent's **data** import
- If parent is full → child waits for parent's **payload** import

## Child continuation

Currently: `continue_child_lookups(block_root)` runs when a lookup completes.

New model — three separate continuation events:

- `on_block_processing_result(id, result)`: block processed. If the block
  stream completes, advance data/payload streams (they can now download and
  process). Does NOT unblock children yet.
- `on_data_processing_result(id, result)`: data imported. Unblock children
  that are waiting on data (empty children in PostGloas, all children in
  PreGloas).
- `on_payload_processing_result(id, result)`: payload imported. Unblock
  children that are waiting on payload (full children in PostGloas).

For PreGloas: `on_data_processing_result` completes the lookup (no payload).
For Gloas without data/payload streams: `on_block_processing_result` completes.

## Completion conditions

A lookup is complete when ALL active streams have finished processing:

- If only block stream (Gloas unknown root, no children ever arrive):
  complete after block processing
- If block + data (pre-Gloas, or Gloas with empty child):
  complete after data import
- If block + data + payload (Gloas with full child):
  complete after both data and payload import

## Processing infrastructure (already exists)

The codebase already has the message types for per-component processing:

- `BlockProcessType::SingleBlock { id }` → block processing result
- `BlockProcessType::SingleBlob { id }` → data (blob) processing result
- `BlockProcessType::SingleCustodyColumn(id)` → data (column) processing result

All flow through `SyncMessage::BlockComponentProcessed` and back to
`on_processing_result`. The handler needs to dispatch based on `process_type`.

Methods already exist (currently dead code):
- `send_blobs_for_processing(id, block_root, blobs, ...)` in network_context.rs
- `send_custody_columns_for_processing(id, block_root, columns, ...)` in network_context.rs

## Dependency diagram

```
                    block downloaded ─────────────────────────┐
                         │                                    │
                         ▼                                    ▼
               create data stream                    create payload stream
               (if has blobs)                        (if block is full, Gloas)
                         │                                    │
                         │         parent processed           │
                         │◄────────────┤────────────────────► │
                         │             │                      │
                         │             ▼                      │
                         │    send block for processing       │
                         │             │                      │
        has peers?───────┤             │           has peers?─┤
        │ yes            │             │           │ yes      │
        ▼                │             ▼           ▼          │
   download data         │    block processing done      download payload
        │                │             │                      │
        ▼                │             │                      ▼
   wait for block done◄──┘─────────────┘──────►wait for block done
        │                                              │
        ▼                                              ▼
   import data                                    import payload
        │                                              │
        ▼                                              ▼
   continue empty children                     continue full children
```

## Pre-Gloas fork behavior

Minimal changes. Data stream always created with lookup peers (not 0).
No payload stream. AwaitingParent::PreGloas. Lookup completes after data
import (or after block processing if no data needed).

## Error handling and retry

Each stream retries independently:
- Block download failure → retry block download
- Data download failure → retry data download
- Payload download failure → retry payload download
- Block processing failure → reset ALL streams, retry from scratch
- Data processing failure → retry data download only
- Payload processing failure → retry payload download only

## Peer tracking

- Block stream: uses the lookup's main peer set (Arc<RwLock<HashSet<PeerId>>>)
- Data stream: own peer set, starts at 0 for Gloas, shared with block for pre-Gloas
- Payload stream: own peer set, always starts at 0

## Interaction with tree sync (future)

The three-stream model enables tree sync naturally:

**Phase 1 — Chain discovery:**
- Walk back the chain. Each lookup only runs its block stream.
- Data/payload streams exist (if block has blobs) but have 0 peers → idle.
- Fast and lightweight.

**Phase 2 — When chain anchors to fork choice:**
- Process blocks in order (parent first via awaiting_parent).
- Children arriving add peers to parent's data/payload streams.
- Streams activate and start downloading.

**Phase 3 — Processing:**
- Block processed → data/payload download starts (if peers available).
- Data imported → continue empty children.
- Payload imported → continue full children.

No upgrade logic needed. The 0-peers pattern means data/payload streams
naturally activate when children provide peers, regardless of timing.

### Depth limit implications

With block streams being lightweight (no data/payload downloading until peers
arrive), `PARENT_DEPTH_TOLERANCE` can be increased. Only block downloads
contribute to bandwidth during chain discovery.

## Implementation changes

### SingleBlockLookup restructure

```rust
struct SingleBlockLookup<T: BeaconChainTypes> {
    id: Id,
    block_root: Hash256,
    // Block stream — always present
    block_request: BlockRequestState<T::EthSpec>,
    block_processing: ProcessingState,
    // Data stream — created after block downloaded if has blobs
    data_request: Option<DataRequestState<T::EthSpec>>,
    data_processing: ProcessingState,
    // Payload stream — created after block downloaded if full (Gloas)
    payload_request: Option<PayloadRequestState<T::EthSpec>>,
    payload_processing: ProcessingState,
    // Peer sets
    peers: Arc<RwLock<HashSet<PeerId>>>,
    data_peers: Arc<RwLock<HashSet<PeerId>>>,
    payload_peers: Arc<RwLock<HashSet<PeerId>>>,
    // Parent tracking
    awaiting_parent: Option<AwaitingParent>,
    created: Instant,
    span: Span,
}

enum ProcessingState {
    NotSent,
    Sent,
    Done,
}
```

### DataRequestState (fork-dependent)

```rust
enum DataRequestState<E: EthSpec> {
    Blobs(BlobRequestState<E>),
    Columns(CustodyRequestState<E>),
}
```

### Modified: on_processing_result (mod.rs)

Dispatch based on `BlockProcessType`:
- `SingleBlock` → update block_processing state, drive data/payload
- `SingleBlob` / `SingleCustodyColumn` → update data_processing, continue
  empty children
- (future) payload type → update payload_processing, continue full children

### Modified: continue_child_lookups

Split into component-specific continuation:
- `on_data_imported(block_root)` → continue children awaiting data
- `on_payload_imported(block_root)` → continue children awaiting payload

### Types removed

- `LookupState` enum (Downloading | Processing)
- `BlockComponentsByRootRequest`
- `DownloadPhase`
- `BlockExtraRequests`
- `BlockExtras`
- `BlockComponentsResult`
