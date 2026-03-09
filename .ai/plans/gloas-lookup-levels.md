# Gloas block lookup: three-stream model

Block lookups use three independent streams: **block**, **data**, **payload**.
Streams are additive only — created, never mutated or removed.

## Core concepts

**Empty vs full blocks (Gloas):** A block is "full" if it has an execution
payload. A block is "empty" if it doesn't. You know if a parent is full or
empty by inspecting the child's `parent_hash`.

**What each block type needs:**
- Empty block: just the block
- Full block with blobs: block + data + payload
- Full block without blobs: block + payload

**When children can continue (post-Gloas):**
- Child of empty parent: after parent's block is processed
- Child of full parent: after parent's data + payload are both imported

**Pre-Gloas:** No empty/full distinction. Children continue after data import
(or block processing if no blobs).

## Stream lifecycle

```
BLOCK stream (always created):
  peers: from lookup creation
  1. download block
  2. wait for parent processed
  3. send block for processing
  4. block processed → create data/payload streams if needed

DATA stream (created if full + has blobs (Gloas), or has blobs (pre-Gloas)):
  peers: 0 (Gloas) or lookup peers (pre-Gloas)
  1. wait for peers > 0
  2. download data
  3. wait for block processed
  4. import data

PAYLOAD stream (created if full, Gloas only):
  peers: 0
  1. wait for peers > 0
  2. download payload
  3. wait for block processed
  4. import payload
```

## Children and peer propagation

When child Y arrives with unknown parent X:

- Parent X is empty → child waits for block processing only. No peers added
  to data/payload streams.
- Parent X is full → add Y's peers to X's data stream (if exists) and
  payload stream. Child waits for both data + payload.

```rust
enum AwaitingParent {
    PreGloas { parent_root: Hash256 },
    PostGloas {
        parent_root: Hash256,
        parent_hash: ExecutionBlockHash,
    },
}
```

## Completion

A lookup completes when all active streams finish:

| Scenario | Streams | Complete when |
|----------|---------|---------------|
| Empty block (Gloas) | block | block processed |
| Full block, no blobs (Gloas) | block + payload | payload imported |
| Full block, has blobs (Gloas) | block + data + payload | data + payload imported |
| Has blobs (pre-Gloas) | block + data | data imported |
| No blobs (pre-Gloas) | block | block processed |

## Dependency diagram

```
                block downloaded
                   │         │
                   ▼         ▼
          data stream?   payload stream?
          (full+blobs)     (full, Gloas)
                   │         │
     parent ───────┤─────────┤
     processed     ▼         │
              block processing
                   │         │
    peers? ────────┤    peers?┤
    │yes           │    │yes  │
    ▼              │    ▼     │
 download data     │  download payload
    │              │         │
    ▼              ▼         ▼
 import data    block done  import payload
    │                            │
    └───► both done? ◄───────────┘
              │
              ▼
     continue full children

         block done (empty parent)
              │
              ▼
     continue empty children
```

## Error handling

- Block download/processing failure → reset ALL streams, retry from scratch
- Data download/processing failure → retry data only
- Payload download/processing failure → retry payload only

## Pre-Gloas behavior

Data stream created with lookup peers (not 0) if block has blobs. No payload
stream. No empty/full distinction.

## Tree sync interaction (future)

Phase 1 (chain discovery): only block streams run. Data/payload streams
don't exist yet (block not downloaded). Lightweight.

Phase 2 (anchored): blocks process parent-first. Full children add peers to
parent data/payload streams, activating downloads.

`PARENT_DEPTH_TOLERANCE` can increase since only block downloads run during
discovery.

## Implementation sketch

```rust
struct SingleBlockLookup<T: BeaconChainTypes> {
    id: Id,
    block_root: Hash256,
    block_request: BlockRequestState<T::EthSpec>,
    block_processing: ProcessingState,
    data_request: Option<DataRequestState<T::EthSpec>>,
    data_processing: ProcessingState,
    payload_request: Option<PayloadRequestState<T::EthSpec>>,
    payload_processing: ProcessingState,
    peers: Arc<RwLock<HashSet<PeerId>>>,
    data_peers: Arc<RwLock<HashSet<PeerId>>>,
    payload_peers: Arc<RwLock<HashSet<PeerId>>>,
    awaiting_parent: Option<AwaitingParent>,
}
```

Continuation split:
- `on_block_processed(root)` → continue children of empty parents
- `on_fully_available(root)` → continue children of full parents (data + payload done)

Types removed: `LookupState`, `BlockComponentsByRootRequest`, `DownloadPhase`,
`BlockExtraRequests`, `BlockExtras`, `BlockComponentsResult`.
