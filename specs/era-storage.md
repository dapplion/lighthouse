# Era Blob Storage

Static-file backend for `BlobSidecar` archival, using E2Store-compatible `.erb`
files. Slot-indexed, append-only forward, sealed in fixed-size eras.

Stored data is blobs only. Column sidecars are derived on read.

**Initialization is via genesis sync or import of an existing era set.
Checkpoint sync and P2P blob backfill are incompatible with this backend
and rejected at startup.**

## Required APIs (active forks: Fulu, Gloas)

```
get_blobs(slot).into_columns ≡
    get_data_column_sidecars_from_block(
        block,
        [compute_cells_and_kzg_proofs(b) for b in blobs]
    )
```
(consensus-specs/fulu/validator.md)

### REST (beacon-APIs)

| Endpoint | blobs_db | era backend |
| - | - | - |
| `GET /eth/v1/beacon/blobs/{block_id}?versioned_hashes=…` | `get_blobs(root)`, HTTP filters by hash | resolve slot → `era.get_blobs(slot)` |
| `GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}?indices=…` | `get_data_columns(root)` | resolve slot → `era.get_blobs(slot).into_columns` |

### P2P Req/Resp (Fulu, carried into Gloas)

| Method | blobs_db | era backend |
| - | - | - |
| `BlobSidecarsByRange` | blobs_db per slot | `era.get_blobs(slot)` |
| `BlobSidecarsByRoot` | blobs_db per root | resolve root → slot → `BlobSidecarsByRange` |
| `DataColumnSidecarsByRange` | `BeaconDataColumn` per slot | `era.get_blobs(slot).into_columns` |
| `DataColumnSidecarsByRoot` | `BeaconDataColumn` per root | resolve root → slot → `DataColumnSidecarsByRange` |

`era.get_blobs(slot)` returns the full per-slot list; HTTP / wire-layer
projection (`versioned_hashes`, `indices`, `columns`) happens above the
store. Blob wire methods are deprecated as of
`FULU_FORK_EPOCH + MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS`.

## Constants

| Name | Value |
| - | - |
| `SLOTS_PER_ERA` | `SLOTS_PER_HISTORICAL_ROOT` (`8192`) |
| `ERA_SEAL_DELAY` | `2 * SLOTS_PER_EPOCH` |

## Custom types

| Name | SSZ |
| - | - |
| `EraNumber` | `uint64` |
| `EraBlobPointers` | `{ back: Slot, forward: Option<Slot> }` |
| `Manifest` | `{ sealed_eras: List[EraNumber], anchor_era: EraNumber }` |

## Layout

```
{datadir}/beacon/era/
  manifest
  {network}-{era:05}-{root_prefix}.erb
```

## API

The era store is **not** a `KeyValueStore`. It is a narrow, slot-indexed type
held as a field on `HotColdDB`:

```rust
fn get_blobs(slot: Slot) -> Result<Option<BlobSidecarList<E>>>;
fn append_blobs(slot: Slot, blobs: BlobSidecarList<E>) -> Result<()>;   // requires slot > forward_pointer
fn forward_pointer() -> Option<Slot>;
fn back_pointer() -> Slot;                // set once at init, read-only
fn is_sealed(era: EraNumber) -> bool;
fn seal(era: EraNumber) -> Result<()>;
```

### Invariants

- `back_pointer` is set at init and never changes:
  - genesis sync → `back_pointer = 0`
  - era-file init → `back_pointer = lowest slot in imported set`
- `forward_pointer` is `None` at genesis-sync init, or `= highest slot in
  imported set` after era-file init. It only advances; `append_blobs`
  requires `slot > forward_pointer`.
- Out-of-order writes return `Err(OutOfOrder)`. The store does not de-dupe.
- `get_blobs(slot)`:
  - in-range, no blobs at slot → `Some([])`
  - in-range, blobs present → `Some(list)`
  - out-of-range → `None`

### Gap fills

When `append_blobs(slot, ...)` advances multiple slots ahead of
`forward_pointer`, intermediate slots are auto-filled with empties internally.
Required for the pre-Deneb → Deneb jump on first append.

## Helpers

```python
def era_of(slot: Slot) -> EraNumber:
    return slot // SLOTS_PER_ERA

def era_range(e: EraNumber) -> (Slot, Slot):
    return (e * SLOTS_PER_ERA, (e + 1) * SLOTS_PER_ERA)

def can_seal(e, back, forward, finalized) -> bool:
    start, end = era_range(e)
    return (forward is not None
        and back <= start and end <= forward
        and end + ERA_SEAL_DELAY <= finalized)
```

## Triggers

| Op | Caller | Source |
| - | - | - |
| `append_blobs` | new step on the migrator thread, after `migrate_database`, before `try_prune_blobs` | drains `blobs_db` for slots that became finalized this migration |
| `seal` | post `append_blobs`; also at startup over imported eras | when `can_seal(e)` holds |

`append_blobs` fires only post-finality; the no-rewrite invariant of `.erb`
files is preserved against reorgs by construction. There is no backfill
trigger — historical data arrives only via era-file import at init.

## Sealing

For each `e` with `can_seal(e)`:
1. Write `.erb.tmp`, append `SlotIndex`, fsync.
2. Atomic rename to final filename.
3. Update `manifest`.
4. Delete overlay rows for `era_range(e)`.

Crash mid-seal leaves a `*.tmp` discarded on restart. Sealing is idempotent.

## Read

`HotColdDB::get_blobs(block_root)` becomes:
1. Resolve `slot` from `block_root` (see Status quo — there is no slot index
   for blobs today; one of the three options below is required).
2. If `era_of(slot)` is sealed → `era_store.get_blobs(slot)`.
3. Else → `blobs_db` as today.

Root → slot resolution options (era-mode only):
- (a) extend the call sites to pass `slot` alongside `block_root` (most
  callers already have it: block import, blob-by-range RPC).
- (b) maintain a `(root → era)` map in the era manifest, sealed eras only.
- (c) on miss, load the block header from the cold DB to recover its slot.

Default plan: (a) where the caller has it cheaply, (b) as fallback for the
HTTP-by-root path. The era store itself stays purely slot-indexed.

## Pruning

Era and existing pruning interlock by capping the prune cursor:

```
prune_horizon = min(retention_horizon, lowest_unsealed_era_start)
```

Sealing must precede the prune cursor advancing into a given era. Pruning
itself is unchanged; only the cursor calculation gains the era clamp when era
mode is enabled.

## Status quo

### Storage

- `blobs_db` is a separate physical DB next to `chain_db` and `freezer_db`,
  same backend (LevelDB / Redb).
  `beacon_node/store/src/hot_cold_store.rs:266-290`.
- `DBColumn::BeaconBlob` rows are **keyed by `block_root` only**; the value
  is the entire `BlobSidecarList` for that block, SSZ-encoded as a single
  row. `beacon_node/store/src/lib.rs:257`.
- No slot index for blobs anywhere. `get_blobs(block_root) -> BlobSidecarListFromRoot`
  is the only read API. `beacon_node/store/src/hot_cold_store.rs:2625`.

### Lifecycle

- **Init.** `BlobInfo.oldest_blob_slot = max(anchor_slot, deneb_fork_slot)` in
  `init_blob_info`. `hot_cold_store.rs:2854`.
- **Forward sync.** `put_blobs(block_root, blobs)` writes directly to
  `blobs_db` per block, no batching. `hot_cold_store.rs:958`.
- **Backfill.** `import_historical_block_batch` builds `StoreOp::PutBlobs`
  ops, commits via `blobs_db.do_atomically(blob_batch)` at line 256, then
  CAS-updates `oldest_blob_slot` to the min slot seen.
  `beacon_chain/src/historical_blocks.rs:159-294`.
- **Finalization migration.** `migrate_database` does **not** touch blobs.
  Hot/cold split applies only to states and block roots.
  `hot_cold_store.rs:3578-3726`.
- **Pruning.** `try_prune_blobs` runs on the migrator thread post-migrate.
  Walks blocks backwards from `min(data_availability_boundary - margin,
  split.epoch - 1)`, deletes blob rows by block_root, advances
  `oldest_blob_slot` to `end_slot + 1`. `hot_cold_store.rs:3320-3483`.

### Implications for the era backend

- **Blobs are root-keyed; routing by slot needs resolution.** Blob reads
  today never compute a slot; era-mode introduces that need (see the Read
  section above for the chosen approach).
- **`append_blobs` cannot live inside `migrate_database`** — that function
  doesn't process blobs today. It hooks as a **new step on the migrator
  thread**, after `migrate_database` returns and before `try_prune_blobs`
  runs.
- **No backfill hook.** `import_historical_block_batch` is unused under era
  mode; checkpoint sync and blob backfill are rejected at startup.
- **`prune_horizon` clamp** lives inside `try_prune_blobs`: when era mode is
  on, intersect the existing horizon with `lowest_unsealed_era_start`.
  Trivially additive.

## Integration

### `beacon_node/store`

- `EraBlobStore` is a field on `HotColdDB`, gated by a runtime flag. **No new
  `BeaconNodeBackend` variant.**
- `HotColdDB::get_blobs` adds the `era_of(slot)` check before falling through
  to `blobs_db`.
- All other store paths unchanged.

### Metadata

- `AnchorInfo` unchanged.
- `BlobInfo` unchanged.
- New `BeaconMeta` entries: `EraBlobPointers { back, forward }`, `EraManifest`.
- Bump `SchemaVersion`.

### CLI

- `--store-era-blobs` (default off). Mutually exclusive with
  `--checkpoint-sync-url` and any blob-backfill flag; node refuses to start
  if both are set.
- `--era-import-dir <path>` — directory of `.era` (blocks + boundary state)
  + `.erb` (blobs) files consumed at init. Required if not genesis-syncing.
- `lcli era blobs export` to produce `.erb` files from an archival node.

## Initialization

Two paths only; the backend refuses to start in any other configuration.

### Genesis sync

- `back_pointer = 0`, `forward_pointer = None`.
- Forward sync fills `blobs_db` from genesis. As eras finalize and pass
  `ERA_SEAL_DELAY`, `append_blobs` drains them into the era backend; sealing
  produces `.erb` files; the overlay rows are deleted.

### Era-file import

- User supplies `--era-import-dir` containing matched `.era` and `.erb`
  files.
- At startup:
  1. `.era` consumer (existing `era-file` branch) loads blocks + boundary
     state, bootstrapping the chain.
  2. Each `.erb` file is validated against the imported blocks: per
     sidecar, check `kzg_commitment` against
     `block.body.blob_kzg_commitments[index]` and run
     `verify_blob_kzg_proof`.
  3. Validated `.erb` files are linked into `{datadir}/beacon/era/`;
     manifest is updated; eras are marked sealed.
- `back_pointer = lowest slot in imported set`,
  `forward_pointer = highest slot in imported set`.
- Forward sync continues from there.

### Compatibility

- **Checkpoint sync incompatible.** A checkpoint-synced node has a gap from
  genesis to anchor that requires backfill — disabled here. Startup error.
- **P2P blob backfill incompatible.** Same reason. Startup error.
- **No in-place opt-in for existing nodes.** A populated default-backend
  node must `lcli era blobs export` its data, also export `.era` blocks +
  state, drop `chain_db` / `freezer_db` / `blobs_db`, and reinitialize via
  era-file import.

Non-canonical blobs never reach the era backend. `append_blobs` runs after
`prune_hot_db` (`migrate.rs:769-778`) deletes orphaned blobs in the same
migrator pass; era-file import only accepts validated canonical data.

## Coexistence

Era is additive. Default `blobs_db` paths are untouched. `.erb` output is
spec-compatible with Nimbus.
