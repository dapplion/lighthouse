# Static Block Storage

Static-file backend for finalized **blinded** `SignedBeaconBlock` archival.
Slot-indexed, append-only forward. Execution payloads, full blocks, and blobs
are out of scope.

**Genesis sync only.** Checkpoint sync, historical block backfill, and
late activation on an existing populated node are incompatible and rejected
at startup.

## API

A field on `HotColdDB`. Not a `KeyValueStore`. No `Hash256` in the API; the
archive is purely slot-keyed. Eras, manifests, file rotation, fsync ordering,
atomic rename — all internal.

```rust
fn open(path: &Path) -> Result<Self>;
fn get(slot: Slot) -> Result<Option<Vec<u8>>>;        // SSZ-encoded blinded block
fn put(slot: Slot, bytes: &[u8]) -> Result<()>;       // durable on return
```

`put` durability on return is the only caller-visible contract; the source-
of-truth flip in `migrate_database` relies on it.

## Interaction with existing DBs

| Concern               | Today                                                | With static blocks                                     |
| --------------------- | ---------------------------------------------------- | ------------------------------------------------------ |
| Blinded body by root  | `hot_db[BeaconBlock][root]`, forever                 | `hot_db` until archived, then `static.get(slot)`       |
| Slot → root           | `cold_db[BeaconBlockRoots][slot]`                    | unchanged                                              |
| Root → slot           | not stored                                           | **new**: `cold_db[BeaconBlockSlot][root]` (SSZ `Slot`) |
| Execution payload     | `hot_db[ExecPayload][root]` / `[PayloadEnvelope]`    | unchanged                                              |
| Blobs / data columns  | `blobs_db`                                           | unchanged                                              |
| Cold-DB block bodies  | none (cold has only indices)                         | unchanged                                              |
| Backfill              | writes blinded bodies to `hot_db`, slot→root to cold | rejected at startup                                    |

## Read path

`HotColdDB::get_block_with(root)`:
1. `hot_db[BeaconBlock][root]` — hits unfinalized blocks and blocks not yet
   archived.
2. else `cold_db[BeaconBlockSlot][root] -> slot`, then `static.get(slot)`.
3. else `None`.

`HotColdDB::block_exists` mirrors (1)+(2) without decoding.

## Write path

Block archival lives **inside `migrate_database`** as a second pass over the
already-collected `state_roots` vector. The migration's existing loop is
unchanged; a new loop after it walks the same range to drive archival. Both
loops contribute to the same `cold_db_block_ops` batch, so `BeaconBlockRoots`
and `BeaconBlockSlot` are committed atomically.

```
migrate_database(finalized_state):
  state_roots = RootsIterator(finalized_state).take_while(slot >= current_split.slot)

  # Loop 1 (existing): BeaconBlockRoots puts + cold-state migration.
  for (block_root, state_root, slot) in state_roots ascending:
      cold_db_block_ops.push(BeaconBlockRoots[slot] = block_root)
      ...cold state ops...

  # Loop 2 (new, gated on static_blocks): archival.
  if static_blocks:
      # Seed from the slot just below the iteration to catch the boundary case
      # where current_split.slot is itself a skip-slot extension of a block
      # archived in a previous migration.
      prev_block_root = cold_db[BeaconBlockRoots][current_split.slot - 1]
                         or Hash256::ZERO   # genesis seed; never collides
      for (block_root, _, slot) in state_roots ascending:
          if block_root == prev_block_root: continue   # skip-slot extension
          prev_block_root = block_root
          if slot >= finalized_state.slot(): continue  # new-split block stays in hot
          bytes = hot_db[BeaconBlock][block_root]      # must be present
          static_blocks.put(slot, bytes)               # durable
          cold_db_block_ops.push(BeaconBlockSlot[block_root] = slot)
          hot_db_block_delete_ops.push(delete BeaconBlock[block_root])

  # Atomic commit of cold ops (BeaconBlockRoots + BeaconBlockSlot together).
  cold_db.do_atomically(cold_db_block_ops)
  cold_db.sync()

  # Split commit.
  ...write SPLIT_KEY, update in-memory split...

  # Reclaim hot-KV space.
  hot_db.do_atomically(hot_db_block_delete_ops)
```

### Why the seed catches the boundary

`RootsIterator` yields the same `block_root` for every slot covered by that
block, including skip-slot extensions. In ascending iteration the **first**
slot of each run is the block's real slot — *except* when the migration
starts inside a run (i.e. `current_split.slot` is itself a skip-slot
extension of a block archived in a previous migration). Reading
`BeaconBlockRoots[current_split.slot - 1]` returns that previous block's root,
the dedup match fires on the first iteration, and we correctly skip.

If the previous-slot lookup is missing, the cold DB is inconsistent and the
migration aborts with `Error::MigrationError`.

### Crash semantics

| Crash window                                  | State after restart                                       | Recovery                                       |
| --------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------- |
| During loops, before cold commit              | Nothing committed.                                        | Migration retried fresh.                       |
| Between cold commit and split commit          | Reverse-index committed but split not advanced.           | Migration retried; cold puts are idempotent, hot bodies still present. |
| Between split commit and hot delete           | Split advanced, reverse-index committed, bodies linger in hot. | Reads still correct (hot returns the same bytes); leaked bodies stay in hot. |

The last window is a bounded leak (~one migration's worth of bodies, ~32
blocks) and a rare crash. No automatic recovery in v1; can be addressed later
by a startup scan if it matters in practice.

## Modes of operation

| Mode                                  | Behavior                                                                |
| ------------------------------------- | ----------------------------------------------------------------------- |
| **Disabled** (default)                | `static_blocks: None`. Byte-identical to current.                       |
| **Genesis sync + static enabled**     | Archive grows from slot 0; bodies migrate out of `hot_db` per epoch.    |
| **Checkpoint sync + static enabled**  | Refused at startup.                                                     |
| **Late activation on existing node**  | Refused at startup.                                                     |

Late activation is unsupported because there is no persisted "lowest unarchived
slot" — the migration relies on `current_split.slot` as the watermark, so the
prefix below it would never be archived. Operator must reinitialize.

## Schema

- New `DBColumn::BeaconBlockSlot` (3-letter tag `bbs`). Key: 32-byte block
  root. Value: SSZ-encoded `Slot` (8 bytes). Lives in `cold_db`.
- No changes to `AnchorInfo`, `BlobInfo`, `Split`, or any existing column.
- Schema version bump on the addition.

## CLI

- `--store-static-blocks` (default off). Mutually exclusive with
  `--checkpoint-sync-url` and any block-backfill flag; node refuses to start
  if both are set. Cannot be enabled on a node previously run without it.

## Coexistence

Additive. Default paths (no flag) are untouched. The `blobs_db` and the
era-blob backend (see `era-storage.md`) are independent of this.
