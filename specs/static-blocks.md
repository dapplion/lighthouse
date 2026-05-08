# Static Block Storage

Static-file backend for finalized **blinded** `SignedBeaconBlock` archival.
Slot-indexed, append-only forward. Execution payloads, full blocks, and blobs
are out of scope.

**Genesis sync only.** Checkpoint sync, historical block backfill, and
late activation on an existing populated node are incompatible and rejected
at startup.

## API

A field on `HotColdDB`. Not a `KeyValueStore`. No `Hash256` in the API; the
archive is purely slot-keyed. File rotation, fsync ordering, and crash recovery
are internal.

```rust
fn open(path: &Path) -> Result<Self>;
fn get(slot: Slot) -> Result<Option<Vec<u8>>>;        // SSZ-encoded blinded block
fn put(slot: Slot, bytes: &[u8]) -> Result<()>;       // durable on return
```

`put` durability on return is the only caller-visible contract; the source-
of-truth flip in `migrate_database` relies on it.

## Static file format

Files live together in one directory:

```
static_blocks_00000
static_blocks_00000.off
static_blocks_00001
static_blocks_00001.off
static_blocks.conf
```

Mapping:

```
SLOTS_PER_FILE = 8192
file_id = slot / SLOTS_PER_FILE
index = slot % SLOTS_PER_FILE
off_pos = index * 8
```

The data file name uses `file_id` as a zero-padded decimal number. The slot
range is derived from the id and is not encoded in the name.

Each data file starts with the e2store version record:

```
65 32 00 00 00 00 00 00
```

Block records are appended after it:

```
type:     [0x01, 0x00]
length:   compressed_data.len() as u32, little-endian
reserved: u16 = 0
data:     snappy-framed(SSZ-encoded blinded SignedBeaconBlock bytes)
```

The `.off` file is fixed-size: `8192 * 8` bytes. Each entry is a little-endian
`u64` absolute byte offset into the matching data file. Offset `0` means no
block is present for that slot. Real block offsets are nonzero because the data
file starts with the version record.

`static_blocks.conf` is global to the static block store and is fixed-size:

```
magic:                [u8; 8] = b"LHSTBLK1"
highest_written_slot: u64 little-endian, u64::MAX means empty
current_data_len:     u64 little-endian
```

`current_data_len` applies to the current file, derived from
`highest_written_slot / SLOTS_PER_FILE`.

Config updates are atomic:

1. Write the full config to `static_blocks.conf.tmp`.
2. Fsync `static_blocks.conf.tmp`.
3. Rename it over `static_blocks.conf`.
4. Fsync the directory.

## `put` contract

`put(slot, bytes)` requires:

```
highest_written_slot == None || slot > highest_written_slot
snappy_framed(bytes).len() <= u32::MAX
```

Skipped slots are allowed. They leave zero offsets in `.off`.

Write sequence:

1. Lock the writer.
2. Reject `slot <= highest_written_slot`.
3. Compute `file_id`, `index`, and `off_pos`.
4. Create or open `static_blocks_{file_id:05}`.
5. If the data file is new, write the e2store version record.
6. Create or open `static_blocks_{file_id:05}.off`.
7. If the `.off` file is new, initialize it to `8192 * 8` zero bytes.
8. Compress `bytes` with snappy-framed compression.
9. Append the compressed block record to the data file, remembering the offset
   of its 8-byte record header.
10. Fsync the data file.
11. Write the offset as `u64` little-endian at `off_pos` in the `.off` file.
12. Fsync the `.off` file.
13. Atomically update `static_blocks.conf` with:
    ```
    highest_written_slot = slot
    current_data_len = data_file_len
    ```
14. Fsync the directory after the rename.

A write is committed only when `static_blocks.conf` reflects it.

On open, the store reads `static_blocks.conf`, truncates the current data file
to `current_data_len`, and clears offsets after `highest_written_slot` in the
current `.off` file.

Crash behavior:

| Crash point | Restart behavior |
| - | - |
| Before `static_blocks.conf` update | Previous slot remains committed; appended data is truncated and offset tail is cleared. |
| During `static_blocks.conf.tmp` write | Previous `static_blocks.conf` remains the commit marker. |
| After `static_blocks.conf` rename | New slot is committed. |

## `get` contract

`get(slot)`:

1. Compute `file_id`, `index`, and `off_pos`.
2. Open `static_blocks_{file_id:05}.off`.
3. Read the `u64` little-endian offset at `off_pos`.
4. If the offset is `0`, return `None`.
5. Open `static_blocks_{file_id:05}`.
6. Seek to the offset.
7. Read and validate the 8-byte block record header:
   ```
   type == [0x01, 0x00]
   reserved == 0
   ```
8. Read `length` compressed bytes.
9. Snappy-decompress the bytes with the consensus maximum
   `SignedBeaconBlock` SSZ size for the active fork as the output bound.
10. Return the decompressed SSZ bytes.

If decompression exceeds the bound, return a corruption error.

Missing files are treated as `None` only when the slot is beyond
`highest_written_slot`. Missing files for committed slots are corruption.

## `open` contract

In-memory state is minimal:

```
dir
highest_written_slot
mutex
```

Files are opened inside `put` and `get`; the store does not cache current file
handles in v1.

`static_blocks.conf` uses `u64::MAX` as the empty-store sentinel for
`highest_written_slot`.

`open(path)`:

1. Create `path` if it does not exist.
2. If `static_blocks.conf` does not exist, create it with:
   ```
   magic = b"LHSTBLK1"
   highest_written_slot = u64::MAX
   current_data_len = 0
   ```
3. Read and validate `static_blocks.conf`.
4. If `highest_written_slot == u64::MAX`, initialize in-memory
   `highest_written_slot = None` and return.
5. Derive the current file from `highest_written_slot / SLOTS_PER_FILE`.
6. Truncate the current data file to `current_data_len`.
7. Clear `.off` entries after `highest_written_slot` in the current `.off`
   file by writing zeroes.
8. Initialize in-memory `highest_written_slot = Some(slot)`.

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
