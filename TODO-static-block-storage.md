# Static Cold Storage TODO

Current spec: [`specs/static-cold-backend.md`](./specs/static-cold-backend.md)
(file format inherited from [`specs/static-blocks.md`](./specs/static-blocks.md)
and generalised per-column).

Implemented in this branch:
- multi-column slot-keyed store: `StaticColdStore` (one type, dispatched on
  `DBColumnCold`)
- per-column subdirectory + per-column conf with persisted `record_type`,
  `compression`, `max_value_bytes` (conf magic `LHSTBLK2`)
- `ColdStore<E>` trait covering both slot-keyed bulk and root-keyed indices
  (`DBColumnColdIndex`); KV backends impl by translating slot/root keys into
  the underlying `KeyValueStore`
- startup healing for interrupted writes (per-column)
- `prune_historic_states` removed (mode it produced is not in the spec's
  startup-path table)

Remaining:

1. Cold backend selection.
   - add a CLI/config flag to switch the cold backend between the existing
     KV implementation and the static-file implementation
   - reject startup combinations the spec doesn't allow (e.g. checkpoint sync
     without complete static history into static-archive mode)

2. Review block read/write paths.
   - decide where finalized blocks live in the static-cold mode
     (`DBColumn::BeaconBlock`? a new slot-keyed `DBColumnCold::Block`?)
   - root → slot resolution: with `BeaconBlockSlot` removed, no on-disk index
     maps a block_root to its slot. Choose a path: bring the index back
     (whether in hot or in the cold backend), perform a slot-walk, or reject
     root-keyed reads in static-cold mode
   - update `HotColdDB::get_block_with` and `block_exists` accordingly

3. Review invariants.
   - it is unclear whether invariants 10/11/12 still hold under static-cold
     mode. Walk through each and confirm or update — in particular, archived
     blocks no longer needing hot-DB block bodies, and the consistency of
     root-to-slot indices once their location is decided in (2)

4. Tests.
   - happy path for `StaticColdStore::open/get/put` per cold column
   - out-of-order put rejection
   - crash windows around data, `.off`, and per-column `.conf`
   - cold backend selection via CLI flag
   - rejected startup-mode combinations
