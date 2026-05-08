# Static Block Storage TODO

Current spec: [`specs/static-blocks.md`](./specs/static-blocks.md)

Implemented:
- static block file format spec
- `StaticBlockStore::open/get/put`
- snappy-framed block records
- fixed-size `.off` sidecar files
- global `static_blocks.conf` commit marker
- startup healing for interrupted writes

Remaining:

1. Wire startup/config.
   - add CLI/config path for enabling static block storage
   - initialize `HotColdDB::static_blocks`
   - reject checkpoint sync, late activation, and historical backfill init modes

2. Bump schema.
   - `DBColumn::BeaconBlockSlot` was added
   - update schema version in `beacon_node/store/src/metadata.rs`

3. Verify static fallback reads.
   - after `static_blocks.get(slot)`, decode and verify the block root matches the requested root
   - treat mismatches as corruption

4. Update invariants.
   - archived finalized blocks no longer require hot-db block bodies
   - root/slot indices must remain consistent with static storage

5. Add tests.
   - archive/read happy path
   - skip-slot dedup
   - out-of-order put rejection
   - crash windows around data, `.off`, and `.conf`
   - wrong `BeaconBlockSlot`
   - unsupported startup modes

6. Decide decompression bound wiring.
   - current implementation uses a local 10 MiB bound
   - consider passing consensus `max_payload_size` or another store config value
