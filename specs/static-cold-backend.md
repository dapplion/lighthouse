# Static Cold Backend

Goal: make the cold archive backend pluggable.

Supported cold backends:

- current KV cold DB
- static range files

## Node modes

| Startup path | Mode |
| - | - |
| Genesis sync with static archive enabled | archive |
| Checkpoint sync with complete static history imported | archive |
| Checkpoint sync without complete static history | full node |

A full node does not become archive by P2P backfill or online reconstruction.

## Ownership

| Store | Owns |
| - | - |
| Hot DB | head data, fork-choice data, unfinalized data, P2P-required recent block window, metadata |
| Cold backend | finalized archive ranges, root-to-slot indices for finalized data (block_root → slot, state_root → slot) |

## Writers

Static cold files are written only by:

- genesis sync, in finalized slot order
- verified complete range import

Network backfill may write recent blocks to Hot DB, but never to static cold.
Online reconstruction never writes static cold.

## Availability

A static range is either complete or absent. Reads below the hot/recent window
require the matching static range. If it is absent, the node is not archive for
that range.

The current KV cold DB remains a valid cold backend.

## Backend API

Slot-keyed bulk: `get`, `put_batch`, `exists`, `iter_from`, `sync`. No deletes.
Batched puts are best-effort, not atomic.

Root-keyed indices: `get_index(col, root)`, `put_index_batch(col, items)`, where
`col` is one of `BlockSlot` or `ColdStateSummary`. The static-file backend embeds
the same KV implementation Lighthouse uses for the main DB at `<root>/index/` to
serve these. Crash-safety rule: slot-keyed bulk data is committed before the
matching root index entry, so a crash leaves cold data without a dangling index.

### `put_batch` durability and fsync semantics

`put_batch(items)` is durable on return for the batch as a whole — the same
caller-visible contract as N×`put` — but it performs O(1) fsyncs per
underlying file regardless of batch size, instead of the 4 fsyncs per slot
that the per-item path issues (data file, offset file, config tmp, config
dir). Within a column, slots in `items` must be strictly ascending; items
that span multiple `file_id` boundaries are handled by grouping internally,
with one data fsync and one offset fsync per touched file plus a single
atomic config commit at the end of the batch.

## Read paths and their performance characteristics

Synthesised from the HTTP API surface, the cold-read code path inside
`HotColdDB::get_state`, and real archive-node bug reports
(sigp/lighthouse #7363, #8459, #8640).

### Endpoint mix that triggers cold reads

| Endpoint shape | Cold work |
|---|---|
| `/eth/v1/beacon/states/{state_id}/{root, fork, finality_checkpoints}` | small slot-keyed read |
| `/eth/v1/beacon/states/{state_id}/{validators, validator_balances, validator_identities, validators/{validator_id}}` | **full state load** — `ColdStateSummary` index lookup + HDiff replay |
| `/eth/v1/beacon/states/{state_id}/{committees, sync_committees, randao, pending_*, proposer_lookahead}` | full state load |
| `/eth/v2/debug/beacon/states/{state_id}` | full state load |
| `/eth/v2/beacon/blocks/{block_id}`, `/eth/v1/beacon/blocks/{block_id}/{root, attestations}` | single block / block-root read |
| `/eth/v1/beacon/headers/{block_id}` | block lookup |

All state-by-* endpoints funnel through one call —
`chain.store.get_state(state_root, slot, true)` —
(`beacon_node/http_api/src/state_id.rs`).

### Hottest path: full-state-at-arbitrary-slot

Most user-visible archive pain (#8459 balance-at-historic-slot,
#8640 SSE finalized_checkpoint subscriber querying validators)
comes from clients asking for a full state at a historic slot:
validator-balance queries from monitoring services, validator-set
snapshots from explorers, debug-state dumps from researchers. For
one such request the cold backend serves:

1. **`ColdStateSummary` index lookup** — `state_root → slot` via the
   embedded KV. One small read.
2. **Walk to nearest snapshot** — read `StateSnapshot` at the
   snapshot-boundary slot ≤ target slot. One large read (tens of MB).
3. **Apply HDiffs forward** — read every `StateDiff` between snapshot
   and target slot. N small-to-medium sequential reads.
4. **State replay** — CPU-only, no further cold reads.

Sequential-slot read throughput on `StateSnapshot` and `StateDiff`
dominates cold-read perf, not random-slot latency.

### Second hottest: block-by-root or block-by-slot

`/eth/v2/beacon/blocks/{block_id}` is one single random-slot read on
the `Block` column. Cheap per call but high-frequency for explorers
that walk recent blocks linearly.

### State cache caveat

`HotColdDB`'s in-memory `state_cache` and `historic_state_cache`
absorb a large fraction of repeated reads — but #7363 documents that
on archive nodes those caches miss frequently enough to matter:
sigp had to walk the default back from 64 to 128 because misses were
producing visible epoch-boundary load. The cold-read path is on the
hot path in production.

### Implications for the library

- `get(slot)` is the headline read primitive. Random and sequential
  patterns both happen; sequential dominates (HDiff replay).
- No `iter_from` in the library — the caller (`StaticColdStore`)
  builds it as a thin `(from..=highest)` loop over `get`, because
  iter is used by `forwards_iter` and invariant checks rather than
  per-request HTTP serving.
- Future read-side work, when scoped, should target the
  `StateSnapshot` + `StateDiff` sequential read path before adding
  per-record caches.

## Removed

- `lighthouse db prune-states` and `HotColdDB::prune_historic_states`. They
  produce a "cold blocks present, cold states absent" mode that is not in the
  startup-path table above, and the spec does not support runtime mode
  transitions in either direction.
