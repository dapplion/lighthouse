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

## Removed

- `lighthouse db prune-states` and `HotColdDB::prune_historic_states`. They
  produce a "cold blocks present, cold states absent" mode that is not in the
  startup-path table above, and the spec does not support runtime mode
  transitions in either direction.
