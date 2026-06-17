# State Cache Memory Tracking

## Problem

The state cache needs to know how much memory cached states consume to enforce
a byte budget (`--state-cache-max-mb`) and avoid OOM. States share tree nodes
via milhouse COW — the marginal cost depends on which nodes are shared.

### Prior art

- **sigp/lighthouse#7803** — Full `MemoryTracker` walk over all cached states.
  Rejected: 450ms+ per measurement at mainnet scale, holds cache mutex.
- **sigp/lighthouse#7449, #7450** — Tracking issues for cache size measurement.
- **Spec-derived estimation** (`estimated_marginal_bytes`) — O(1) heuristic from
  spec knowledge. Implemented in this branch as a fallback, with 25 tests. Tight
  at epoch boundary (1.04x) but loose mid-epoch (3x). No milhouse dependency.

## Current design: ApproxOwnedBytes + cow_bytes

### How it works

Each `BeaconState` carries a `Vec<Arc<ApproxOwnedBytes>>` — byte counts for
chunks of tree memory it owns. States that share ancestry (via clone) share the
same `Arc` entries. Total cache memory = sum of unique entries (deduplicated by
Arc pointer) across all cached states.

Measurement uses milhouse's `cow_bytes` (PR sigp/milhouse#100): a pairwise tree
walk that compares two trees by `Arc::ptr_eq` at each node, skipping shared
subtrees. O(dirty_nodes) with zero allocations.

### Two-layer approach

**Fast path (every `put_state`):** Sum `ApproxOwnedBytesList` segments across all
states. Overcounts due to repeated mutations to the same tree path, but overcounting
is safe — it triggers eviction earlier, never too late. Cost: microseconds.

**Slow path (on finalization):** Run `cow_bytes_between(finalized, state)` for every
cached state, replacing segments with exact measurements. Corrects accumulated
overcount. Cost: ~2ms for slot-only caches, ~225ms with epoch boundary states.

### Three measurement points

1. **Initial finalized state** — `total_state_tree_bytes()` walks all tree nodes
   once. ~25ms at 1M validators. Happens once per finalization (~every 6 min).

2. **State loaded from disk after rebase** — `cow_bytes_between(finalized, state)`
   measures unique bytes vs finalized. O(dirty_nodes).

3. **After block/slot processing** — `TreeSnapshot` clones pre-state (cheap Arc
   bumps), then `cow_bytes_between(pre, post)` after transition. Pushed as a new
   `ApproxOwnedBytes` entry.

### Performance (benchmarked at 1M validators, MainnetEthSpec)

| Operation | Time |
|-----------|------|
| cow_bytes slot transition | **541 ns** |
| cow_bytes epoch transition | **12.8 ms** |
| total_tree_bytes (initial) | **25.1 ms** |
| MemoryTracker (for comparison) | **458 ms** |

### Eviction

`put_state` checks `total_approx_owned_bytes()` against `max_bytes`. If over
budget, culls states by priority (advanced → old boundary → mid-epoch → good
boundary) until under budget. The total is recomputed each check by iterating
all cached states and deduplicating `ApproxOwnedBytes` entries — ~6400 pointer
comparisons, trivial.

### Data flow

```
per_slot_processing / per_block_processing:
  TreeSnapshot::new(state)     ← cheap clone (Arc bumps)
  ... process ...
  snapshot.cow_bytes(state)    ← O(dirty_nodes), ~541ns slot / ~12.8ms epoch
  state.approx_owned_bytes.push(delta)

rebase_on_finalized:
  state.rebase_on(finalized)
  cow_bytes_between(finalized, state)  ← O(dirty_nodes)
  state.approx_owned_bytes = finalized.approx_owned_bytes + unique

update_finalized_state:
  total_state_tree_bytes(state)  ← O(all_nodes), ~25ms, once
  state.approx_owned_bytes.push(base_size)

put_state:
  total = total_approx_owned_bytes()  ← deduplicate Arc pointers
  if total > max_bytes: cull(...)
```

## What's implemented

- `ApproxOwnedBytes` / `ApproxOwnedBytesList` on `BeaconState` (all variants)
- `cow_bytes_between()`, `total_state_tree_bytes()` in `consensus/types`
- `TreeSnapshot` in `per_slot_processing` and `per_block_processing`
- `rebase_on_finalized` resets segments to finalized's + unique cost
- `update_finalized_state` measures base size for new finalized states
- `total_approx_owned_bytes()` on `StateCache`
- Eviction wired to `total_approx_owned_bytes()` in `put_state`
- `--state-cache-max-mb` CLI flag (default: None = count-based only)
- Metrics: `store_beacon_state_cache_cow_byte_size` gauge,
  `store_beacon_state_cache_evictions_total` counter
- Debug tracing on finalized base size, rebase cow_bytes, eviction events
- `MemorySize` for `BeaconState` and all subtypes (from #7803)
- `estimated_marginal_bytes` fallback with 25 tests (not used for eviction)
- milhouse `cow_bytes` PR: sigp/milhouse#100

## What's not tracked

- **Non-tree caches**: committee_caches (~30-60MB Arc-shared), pubkey_cache
  (~100-150MB rpds), epoch_cache (~5MB Arc). Marginal cost ~0 when shared,
  but the base finalized state's caches aren't measured.
- **Scalar fields**: fork, checkpoints, eth1_data. Small, fixed per state.

## References

- sigp/lighthouse#7449 — Measure state cache size
- sigp/lighthouse#7450 — Prune state cache based on size
- sigp/lighthouse#7803 — Memory Aware Caching (rejected)
- sigp/milhouse#100 — cow_bytes pairwise tree walk
