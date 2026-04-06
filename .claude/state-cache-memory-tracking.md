# State Cache Memory Tracking

## Problem

The state cache needs to know how much memory cached states consume to enforce
a byte budget and avoid OOM. States share tree nodes via milhouse COW — the
marginal cost of a state depends on which nodes it shares with other states.

Prior art: sigp/lighthouse#7803 implemented full `MemoryTracker` walks over all
cached states on every Nth insert. Rejected — walking every node of every cached
state is O(all_nodes × all_states), far too expensive at mainnet scale.

## Design: ApproxOwnedBytes

Each `BeaconState` carries a `Vec<Arc<ApproxOwnedBytes>>` — a list of byte counts
representing chunks of tree memory it owns. States that share ancestry (via clone)
share the same `Arc` entries. Total cache memory = sum of unique entries (deduplicated
by Arc pointer identity) across all cached states.

### Data structures

```rust
// On BeaconState (skipped from serde/ssz/tree_hash):
pub approx_owned_bytes: ApproxOwnedBytesList,

// where:
pub struct ApproxOwnedBytes { pub bytes: usize }
pub struct ApproxOwnedBytesList(pub Vec<Arc<ApproxOwnedBytes>>);
```

### Operations

- **Clone**: `Vec<Arc<_>>` is cloned — same Arcs, refcounts bump. O(entries).
- **Push**: after measuring a transition's COW cost, push a new entry.
- **Reset**: after rebase, replace with finalized's entries + unique cost entry.
- **Total**: iterate all cached states, deduplicate by Arc pointer, sum bytes.
  ~100 states × ~64 entries = ~6400 pointer comparisons. Trivial.

## Three measurement cases

Every state in the cache enters through one of these paths:

### Case 1: Initial finalized state

The finalized state is set once (and updated when finalization advances). We need
its full tree size as the base `ApproxOwnedBytes` entry.

**Approach**: Full `MemoryTracker::track_item(&state)` walk. Returns `total_size`.

**Cost**: ~450ms at 1M validators, ~1s at 2M. Acceptable — happens rarely
(once per finalization advance, every ~6 minutes).

### Case 2: State loaded from disk after rebase

States loaded from disk are rebased onto the finalized state via `rebase_on_finalized`.
After rebase, the state shares the finalized tree — we need the remaining unique cost.

**Approach**: The finalized state's nodes are already in the tracker (from Case 1).
Call `tracker.track_item(&loaded_state)` — shared nodes are already in the seen-set
and return `differential_size: 0`. Only unique nodes are counted.

**Cost**: O(unique_nodes). For a state close to finalized, this is cheap (few dirty
paths). For a state far from finalized, it could be significant but still less than
a full walk since shared nodes are skipped.

### Case 3: New owned data after block/slot processing

After `per_slot_processing` or `per_block_processing`, we need the COW bytes
produced by that transition.

**Approach**: Use `MemoryTracker::total_size()` delta:
```
tracker already has pre-state nodes (from the previous measurement)
→ track_item(&post_state)
→ delta = tracker.total_size() - pre_total
→ push ApproxOwnedBytes { bytes: delta }
```

The post-state walk only visits new COW'd nodes (shared nodes already in the seen-set).

**Cost at 1M validators** (benchmarked):
- Slot transition (mid-epoch): ~2ms — few dirty paths
- Epoch transition: ~115ms — all balances/participation rewritten

## Current status

### Completed

- [x] `ApproxOwnedBytes` / `ApproxOwnedBytesList` types in `consensus/types`
- [x] Field on `BeaconState` (all variants, skipped from serde/ssz/tree_hash)
- [x] Push sites in `per_slot_processing` and `per_block_processing`
- [x] All 7 fork upgrades preserve field via `mem::take`
- [x] `rebase_on_finalized` resets to finalized's entries + unique cost
- [x] `StateCache::total_approx_owned_bytes()` — iterate + deduplicate
- [x] `MemorySize` impls for `BeaconState` and all subtypes (tree fields, caches,
      sync committees, all leaf types) — cherry-picked from #7803
- [x] Benchmarks: `state_memory` bench with 1M and 2M validators
- [x] `estimated_marginal_bytes` — spec-derived fallback (25 tests with ratio bounds)

### Stubbed (returns 0)

- [ ] `TreeSnapshot::approx_owned_bytes()` — the actual measurement. Currently
      returns 0. Needs to be replaced with the MemoryTracker approach.

## Challenge: making the measurement fast

The core tension is that `MemoryTracker::track_item` needs a seen-set of all
previously-tracked nodes to identify shared vs new nodes. Building this set from
scratch costs ~450ms at 1M validators (full tree walk). But once built, subsequent
walks are cheap (only visit new nodes).

### The persistent tracker approach

Keep a `MemoryTracker` alive across transitions:

```
Finalization:
  tracker = MemoryTracker::new()
  tracker.track_item(&finalized_state)     // ~450ms, once
  base_total = tracker.total_size()

Per slot:
  // pre-state nodes already in tracker from previous slot
  tracker.track_item(&post_state)          // ~2ms (only new nodes)
  delta = tracker.total_size() - prev_total
  state.approx_owned_bytes.push(delta)
  prev_total = tracker.total_size()
```

**Problem: where does the tracker live?**

The tracker is a `HashMap<usize, usize>` with millions of entries (~100MB at 1M
validators). It can't travel with the state (too expensive to clone). It needs to
live in the processing pipeline — tied to a specific chain of state transitions.

Options:

1. **On the `BeaconChain` struct** — one tracker per chain. Reset on finalization.
   Simple but requires plumbing through the call stack to `per_slot_processing`.

2. **Thread-local** — no plumbing needed but tricky with async/tokio.

3. **Passed as a parameter** — explicit but invasive API change.

### The fork problem

When the chain forks, multiple states diverge from a common ancestor. A single
persistent tracker accumulates nodes from all forks. This means:

- Nodes from fork A are in the seen-set when measuring fork B
- This causes undercounting — fork B's nodes might be falsely "seen" if fork A
  happened to allocate at the same address (after fork A's nodes were freed)

In practice this is unlikely (Arc allocations at the same address require the
original to be freed first, which means no state holds it). But it's a
correctness concern.

**Mitigation**: The tracker is approximate (it's `ApproxOwnedBytes`, not exact).
Small undercounting from address reuse is acceptable for eviction decisions.

### The HashMap memory overhead

At 1M validators, the tracker's HashMap has ~2-4M entries (one per unique tree
node across all tracked states). At ~40 bytes per entry, that's ~80-160MB just
for the tracker itself.

**Mitigation**: Reset the tracker on each finalization advance. The finalized
walk rebuilds it from scratch (~450ms). Between finalizations, the tracker
grows by the COW nodes from ~32 slots × ~100 cached states. This is bounded.

### Alternative: milhouse-native cow_bytes

Instead of using `MemoryTracker` (external HashMap), milhouse could expose a
pairwise tree walk:

```rust
fn cow_bytes<T: Value>(base: &Arc<Tree<T>>, derived: &Arc<Tree<T>>) -> usize {
    if Arc::ptr_eq(base, derived) { return 0; }
    let cost = node_size(derived);
    match (base.as_ref(), derived.as_ref()) {
        (Node { left: bl, right: br, .. },
         Node { left: dl, right: dr, .. }) => {
            cost + cow_bytes(bl, dl) + cow_bytes(br, dr)
        }
        _ => cost
    }
}
```

This is O(dirty_nodes) with zero external state — no HashMap, no persistent
tracker. But it requires changes to milhouse and doesn't cover non-tree fields
(caches). The MemoryTracker approach covers everything MemorySize is implemented for.

## Benchmarks (MinimalEthSpec)

| Benchmark | 1024 vals |
|-----------|-----------|
| Full walk | 316 µs |
| Pre+post slot | 350 µs |
| Pre+post epoch | 343 µs |

## Benchmarks (MainnetEthSpec, synthetic state)

| Benchmark | 1M validators | 2M validators |
|-----------|--------------|--------------|
| Full walk | 459 ms | 1.07 s |
| Pre+post slot transition | 451 ms | 1.02 s |
| Pre+post epoch transition | 566 ms | 1.32 s |

The pre+post cost is dominated by the pre-state walk (~450ms). The post-state
delta adds ~2ms (slot) or ~115ms (epoch). With a persistent tracker, only the
delta cost is paid per transition.
