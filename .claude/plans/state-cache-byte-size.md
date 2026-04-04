# State Cache Byte-Size Awareness

Design document for making Lighthouse's state cache aware of actual memory consumption,
enabling budget-based eviction instead of count-based.

## Problem

The state cache (`StateCache` in `store/src/state_cache.rs`) uses a count-based LRU with
a default capacity of 128 states. All states are treated as equal cost.

In reality, state memory costs vary by orders of magnitude:

- **Epoch boundary state** (all balances rewritten): ~16-20MB differential
- **Mid-epoch state** (few attesters touched): ~100KB-1MB differential
- **State sharing most structure with finalized** (just rebased): ~0 marginal cost

With 128 states, worst case is 128 epoch boundary states × 20MB = 2.5GB. Best case is
128 mid-epoch states at ~100KB = 13MB. The cache has no idea which situation it's in.

This led to OOM issues documented in sigp/lighthouse#7053, partially addressed by
heuristic eviction improvements, but the fundamental problem remains: eviction decisions
are made without knowing what anything costs.

## Prior Art

### PR #7803 — Exact measurement approach (rejected)

Used milhouse's `MemoryTracker` (from milhouse PR #51) to walk the full tree structure
across all cached states and compute exact differential byte sizes.

**Why it was rejected:**
1. **1.5-4+ seconds** to measure the full cache — walks millions of tree nodes
2. **Holds the state cache mutex** during measurement, blocking block processing
3. **Must re-measure after every eviction** — structural sharing means removing one state
   changes others' differential costs
4. **Pruning loop**: measure → evict one → measure again → repeat until under budget
5. Michael Sproul (Feb 2026): *"No we have decided not to pursue this approach. The
   overhead from calculating the true memory size of the cache entries is too high."*

### Tracking issues (open)

- **#7449** — Measure state cache size in memory
- **#7450** — Prune state cache based on size

### What shipped instead

- `intra_rebase` for inactivity_scores (PR #7062) — 70MB → 5MB per state
- Heuristic eviction categories (advanced, old boundary, mid-epoch, good boundary)
- Removed redundant LRU cache layer (PR #8724)
- Lowered default `--state-cache-size` to 4 for OOM-prone setups

## Proposed Approach: Spec-Derived Cost Estimation

Instead of exact measurement (walking the tree) or instrumenting milhouse internals,
**derive the cost estimate from the state transition spec itself**. The state transition
is deterministic — we know exactly which fields get dirtied at each point.

### Core Insight

After `rebase_on_finalized()`, every cached state shares the finalized state's milhouse
tree as its base. Each state's unique nodes (created by copy-on-write during mutations)
are **independent allocations**. This means:

```
total_cache_memory ≈ finalized_base_size + Σ marginal_cost(state_i)
```

The marginal cost of each state can be estimated independently — no cross-state tree
walk needed.

Because the spec defines exactly what mutates at each point, we can compute the dirty
leaf count for each milhouse field without any milhouse instrumentation.

### What Mutates When

#### Per-slot (every slot)

| Field | Type | Dirty leaves | Cause |
|-------|------|-------------|-------|
| `state_roots` | `Vector<Hash256, 8192>` | 1 | `state_roots[slot % SLOTS_PER_HISTORICAL_ROOT]` |
| `block_roots` | `Vector<Hash256, 8192>` | 1 | `block_roots[slot % SLOTS_PER_HISTORICAL_ROOT]` |
| `randao_mixes` | `Vector<Hash256, 65536>` | 1 | block proposer mixes randomness |
| `balances` | `List<u64, N>` | ~committee_size | proposer reward + attestation reward processing |
| `validators` | `List<Validator, N>` | 0-few | only on activation/exit (rare) |
| `slashings` | `Vector<u64, 8192>` | 0-few | only when slashing occurs (rare) |
| `inactivity_scores` | `List<u64, N>` | 0 | not touched mid-epoch |

**Mid-slot total: ~committee_size dirty leaves in balances + a handful of fixed-size fields.**

#### Per-epoch (at epoch boundary slots)

Everything above, PLUS:

| Field | Type | Dirty leaves | Cause |
|-------|------|-------------|-------|
| `balances` | `List<u64, N>` | **ALL N** | rewards/penalties for every validator |
| `inactivity_scores` | `List<u64, N>` | **ALL N** | updated for every validator |
| `validators` | `List<Validator, N>` | 0-few | activation/exit queue processing |

**Epoch boundary total: ~2N leaves dirty across balances + inactivity_scores. This is
the dominant cost — everything else is negligible by comparison.**

Non-milhouse fields also update at epoch boundaries (`justification_bits`,
`current/previous_justified_checkpoint`, `finalized_checkpoint`) but these are fixed-size
and small.

### The Two Bins That Matter

The insight is that the cost distribution is essentially bimodal:

```
Epoch boundary state:  cost ≈ 2 × num_validators × 16 bytes  (~32MB on mainnet)
Non-boundary state:    cost ≈ ~1MB or less
```

This single binary distinction captures ~95% of the variance. The remaining refinement
(exact committee size, number of slashings, etc.) is noise compared to this 30x gap.

### Estimation Function

```rust
/// Estimate the marginal memory cost of a cached state relative to the finalized base.
///
/// This uses knowledge of the state transition spec to approximate how many milhouse
/// tree leaves were copy-on-write'd since the state was rebased on finalized.
/// No milhouse instrumentation required.
fn estimated_marginal_bytes<E: EthSpec>(state: &BeaconState<E>) -> usize {
    let n = state.validators().len();
    let is_epoch_boundary = state.slot() % E::slots_per_epoch() == 0;

    // Balances: epoch processing touches ALL validators, mid-epoch touches ~1 committee
    let balances_dirty = if is_epoch_boundary {
        n
    } else {
        // Upper bound: target committee size. In practice fewer are touched.
        E::target_committee_size()
    };

    // Inactivity scores: epoch processing touches ALL, mid-epoch touches none
    let inactivity_dirty = if is_epoch_boundary { n } else { 0 };

    // Validators: rarely mutates (activations/exits). Negligible for estimation.
    let validators_dirty: usize = 0;

    // Fixed-size vectors: 1-2 leaves per slot, negligible
    let randao_dirty: usize = 1;
    let roots_dirty: usize = 2; // state_roots + block_roots

    estimate_tree_bytes::<u64>(balances_dirty, n)           // balances
        + estimate_tree_bytes::<u64>(inactivity_dirty, n)   // inactivity_scores
        + estimate_tree_bytes::<Validator>(validators_dirty, n)
        + estimate_tree_bytes::<Hash256>(randao_dirty, SLOTS_PER_HISTORICAL_ROOT)
        + estimate_tree_bytes::<Hash256>(roots_dirty, SLOTS_PER_HISTORICAL_ROOT)
}

/// Estimate bytes consumed by COW'd nodes in a milhouse tree.
///
/// For sparse changes: each dirty leaf COW's ~log2(N) internal nodes along its path.
/// For fully-dirty trees: the entire tree is a new allocation (~2N nodes).
/// The sparse formula overcounts for adjacent leaves (shared paths) — this is an
/// intentional upper bound (safe direction for eviction).
fn estimate_tree_bytes<T>(dirty: usize, total: usize) -> usize {
    if dirty == 0 {
        return 0;
    }
    let node_size = std::mem::size_of::<T>();
    if dirty >= total {
        // Full tree copy: all leaves + all internal nodes
        (2 * total) * node_size
    } else {
        // Sparse: each dirty leaf creates ~log2(total) new nodes
        let depth = usize::BITS as usize - total.leading_zeros() as usize;
        dirty * depth * node_size
    }
}
```

### Tradeoffs vs milhouse Counter Approach

An alternative approach is to instrument milhouse's COW path directly — add a
`cow_leaf_count` that increments on every actual copy-on-write allocation (when
`Arc::strong_count > 1`) and resets on clone/rebase.

| | Spec-derived estimate | milhouse COW counter |
|---|---|---|
| **Accuracy** | Approximation from spec rules | Exact COW count per field |
| **milhouse changes** | None | Must instrument COW hot path |
| **Maintenance** | Must update if spec adds new fields or changes transition logic | Auto-correct as spec changes |
| **Edge cases** | Misses rare events (slashings, sync committee rewards) | Captures everything |
| **Complexity** | Self-contained in lighthouse `store` crate | Touches a shared library dependency |
| **Shipping risk** | Zero — pure addition, no behavior change until eviction logic updated | Requires milhouse release + lighthouse dep bump |

The spec-derived approach is recommended as a first step because it requires zero
dependency changes and captures the dominant cost factor (epoch boundary vs non-boundary).
A milhouse counter could be added later for improved accuracy.

### Accuracy Limitations

1. **Rare events ignored**: Slashings, sync committee rewards, large validator churn
   epochs are not accounted for. These contribute negligible bytes compared to the epoch
   boundary all-balances update.
2. **Committee size is approximate**: The actual number of balances touched mid-slot
   depends on which attestations are included. Using `target_committee_size` as an upper
   bound is safe.
3. **Non-milhouse fields**: `committee_caches`, `pubkey_cache`, `tree_hash_cache` have
   memory cost not captured by this estimate. These could use `mem::size_of` estimates
   (they're not structurally shared).
4. **Post-rebase accuracy**: The estimate assumes the state was rebased on finalized.
   If not, the actual cost could be higher (state carries inherited unique nodes not
   reflected in the estimate). The cache enforces rebase before insertion, so this
   shouldn't occur in practice.

## Cache Eviction Redesign

### Current Algorithm (`state_cache.rs:cull`)

```
trigger:  cache.len() > capacity (128)
exempt:   10% most-recently-used states
priority: advanced → old_boundary → mid_epoch → good_boundary (LRU within each)
stop:     cache.len() <= capacity - headroom
```

### Proposed Algorithm: Fork-Aware Byte-Budget Eviction

The state cache exists to avoid expensive state reconstruction. Eviction should minimize
reconstruction cost within a memory budget. This requires awareness of:

1. **How much memory each state costs** (dirty leaf estimates)
2. **How expensive it would be to reconstruct** (position in chain, distance from
   nearest retained state)
3. **Fork topology** (competing chains need independent skeletons)

#### Fork Topology Awareness

During forks, the cache holds states on multiple competing chains:

```
         finalized (shared base)
              |
         fork point
            /    \
      chain A     chain B
      (canonical)  (competing)
```

Each chain needs a minimum skeleton to avoid catastrophic reconstruction costs on head
switch. The unit of pruning is not an individual state — it's a **chain segment**.

**Per-fork minimum:**
- The **tip state** (needed to process the next block — evicting a tip is catastrophic)
- The **fork point boundary state** (common ancestor, needed to reconstruct either chain)

**Per-fork desirable:**
- Epoch boundary states along the chain (anchor points for reconstruction)
- The density of these anchors depends on the byte budget

#### Byte Budget Allocation Across Forks

```
budget = max_cache_bytes - finalized_base_size
canonical_budget = budget * 0.7   # canonical chain gets the lion's share
competing_budget = budget * 0.3   # split across competing forks by weight
```

Within each fork's budget:
1. Reserve space for **tip** (mandatory, any cost)
2. Reserve space for **fork point boundary** (mandatory)
3. Fill with **epoch boundary states** (high reconstruction cost, expensive to keep
   but worth it)
4. Fill remaining with **mid-epoch states** (cheap to keep AND cheap to reconstruct)

#### Eviction Algorithm

```
fn cull_to_budget(&mut self):
    // Phase 0: identify fork topology
    forks = identify_active_forks()  // from block_map / fork choice

    for fork in forks:
        fork.tip         = most recent state on this fork
        fork.boundary_states = epoch-aligned states on this fork
        fork.mid_epoch   = everything else

    // Phase 1: evict cheap low-utility states across all forks
    // Advanced states (speculative, often wasted)
    evict all advanced states (any fork)

    // Phase 2: thin interior states
    // Mid-epoch states are cheap to keep but also cheap to reconstruct.
    // On competing forks, remove all mid-epoch states.
    // On canonical fork, remove the oldest mid-epoch states first.
    for fork in competing_forks:
        evict all mid_epoch states on fork (keep tip + boundaries)
    for state in canonical_fork.mid_epoch sorted by slot ASC:
        if cached_bytes <= target: break
        evict state

    // Phase 3: if still over budget, reduce boundary density
    // On competing forks first, then canonical. Keep the most recent
    // boundaries (closest to tip) and evict the oldest.
    for fork in forks sorted by weight ASC:  // lightest fork first
        for state in fork.boundary_states sorted by slot ASC:
            if cached_bytes <= target: break
            if state == fork.tip: continue       // never evict tips
            if state == fork.fork_point: continue // never evict fork point
            evict state

    // Phase 4: last resort — evict competing fork tips
    // Only if memory is critical. Means full reconstruction on head switch.
    for fork in competing_forks sorted by weight ASC:
        if cached_bytes <= target: break
        evict fork.tip  // painful but necessary

    // NEVER evict: canonical tip, finalized state
```

#### Running Byte Total (No Re-measurement)

```rust
struct StateCache<E: EthSpec> {
    // ... existing fields ...
    max_bytes: usize,           // configurable budget (e.g. 2GB)
    cached_bytes: usize,        // running sum of estimates
}

fn put_state(&mut self, state_root, block_root, state) -> Result<PutStateOutcome> {
    // ... existing checks ...

    let cost = state.estimated_marginal_bytes();

    // Evict if over budget (not over count)
    if self.cached_bytes + cost > self.max_bytes {
        self.cull_to_budget();
    }

    self.states.insert(state_root, (state, cost));
    self.cached_bytes += cost;

    Ok(PutStateOutcome::New(deleted))
}

fn delete_state(&mut self, state_root: &Hash256) {
    if let Some((_, (_, cost))) = self.states.remove(state_root) {
        self.cached_bytes -= cost;
    }
    self.block_map.delete(state_root);
}
```

This works because estimates are independent after rebasing. Removing a state frees
approximately its estimated bytes. No need to re-measure the whole cache.

#### Refresh Estimates on Rebase

When finalized state updates, all cached states get rebased. Their dirty leaf counts
change (most reset to near-zero relative to the new finalized base). The
`update_finalized_state` method should refresh estimates:

```rust
fn update_finalized_state(&mut self, ...) {
    // ... existing finalization logic ...

    // Refresh all cached state estimates after rebase
    self.cached_bytes = 0;
    for (_, (state, cost)) in self.states.iter_mut() {
        *cost = state.estimated_marginal_bytes();
        self.cached_bytes += *cost;
    }
}
```

This is O(states × fields) ≈ O(128 × 5) = O(640) — trivial.

## Implementation Plan

### Phase 1: Cost Estimation Function (no behavior change)

Add `estimated_marginal_bytes()` to the `store` crate. Wire it into `put_state` to
compute and store the estimate alongside each cached state. Add a Prometheus gauge
exposing `cached_bytes` (sum of estimates). **No eviction changes yet** — this phase
is pure observability.

This lets us validate the estimates against real nodes in production before trusting
them for eviction decisions.

### Phase 2: Byte-Budget Eviction (replaces count-based)

1. Add `--state-cache-max-mb` CLI flag (default: 2048MB)
2. Replace count-based cull trigger with byte-budget trigger
3. Implement fork-aware `cull_to_budget` as described above
4. Keep `--state-cache-size` as a hard upper bound on count (safety net)
5. Refresh estimates in `update_finalized_state` after rebase

### Phase 3: Fork Topology Integration

1. Plumb fork choice weight info into the state cache (or into the cull call)
2. Implement per-fork budget allocation
3. Skeleton-based eviction: mandatory tips + fork points, variable boundary density

### Phase 4: Metrics & Observability

- `state_cache_estimated_bytes` gauge — total estimated cache size
- `state_cache_state_estimated_bytes` histogram — per-state cost distribution
- `state_cache_num_forks` gauge — active fork count
- `state_cache_evictions_total` counter with labels (phase, fork_position)

### Future: milhouse COW Counter (optional accuracy upgrade)

If the spec-derived estimates prove insufficient (e.g., edge cases where actual memory
diverges significantly from estimates), instrument milhouse's COW path:

1. Add `cow_leaf_count: usize` to milhouse `List`/`Vector`
2. Increment on actual COW (when `Arc::strong_count > 1` during leaf mutation)
3. Reset on `clone()`, `rebase_on()`, `intra_rebase()`
4. Expose `fn num_dirty_leaves(&self) -> usize`
5. Replace spec-derived estimates with direct COW counts

This gives exact per-field dirty leaf counts at O(1) per mutation. The estimation
formula stays the same — only the input (dirty leaf count) becomes exact instead of
approximate.

## Open Questions

1. **How does fork choice info reach the state cache?** Currently `StateCache` only knows
   about `head_block_root`. It doesn't have fork choice weights or the full fork tree.
   Either the cache needs a reference to fork choice, or the caller passes topology info
   during `put_state`/`cull`. The `block_map` already tracks block_root → slot mappings
   which provides some fork structure, but not weights.

2. **What's the right default budget?** 2GB covers ~100 epoch boundary states or thousands
   of mid-epoch states. Operators with 64GB+ RAM might want 8GB+. Should be CLI-configurable.

3. **Advanced states: how many slots ahead?** A state advanced by 1 slot has ~committee_size
   dirty balances. Advanced by 32 slots has ~32×committee_size. The current estimate treats
   all non-boundary states equally. Could refine by tracking `state.slot() - state.latest_block_header().slot`
   and scaling the committee-size estimate accordingly.

4. **Interaction with `intra_rebase`**: PR #7062 added `intra_rebase` for inactivity_scores
   to exploit internal structural sharing. After `intra_rebase`, the effective dirty leaf
   count is much lower than N even at epoch boundaries. The estimate should account for
   whether `intra_rebase` has been applied (reduces inactivity_scores cost from ~16MB to
   ~4-5MB).

## References

- sigp/lighthouse#7449 — Measure state cache size in memory
- sigp/lighthouse#7450 — Prune state cache based on size
- sigp/lighthouse#7803 — Memory Aware Caching (rejected implementation)
- sigp/lighthouse#6532 — State cache memory size WIP (PoC)
- sigp/lighthouse#7053 — OOM mitigations
- sigp/lighthouse#7062 — intra_rebase for inactivity_scores
- sigp/milhouse#51 — Differential memory usage tracking
