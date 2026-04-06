# State Cache Size Estimation: Progress & TODO

## Context

`estimated_marginal_bytes` estimates the per-state COW memory cost for byte-budget eviction
in `StateCache`. It must be an **upper bound** — underestimates cause OOM, overestimates
just reduce cache utilisation.

After `rebase_on_finalized()`, all cached states share the finalized state's milhouse tree
as their base. The estimate approximates how many leaves each state has COW'd using
spec knowledge (is_epoch_boundary, committee_size, etc.).

## What the current estimate covers

Tree-backed milhouse fields only:
- balances (u64 × n)
- inactivity_scores (u64 × n)
- previous/current_epoch_participation (u8 × n)
- validators (Validator × n) — currently estimated as 0 dirty
- state_roots + block_roots (Hash256 × SlotsPerHistoricalRoot)
- randao_mixes (Hash256 × EpochsPerHistoricalVector)
- Container overhead (7 × sizeof(List))

## Known gaps in the estimate

### A. Missing tree-backed fields

| Field | Type | When mutated | Impact |
|-------|------|-------------|--------|
| slashings | Vector<u64, EpochsPerSlashingsVector> | epoch boundary (1 entry reset) | negligible |
| eth1_data_votes | List<Eth1Data, SlotsPerEth1VotingPeriod> | 1 per slot | small |
| historical_roots | List<Hash256, HistoricalRootsLimit> | frozen since Capella | 0 |
| historical_summaries | List<HistoricalSummary, ...> | 1 per epoch (Capella+) | small |
| pending_deposits | List<PendingDeposit, ...> | Electra+, varies | TBD |
| pending_partial_withdrawals | List<...> | Electra+, varies | TBD |
| pending_consolidations | List<...> | Electra+, varies | TBD |

### B. Non-tree-backed state (caches)

These are NOT milhouse trees. They're regular heap allocations carried on every
BeaconState clone. `estimated_marginal_bytes` ignores them entirely.

| Cache | Sharing | Approx size (650k vals) | On clone |
|-------|---------|------------------------|----------|
| committee_caches[3] | Arc | 30-60 MB | Arc clone (shared) |
| epoch_cache | Arc | ~5 MB | Arc clone (shared) |
| pubkey_cache | rpds trie | 100-150 MB | structural sharing |
| slashings_cache | rpds trie | <50 KB | structural sharing |
| progressive_balances_cache | plain | 104 B | deep copy |
| exit_cache | plain | 17 B | deep copy |
| total_active_balance | Option | 16 B | copy |
| current/next_sync_committee | Arc | 2 × 52 KB | Arc clone (shared) |

**Key concern:** Arc-shared caches (committee_caches, epoch_cache) have large intrinsic
size but zero marginal cost when shared. However, if only ONE state holds a particular
cache (e.g. after other states are evicted), pruning that state frees the cache memory.
The current estimate doesn't track this at all.

### C. Clone chain / pruning hazard

After `rebase_on_finalized()`, states share the finalized tree base. But states also
share COW'd nodes with each other when cloned (e.g. state B cloned from state A both
share A's COW'd nodes, not just finalized's).

When state A is pruned:
- Milhouse nodes shared ONLY between A and finalized are freed (A's COW'd nodes)
- Milhouse nodes shared between A and B are NOT freed (B still holds Arc refs)
- But B's "marginal cost" was estimated assuming it only shares with finalized
- The estimate for B already accounts for this (it estimates based on B's slot/epoch
  relative to finalized), so this should be roughly correct

**Real risk:** Two states at the same slot (e.g. pending vs full payload status) share
almost all nodes with the finalized base. Evicting one doesn't free much memory, but the
estimate counts each independently. This is conservative (overestimate) so it's safe
but wastes cache slots.

**Confirmed by tests:**
- Two independently cloned states at the same slot have INDEPENDENT COW'd nodes
  (no sharing between them, only sharing with the finalized base)
- Dropping an intermediate state doesn't change the total_size of states that hold
  Arc refs to shared nodes (Arc refcount keeps nodes alive)
- A state's total_size (without a base) is ~9x its marginal differential, showing
  the bulk of memory is in the shared finalized base tree

## Completed

- [x] MemorySize impl for ParticipationFlags
- [x] estimate_tree_bytes formula fixes (Zero nodes, Leaf<T> Arc, internal node count)
- [x] Test: estimate_tree_bytes sparse single mutation (u64)
- [x] Test: estimate_tree_bytes sparse many scattered (u64)
- [x] Test: estimate_tree_bytes sparse adjacent (u64)
- [x] Test: estimate_tree_bytes full mutation (u64)
- [x] Test: estimate_tree_bytes u8 full (participation)
- [x] Test: estimate_tree_bytes Hash256 sparse (roots)
- [x] Test: estimate_tree_bytes Hash256 full (all 64 entries)
- [x] Test: estimate_tree_bytes slashings single (Vector<u64, U64>)
- [x] Test: estimated_marginal_bytes epoch boundary (simulated)
- [x] Test: estimated_marginal_bytes mid-epoch (simulated)
- [x] Test: per_field balances single proposer reward
- [x] Test: per_field participation 128 committee members
- [x] Test: per_field participation replaced (epoch rotation)
- [x] Test: per_field state_roots single mutation
- [x] Test: per_field randao single mutation
- [x] Test: per_field inactivity_scores all-dirty (epoch boundary)
- [x] Test: clone_chain_shared_cow (A from base, B from A)
- [x] Test: prune_intermediate_state (drop A, verify B's total_size unchanged)
- [x] Test: prune_shared_base_differential_increases (total >> marginal diff)
- [x] Test: two_states_same_slot_independent_cow
- [x] Test: multi_slot_accumulation (4 mid-epoch slots)

### Key test observations

| Test | Estimated | Actual | Ratio | Notes |
|------|-----------|--------|-------|-------|
| sparse(1/1024) u64 | 1,472 | 1,472 | 1.00 | exact match |
| full(1024/1024) u64 | 46,496 | 45,776 | 1.02 | slight overcount |
| u8_full(1024/1024) | 7,072 | 6,352 | 1.11 | good |
| hash256_full(64/64) | 11,768 | 11,768 | 1.00 | exact |
| slashings(1/64) | 456 | 456 | 1.00 | exact |
| epoch_boundary(n=1024) | 120,504 | 116,160 | 1.04 | good upper bound |
| mid_epoch(n=1024) | 172,912 | 7,960 | 21.7 | large overestimate (safe) |
| participation(128/1024) | 84,040 | 3,080 | 27.3 | sparse path sharing |
| multi_slot(4 slots) | 70,392 | 9,184 | 7.66 | safe overestimate |

The mid-epoch overestimate is large because the sparse formula assumes worst-case
scattered mutations (each dirty leaf gets its own root-to-leaf path). In practice,
128 participation changes share many path nodes. This is intentionally conservative.

## TODO

### Alternative approach: exact milhouse measurement at state transition

Instead of estimating from spec knowledge, use milhouse's `MemoryTracker` to measure
the exact COW cost at each state transition (before/after diff). This would be:
- **Exact**: no estimation error, no missing fields
- **Automatic**: picks up new fields without code changes
- **Question**: is it fast enough to run on every slot transition?

See discussion below.

### Phase 3: Cache memory accounting

Decide how to handle non-tree-backed caches in the size estimate.

- [ ] Measure: sizeof each cache type at runtime (CommitteeCache, PubkeyCache, etc.)
- [ ] Analyze: which caches are Arc-shared vs deep-cloned
- [ ] Decide: should estimated_marginal_bytes include cache overhead?
      - Option A: Add a flat constant for caches (simple, conservative)
      - Option B: Track Arc refcount=1 caches separately (complex, accurate)
      - Option C: Ignore caches (current behavior — risky if caches dominate)
- [ ] Implement chosen approach

### Remaining gaps

- [ ] Electra pending_* lists (need to understand mutation patterns)
- [ ] Validators: effective_balance updates — currently estimated as 0,
      real-world is O(few) per epoch. Consider adding a small constant.
