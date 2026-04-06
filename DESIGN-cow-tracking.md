# COW Memory Tracking Design

## Problem

The state cache needs to know how much memory cached states consume to enforce
a byte budget. States share tree nodes via milhouse COW (copy-on-write). The
marginal cost of a state depends on which nodes it shares with other states.

## Design: MutationBlock tracking

Each state carries a `Vec<Arc<MutationBlock>>` recording the COW bytes produced
by each transition it (or its ancestors) went through. Shared ancestry = shared
Arcs. Total cache cost = sum of unique MutationBlocks across all cached states.

### Data structures

```rust
/// Byte cost of one state transition (slot processing, block processing, etc).
/// Identity is by Arc pointer — two states sharing the same Arc<MutationBlock>
/// inherited it from a common ancestor.
pub struct MutationBlock {
    pub bytes: usize,
}
```

On `BeaconState` (skipped from serde/ssz/tree_hash like other caches):

```rust
#[serde(skip_serializing, skip_deserializing)]
#[ssz(skip_serializing, skip_deserializing)]
#[tree_hash(skip_hashing)]
pub mutation_blocks: Vec<Arc<MutationBlock>>,
```

### When measurements happen

**1. State transitions** (`per_slot_processing`, `per_block_processing`)

After each transition, measure the COW bytes produced:

```rust
// In per_slot_processing or per_block_processing:
let before = state.clone();  // snapshot (shares all nodes)
process_slot(state, ...)?;   // actual transition
let delta = cow_bytes(&before, state);  // O(dirty_nodes)
state.mutation_blocks.push(Arc::new(MutationBlock { bytes: delta }));
```

Cost: O(dirty_nodes per transition).
- Mid-epoch slot: ~200 dirty nodes → <0.1ms
- Epoch boundary: ~500K dirty nodes → ~25ms (acceptable alongside epoch processing)

**2. Rebase** (`rebase_on_finalized`)

After rebasing state S onto finalized F, the tree structure changes — S now
shares F's tree. Recompute S's unique cost relative to F:

```rust
fn rebase_on_finalized(state: &mut BeaconState<E>, finalized: &BeaconState<E>) {
    state.rebase_on(finalized)?;

    // After rebase, state shares finalized's tree. Measure what's unique to state.
    let unique_bytes = cow_bytes(finalized, state);

    // Replace mutation_blocks: inherit finalized's blocks + own unique cost
    state.mutation_blocks = finalized.mutation_blocks.clone();
    if unique_bytes > 0 {
        state.mutation_blocks.push(Arc::new(MutationBlock { bytes: unique_bytes }));
    }
}
```

**3. Clone**

`BeaconState::clone()` copies the `Vec<Arc<MutationBlock>>`. Each Arc's
refcount increments. No measurement needed.

**4. `put_state`**

Nothing. The state already carries its cost history.

### Computing total cache size

```rust
impl StateCache {
    pub fn total_cached_bytes(&self) -> usize {
        let mut seen = HashSet::new();
        let mut total = 0;
        for (_, state, _) in self.states.iter() {
            for mb in &state.mutation_blocks {
                let ptr = Arc::as_ptr(mb);
                if seen.insert(ptr) {
                    total += mb.bytes;
                }
            }
        }
        total
    }
}
```

Called when making eviction decisions. With ~100 cached states × ~64 blocks
each = ~6400 entries to deduplicate. Trivial cost.

### Example: star topology

```
Finalized F: mutation_blocks = [MB0(500MB)]

Clone F → process slot → cache S1:
  S1.mutation_blocks = [Arc(MB0), Arc(MB1(2MB))]

Clone F → process slot → cache S2:
  S2.mutation_blocks = [Arc(MB0), Arc(MB2(3MB))]

Unique MBs across {F, S1, S2}: {MB0:500, MB1:2, MB2:3}
Total: 505MB
```

### Example: chain topology

```
Clone F → process 32 slots → cache S1:
  S1.mutation_blocks = [Arc(MB0), Arc(MB1), ..., Arc(MB32)]

Clone S1 → process 1 slot → cache S2:
  S2.mutation_blocks = [Arc(MB0), Arc(MB1), ..., Arc(MB32), Arc(MB33)]

Unique MBs: {MB0..MB33} — MB0..MB32 shared between S1 and S2
Drop S1: MB0..MB32 still alive (S2 holds them). Only S1's entry removed.
Drop S2: All MBs freed.
```

### Example: rebase

```
S was cloned from S_old (not finalized), processed several slots:
  S.mutation_blocks = [MB_old_base, MB_old1, ..., MB_s1, MB_s2]

rebase_on_finalized(S, F):
  After rebase, S shares F's tree. Measure cow_bytes(F, S) = 80MB.
  S.mutation_blocks = [Arc(MB0_from_F), Arc(MB_rebase(80MB))]

Now S shares MB0 with F and any other states rebased on F.
```

## Why not cow_bytes at put_state time?

For epoch boundary states, cow_bytes(finalized, state) walks ~500K dirty nodes
(~30ms). This is the same cost whether measured incrementally or all at once.
But measuring at transition time:

1. **Captures the actual lineage** — the state knows exactly which transitions
   produced its COW nodes, not just the total diff vs finalized.
2. **Handles arbitrary clone patterns** — states can be cloned anywhere in
   beacon_chain. The mutation_blocks travel with the state automatically.
3. **Rebase resets the baseline** — after rebase, the state gets the finalized
   base blocks, so it shares correctly with siblings.
4. **put_state does nothing** — no measurement, no parent lookup, no finalized
   state access needed.

## What needs to be built

1. **`cow_bytes` in milhouse** — pairwise tree walk comparing two trees by Arc
   identity. O(dirty_nodes). This is the only new milhouse API needed.

2. **MutationBlock field on BeaconState** — with skip attributes, excluded from
   PartialEq/serde/ssz/tree_hash.

3. **Push sites in state_processing** — after per_slot_processing and
   per_block_processing, measure delta and push MutationBlock.

4. **Rebase integration** — after rebase_on_finalized, recompute mutation_blocks.

5. **total_cached_bytes on StateCache** — iterate + deduplicate.

6. **Remove estimated_marginal_bytes** — no longer needed once cow_bytes exists.
