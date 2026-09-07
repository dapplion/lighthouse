# Formalising the tree-sync core in Lean 4 — findings

A Lean 4 formalisation of the pure, size-generic core of [`specs/tree-sync.md`](../tree-sync.md): the `Chain` record, the `Split` and `Merge` operations, the structural invariants 2, 4 and 5, and the termination of the header walk.

**Status: everything in this project builds, `sorry`-free.** `lake build` succeeds from a clean `.lake`. Every theorem listed below is fully proved; five of them are *refutations* — machine-checked counterexamples showing the spec is false as written.

```
$ grep -rnE '\bsorry\b|sorryAx|native_decide' TreeSync/ | wc -l
0
```

No `sorry`, no `native_decide`, no `axiom`. `#print axioms` on every one of the 75 declarations in the library returns only Lean's three standard axioms (`propext`, `Quot.sound`, `Classical.choice`) — never `sorryAx` and never `Lean.ofReduceBool`.

## Build

```
curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y
cd specs/lean && lake build
```

Lean 4.15.0, **core + `Init` only — no mathlib, no Std dependency**. Nothing here needed it: the entire argument is list algebra over one recursive predicate. A clean build takes under three seconds; mathlib would have cost tens of minutes for no benefit. `TreeSync/List.lean` re-proves the four or five list facts that would otherwise have come from mathlib, each in two to five lines.

## Layout

| File | Contents |
|---|---|
| `TreeSync/List.lean` | `Linked`, the one predicate all three structural invariants instantiate, plus its `take`/`drop`/`append`/`map`/`reverse` closure lemmas |
| `TreeSync/Basic.lean` | `Root`, `Slot`, `Peer`, `Block`, `BackfillChain`, `ForwardChain`, `Chain` |
| `TreeSync/Ops.lean` | `rootIdx`, `restrict` (`↾`), `splitBackfill`, `splitForward`, `mergeBackfill`, `mergeForwardLiteral`, `mergeForward` |
| `TreeSync/Invariants.lean` | `Inv2`, `Inv4`, `Inv5`, `Inv5FC`, and the omitted side conditions `NoDupRoots`, `AnchorSound`, `AnchorSlotSound` |
| `TreeSync/Split.lean` | Theorems 2 and 3 |
| `TreeSync/Merge.lean` | Theorem 1, plus what `Merge` needs to preserve Inv 2 and Inv 4 |
| `TreeSync/Inv5.lean` | Theorem 4 |
| `TreeSync/Discovery.lean` | Theorem 5 |
| `TreeSync/Counterexamples.lean` | Every refutation, plus non-vacuity checks |

## Modelling choices

These were judgement calls; they are recorded here and in the file headers.

- **`Root` is opaque.** A one-field structure over `Nat` with `DecidableEq`, so no proof can accidentally do arithmetic on a root. Hashing is not modelled. `parent : Root → Root` is an abstract parameter carried wherever Inv 2 is stated. Blocks carry their own `parentRoot` field; `blocksLinked_of_inv2` connects the two under the hypothesis that a block reports its parent honestly.
- **`Slot` is `Nat`**, declared as `notation "Slot" => Nat` rather than `abbrev Slot := Nat`. This is not cosmetic: `omega` in Lean 4.15 does not unfold reducible type aliases, so with an `abbrev` every arithmetic goal about slots failed with "no usable constraints found". This cost about twenty minutes to diagnose and is worth knowing for anyone extending the file.
- **`peers : List Peer`** — a set by value, no interior mutability. The Rust uses `Arc<RwLock<HashSet<PeerId>>>` and `Chain::split_at` deep-copies it for the newer half, so a by-value list is the right abstraction of the post-copy state. Consequences in Gap 8 below.
- **`Backfill` and `ForwardSync` are separate structures** joined by an `inductive Chain`, rather than one record with a sum-typed state. This keeps `Split`'s two cases and `Merge`'s Backfill-only guard honest and removes a great deal of case noise.
- **`Split` returns `Option (Chain × Chain)`**, `none` exactly when the guard `r ∈ c.roots ∧ r ≠ c.roots[0]` fails. `r ∈ c.roots` is resolved to the *first* index at which `r` occurs, matching `Vec::position` in the Rust. Under the `NoDupRoots` side condition of Gap 3 the choice is irrelevant.
- **`Y` is the older half, `Z` the newer**, as in the spec and as in the Rust (where the older half keeps `chain_id`).
- **Scope.** No `loc`, no `FC` as mutable state, no peers-as-shared-state, no transition system. `FC` appears only as an abstract `Root → Prop` where Inv 5 mentions it. Invariants 1, 3 and 6 quantify over the transition system and are out of scope.

## Results

### Theorem 1 — `merge_split` — **PROVED**

```lean
theorem merge_split {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) : mergeBackfill Y Z = some c
```

The spec's unproved assertion "`Merge(Split(c, r)) = c` for `Backfill`". Holds on the nose — as record equality, not up to some equivalence — for every `r` admitted by `Split`'s guard, including chains with duplicate roots.

What carries the proof: `Split`'s guard `r ≠ c.roots[0]` forces the pivot index to be at least 1, hence `Y.roots` is non-empty and `Y.roots[0] = r`, which is exactly what `Merge`'s guard `Z.state = Anchored(Y.roots[0])` tests. The `peers` half of the guard is discharged because `Split` hands both halves the same `c.peers`.

**This theorem is false as the spec is literally written** — see Gap 1. It required choosing `errors := Y.errors`, a field the spec's `Merge` record omits entirely.

The `ForwardSync` analogue also holds, but only for the *repaired* `Merge` of Gap 2:

```lean
theorem merge_split_forward_of_inv5 {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z))
    (hnodup : NoDupRoots c.roots) (hinv : c.state.Inv5 c.roots) :
    mergeForward Y Z = some c
```

### Theorem 2 — `split_partition` (`Y ⊎ Z = c`) — **PROVED**

```lean
theorem split_partition {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) : Z.roots ++ Y.roots = c.roots

theorem split_partition_forward {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z)) : Z.roots ++ Y.roots = c.roots
```

Unconditional. Also proved, and used repeatedly:

```lean
theorem split_pivot {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) :
    Y.roots.head?.map Prod.fst = some r ∧ Y.roots ≠ [] ∧ Z.roots ≠ []
```

This is the spec's parenthetical `Z.parent = Y.roots[0]`, discharged rather than assumed. It is also the fact that makes `Merge`'s guard satisfiable after a `Split`, and the reason both halves of a `Split` are non-empty — which the spec asserts informally when it says "At `|c.roots| = B` the `B`th-oldest root is the tip, which `Split` rejects".

### Theorem 3 — `split_preserves_inv2` / `split_preserves_inv4` — **PROVED**

```lean
theorem split_preserves_inv2 (parent : Root → Root) {c : BackfillChain} {r : Root}
    {Y Z : BackfillChain} (h : splitBackfill c r = some (Y, Z)) (hc : Inv2 parent c.roots) :
    Inv2 parent Y.roots ∧ Inv2 parent Z.roots

theorem split_preserves_inv4 {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) (hc : Inv4 c.roots) :
    Inv4 Y.roots ∧ Inv4 Z.roots
```

Unconditional, with `_forward` variants for `ForwardChain`. Both are one-liners once `Inv2` and `Inv4` are recognised as instances of a single predicate

```lean
def Linked (R : α → α → Prop) : List α → Prop
  | [] => True
  | [_] => True
  | a :: b :: t => R a b ∧ Linked R (b :: t)
```

with `Inv2 parent = Linked (fun a b => parent a.1 = b.1)` and `Inv4 = Linked (fun a b => b.2 < a.2)`. `Linked.take` and `Linked.drop` then discharge both invariants for both halves at once. Inv 5's linkage clause is the third instance.

Also proved, because the Inv 5 proof needs the side condition to be stable under the operation:

```lean
theorem split_preserves_nodup {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) (hc : NoDupRoots c.roots) :
    NoDupRoots Y.roots ∧ NoDupRoots Z.roots
```

### Theorem 4 — `split_preserves_inv5` — **PROVED, with a side condition the spec omits**

```lean
theorem split_preserves_inv5 {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    {bs : List Block}
    (h : splitForward c r = some (Y, Z))
    (hnodup : NoDupRoots c.roots)
    (hinv : Inv5 bs c.roots) :
    Inv5 (restrict bs Y.roots) Y.roots ∧ Inv5 (restrict bs Z.roots) Z.roots
```

with a packaged form over the whole state:

```lean
theorem split_preserves_inv5_state {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z))
    (hnodup : NoDupRoots c.roots)
    (hinv : c.state.Inv5 c.roots) :
    Y.state.Inv5 Y.roots ∧ Z.state.Inv5 Z.roots
```

`hnodup` is **not** implied by the spec's stated invariants — see Gap 3, which is the single most valuable finding here.

The content of the proof is the lemma that makes the reversal concrete:

```lean
theorem restrict_of_split {bs : List Block} {rs : List Entry} (i : Nat)
    (hmap : bs.map Block.root = (rootsOf rs).reverse) (hnodup : NoDupRoots rs) :
    restrict bs (rs.drop i) = bs.take (rs.drop i).length ∧
    restrict bs (rs.take i) = bs.drop (rs.drop i).length
```

`↾` is defined in the spec as a *filter* ("blocks whose root ∈ `c.roots`"), and this says that under `NoDupRoots` the filter is in fact a *cut*: the older half `Y` gets exactly the first `|Y.roots|` blocks, the newer half `Z` gets exactly the rest, and neither half's blocks are reordered. That is precisely the point where `roots` (tip first) and `blocks` (import order) meet through the reversal, and it is what lets `Linked.take` / `Linked.drop` finish the job. Without `NoDupRoots` the filter is not a cut and the theorem is false for *both* halves simultaneously.

### Theorem 5 — `discovery_terminates` — **PROVED**

```lean
structure Walk where
  finalizedSlot : Slot
  step : Entry → Option Entry
  decreasing : ∀ e e', step e = some e' → e'.2 < e.2
  aboveFloor : ∀ e e', step e = some e' → finalizedSlot < e'.2

def Walk.run (w : Walk) (e : Entry) : List Entry :=
  match hs : w.step e with
  | none => [e]
  | some e' => e :: w.run e'
termination_by e.2 - w.finalizedSlot
decreasing_by
  have h1 := w.decreasing e e' hs
  have h2 := w.aboveFloor e e' hs
  omega
```

`Walk` bundles exactly the two guarantees the spec gives: `SendHeaders`' `h[i].slot < h[i−1].slot`, and `OnHeaders`' floor guard `header.slot ≤ slot(finalized) → Drop`. Lean accepting `Walk.run` *is* the termination proof — the measure is `slot − slot(finalized)` and it strictly decreases at every step. Four further theorems make it quantitative and connect it to the invariants:

```lean
theorem Walk.run_length_le (w : Walk) (e : Entry) (h : w.finalizedSlot < e.2) :
    (w.run e).length ≤ e.2 - w.finalizedSlot

theorem Walk.run_above_floor (w : Walk) (e : Entry) (h : w.finalizedSlot < e.2) :
    ∀ p ∈ w.run e, w.finalizedSlot < p.2

theorem Walk.run_inv4 (w : Walk) (e : Entry) : Inv4 (w.run e)

theorem Walk.run_inv2 (w : Walk) (parent : Root → Root)
    (hpar : ∀ e e', w.step e = some e' → parent e.1 = e'.1) (e : Entry) :
    Inv2 parent (w.run e)
```

The last two are worth flagging: they say the header walk is what *creates* Inv 2 and Inv 4, and `Split` (Theorem 3) is what preserves them. Together they cover the invariants' whole life cycle on the `Backfill` side.

See Gap 9 for a small correction to the spec's stated reason for termination.

## Spec defects found

These are the substance of the exercise. Each is backed by a machine-checked witness in `TreeSync/Counterexamples.lean`.

### Gap 1 — `Merge` does not say what `errors` becomes — **genuine spec defect, incompleteness**

The spec's `Merge` is

```
c = { roots: Z.roots ++ Y.roots, peers: Y.peers, state: Y.state }
```

but `Chain` is declared with an `errors: Nat` field, and `Split` explicitly says "both inherit `c.errors`". `Merge` therefore has to say something, and the only reading under which `Merge(Split(c, r)) = c` holds is `errors := Y.errors` (equivalently `Z.errors`, which `Split` makes equal). We adopt that.

```lean
theorem merge_split_needs_errors :
    mergeBackfillResetErrors
        { roots := [(r1, 4), (r0, 3)], peers := [], errors := 3, state := .anchored r3 }
        { roots := [(r2, 5)], peers := [], errors := 3, state := .anchored r1 }
      ≠ some errChain
```

`mergeBackfillResetErrors` is the other obvious reading, `errors := 0`. It breaks the round trip. **Fix: write `errors := Y.errors` into the spec's `Merge`.**

There is a secondary question the spec should also settle: after `Y` and `Z` have evolved independently their `errors` may differ, and `Merge` then silently discards one retry budget. Adding `Y.errors = Z.errors` to the guard, or taking the max, would make `Merge` canonical. We did not need to choose for the round trip, since `Split` makes them equal.

### Gap 2 — `Merge` is unsound for `ForwardSync` — **genuine spec defect**

`Merge` takes `state := Y.state`. For `Backfill` that is right, because `Split` gives `Y` the whole of `c.state`. For `ForwardSync`, `Split` gives `Y` only `c.state↾Y`, so a literal `Merge` **silently discards every block `Z` had already downloaded**.

```lean
theorem mergeForwardLiteral_loses_blocks : mergeForwardLiteral okY okZ ≠ some okChain
```

where `okChain` is a well-formed three-root `Ready` chain and `(okY, okZ) = Split(okChain, r1)` (itself proved by `ok_split`). The merged chain comes back with two of the three blocks.

The spec does restrict its round-trip claim to `Backfill`. But it does not say `Merge` must not be applied to a `ForwardSync` pair, and it describes `Merge` as a general background compaction over `Chain`. A `Merge` that drops downloaded blocks while keeping their roots also breaks Inv 5 outright, so this is not merely a lost-work bug.

**Fix:** define `Merge` for `ForwardSync` to concatenate the halves' block sequences, older half first (`blocks` is import order, so `Y` — the older half — comes first; this is the reversal again). With that:

```lean
theorem mergeForward_ok : mergeForward okY okZ = some okChain
```

and the general round trip `merge_split_forward_of_inv5` above. The `Anchored` half of `Merge`'s guard also has no `ForwardSync` counterpart; we used the corresponding `Z.parent = Y.roots[0]`, which the spec should state.

### Gap 3 — `c.roots` is never required to be duplicate-free, and Inv 5 needs it — **genuine spec defect, and the most important one**

Invariants 2 and 4 do **not** imply that a chain's roots are pairwise distinct:

```lean
theorem nodup_not_implied :
    ∃ (p : Root → Root) (rs : List Entry), Inv2 p rs ∧ Inv4 rs ∧ ¬ NoDupRoots rs
```

The witness is `rs = [(r0,5), (r1,4), (r0,3)]` with `parent r0 = r1`, `parent r1 = r0`. Contiguity holds — a `parent` function may cycle, and nothing in the spec forbids it. Slots strictly decrease — and distinct slots do not force distinct roots, because **nothing in the spec ties a root to a slot**. Inv 5 even holds for this chain (`cyc_inv5`), because `[r0, r1, r0]` is its own reverse.

Now `Split` it at `r1`:

```lean
theorem cyc_split : splitForward cycChain r1 = some (cycY, cycZ)

theorem split_inv5_fails_without_nodup :
    ¬ Inv5 (restrict cycBlocks cycY.roots) cycY.roots ∧
    ¬ Inv5 (restrict cycBlocks cycZ.roots) cycZ.roots
```

**Both halves violate Inv 5.** `↾` is a filter on "root ∈ this half's roots", so when a root occurs in both halves its block is copied into *both*: `cycY` gets three blocks for its two roots, `cycZ` gets two blocks for its one root. Neither half's block sequence is its roots reversed any more.

This is a genuine spec defect rather than a proof-engineering problem. It also has consequences beyond Inv 5: Invariant 1 reads `loc(r) = c ⟺ r ∈ c.roots ∨ c.state = Discovering(r)`, which makes `loc` a *function* from roots to chains — a root occurring twice in one chain is survivable there, but a root occurring in two chains is not, and the spec has no statement ruling either out. `OnDownload`'s "`Ok(blocks)` covers exactly the roots of `R` as a set" and `Ready(blocks↾c)` similarly presume distinctness.

**Fix — two options, and they are not equivalent:**

1. State the invariant directly: **"the roots of a chain are pairwise distinct"**, and ideally the global form, "`loc` is injective on chains: each root belongs to at most one chain, at most once". `Split` preserves it (`split_preserves_nodup`); `OnHeaders` must establish it, which needs the walk not to revisit a root.
2. Better, because it also fixes Gap 6: state that **slot is a function of root** (`slotOf : Root → Slot`) and that `slot(parent(r)) < slot(r)`. Then Inv 4 becomes a *corollary* of Inv 2 rather than an independent invariant, and distinctness of roots follows from distinctness of slots. See `inv4_of_inv2` below.

Option 2 is closer to reality — a block root does determine its slot — and it removes an invariant instead of adding one.

### Gap 4 — `Merge`'s guard is undefined when `Y.roots` is empty — **spec defect, minor**

`Search` creates `Backfill{roots: [], peers: P, errors: 0}`, so empty-`roots` chains exist, and `Y.roots[0]` in `Merge`'s guard has no value for them. We read the guard as failing (`merge_empty_y : mergeBackfill emptyY badZ = none`). **Fix: add `Y.roots ≠ ∅` to `Merge`'s guard explicitly.**

### Gap 5 — `Merge` does not preserve Inv 2 — **genuine spec defect**

`Merge`'s guard checks only `Z.state = Anchored(Y.roots[0])`. Invariant 6 asks of an `Anchored(p)` only that `p ∈ FC ∨ p ∈ dom(loc)`. **Nothing in the spec says `p` is the parent of the anchored chain's own oldest root.** So nothing links `Z`'s tail to `Y`'s head, and the concatenation `Z.roots ++ Y.roots` need not be contiguous:

```lean
theorem bad_merge : mergeBackfill badY badZ = some badMerged
theorem bad_inv2_halves : Inv2 badParent badY.roots ∧ Inv2 badParent badZ.roots
theorem merge_breaks_inv2 : ¬ Inv2 badParent badMerged.roots
```

`badY.roots = [(r1,4), (r0,3)]`, `badZ.roots = [(r3,9)]`, `badZ.state = Anchored(r1)` so the guard passes — but `parent r3 = r2 ≠ r1`. Both halves satisfy Inv 2; the merge does not.

**Fix: state the missing invariant.** Call it Inv 6b: `state = Anchored(p) ⟹ p = parent_root(last(c.roots))` when `c.roots ≠ ∅`, and likewise `ForwardSync.parent = parent_root(last(c.roots))`. This is what `OnHeaders` actually establishes (`state := Anchored(p)` is set with `p := header.parent_root` of the last pushed header) and what `Split` preserves (`Z.parent := r`, and `r` really is the parent of `Z`'s oldest root by Inv 2). It is simply never written down. With it, `Merge` preserves Inv 2:

```lean
theorem merge_preserves_inv2 (parent : Root → Root) {Y Z c : BackfillChain} {zp : Root}
    (hstate : Z.state = .anchored zp)
    (hsound : AnchorSound parent Z.roots zp)
    (h : mergeBackfill Y Z = some c)
    (hY : Inv2 parent Y.roots) (hZ : Inv2 parent Z.roots) :
    Inv2 parent c.roots
```

where `AnchorSound parent rs p := ∀ e ∈ rs.getLast?, parent e.1 = p`.

Note that this defect is invisible if you only ever call `Merge` on the output of `Split` — `merge_split` holds regardless. It bites exactly in `Merge`'s stated role as "a background compaction" applied to two chains that arrived at the guard independently, which is the only role the spec gives it.

### Gap 6 — `Merge` does not preserve Inv 4, and its guard *cannot* be strengthened to fix it — **genuine spec defect**

```lean
theorem slot_merge : mergeBackfill slotY slotZ = some slotMerged
theorem slot_inv4_halves : Inv4 slotY.roots ∧ Inv4 slotZ.roots
theorem merge_breaks_inv4 : ¬ Inv4 slotMerged.roots
```

`slotY.roots = [(r1,4), (r0,3)]`, `slotZ.roots = [(r3,2)]`, `slotZ.state = Anchored(r1)`. Guard passes; merged slots are `2, 4, 3`.

What makes this worse than Gap 5 is that **`Anchored(p)` records a `Root` and no `Slot`**, so the guard cannot even *mention* the anchor's slot. Adding an `AnchorSlotSound` condition would require changing the state representation.

**Fix: don't.** Record instead that slots are a function of the root and increase along child links, and Inv 4 falls out of Inv 2 with no `Merge` guard at all:

```lean
theorem inv4_of_inv2 (parent : Root → Root) (slotOf : Root → Slot)
    (hmono : ∀ r, slotOf (parent r) < slotOf r) {rs : List Entry}
    (hagree : ∀ e ∈ rs, e.2 = slotOf e.1) (h2 : Inv2 parent rs) : Inv4 rs

theorem merge_preserves_inv4 (parent : Root → Root) (slotOf : Root → Slot)
    (hmono : ∀ r, slotOf (parent r) < slotOf r) {Y Z c : BackfillChain} {zp : Root}
    (hstate : Z.state = .anchored zp)
    (hsound : AnchorSound parent Z.roots zp)
    (h : mergeBackfill Y Z = some c)
    (hagree : ∀ e ∈ c.roots, e.2 = slotOf e.1)
    (hY : Inv2 parent Y.roots) (hZ : Inv2 parent Z.roots) :
    Inv4 c.roots
```

This is the same repair as option 2 of Gap 3, and it resolves both. **Invariant 4 as stated is redundant**: it should be a consequence, not an assumption.

### Gap 7 — `Split` breaks Inv 5's fork-choice clause for `Processing` — **genuine spec defect**

Invariant 5 ends: "`Processing` also ⟹ `parent(blocks[0]) ∈ FC`". `SendProcess` establishes it via its own guard `c.parent ∈ FC`. But `Search` may `Split` any chain it reaches through `loc`, including one in `Processing` — and the spec explicitly specifies that case (`ForwardSync Y.state := c.state↾Y Z.state := c.state↾Z` covers `Processing`, and "Both halves keep awaiting the shared in-flight call: `OnDownload` and `OnProcess` dispatch its result per root via `loc`" says splitting mid-flight is intended).

After the split, `parent(Z.blocks[0]) = r`, the pivot — a root of `Y` that has not been imported and is therefore not in `FC`.

```lean
theorem fc_split : splitForward fcChain r1 = some (fcY, fcZ)
theorem fc_before : Inv5FC FCr3 okBlocks
theorem split_breaks_inv5_fc : ¬ Inv5FC FCr3 [okB2]
```

`Split` is a pure operation on chains — it does not change `FC` — so this is a genuine gap in the invariant as stated, not a transient of some larger step that restores it.

**Fix:** weaken the clause to `Processing(blocks) ⟹ parent(blocks[0]) ∈ FC ∨ parent(blocks[0]) ∈ dom(loc)`, matching Inv 6's shape; or scope it to chains that have not been split since `SendProcess`. The first is closer to what the code relies on.

### Gap 8 — `Merge`'s `peers` guard is not set equality — **spec ambiguity, minor**

`peers` is a `Set<Peer>` but the guard `Y.peers = Z.peers` has to be decided on a representation. Read as list equality it is over-strict:

```lean
theorem merge_guard_order_sensitive : mergeBackfill permY permZ = none
```

where `permY.peers = [7, 8]` and `permZ.peers = [8, 7]`. Read as extensional set equality it is right, but then `Merge` must pick a representative for the result and `Merge(Split(c, r)) = c` only holds up to peer-set equality rather than on the nose. `merge_split` above is stated with list equality, which is the stronger claim and the one that holds because `Split` hands both halves the identical list. This is a note for anyone mechanising further, not a bug in the design.

### Gap 9 — the spec's reason for discovery terminating is not the real reason — **imprecision, harmless**

The Liveness section says "Discovery terminates: `slot` strictly decreases (Inv 4), bounded below by `slot(finalized)`." Over `Nat` slots the boundedness is not needed: any strictly decreasing sequence of naturals is finite. Machine-checked:

```lean
structure WalkNoFloor where
  step : Entry → Option Entry
  decreasing : ∀ e e', step e = some e' → e'.2 < e.2

def WalkNoFloor.run (w : WalkNoFloor) (e : Entry) : List Entry := …
termination_by e.2
decreasing_by exact w.decreasing e e' hs
```

What `slot(finalized)` actually buys is the **quantitative** bound `run_length_le` — at most `slot(seed) − slot(finalized)` roots — which is the property that matters against an adversarial peer, since it caps the work and the `loc` growth a single header walk can cause. Worth restating in those terms.

### Gap 10 — spec/implementation divergence in `Processing` — **not a proof result, but found while reading**

The spec declares `Processing(Seq<Block>)`; the Rust declares `Processing` with no payload, and `Sync::partition` maps `Processing => (Processing, Processing)`. So Inv 5's clauses about `Processing`'s `blocks` are unimplementable as written against the current code — there are no blocks to check. This is also why the implementation cannot exhibit Gap 7: it has nothing to violate. Either the spec should drop the payload from `Processing`, or the code should keep the blocks so that `OnProcess`'s per-root dispatch has something to dispatch.

## Things checked and found sound

- **`Split`'s guard is always satisfiable where `Search` invokes it.** `Search`'s third bullet handles `r = c.roots[0] ∨ c.state = Discovering(r)` before falling through to `Split`, so by Inv 1 the `Split` branch has `r ∈ c.roots` and `r ≠ c.roots[0]`. Checked by hand, not formalised — it needs `loc`, which is out of scope.
- **`Promote`'s `Split` index is always legal.** `|c.roots| > B` makes the `B`th-oldest root distinct from the tip. The spec already argues this; it holds.
- **`Split` preserves Inv 3.** `Z.roots[0] = c.roots[0]`, and `Y.roots[0] = r` is an ancestor of `c.roots[0]`, so "`p` claimed `c.roots[0]`" transfers to both halves under the spec's own "holding `r` implies holding its ancestors". Not formalised — Inv 3 is about peer claims, outside the pure core.
- **Inv 5's linkage clause is redundant.** Given Inv 2, the root correspondence, and blocks that report their own parent honestly, `∀ i > 0. parent(blocks[i]) = blocks[i−1]` follows:

  ```lean
  theorem blocksLinked_of_inv2 {bs : List Block} {rs : List Entry}
      (h2 : Inv2 parent rs)
      (hmap : bs.map Block.root = (rootsOf rs).reverse)
      (hpar : ∀ b ∈ bs, b.parentRoot = parent b.root) :
      BlocksLinked bs
  ```

  This is the formal content of the spec's remark that "`roots` is tip first and `blocks` is import order, so the reversal is where they meet": the two are one fact read in opposite directions. Inv 5 could state only the root correspondence and derive the rest.
- **`↾` preserving relative order matters and the Rust gets it right.** `Iterator::partition` is order-preserving, which is what makes each half's blocks a contiguous slice of the original. A `HashSet`-based regrouping would break Inv 5 even with distinct roots.

## Non-vacuity

Every side condition used above is satisfiable, and the general theorems are exercised on concrete data in `TreeSync/Counterexamples.lean`:

```lean
example : Inv5 (restrict okBlocks okY.roots) okY.roots ∧
          Inv5 (restrict okBlocks okZ.roots) okZ.roots :=
  split_preserves_inv5 ok_split ok_nodup ok_inv5

example : mergeBackfill … … = some errChain := merge_split err_split

example : (demoWalk.run (r0, 6)).length ≤ 4 :=
  demoWalk.run_length_le (r0, 6) (by show (2 : Nat) < 6; omega)
```

The invariant predicates were also checked not to be degenerate. A formalisation whose invariants are accidentally `True` proves nothing, so the following are in the repository and machine-checked:

```lean
theorem inv4_rejects_increasing  : ¬ Inv4 [(r0, 3), (r1, 4)]
theorem inv2_rejects_wrong_parent : ¬ Inv2 (fun _ => r3) [(r0, 3), (r1, 4)]
theorem inv5_rejects_wrong_count  : ¬ Inv5 [okB0] okRoots
theorem inv5_rejects_wrong_order  : ¬ Inv5 [okB2, okB1, okB0] okRoots
```

Separately, `Linked R l`, `Inv2 p rs`, `Inv4 rs` and `Inv5 bs rs` were each confirmed *not* provable by `simp` for arbitrary arguments.

## `sorry` audit

**Zero.** Confirmed three ways:

1. `grep -rnE '\bsorry\b|sorryAx|native_decide' TreeSync/` returns nothing.
2. `lake build` from a deleted `.lake/build` succeeds with one warning (an unused match binder in `Walk.run`'s `none` branch — the binder is required by the `some` branch's `decreasing_by`).
3. `#print axioms` was run on **every** theorem and every recursive definition in the library — 75 declarations, generated mechanically from the sources rather than hand-picked. The only axiom sets that appear are `[propext]`, `[propext, Quot.sound]` and `[propext, Classical.choice, Quot.sound]`. `sorryAx` would appear there even if a `sorry` were hidden behind an `import`; `native_decide` would show as `Lean.ofReduceBool`. Neither appears anywhere.

The library contains 74 theorems and 3 `example`s across nine modules.

## What was not attempted, and why

The transition system (`Search`, `OnHeaders`, `Promote`, `OnDownload`, `OnProcess`, `Drop`, `Prune`), `loc` and `chains` as mutable maps, `FC` and `finalized` as monotone external state, and peers as shared mutable state. Invariants 1, 3 and 6 live entirely there. That is a substantially larger exercise — it needs a state-monad or explicit-store encoding and a full inductive-invariant argument over every transition — and the brief scoped it out. The results above are the part that can be settled by structural reasoning alone, and the gaps they expose (3, 5, 6, 7 in particular) are exactly the ones that would otherwise surface as unprovable obligations in the middle of that larger proof.
