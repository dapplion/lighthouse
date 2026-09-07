import TreeSync.Inv5
import TreeSync.Merge
import TreeSync.Discovery

/-!
# Refutations — what the spec asserts that is not true as written

Each theorem here is a machine-checked counterexample.  They are the reason the theorems in
the other files carry side conditions, and they are the substance of `FINDINGS.md`.
-/

namespace TreeSync

def r0 : Root := ⟨0⟩
def r1 : Root := ⟨1⟩
def r2 : Root := ⟨2⟩
def r3 : Root := ⟨3⟩

/-! ## Gap 3 — Inv 2 ∧ Inv 4 do not imply that a chain's roots are distinct

The spec never says `c.roots` is duplicate-free.  Inv 2 (contiguity) and Inv 4 (strictly
decreasing slots) do not give it: a `parent` function may cycle, and distinct slots do not
force distinct roots because nothing in the spec ties a root to a slot. -/

/-- `parent r0 = r1`, `parent r1 = r0` — a two-cycle.  Nothing in the spec forbids it. -/
def cycParent : Root → Root := fun x => if x = r0 then r1 else r0

/-- `[(r0,5), (r1,4), (r0,3)]` — contiguous, strictly slot-decreasing, and `r0` appears twice. -/
def cycRoots : List Entry := [(r0, 5), (r1, 4), (r0, 3)]

theorem cyc_inv2 : Inv2 cycParent cycRoots := ⟨rfl, rfl, trivial⟩

theorem cyc_inv4 : Inv4 cycRoots := ⟨by decide, by decide, trivial⟩

theorem cyc_not_nodup : ¬ NoDupRoots cycRoots := by
  unfold NoDupRoots rootsOf cycRoots
  decide

/-- **Inv 2 and Inv 4 do not imply `NoDupRoots`.**  So `NoDupRoots` really is an extra
assumption, not a consequence of the stated invariants. -/
theorem nodup_not_implied :
    ∃ (p : Root → Root) (rs : List Entry), Inv2 p rs ∧ Inv4 rs ∧ ¬ NoDupRoots rs :=
  ⟨cycParent, cycRoots, cyc_inv2, cyc_inv4, cyc_not_nodup⟩

/-! ## Gap 3, continued — `Split` does not preserve Inv 5 without `NoDupRoots`

`↾` is a filter on "root ∈ this half's roots".  When a root occurs in both halves its block
is copied into *both*, and neither half's block sequence is its roots reversed any more. -/

def cycB1 : Block := ⟨r0, r1, 3⟩
def cycB2 : Block := ⟨r1, r0, 4⟩
def cycB3 : Block := ⟨r0, r1, 5⟩
def cycBlocks : List Block := [cycB1, cycB2, cycB3]

def cycChain : ForwardChain :=
  { roots := cycRoots, peers := [], parent := r2, errors := 0, state := .ready cycBlocks }

/-- `c` itself satisfies Inv 5: three blocks, oldest first, correctly linked. -/
theorem cyc_inv5 : Inv5 cycBlocks cycRoots := ⟨by decide, by decide, by decide, trivial⟩

def cycY : ForwardChain :=
  { roots := [(r1, 4), (r0, 3)], peers := [], parent := r2, errors := 0,
    state := .ready [cycB1, cycB2, cycB3] }

def cycZ : ForwardChain :=
  { roots := [(r0, 5)], peers := [], parent := r1, errors := 0,
    state := .ready [cycB1, cycB3] }

theorem cyc_split : splitForward cycChain r1 = some (cycY, cycZ) := by decide

/-- **`split_preserves_inv5` is false without `NoDupRoots`** — and it fails for *both*
halves at once.  `cycY` is handed all three blocks for its two roots; `cycZ` is handed two
blocks for its one root. -/
theorem split_inv5_fails_without_nodup :
    ¬ Inv5 (restrict cycBlocks cycY.roots) cycY.roots ∧
    ¬ Inv5 (restrict cycBlocks cycZ.roots) cycZ.roots := by
  constructor
  · intro h; exact absurd h.1 (by decide)
  · intro h; exact absurd h.1 (by decide)

/-! ## Gap 2 — the spec's `Merge` is unsound for `ForwardSync`

`Merge` takes `state := Y.state`.  For `Backfill` that is right, because `Split` gives `Y`
the whole of `c.state`.  For `ForwardSync`, `Split` gives `Y` only `c.state↾Y`, so a literal
`Merge` silently discards every block `Z` had already downloaded.  The spec restricts its
round-trip claim to `Backfill`, but it does not say `Merge` must not be applied to a
`ForwardSync` pair — and `Merge` is described as a background compaction. -/

def okB0 : Block := ⟨r0, r3, 3⟩
def okB1 : Block := ⟨r1, r0, 4⟩
def okB2 : Block := ⟨r2, r1, 5⟩
def okBlocks : List Block := [okB0, okB1, okB2]
def okRoots : List Entry := [(r2, 5), (r1, 4), (r0, 3)]

def okChain : ForwardChain :=
  { roots := okRoots, peers := [7], parent := r3, errors := 2, state := .ready okBlocks }

def okY : ForwardChain :=
  { roots := [(r1, 4), (r0, 3)], peers := [7], parent := r3, errors := 2,
    state := .ready [okB0, okB1] }

def okZ : ForwardChain :=
  { roots := [(r2, 5)], peers := [7], parent := r1, errors := 2, state := .ready [okB2] }

theorem ok_split : splitForward okChain r1 = some (okY, okZ) := by decide

/-- **The literal `Merge` does not invert `Split` for a `Ready` `ForwardSync` chain**: it
returns a chain missing `Z`'s block. -/
theorem mergeForwardLiteral_loses_blocks : mergeForwardLiteral okY okZ ≠ some okChain := by
  decide

/-- The repaired `Merge` (concatenating the halves' blocks, older first) does invert it. -/
theorem mergeForward_ok : mergeForward okY okZ = some okChain := by decide

/-! ## Gap 5 — `Merge`'s guard does not preserve Inv 2

`Merge` checks only `Z.state = Anchored(Y.roots[0])`.  Inv 6 asks of an `Anchored(p)` only
that `p ∈ FC ∨ p ∈ dom(loc)`.  Nothing says `p` is the parent of `Z`'s *oldest* root, so
nothing links `Z`'s tail to `Y`'s head, and the concatenation need not be contiguous. -/

/-- `parent r1 = r0`, and everything else maps to `r2`. -/
def badParent : Root → Root := fun x => if x = r1 then r0 else r2

def badY : BackfillChain :=
  { roots := [(r1, 4), (r0, 3)], peers := [], errors := 0, state := .anchored r3 }

/-- `Z` is `Anchored(r1)`, so `Merge`'s guard passes — but `parent r3 = r2 ≠ r1`. -/
def badZ : BackfillChain :=
  { roots := [(r3, 9)], peers := [], errors := 0, state := .anchored r1 }

def badMerged : BackfillChain :=
  { roots := [(r3, 9), (r1, 4), (r0, 3)], peers := [], errors := 0, state := .anchored r3 }

theorem bad_merge : mergeBackfill badY badZ = some badMerged := by decide

theorem bad_inv2_halves : Inv2 badParent badY.roots ∧ Inv2 badParent badZ.roots :=
  ⟨⟨rfl, trivial⟩, trivial⟩

/-- **`Merge` does not preserve Inv 2** under its stated guard. -/
theorem merge_breaks_inv2 : ¬ Inv2 badParent badMerged.roots := by
  intro h
  exact absurd h.1 (by decide)

/-! ## Gap 6 — `Merge`'s guard does not preserve Inv 4 either

`Anchored(p)` records a `Root` and no `Slot`, so the guard cannot even *mention* the anchor's
slot.  Here both halves are strictly slot-decreasing and the guard passes, but the merge is
not. -/

def slotY : BackfillChain :=
  { roots := [(r1, 4), (r0, 3)], peers := [], errors := 0, state := .anchored r3 }

def slotZ : BackfillChain :=
  { roots := [(r3, 2)], peers := [], errors := 0, state := .anchored r1 }

def slotMerged : BackfillChain :=
  { roots := [(r3, 2), (r1, 4), (r0, 3)], peers := [], errors := 0, state := .anchored r3 }

theorem slot_merge : mergeBackfill slotY slotZ = some slotMerged := by decide

theorem slot_inv4_halves : Inv4 slotY.roots ∧ Inv4 slotZ.roots :=
  ⟨⟨by decide, trivial⟩, trivial⟩

/-- **`Merge` does not preserve Inv 4** under its stated guard. -/
theorem merge_breaks_inv4 : ¬ Inv4 slotMerged.roots := by
  intro h
  exact absurd h.1 (by decide)

/-! ## Gap 7 — `Split` breaks Inv 5's fork-choice clause for `Processing`

Inv 5 says `Processing(blocks) ⟹ parent(blocks[0]) ∈ FC`.  `SendProcess` establishes that
via its own guard `c.parent ∈ FC`.  But `Search` may `Split` any chain it finds through
`loc`, including one in `Processing`; the newer half `Z` then has
`parent(Z.blocks[0]) = r`, the pivot, which is a root of `Y` that has not been imported and
is therefore not in `FC`. -/

def fcChain : ForwardChain :=
  { roots := okRoots, peers := [7], parent := r3, errors := 0, state := .processing okBlocks }

def fcY : ForwardChain :=
  { roots := [(r1, 4), (r0, 3)], peers := [7], parent := r3, errors := 0,
    state := .processing [okB0, okB1] }

def fcZ : ForwardChain :=
  { roots := [(r2, 5)], peers := [7], parent := r1, errors := 0,
    state := .processing [okB2] }

theorem fc_split : splitForward fcChain r1 = some (fcY, fcZ) := by decide

/-- Fork choice holds exactly the chain's anchor `r3` — nothing of this chain is imported. -/
def FCr3 : Root → Prop := fun x => x = r3

theorem fc_before : Inv5FC FCr3 okBlocks := by
  intro b hb
  simp only [okBlocks, List.head?_cons, Option.mem_def, Option.some.injEq] at hb
  subst hb
  rfl

/-- **`Split` does not preserve Inv 5's `Processing ⟹ parent(blocks[0]) ∈ FC` clause.**
`Split` is a pure operation on chains: it does not change `FC`, so this is a genuine gap in
the invariant as stated, not merely a transient of some larger step. -/
theorem split_breaks_inv5_fc : ¬ Inv5FC FCr3 [okB2] := by
  intro h
  have hfc : okB2.parentRoot = r3 := h okB2 rfl
  exact absurd hfc (by decide)

/-! ## Gap 1 — `Merge` must inherit `Y.errors`

The spec's `Merge` record omits `errors`, which `Chain` requires.  Any reading other than
`errors := Y.errors` (equivalently `Z.errors`, which `Split` makes equal) breaks the
round trip. -/

/-- `Merge` with the retry budget reset, the other obvious reading. -/
def mergeBackfillResetErrors (Y Z : BackfillChain) : Option BackfillChain :=
  match Y.roots.head? with
  | none => none
  | some y0 =>
      if Z.state = .anchored y0.1 ∧ Y.peers = Z.peers then
        some { roots := Z.roots ++ Y.roots, peers := Y.peers, errors := 0, state := Y.state }
      else none

def errChain : BackfillChain :=
  { roots := [(r2, 5), (r1, 4), (r0, 3)], peers := [], errors := 3, state := .anchored r3 }

theorem err_split :
    splitBackfill errChain r1 =
      some ({ roots := [(r1, 4), (r0, 3)], peers := [], errors := 3, state := .anchored r3 },
            { roots := [(r2, 5)], peers := [], errors := 3, state := .anchored r1 }) := by
  decide

theorem merge_split_needs_errors :
    mergeBackfillResetErrors
        { roots := [(r1, 4), (r0, 3)], peers := [], errors := 3, state := .anchored r3 }
        { roots := [(r2, 5)], peers := [], errors := 3, state := .anchored r1 }
      ≠ some errChain := by
  decide

/-! ## Gap 8 — `Merge`'s `peers` guard is not set equality

`peers` is a `Set<Peer>` in the spec but the guard `Y.peers = Z.peers` has to be decided on
a representation.  Read as list equality it is over-strict: two halves with the same peer
*set* in a different order are refused. -/

def permY : BackfillChain :=
  { roots := [(r1, 4), (r0, 3)], peers := [7, 8], errors := 0, state := .anchored r3 }

def permZ : BackfillChain :=
  { roots := [(r2, 5)], peers := [8, 7], errors := 0, state := .anchored r1 }

theorem merge_guard_order_sensitive : mergeBackfill permY permZ = none := by decide

/-! ## Gap 4 — `Merge`'s guard is undefined when `Y.roots` is empty

`Search` creates `Backfill{roots: [], …}`, so empty-`roots` chains exist, and `Y.roots[0]`
in `Merge`'s guard has no value for them.  We read the guard as failing. -/

def emptyY : BackfillChain :=
  { roots := [], peers := [], errors := 0, state := .discovering r0 }

theorem merge_empty_y : mergeBackfill emptyY badZ = none := by decide

/-! ## Sanity — the invariants are not degenerate

A formalisation whose invariants are accidentally `True` proves nothing.  These say the
predicates really do reject the things they are meant to reject. -/

theorem inv4_rejects_increasing : ¬ Inv4 [(r0, 3), (r1, 4)] := by
  intro h; exact absurd h.1 (by decide)

theorem inv2_rejects_wrong_parent : ¬ Inv2 (fun _ => r3) [(r0, 3), (r1, 4)] := by
  intro h; exact absurd h.1 (by decide)

theorem inv5_rejects_wrong_count : ¬ Inv5 [okB0] okRoots := by
  intro h; exact absurd h.1 (by decide)

theorem inv5_rejects_wrong_order : ¬ Inv5 [okB2, okB1, okB0] okRoots := by
  intro h; exact absurd h.1 (by decide)

/-! ## Sanity — the positive theorems are not vacuous

`okChain` satisfies every side condition, and the general theorems fire on it. -/

theorem ok_nodup : NoDupRoots okRoots := by
  unfold NoDupRoots rootsOf okRoots
  decide

theorem ok_inv5 : Inv5 okBlocks okRoots := ⟨by decide, by decide, by decide, trivial⟩

example : Inv5 (restrict okBlocks okY.roots) okY.roots ∧
          Inv5 (restrict okBlocks okZ.roots) okZ.roots :=
  split_preserves_inv5 ok_split ok_nodup ok_inv5

/-- `merge_split` instantiated at a concrete `Backfill` chain with a non-zero retry budget. -/
example :
    mergeBackfill
      { roots := [(r1, 4), (r0, 3)], peers := [], errors := 3, state := .anchored r3 }
      { roots := [(r2, 5)], peers := [], errors := 3, state := .anchored r1 }
      = some errChain :=
  merge_split err_split

/-- A concrete header walk: step back one slot at a time, stopping at slot 3 with the
finalized floor at slot 2. -/
def demoWalk : Walk where
  finalizedSlot := 2
  step := fun e => if 3 < e.2 then some (⟨e.1.id + 1⟩, e.2 - 1) else none
  decreasing := by
    intro e e' h
    dsimp only at h
    by_cases hc : 3 < e.2
    · rw [if_pos hc] at h
      injection h with h'
      subst h'
      show e.2 - 1 < e.2
      omega
    · rw [if_neg hc] at h
      exact absurd h (by simp)
  aboveFloor := by
    intro e e' h
    dsimp only at h
    by_cases hc : 3 < e.2
    · rw [if_pos hc] at h
      injection h with h'
      subst h'
      show 2 < e.2 - 1
      omega
    · rw [if_neg hc] at h
      exact absurd h (by simp)

/-- `discovery_terminates` instantiated: from slot 6 the walk records at most 4 roots. -/
example : (demoWalk.run (r0, 6)).length ≤ 4 :=
  demoWalk.run_length_le (r0, 6) (by show (2 : Nat) < 6; omega)

end TreeSync
