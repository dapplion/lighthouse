import TreeSync.Invariants

/-!
# Discovery terminates

Theorem 5 of the brief.  The spec's Liveness section claims

> Discovery terminates: `slot` strictly decreases (Inv 4), bounded below by
> `slot(finalized)`.

`SendHeaders` guarantees `h[i].root = h[i−1].parent_root ∧ h[i].slot < h[i−1].slot`, and
`OnHeaders` drops the chain the moment a header has `slot ≤ slot(finalized)`.  A `Walk`
below bundles exactly those two guarantees; `Walk.run` is the header walk, defined by
**well-founded recursion on `slot − slot(finalized)`**.  Lean accepting that definition *is*
the termination proof; `run_length_le` turns it into a concrete step bound.

Note which hypothesis does the work.  `decreasing` alone is *not* enough: `Slot = Nat` is
well founded, but the measure `e.2 - finalizedSlot` only decreases while the walk stays
above the floor, and it is `aboveFloor` — the `header.slot ≤ slot(finalized)` guard in
`OnHeaders` — that supplies it.  A spec with the strict-decrease guarantee but no floor
guard would still terminate over `Nat`; over an unbounded slot type it would not.
-/

namespace TreeSync

/-- The header walk's contract, as guaranteed by `SendHeaders`/`OnHeaders`. -/
structure Walk where
  /-- `slot(finalized)`; external and monotone, so fixed for the duration of one walk. -/
  finalizedSlot : Slot
  /-- The next `(root, slot)` the walk consumes, or `none` once it resolves
      (`p ∈ FC`, or `loc(p)` defined — the two `halt` cases of `OnHeaders`). -/
  step : Entry → Option Entry
  /-- `SendHeaders`' guarantee `h[i].slot < h[i−1].slot`. -/
  decreasing : ∀ e e', step e = some e' → e'.2 < e.2
  /-- `OnHeaders`' floor guard: a header at or below `slot(finalized)` is never pushed
      (the chain is dropped and the peers reported), so every consumed header is above it. -/
  aboveFloor : ∀ e e', step e = some e' → finalizedSlot < e'.2

/-- **`discovery_terminates`** — the header walk, as a total function.

`roots` comes out tip first, exactly the order the spec's `roots` is kept in.  The
`termination_by`/`decreasing_by` block below *is* the termination argument: the measure is
`slot − slot(finalized)` and it strictly decreases at every step. -/
def Walk.run (w : Walk) (e : Entry) : List Entry :=
  match hs : w.step e with
  | none => [e]
  | some e' => e :: w.run e'
termination_by e.2 - w.finalizedSlot
decreasing_by
  have h1 := w.decreasing e e' hs
  have h2 := w.aboveFloor e e' hs
  omega

/-! ### Unfolding lemmas for `Walk.run` -/

theorem Walk.run_none {w : Walk} {e : Entry} (h : w.step e = none) : w.run e = [e] := by
  rw [Walk.run, h]

theorem Walk.run_some {w : Walk} {e e' : Entry} (h : w.step e = some e') :
    w.run e = e :: w.run e' := by
  rw [Walk.run, h]

/-- The walk always records at least its seed, so it is a `cons`. -/
theorem Walk.run_cons (w : Walk) (e : Entry) : ∃ t, w.run e = e :: t := by
  cases hr : w.step e with
  | none => exact ⟨[], Walk.run_none hr⟩
  | some e' => exact ⟨w.run e', Walk.run_some hr⟩

/-- Every root the walk records lies strictly above `slot(finalized)`, given the seed does. -/
theorem Walk.run_above_floor (w : Walk) (e : Entry) (h : w.finalizedSlot < e.2) :
    ∀ p ∈ w.run e, w.finalizedSlot < p.2 := by
  induction e using Walk.run.induct (w := w) with
  | case1 e hs =>
      intro p hp
      rw [Walk.run_none hs] at hp
      simp only [List.mem_singleton] at hp
      subst hp
      exact h
  | case2 e e' hs ih =>
      intro p hp
      rw [Walk.run_some hs] at hp
      rcases List.mem_cons.1 hp with rfl | hp'
      · exact h
      · exact ih (w.aboveFloor e e' hs) p hp'

/-- **`discovery_terminates`, quantitative form** — the walk visits at most
`slot(seed) − slot(finalized)` roots.  This is the spec's "bounded below by
`slot(finalized)`" made into a number. -/
theorem Walk.run_length_le (w : Walk) (e : Entry) (h : w.finalizedSlot < e.2) :
    (w.run e).length ≤ e.2 - w.finalizedSlot := by
  induction e using Walk.run.induct (w := w) with
  | case1 e hs => rw [Walk.run_none hs]; simp only [List.length_singleton]; omega
  | case2 e e' hs ih =>
      have h1 := w.decreasing e e' hs
      have h2 := w.aboveFloor e e' hs
      have hih := ih h2
      rw [Walk.run_some hs]
      simp only [List.length_cons]
      omega

/-- The walk establishes Inv 4 on the roots it produces: slots strictly decrease, tip first. -/
theorem Walk.run_inv4 (w : Walk) (e : Entry) : Inv4 (w.run e) := by
  induction e using Walk.run.induct (w := w) with
  | case1 e hs => rw [Walk.run_none hs]; trivial
  | case2 e e' hs ih =>
      rw [Walk.run_some hs]
      cases hr : w.step e' with
      | none =>
          rw [Walk.run_none hr] at ih ⊢
          exact ⟨w.decreasing e e' hs, ih⟩
      | some e'' =>
          rw [Walk.run_some hr] at ih ⊢
          exact ⟨w.decreasing e e' hs, ih⟩

/-- If the walk also follows `parent_root` links — the other half of `SendHeaders`'
guarantee, `h[i].root = h[i−1].parent_root` — then it establishes Inv 2 as well.  So the
header walk is what *creates* Inv 2, and `Split` (proved elsewhere) is what preserves it. -/
theorem Walk.run_inv2 (w : Walk) (parent : Root → Root)
    (hpar : ∀ e e', w.step e = some e' → parent e.1 = e'.1) (e : Entry) :
    Inv2 parent (w.run e) := by
  induction e using Walk.run.induct (w := w) with
  | case1 e hs => rw [Walk.run_none hs]; trivial
  | case2 e e' hs ih =>
      rw [Walk.run_some hs]
      cases hr : w.step e' with
      | none =>
          rw [Walk.run_none hr] at ih ⊢
          exact ⟨hpar e e' hs, ih⟩
      | some e'' =>
          rw [Walk.run_some hr] at ih ⊢
          exact ⟨hpar e e' hs, ih⟩

/-! ### What the finalized floor is really for

Over `Nat` slots, strict decrease *alone* is well founded, so the walk terminates without
any floor.  `WalkNoFloor` below machine-checks that.  What `slot(finalized)` buys is the
quantitative bound (`run_length_le`) and a cap on how far a hostile peer can drive the
walk — not termination itself.  The spec's Liveness bullet attributes termination to the
floor; that is a (harmless) over-attribution. -/

structure WalkNoFloor where
  step : Entry → Option Entry
  decreasing : ∀ e e', step e = some e' → e'.2 < e.2

def WalkNoFloor.run (w : WalkNoFloor) (e : Entry) : List Entry :=
  match hs : w.step e with
  | none => [e]
  | some e' => e :: w.run e'
termination_by e.2
decreasing_by exact w.decreasing e e' hs

end TreeSync
