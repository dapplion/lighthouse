import TreeSync.Invariants

/-!
# `Split` — partition and invariant preservation

Theorems 2 and 3 of the brief:

* `split_partition` — `Y ⊎ Z = c`: concatenating the halves recovers `c.roots`.
* `split_preserves_inv2` / `split_preserves_inv4` — both halves stay contiguous and
  strictly slot-decreasing.

Everything here is unconditional: no side condition beyond `Split`'s own guard is needed.
-/

namespace TreeSync

/-! ### Destructuring a successful `Split` -/

theorem splitBackfill_eq {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) :
    ∃ i, rootIdx r c.roots = some (i + 1) ∧
      Y = { roots := c.roots.drop (i + 1), peers := c.peers, errors := c.errors,
            state := c.state } ∧
      Z = { roots := c.roots.take (i + 1), peers := c.peers, errors := c.errors,
            state := .anchored r } := by
  unfold splitBackfill at h
  cases hh : rootIdx r c.roots with
  | none => rw [hh] at h; exact absurd h (by simp)
  | some n =>
      cases n with
      | zero => rw [hh] at h; exact absurd h (by simp)
      | succ i =>
          rw [hh] at h
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          exact ⟨i, rfl, h.1.symm, h.2.symm⟩

theorem splitForward_eq {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z)) :
    ∃ i, rootIdx r c.roots = some (i + 1) ∧
      Y = { roots := c.roots.drop (i + 1), peers := c.peers, parent := c.parent,
            errors := c.errors, state := c.state.restrictTo (c.roots.drop (i + 1)) } ∧
      Z = { roots := c.roots.take (i + 1), peers := c.peers, parent := r,
            errors := c.errors, state := c.state.restrictTo (c.roots.take (i + 1)) } := by
  unfold splitForward at h
  cases hh : rootIdx r c.roots with
  | none => rw [hh] at h; exact absurd h (by simp)
  | some n =>
      cases n with
      | zero => rw [hh] at h; exact absurd h (by simp)
      | succ i =>
          rw [hh] at h
          simp only [Option.some.injEq, Prod.mk.injEq] at h
          exact ⟨i, rfl, h.1.symm, h.2.symm⟩

/-! ### Theorem 2 — `split_partition` (`Y ⊎ Z = c`) -/

/-- **`split_partition`** — `Split` preserves the root sequence: concatenating the newer
half `Z` (tip side) with the older half `Y` recovers `c.roots` exactly. -/
theorem split_partition {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) : Z.roots ++ Y.roots = c.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitBackfill_eq h
  exact List.take_append_drop (i + 1) c.roots

/-- The same for a `ForwardSync` chain. -/
theorem split_partition_forward {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z)) : Z.roots ++ Y.roots = c.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitForward_eq h
  exact List.take_append_drop (i + 1) c.roots

/-- Both halves are non-empty, and `Y`'s tip is the pivot `r` — the fact the spec writes as
`Z.parent = Y.roots[0]`.  This is exactly where `Split`'s guard is used. -/
theorem split_pivot {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) :
    Y.roots.head?.map Prod.fst = some r ∧ Y.roots ≠ [] ∧ Z.roots ≠ [] := by
  obtain ⟨i, hidx, rfl, rfl⟩ := splitBackfill_eq h
  have hhead := rootIdx_head? hidx
  have hlt := rootIdx_lt hidx
  refine ⟨hhead, ?_, ?_⟩
  · intro hnil
    have hnil' : List.drop (i + 1) c.roots = [] := hnil
    rw [hnil'] at hhead
    simp at hhead
  · intro hnil
    have hnil' : List.take (i + 1) c.roots = [] := hnil
    have hlen : (List.take (i + 1) c.roots).length = 0 := by rw [hnil']; rfl
    rw [List.length_take] at hlen
    omega

/-! ### Theorem 3 — `split_preserves_inv2` and `split_preserves_inv4` -/

/-- **`split_preserves_inv2`** — both halves of a `Split` are still contiguous by
`parent_root`. -/
theorem split_preserves_inv2 (parent : Root → Root) {c : BackfillChain} {r : Root}
    {Y Z : BackfillChain} (h : splitBackfill c r = some (Y, Z)) (hc : Inv2 parent c.roots) :
    Inv2 parent Y.roots ∧ Inv2 parent Z.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitBackfill_eq h
  exact ⟨Linked.drop _ hc, Linked.take _ hc⟩

/-- **`split_preserves_inv4`** — slots still strictly decrease in both halves. -/
theorem split_preserves_inv4 {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) (hc : Inv4 c.roots) :
    Inv4 Y.roots ∧ Inv4 Z.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitBackfill_eq h
  exact ⟨Linked.drop _ hc, Linked.take _ hc⟩

theorem split_preserves_inv2_forward (parent : Root → Root) {c : ForwardChain} {r : Root}
    {Y Z : ForwardChain} (h : splitForward c r = some (Y, Z)) (hc : Inv2 parent c.roots) :
    Inv2 parent Y.roots ∧ Inv2 parent Z.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitForward_eq h
  exact ⟨Linked.drop _ hc, Linked.take _ hc⟩

theorem split_preserves_inv4_forward {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z)) (hc : Inv4 c.roots) :
    Inv4 Y.roots ∧ Inv4 Z.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitForward_eq h
  exact ⟨Linked.drop _ hc, Linked.take _ hc⟩

/-- `Split` also preserves `NoDupRoots`, so the side condition Inv 5 needs is itself stable
under the operation. -/
theorem split_preserves_nodup {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) (hc : NoDupRoots c.roots) :
    NoDupRoots Y.roots ∧ NoDupRoots Z.roots := by
  have hpart := split_partition h
  unfold NoDupRoots rootsOf at *
  rw [← hpart, List.map_append] at hc
  exact ⟨(List.Nodup.sublist (List.sublist_append_right _ _) hc),
         (List.Nodup.sublist (List.sublist_append_left _ _) hc)⟩

/-- `Split` preserves `c.errors` in both halves, as the spec says ("both inherit `c.errors`"). -/
theorem split_errors {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) : Y.errors = c.errors ∧ Z.errors = c.errors := by
  obtain ⟨i, _, rfl, rfl⟩ := splitBackfill_eq h
  exact ⟨rfl, rfl⟩

/-- `Split` gives both halves `c.peers`. -/
theorem split_peers {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) : Y.peers = c.peers ∧ Z.peers = c.peers := by
  obtain ⟨i, _, rfl, rfl⟩ := splitBackfill_eq h
  exact ⟨rfl, rfl⟩

end TreeSync
