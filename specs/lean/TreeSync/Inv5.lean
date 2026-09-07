import TreeSync.Split
import TreeSync.Merge

/-!
# `Split` and Invariant 5 — where `roots` and `blocks` meet through a reversal

Theorem 4 of the brief.  The spec says of Inv 5:

> `roots` is tip first and `blocks` is import order, so the reversal is where they meet.

Concretely: `c.roots = Z.roots ++ Y.roots` (newer half first), so
`blocks = reverse(c.roots) = reverse(Y.roots) ++ reverse(Z.roots)` — the *older* half's
blocks come first.  `Split`'s restriction `↾` is a `filter`, and the content of this file is
that the filter cuts `blocks` at exactly `|Y.roots|`, so each half's blocks are a
contiguous slice and Inv 5 follows from the `take`/`drop` closure of `Linked`.

**This needs a side condition the spec does not state**: the roots of a chain must be
pairwise distinct (`NoDupRoots`).  Without it the filter is not a cut at all — a root
appearing in both halves sends its block to *both*, and Inv 5 fails for both halves.  See
`Counterexamples.lean` and `FINDINGS.md` §Gap 3.
-/

namespace TreeSync

theorem restrict_of_append {bs : List Block} {A B : List Entry}
    (hmap : bs.map Block.root = (rootsOf (A ++ B)).reverse)
    (hnodup : (rootsOf (A ++ B)).Nodup) :
    restrict bs B = bs.take B.length ∧ restrict bs A = bs.drop B.length := by
  have hrootsAB : rootsOf (A ++ B) = rootsOf A ++ rootsOf B := List.map_append _ _ _
  have hlenB : (rootsOf B).reverse.length = B.length := by simp [rootsOf]
  -- `bs` in root form, cut into the `B` part and the `A` part
  have hmap' : bs.map Block.root = (rootsOf B).reverse ++ (rootsOf A).reverse := by
    rw [hmap, hrootsAB, List.reverse_append]
  have hB : (bs.take B.length).map Block.root = (rootsOf B).reverse := by
    rw [List.map_take, hmap', ← hlenB, take_length_append]
  have hA : (bs.drop B.length).map Block.root = (rootsOf A).reverse := by
    rw [List.map_drop, hmap', ← hlenB, drop_length_append]
  -- membership consequences
  have hmemB : ∀ b ∈ bs.take B.length, b.root ∈ rootsOf B := by
    intro b hb
    have : b.root ∈ (bs.take B.length).map Block.root := List.mem_map_of_mem _ hb
    rw [hB] at this
    simpa using this
  have hmemA : ∀ b ∈ bs.drop B.length, b.root ∈ rootsOf A := by
    intro b hb
    have : b.root ∈ (bs.drop B.length).map Block.root := List.mem_map_of_mem _ hb
    rw [hA] at this
    simpa using this
  -- the two halves' root sets are disjoint, which is exactly where `Nodup` is used
  rw [hrootsAB] at hnodup
  have hdisj : ∀ x ∈ rootsOf A, x ∉ rootsOf B := notMem_right_of_nodup_append hnodup
  have hsplit : bs.take B.length ++ bs.drop B.length = bs := List.take_append_drop _ _
  refine ⟨?_, ?_⟩
  · have key : List.filter (fun b => decide (b.root ∈ rootsOf B))
        (bs.take B.length ++ bs.drop B.length) = bs.take B.length := by
      rw [List.filter_append,
        List.filter_eq_self.mpr (by intro b hb; simpa using hmemB b hb),
        List.filter_eq_nil_iff.mpr (by
          intro b hb
          simp only [Bool.not_eq_true, decide_eq_false_iff_not]
          exact hdisj b.root (hmemA b hb))]
      simp
    rw [hsplit] at key
    exact key
  · have key : List.filter (fun b => decide (b.root ∈ rootsOf A))
        (bs.take B.length ++ bs.drop B.length) = bs.drop B.length := by
      rw [List.filter_append,
        List.filter_eq_nil_iff.mpr (by
          intro b hb
          simp only [Bool.not_eq_true, decide_eq_false_iff_not]
          intro hmem
          exact hdisj b.root hmem (hmemB b hb)),
        List.filter_eq_self.mpr (by intro b hb; simpa using hmemA b hb)]
      simp
    rw [hsplit] at key
    exact key

/-- The restriction of a block sequence to the two halves of a `Split` is a *cut*: the older
half `Y` gets the first `|Y.roots|` blocks, the newer half `Z` gets the rest. -/
theorem restrict_of_split {bs : List Block} {rs : List Entry} (i : Nat)
    (hmap : bs.map Block.root = (rootsOf rs).reverse) (hnodup : NoDupRoots rs) :
    restrict bs (rs.drop i) = bs.take (rs.drop i).length ∧
    restrict bs (rs.take i) = bs.drop (rs.drop i).length := by
  have hAB : rs.take i ++ rs.drop i = rs := List.take_append_drop i rs
  exact restrict_of_append (A := rs.take i) (B := rs.drop i) (by rw [hAB]; exact hmap)
    (by rw [hAB]; exact hnodup)

/-! ### Theorem 4 — `split_preserves_inv5` -/

/-- **`split_preserves_inv5`** — the `↾` of a `Ready`/`Processing` block sequence to each
half of a `Split` satisfies Inv 5, given `c` does and given `NoDupRoots c.roots`. -/
theorem split_preserves_inv5 {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    {bs : List Block}
    (h : splitForward c r = some (Y, Z))
    (hnodup : NoDupRoots c.roots)
    (hinv : Inv5 bs c.roots) :
    Inv5 (restrict bs Y.roots) Y.roots ∧ Inv5 (restrict bs Z.roots) Z.roots := by
  obtain ⟨i, _, rfl, rfl⟩ := splitForward_eq h
  obtain ⟨hmap, hlink⟩ := hinv
  obtain ⟨hY, hZ⟩ := restrict_of_split (bs := bs) (rs := c.roots) (i + 1) hmap hnodup
  show Inv5 (restrict bs (c.roots.drop (i+1))) (c.roots.drop (i+1)) ∧
       Inv5 (restrict bs (c.roots.take (i+1))) (c.roots.take (i+1))
  refine ⟨⟨?_, ?_⟩, ⟨?_, ?_⟩⟩
  · rw [hY, List.map_take, hmap]
    have : (c.roots.drop (i+1)).length = (rootsOf (c.roots.drop (i+1))).reverse.length := by
      simp [rootsOf]
    rw [this]
    have hrw : (rootsOf c.roots).reverse
        = (rootsOf (c.roots.drop (i+1))).reverse ++ (rootsOf (c.roots.take (i+1))).reverse := by
      have base : (rootsOf (c.roots.take (i+1) ++ c.roots.drop (i+1))).reverse
          = (rootsOf (c.roots.drop (i+1))).reverse ++ (rootsOf (c.roots.take (i+1))).reverse := by
        rw [show rootsOf (c.roots.take (i+1) ++ c.roots.drop (i+1))
              = rootsOf (c.roots.take (i+1)) ++ rootsOf (c.roots.drop (i+1)) from
            List.map_append _ _ _, List.reverse_append]
      rw [List.take_append_drop] at base
      exact base
    rw [hrw, take_length_append]
  · rw [hY]; exact Linked.take _ hlink
  · rw [hZ, List.map_drop, hmap]
    have : (c.roots.drop (i+1)).length = (rootsOf (c.roots.drop (i+1))).reverse.length := by
      simp [rootsOf]
    rw [this]
    have hrw : (rootsOf c.roots).reverse
        = (rootsOf (c.roots.drop (i+1))).reverse ++ (rootsOf (c.roots.take (i+1))).reverse := by
      have base : (rootsOf (c.roots.take (i+1) ++ c.roots.drop (i+1))).reverse
          = (rootsOf (c.roots.drop (i+1))).reverse ++ (rootsOf (c.roots.take (i+1))).reverse := by
        rw [show rootsOf (c.roots.take (i+1) ++ c.roots.drop (i+1))
              = rootsOf (c.roots.take (i+1)) ++ rootsOf (c.roots.drop (i+1)) from
            List.map_append _ _ _, List.reverse_append]
      rw [List.take_append_drop] at base
      exact base
    rw [hrw, drop_length_append]
  · rw [hZ]; exact Linked.drop _ hlink

/-- Packaged for the actual `Split` of a `Ready` chain: `c.state↾Y` and `c.state↾Z` both
satisfy Inv 5. -/
theorem split_preserves_inv5_state {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z))
    (hnodup : NoDupRoots c.roots)
    (hinv : c.state.Inv5 c.roots) :
    Y.state.Inv5 Y.roots ∧ Z.state.Inv5 Z.roots := by
  have hpart := splitForward_eq h
  obtain ⟨i, _, hy, hz⟩ := hpart
  cases hst : c.state with
  | downloading =>
      subst hy; subst hz
      simp [SyncState.Inv5, SyncState.restrictTo, hst]
  | ready bs =>
      rw [hst] at hinv
      have := split_preserves_inv5 (bs := bs) h hnodup hinv
      subst hy; subst hz
      simpa [SyncState.Inv5, SyncState.restrictTo, hst] using this
  | processing bs =>
      rw [hst] at hinv
      have := split_preserves_inv5 (bs := bs) h hnodup hinv
      subst hy; subst hz
      simpa [SyncState.Inv5, SyncState.restrictTo, hst] using this

/-! ### Consequence: the `ForwardSync` round trip needs no extra state hypothesis

`restrict`ing a state to the two halves and recombining is the identity, so the repaired
`Merge` of `FINDINGS.md` §Gap 2 inverts `Split` for `ForwardSync` chains too — under the
same `NoDupRoots` side condition, and nothing else. -/

theorem state_restrict_combine {st : SyncState} {rs : List Entry} (i : Nat)
    (hnodup : NoDupRoots rs) (hinv : st.Inv5 rs) :
    (st.restrictTo (rs.drop i)).combine (st.restrictTo (rs.take i)) = some st := by
  cases st with
  | downloading => rfl
  | ready bs =>
      obtain ⟨hmap, _⟩ := hinv
      obtain ⟨hY, hZ⟩ := restrict_of_split i hmap hnodup
      simp only [SyncState.restrictTo, SyncState.combine, hY, hZ, List.take_append_drop]
  | processing bs =>
      obtain ⟨hmap, _⟩ := hinv
      obtain ⟨hY, hZ⟩ := restrict_of_split i hmap hnodup
      simp only [SyncState.restrictTo, SyncState.combine, hY, hZ, List.take_append_drop]

/-- **`merge_split` for `ForwardSync`** — the repaired `Merge` inverts `Split` on the nose,
assuming only `NoDupRoots` and Inv 5. -/
theorem merge_split_forward_of_inv5 {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z))
    (hnodup : NoDupRoots c.roots) (hinv : c.state.Inv5 c.roots) :
    mergeForward Y Z = some c :=
  merge_split_forward h (state_restrict_combine (rootIdxVal r c.roots) hnodup hinv)

end TreeSync
