import TreeSync.Split

/-!
# `Merge` — the round-trip law and invariant preservation

Theorem 1 of the brief, the spec's unproved assertion

> `Merge(Split(c, r)) = c` for `Backfill`.

plus what `Merge` needs in order to preserve Inv 2 and Inv 4 — which turns out to be
strictly more than its stated guard.
-/

namespace TreeSync

/-! ### Theorem 1 — `merge_split` -/

/-- **`merge_split`** — for a `Backfill` chain, `Merge` inverts `Split` exactly, on the
nose, for every `r` admitted by `Split`'s guard.

Note what carries the proof: `Split`'s guard `r ≠ c.roots[0]` forces the pivot index to be
`≥ 1`, hence `Y.roots` is non-empty and `Y.roots[0] = r`, which is exactly what `Merge`'s
guard `Z.state = Anchored(Y.roots[0])` tests.  The `peers` half of the guard is discharged
because `Split` hands both halves the *same* `c.peers`.

`errors := Y.errors` in `mergeBackfill` is our reading of a field the spec's `Merge` omits;
see `FINDINGS.md` §Gap 1.  With any other reading (e.g. `errors := 0`) this theorem is
false. -/
theorem merge_split {c : BackfillChain} {r : Root} {Y Z : BackfillChain}
    (h : splitBackfill c r = some (Y, Z)) : mergeBackfill Y Z = some c := by
  obtain ⟨i, hidx, rfl, rfl⟩ := splitBackfill_eq h
  have hhead := rootIdx_head? hidx
  unfold mergeBackfill
  cases hd : (List.drop (i + 1) c.roots).head? with
  | none => rw [hd] at hhead; exact absurd hhead (by simp)
  | some e =>
      rw [hd] at hhead
      simp only [Option.map_some', Option.some.injEq] at hhead
      subst hhead
      simp [hd, List.take_append_drop]

/-- The `ForwardSync` analogue, with the repaired `Merge` of `FINDINGS.md` §Gap 2.  The
literal spec `Merge` is refuted in `Counterexamples.lean`. -/
theorem merge_split_forward {c : ForwardChain} {r : Root} {Y Z : ForwardChain}
    (h : splitForward c r = some (Y, Z))
    (hstate : (c.state.restrictTo (c.roots.drop (rootIdxVal r c.roots))).combine
                (c.state.restrictTo (c.roots.take (rootIdxVal r c.roots))) = some c.state) :
    mergeForward Y Z = some c := by
  obtain ⟨i, hidx, rfl, rfl⟩ := splitForward_eq h
  have hval : rootIdxVal r c.roots = i + 1 := by unfold rootIdxVal; rw [hidx]; rfl
  rw [hval] at hstate
  have hhead := rootIdx_head? hidx
  unfold mergeForward
  cases hd : (List.drop (i + 1) c.roots).head? with
  | none => rw [hd] at hhead; exact absurd hhead (by simp)
  | some e =>
      rw [hd] at hhead
      simp only [Option.map_some', Option.some.injEq] at hhead
      subst hhead
      simp [hd, hstate, List.take_append_drop]

/-! ### What `Merge` needs to preserve Inv 2

`Merge`'s guard only checks `Z.state = Anchored(Y.roots[0])`.  Nothing in the spec ties an
`Anchored(p)` to the chain's own roots: Inv 6 only asks `p ∈ FC ∨ p ∈ dom(loc)`.  Inv 2 for
the merged chain needs the link across the seam, i.e. `AnchorSound`. -/
theorem merge_preserves_inv2 (parent : Root → Root) {Y Z c : BackfillChain} {zp : Root}
    (hstate : Z.state = .anchored zp)
    (hsound : AnchorSound parent Z.roots zp)
    (h : mergeBackfill Y Z = some c)
    (hY : Inv2 parent Y.roots) (hZ : Inv2 parent Z.roots) :
    Inv2 parent c.roots := by
  unfold mergeBackfill at h
  cases hd : Y.roots.head? with
  | none => simp [hd] at h
  | some y0 =>
      simp only [hd] at h
      by_cases hg : Z.state = .anchored y0.1 ∧ Y.peers = Z.peers
      · rw [if_pos hg] at h
        have hzp : zp = y0.1 := by
          rw [hstate] at hg
          exact BackfillState.anchored.inj hg.1
        have hc : c.roots = Z.roots ++ Y.roots := by
          injection h with h'; rw [← h']
        rw [hc]
        refine linked_append hZ hY ?_
        intro x hx y hy
        have := hsound x hx
        rw [hzp] at this
        simp only [hd, Option.mem_def, Option.some.injEq] at hy
        subst hy
        exact this
      · rw [if_neg hg] at h; exact absurd h (by simp)

/-! ### Inv 4 is not independent — and that is what `Merge` is missing

`Anchored(p)` records a `Root` and no `Slot`, so `Merge`'s guard cannot possibly express
"the anchor's slot is above `Y`'s tip slot".  Instead of adding a slot to the state, the
right repair is to record the fact the spec leaves implicit: a chain's slots are the slots
*of* its roots, and a block's slot exceeds its parent's.  Under that, Inv 4 is a corollary
of Inv 2 and needs no separate `Merge` guard at all. -/
theorem inv4_of_inv2 (parent : Root → Root) (slotOf : Root → Slot)
    (hmono : ∀ r, slotOf (parent r) < slotOf r) {rs : List Entry}
    (hagree : ∀ e ∈ rs, e.2 = slotOf e.1) (h2 : Inv2 parent rs) : Inv4 rs := by
  refine Linked.imp_mem (fun a ha b hb hab => ?_) h2
  rw [hagree a ha, hagree b hb, ← hab]
  exact hmono a.1

/-- Consequently `Merge` preserves Inv 4 whenever it preserves Inv 2, under the same
slot-agreement hypothesis. -/
theorem merge_preserves_inv4 (parent : Root → Root) (slotOf : Root → Slot)
    (hmono : ∀ r, slotOf (parent r) < slotOf r) {Y Z c : BackfillChain} {zp : Root}
    (hstate : Z.state = .anchored zp)
    (hsound : AnchorSound parent Z.roots zp)
    (h : mergeBackfill Y Z = some c)
    (hagree : ∀ e ∈ c.roots, e.2 = slotOf e.1)
    (hY : Inv2 parent Y.roots) (hZ : Inv2 parent Z.roots) :
    Inv4 c.roots :=
  inv4_of_inv2 parent slotOf hmono hagree
    (merge_preserves_inv2 parent hstate hsound h hY hZ)

end TreeSync
