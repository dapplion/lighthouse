import TreeSync.Basic

/-!
# The `Split` and `Merge` operations

Transcribed from the Operations block of `specs/tree-sync.md`:

```
Split(c, r) = (Y, Z)      guard r ∈ c.roots ∧ r ≠ c.roots[0]
  c.roots = [tip … r⁺] ++ [r … oldest]
  Z = { roots: [tip … r⁺],   peers: c.peers }      -- Z.parent = Y.roots[0]
  Y = { roots: [r … oldest], peers: c.peers }      -- Y.parent = c.parent

  Backfill      Y.state := c.state     Z.state := Anchored(r)
  ForwardSync   Y.state := c.state↾Y   Z.state := c.state↾Z
  both inherit c.errors

  x↾c = x with its blocks restricted to those whose root ∈ c.roots

Merge(Y, Z) = c           guard Z.state = Anchored(Y.roots[0]) ∧ Y.peers = Z.peers
  c = { roots: Z.roots ++ Y.roots, peers: Y.peers, state: Y.state }
```

`Y` is the **older** half (it keeps `c`'s state, parent and any in-flight call — matching
`ForwardSync::split` in the Rust, where the older half keeps `chain_id`); `Z` is the newer.

## Recorded choices where the spec is silent

1. **`Merge` does not say what `errors` becomes.**  `Chain` requires an `errors : Nat`, and
   `Split` says "both inherit `c.errors`", so a `Merge` that is to invert `Split` must take
   `errors := Y.errors`.  We adopt that.  See `FINDINGS.md` §Spec gap 1.
2. **`Merge` does not say what `ForwardSync.parent` becomes.**  We take `parent := Y.parent`,
   which is what inverts `Split` (`Y.parent = c.parent`).
3. `r ∈ c.roots` is resolved to the *first* index at which `r` occurs, matching the Rust's
   `position`.  Under the extra `Nodup` side condition of `FINDINGS.md` §Spec gap 3 the
   choice is irrelevant.
-/

namespace TreeSync

/-- Index of the first entry whose root is `r`.  Mirrors `Vec::position` in the Rust. -/
def rootIdx (r : Root) : List Entry → Option Nat
  | [] => none
  | p :: t => if p.1 = r then some 0 else (rootIdx r t).map (· + 1)

theorem rootIdx_lt : ∀ {rs : List Entry} {r : Root} {i : Nat}, rootIdx r rs = some i → i < rs.length
  | [], _, _, h => by simp [rootIdx] at h
  | p :: t, r, i, h => by
      by_cases hp : p.1 = r
      · simp [rootIdx, hp] at h ⊢; omega
      · simp [rootIdx, hp] at h
        obtain ⟨j, hj, rfl⟩ := h
        have := rootIdx_lt (rs := t) hj
        simpa using Nat.succ_lt_succ this

/-- The entry at the found index really has root `r`: `(rs.drop i).head?` is `(r, _)`. -/
theorem rootIdx_head? : ∀ {rs : List Entry} {r : Root} {i : Nat}, rootIdx r rs = some i →
    ((rs.drop i).head?).map Prod.fst = some r
  | [], _, _, h => by simp [rootIdx] at h
  | p :: t, r, i, h => by
      by_cases hp : p.1 = r
      · simp [rootIdx, hp] at h; subst h; simp [hp]
      · simp [rootIdx, hp] at h
        obtain ⟨j, hj, rfl⟩ := h
        simpa using rootIdx_head? (rs := t) hj

/-- The index as a plain `Nat`, for stating `Split`'s ForwardSync round trip. -/
def rootIdxVal (r : Root) (rs : List Entry) : Nat := (rootIdx r rs).getD 0

/-! ### `↾` — restriction of a block sequence to the roots of a half -/

/-- `x↾c` — keep the blocks whose root is one of `rs`.  Order preserving, like the Rust's
`Iterator::partition`. -/
def restrict (bs : List Block) (rs : List Entry) : List Block :=
  bs.filter (fun b => decide (b.root ∈ rootsOf rs))

/-- `c.state↾half` for a `ForwardSync` state. -/
def SyncState.restrictTo : SyncState → List Entry → SyncState
  | .downloading, _ => .downloading
  | .ready bs, rs => .ready (restrict bs rs)
  | .processing bs, rs => .processing (restrict bs rs)

/-! ### `Split` -/

/-- `Split(c, r)` for a `Backfill` chain.  `none` when the guard `r ∈ c.roots ∧ r ≠ c.roots[0]`
fails.  Returns `(Y, Z)` = (older, newer). -/
def splitBackfill (c : BackfillChain) (r : Root) : Option (BackfillChain × BackfillChain) :=
  match rootIdx r c.roots with
  | none => none          -- r ∉ c.roots
  | some 0 => none        -- r = c.roots[0]
  | some (i + 1) =>
      some
        ( { roots := c.roots.drop (i + 1), peers := c.peers, errors := c.errors,
            state := c.state }                                          -- Y, the older half
        , { roots := c.roots.take (i + 1), peers := c.peers, errors := c.errors,
            state := .anchored r } )                                    -- Z, the newer half

/-- `Split(c, r)` for a `ForwardSync` chain. -/
def splitForward (c : ForwardChain) (r : Root) : Option (ForwardChain × ForwardChain) :=
  match rootIdx r c.roots with
  | none => none
  | some 0 => none
  | some (i + 1) =>
      let yRoots := c.roots.drop (i + 1)
      let zRoots := c.roots.take (i + 1)
      some
        ( { roots := yRoots, peers := c.peers, parent := c.parent, errors := c.errors,
            state := c.state.restrictTo yRoots }
        , { roots := zRoots, peers := c.peers, parent := r, errors := c.errors,
            state := c.state.restrictTo zRoots } )

def Chain.split : Chain → Root → Option (Chain × Chain)
  | .backfill c, r => (splitBackfill c r).map (fun p => (.backfill p.1, .backfill p.2))
  | .forward c, r => (splitForward c r).map (fun p => (.forward p.1, .forward p.2))

/-! ### `Merge` -/

/-- `Merge(Y, Z)` for `Backfill`, exactly as written in the spec (plus the `errors` choice). -/
def mergeBackfill (Y Z : BackfillChain) : Option BackfillChain :=
  match Y.roots.head? with
  | none => none    -- `Y.roots[0]` does not exist; see FINDINGS §Spec gap 4
  | some y0 =>
      if Z.state = .anchored y0.1 ∧ Y.peers = Z.peers then
        some { roots := Z.roots ++ Y.roots, peers := Y.peers, errors := Y.errors,
               state := Y.state }
      else none

/-- `Merge(Y, Z)` for `ForwardSync`, read *literally*: `state := Y.state`.  The `Anchored`
guard has no `ForwardSync` counterpart, so we use the corresponding `Z.parent = Y.roots[0]`.
This is refuted in `Counterexamples.lean`: it silently drops `Z`'s downloaded blocks. -/
def mergeForwardLiteral (Y Z : ForwardChain) : Option ForwardChain :=
  match Y.roots.head? with
  | none => none
  | some y0 =>
      if Z.parent = y0.1 ∧ Y.peers = Z.peers then
        some { roots := Z.roots ++ Y.roots, peers := Y.peers, parent := Y.parent,
               errors := Y.errors, state := Y.state }
      else none

/-- Recombining two halves' block sequences.  `blocks` is oldest-first, `Y` is the older
half, so `Y`'s blocks come first — this is the reversal of the `roots` order. -/
def SyncState.combine : SyncState → SyncState → Option SyncState
  | .downloading, .downloading => some .downloading
  | .ready ys, .ready zs => some (.ready (ys ++ zs))
  | .processing ys, .processing zs => some (.processing (ys ++ zs))
  | _, _ => none

/-- The repaired `ForwardSync` merge.  See `FINDINGS.md` §Spec gap 2. -/
def mergeForward (Y Z : ForwardChain) : Option ForwardChain :=
  match Y.roots.head?, Y.state.combine Z.state with
  | none, _ => none
  | _, none => none
  | some y0, some st =>
      if Z.parent = y0.1 ∧ Y.peers = Z.peers then
        some { roots := Z.roots ++ Y.roots, peers := Y.peers, parent := Y.parent,
               errors := Y.errors, state := st }
      else none

end TreeSync
