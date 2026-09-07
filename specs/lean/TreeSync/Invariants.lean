import TreeSync.Ops

/-!
# The structural invariants

From the Invariants block of `specs/tree-sync.md`.  We formalise the *structural* ones —
2, 4 and 5 — which are the ones that talk about the shape of `roots` and `blocks` alone.
Invariants 1, 3 and 6 quantify over `loc`, `FC` and peer claims, i.e. over the transition
system, which is out of scope here; 5's `FC` clause is stated with `FC` abstract.

All three are instances of `Linked` (see `TreeSync/List.lean`), which is why `Split`
preserves all of them by the same two lemmas.
-/

namespace TreeSync

variable (parent : Root → Root)

/-- **Inv 2** — `c.roots` contiguous by `parent_root`, tip first.

`roots` is newest-first, so the *next* entry is the parent of the current one. -/
def Inv2 (rs : List Entry) : Prop :=
  Linked (fun a b => parent a.1 = b.1) rs

/-- **Inv 4** — `slot` strictly decreases along `c.roots`. -/
def Inv4 (rs : List Entry) : Prop :=
  Linked (fun a b => b.2 < a.2) rs

/-- Invariant 5's linkage clause: `∀ i > 0. parent (blocks[i]) = blocks[i-1]`.
`blocks` is import order (oldest first), so each block's parent is its *predecessor*. -/
def BlocksLinked (bs : List Block) : Prop :=
  Linked (fun a b => b.parentRoot = a.root) bs

/-- **Inv 5** (structural part) — `blocks` is `c.roots` reversed, oldest first, one block
per root, and consecutively linked by `parentRoot`. -/
def Inv5 (bs : List Block) (rs : List Entry) : Prop :=
  bs.map Block.root = (rootsOf rs).reverse ∧ BlocksLinked bs

/-- **Inv 5**'s fork-choice clause, kept separate because it mentions external state:
`Processing(blocks) ⟹ parent(blocks[0]) ∈ FC`.  `FC` is an abstract predicate. -/
def Inv5FC (FC : Root → Prop) (bs : List Block) : Prop :=
  ∀ b ∈ bs.head?, FC b.parentRoot

/-- Inv 5 for a whole `ForwardSync` state. -/
def SyncState.Inv5 : SyncState → List Entry → Prop
  | .downloading, _ => True
  | .ready bs, rs => TreeSync.Inv5 bs rs
  | .processing bs, rs => TreeSync.Inv5 bs rs

/-! ### Side conditions the spec omits

`Inv2 ∧ Inv4` do **not** imply that the roots of a chain are pairwise distinct: the entry
list `[(a,5), (b,4), (a,3)]` is contiguous for `parent a = b`, `parent b = a`, and its slots
strictly decrease.  `NoDupRoots` is what the Inv 5 proofs actually need; see `FINDINGS.md`
§Gap 3 and the refutation in `Counterexamples.lean`. -/
def NoDupRoots (rs : List Entry) : Prop := (rootsOf rs).Nodup

/-- The anchor soundness condition the spec never states: `Anchored(p)` (and
`ForwardSync.parent`) must name the parent of the chain's *oldest* root, otherwise `Merge`
does not preserve Inv 2.  See `FINDINGS.md` §Gap 5. -/
def AnchorSound (rs : List Entry) (p : Root) : Prop :=
  ∀ e ∈ rs.getLast?, parent e.1 = p

/-- The slot counterpart of `AnchorSound`, needed for `Merge` to preserve Inv 4. -/
def AnchorSlotSound (rs : List Entry) (pslot : Slot) : Prop :=
  ∀ e ∈ rs.getLast?, pslot < e.2

/-! ### Inv 2 and Inv 5's linkage clause are one fact read in opposite directions

The spec says of Inv 5: "`roots` is tip first and `blocks` is import order, so the reversal
is where they meet."  Made precise: if every block reports its own parent honestly, then the
linkage half of Inv 5 is *implied by* Inv 2 and the root correspondence.  It is therefore
not an independent obligation. -/
theorem blocksLinked_of_inv2 {bs : List Block} {rs : List Entry}
    (h2 : Inv2 parent rs)
    (hmap : bs.map Block.root = (rootsOf rs).reverse)
    (hpar : ∀ b ∈ bs, b.parentRoot = parent b.root) :
    BlocksLinked bs := by
  have h1 : Linked (fun x y => parent x = y) (rootsOf rs) := linked_map.mp h2
  have h3 : Linked (fun x y => parent y = x) ((rootsOf rs).reverse) := linked_reverse h1
  rw [← hmap] at h3
  have h4 : Linked (fun a b => parent b.root = a.root) bs := linked_map.mpr h3
  exact Linked.imp_mem (fun _ _ b hb hab => by rw [hpar b hb]; exact hab) h4

end TreeSync
