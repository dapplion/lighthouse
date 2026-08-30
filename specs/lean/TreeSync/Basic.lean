import TreeSync.List

/-!
# The tree-sync data model

A formalisation of the *pure, size-generic core* of `specs/tree-sync.md`: the `Chain` record
and the `Split` / `Merge` operations.  Peers, network I/O, `loc`, `FC` as mutable state and
the transition system are all out of scope; `FC` appears only as an abstract predicate where
Invariant 5 mentions it.

## Modelling choices (recorded, per the brief)

* `Root` is an opaque identity: a `Nat` wrapped in a structure so that no proof can
  accidentally do arithmetic on it.  Hashing is *not* modelled; instead an abstract
  `parent : Root → Root` is carried as a parameter wherever Invariant 2 is stated.
* `Slot` is `Nat`.  The spec only ever compares slots and needs a floor at `slot(finalized)`.
* `Peer` is `Nat` and `peers` is a `List Peer` — a set *by value*, with no interior
  mutability.  The Rust uses `Arc<RwLock<HashSet<PeerId>>>` and `Split` deep-copies it for
  the newer half, so a by-value list is the right abstraction of the post-copy state.
  See `FINDINGS.md` for why list equality vs. set equality matters for `Merge`'s guard.
* `roots : List (Root × Slot)` is **tip first** (head = newest, highest slot).
* `Block` carries `root`, `parentRoot` and `slot`.  Invariant 5's `parent (blocks[i])` is
  read as `blocks[i].parentRoot = blocks[i-1].root`.
-/

namespace TreeSync

/-- Opaque block root.  Wrapped so arithmetic on roots is not accidentally available. -/
structure Root where
  id : Nat
deriving DecidableEq, Repr, Inhabited

/-- Slot number.  A `notation` rather than an `abbrev` so that `omega` sees `Nat`
directly — `omega` in Lean 4.15 does not unfold reducible type aliases. -/
notation "Slot" => Nat

abbrev Peer := Nat

/-- An entry of `roots : Seq<(Root, Slot)>`. -/
abbrev Entry := Root × Slot

/-- A block, kept abstract: it knows its own root and its parent's root. -/
structure Block where
  root : Root
  parentRoot : Root
  slot : Slot
deriving DecidableEq, Repr, Inhabited

/-- `Backfill`'s state:  `Discovering(Root) | Anchored(Root)`. -/
inductive BackfillState where
  /-- A header request for this root is in flight. -/
  | discovering (next : Root)
  /-- Discovery done; `parent` is in fork choice or owned by another chain (Inv 6). -/
  | anchored (parent : Root)
deriving DecidableEq, Repr

/-- `ForwardSync`'s state:  `Downloading | Ready(Seq<Block>) | Processing(Seq<Block>)`. -/
inductive SyncState where
  | downloading
  | ready (blocks : List Block)
  | processing (blocks : List Block)
deriving DecidableEq, Repr

/-- `Chain = Backfill { roots, peers, errors, state }`. -/
structure BackfillChain where
  /-- Tip first; `slot` strictly decreases (Inv 4). -/
  roots : List Entry
  /-- Each has claimed every root (Inv 3). -/
  peers : List Peer
  errors : Nat
  state : BackfillState
deriving DecidableEq, Repr

/-- `Chain = ForwardSync { roots, peers, parent, errors, state }`. -/
structure ForwardChain where
  roots : List Entry
  peers : List Peer
  parent : Root
  errors : Nat
  state : SyncState
deriving DecidableEq, Repr

inductive Chain where
  | backfill (c : BackfillChain)
  | forward (c : ForwardChain)
deriving DecidableEq, Repr

namespace Chain

def roots : Chain → List Entry
  | .backfill c => c.roots
  | .forward c => c.roots

def peers : Chain → List Peer
  | .backfill c => c.peers
  | .forward c => c.peers

def errors : Chain → Nat
  | .backfill c => c.errors
  | .forward c => c.errors

/-- Newest root — the spec's `c.roots[0]`. -/
def tip (c : Chain) : Option Root := c.roots.head?.map Prod.fst

end Chain

/-- The roots of an entry list, forgetting slots. -/
abbrev rootsOf (rs : List Entry) : List Root := rs.map Prod.fst

end TreeSync
