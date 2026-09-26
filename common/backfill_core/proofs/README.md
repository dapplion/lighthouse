# Proofs for `backfill_core`

The theorems in `Backfill/Properties.lean` are about `../src/lib.rs` itself, not a
transcription of it. `Backfill/Core.lean` is generated from that file by Charon and Aeneas
and is checked in so `lake build` works without either tool installed.

```
../src/lib.rs
    │  charon cargo --preset=aeneas          rustc/MIR frontend; pinned nightly
    ▼
backfill_core.llbc
    │  aeneas -backend lean -loops-to-rec    borrows out, loops as recursive functions
    ▼
Backfill/Core.lean                           the model
Backfill/Properties.lean                     the theorems
```

## Running it

```bash
../extract.sh          # needs charon and aeneas on PATH, or CHARON= and AENEAS=
lake build             # checks the proofs; prints the axioms each theorem rests on
```

`extract.sh` must be re-run after any change to `src/lib.rs`, or the proofs are about the
old code. Each theorem ends with `#print axioms`; every one must report exactly
`[propext, Classical.choice, Quot.sound]` — anything else, in particular `sorryAx`, means a
proof is not closed.

Built against charon `fea3fc6`, aeneas `e03feeb`, Lean `v4.31.0`. `lakefile.lean` expects an
aeneas checkout four directories up; point it elsewhere if yours lives somewhere else.

## What is proved

| | claim |
|---|---|
| **S** | `store_is_verified_descent` — every `Store` action carries a run hash-linked from the frontier, and the header staged to replace the frontier is that run's oldest. |
| **A** | `penalize_names_the_server` — every `Penalize` names either the sender of the run that failed the check, or the peer the state remembers as having served the run the store rejected. |
| **P** | `progress` — every event but `PeerJoined` either leaves the state untouched and emits nothing, or strictly decreases `mu`. No internal loop. |
| **R** | `inv_from_anchor`, `inv_step` — the invariant holds of a state rebuilt from the anchor, and every step preserves it. |

Each is stated as a total-correctness triple, so they also prove `step` never fails: that is
what covers the bare indexing in `check_run`, which cannot go out of bounds.

## What is not proved

- **The store.** Proposer signatures, KZG, Gloas envelopes, the write batch. It is the
  trusted arbiter; the core's job is to never hand it a run that is structurally wrong, and
  to name the right peer when the store rejects one for a reason the block root does not
  cover.
- **Peer selection.** Deliberately outside the core, which cannot see custody or sync status.
  The core constrains it only through `avoid`.
- **The adapter.** Its correctness property is negative and checkable by reading: it contains
  no decisions. Translate types, dispatch actions, forward events. Any `if` in it that is not
  a `match` on an action or event variant is unverified logic that belongs in the core.
- **Liveness.** "Backfill reaches genesis" needs an honest peer to be selected eventually,
  which is an assumption about the world, not a property of the machine.
