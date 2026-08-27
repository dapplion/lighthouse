# Model-checking `specs/tree-sync.md`

Model: [`treesync.qnt`](treesync.qnt). Source of truth: `specs/tree-sync.md`. The Rust
implementation (`beacon_node/network/src/sync/forward_sync.rs`) was read only to
disambiguate the spec, never to override it; where the two disagree that is recorded as a
finding, not silently resolved.

## Engine and bounds

| | |
|---|---|
| Modelling language | Quint 0.32.0 |
| **Engine that produced every result below** | **`quint run` — randomised simulation, TypeScript evaluator** |
| Apalache (`quint verify`) | **Attempted, did not complete — see "Engine caveat"** |

**Read the verdicts accordingly.** A `FAIL` is solid: it is a concrete trace, replayed and
hand-checked line by line against the spec text, and each one is reproduced below. A
`PASS` is **not a proof** — it means only "randomised simulation found no counterexample
within these bounds". Do not report any `PASS` here as a verified property.

### Engine caveat

* The bundled **Rust evaluator does not run on this machine** (it needs `GLIBC_2.39`;
  Debian 12 has 2.36). Everything was run with `--backend=typescript`.
* **Apalache 0.56.1 could not check even one step of the full model.** On the `MAXC = 6`
  instance, `quint verify --max-steps=1` died with **`Ran out of heap memory: Java heap
  space`**; `--max-steps=2` had already timed out at 600 s. The model's transitions contain
  bounded fixpoints (`Drop`'s transitive closure, `Promote`'s loop, the ascent) written as
  folds of length 6–7 over a 6-element map of records; Apalache unrolls all of that into a
  single SMT query per step and blows up. Java 17 and Apalache were both installed and
  working — the checker ran and reached its passes — so this is a capacity limit of the
  encoding, not a setup failure.
* Two further attempts were made rather than giving up on it:
  * a **reduced instance** (`MAXC = 3`, modules `base3`/`fixed3`; a `NoBudgetHit` probe
    confirms the smaller chain pool does not bind at 2–3 steps), and
  * the same instance with the **heap raised from the default 4 GB to 24 GB**
    (`JVM_ARGS=-Xmx24g`; the machine has 62 GB).
  Together these got further — Apalache stopped running out of memory and worked through
  steps 0 and 1, reaching step 2 — but then spent over 20 minutes inside a single
  transition's SMT translation and hit a 1500 s cap: `base3/stepStrict/NoOrphanedWait
  k=2 -> TIMEOUT 1500s`. **No `quint verify` run completed, so nothing in this report is
  exhaustively verified.**
* Consequence: **every `PASS` row below is the weak kind of evidence** — "no counterexample
  found by random search", not "no counterexample exists". The `FAIL` rows are unaffected:
  a counterexample is a counterexample regardless of how it was found, and each one below
  was replayed by hand against the spec text. Turning the `PASS` rows into real bounded
  proofs would need a model written for symbolic checking: replace the fold-based bounded
  fixpoints (`Drop`'s closure, `Promote`'s loop, the ascent) with separate atomic actions,
  and shrink the root/chain/peer domains further.

### Constants (shrunk, spec value in brackets)

`B = 2` [32] · `N = 4` [256] · `RETRY_MAX = 2` [5] · `ROOTS_MAX = 6` [1 000 000] ·
3 peers · at most 6 chains · traces of 12–18 steps, up to 15 000 samples per check.

`ROOTS_MAX` and the chain-pool size are constants of the module, so several instances are
built from the same text:

| module | `FIX` | `ROOTS_MAX` | purpose |
|---|---|---|---|
| `base` | off | 6 | the spec exactly as written |
| `fixed` | on | 6 | with the recommended edits, to check they suffice |
| `basePrune` / `fixedPrune` | off / on | 3 | `Prune` fires constantly |
| `base3` / `fixed3` | off / on | 6 | 3-chain pool, for symbolic checking |

`ROOTS_MAX = 6` equals the total number of roots, so `Prune` never fires in the main runs;
the `*Prune` instances exist to cover it (results below). The chain pool of 6 is the natural
ceiling — every chain owns at least one `loc` entry and there are 6 roots — and a
`NoBudgetHit` probe confirms it never bound a behaviour in any instance.

### Block tree

```
0  slot 0  genesis, in FC at init, = finalized
|
1  slot 1
|\
2 4  slot 2          2 and 4 are siblings: the fork matters for Inv 3 and Inv 6
| |
3 5  slot 3
```

A block is identified with its root. In Ethereum `root = hash(header)`, so a peer cannot
lie about a header's slot or parent without changing its root; `slotOf` and `parentOf` are
therefore static functions rather than peer-supplied data. This is a modelling decision,
not a restriction on the adversary.

### The adversary

Modelled explicitly, as instructed. Every header response is `Err`, or `Ok(h)` for `h` any
prefix of the true ancestor walk **including the empty one**; every download is `Err`,
`Ok` covering `R` exactly, or (in the `step` relation only) `Ok` with an arbitrary subset,
which *breaks* the spec's stated guarantee; every process call is `Err` or `Ok`; any peer
may `Disconnect` at any time, including while serving an in-flight request. Requests are
modelled explicitly as state (`flight`), so "is anything actually going to arrive?" is a
checkable question.

Two step relations are used:

* **`stepStrict`** — peers keep every guarantee the spec writes down. Empty header
  responses stay in, because the spec's guarantee admits them (see D1).
* **`step`** — as above plus short/empty download responses, which violate the guarantee.

Unless a row says otherwise, results are under **`stepStrict`**: the spec fails on its own
terms, without the adversary having to break any promise it makes.

---

## Results

`base` = the spec exactly as written. `fixed` = the same model with the repairs in
"Recommended edits" applied, used to check that those repairs are sufficient.

| Property | base | fixed | shortest trace found¹ |
|---|---|---|---|
| Inv 1 `loc(r)=c ⟺ r ∈ c.roots ∨ Discovering(r)` | **FAIL** | PASS | 11 steps |
| Inv 2 `roots` contiguous by `parent_root` | PASS | PASS | — |
| Inv 3 `p ∈ c.peers ⟹ p claimed every root` | **FAIL** | PASS | 4 steps |
| Inv 4 `slot` strictly decreases | PASS | PASS | — |
| Inv 5 `Ready`/`Processing` block list | **FAIL** | **FAIL** (invariant is wrong, see D6) | 4 steps |
| Inv 5′ (Inv 5 with the `Processing` clause weakened) | **FAIL** | PASS | 13 steps (via D7) |
| Inv 6 `Anchored(p) ⟹ p ∈ FC ∨ p ∈ dom(loc)` | **FAIL** | PASS | 7 steps |
| **NoOrphanedWait** (not in the spec) | **FAIL** | PASS | **2 steps** |
| NoStuckForest (bounded liveness) | **FAIL** | PASS | **2 steps** |
| NoStaleDispatch (not in the spec) | **FAIL** | PASS | 6 steps (needs `k≥8` from an arbitrary seed) |
| NoEmptyDownload (not in the spec) | **FAIL** | PASS | 18 steps (via D7) |
| ErrorsAreConsecutive (defect 2 probe) | **FAIL** | PASS | 3 steps |
| NoEarlyDrop (defect 2, the harm) | **FAIL** | PASS | 5 steps |
| Strengthened liveness, honest peer present | **FAIL** | PASS² | 5 steps |

¹ Lengths are the shortest trace the search actually produced, not proven minima —
simulation cannot establish minimality. They are a guide to how deep each defect sits.

² `fixed` still abandons a root after `RETRY_MAX + 1` **consecutive** failures of the same
step. That is the spec's intended behaviour, not a defect, and `NoEarlyDrop` confirms no
chain is dropped with budget left.

Three of these properties are not in the spec and are stated here:

* **NoOrphanedWait**, as instructed:
  `state ∈ {Discovering(_), Downloading, Processing(_)} ⟹ that chain has a request in
  flight`. "In flight" is the explicit `flight` state variable, and "reaches this chain"
  uses the very same dispatch relation the transitions use, so the property cannot be
  satisfied by an accounting trick.
* **NoStaleDispatch**: every chain that an in-flight download/process result would be
  delivered to is in the matching state (`Downloading` / `Processing`) and its roots are a
  subset of the request's root set. This is the property `owners(R)` silently assumes.
* **NoEmptyDownload**: a chain in `Downloading` has at least one root — i.e. no chain is
  ever waiting on a request for nothing.

**Liveness.** The spec's own clause (L120, "every root reaches `FC` or is dropped") is
vacuous — dropping everything satisfies it, so it cannot fail. The strengthened version
checked here: *every chain permanently holds one honest peer that holds the whole chain and
never disconnects; requests may still fail transiently, which is what `RETRY_MAX` is for;
under fairness every root must then reach `FC`.* Quint cannot check the temporal form here
(no Apalache), so it is approximated by two state invariants: `NoStuckForest` (no reachable
state where the forest is non-empty but nothing is in flight, nothing is `Ready` with its
parent imported, and nothing is promotable) and `NoEarlyDrop`. Both fail on `base`.

---

## The two suspected defects

### Defect 1 — `Ok([])` leaves the chain stuttering in `Discovering` forever: **CONFIRMED**

Two steps. `NoOrphanedWait` and `NoStuckForest` both fail on it.

```
1. Search(4, {p3})        chain 0 = Backfill{roots:[], peers:{p3}, errors:0, Discovering(4)}
                          loc(4) = chain 0;  SendHeaders(chain 0, 4)   -- request in flight
2. OnHeaders(chain 0, Ok([]))
                          the `for header ∈ headers` loop body never runs, so no header is
                          pushed and no `p` is ever assigned; the trailing clause
                          "unresolved after the walk → SendHeaders(c, p) for the last p"
                          has no `p` to use.

final state: chain 0 still Discovering(4), errors still 0, NOTHING in flight.
```

The chain is stuck forever: `errors` was not even incremented, so the `RETRY_MAX` escape
never fires, and no other transition targets a `Discovering` chain. Root 4 is never synced
and never dropped — it just sits in `loc` blocking any future `Search(4)`.

The diagnosis in the task is exactly right: `SendHeaders`' guarantee (L62) is
`h[0].root = root ∧ h[i].root = h[i−1].parent_root ∧ h[i].slot < h[i−1].slot`, and for
`h = []` all three conjuncts are **vacuously true**. A peer that answers a `blocks_by_root`
for a root it advertised with an empty response is behaving within the stated contract.

The implementation already knows this and handles it — `forward_sync.rs` matches
`Ok(blocks) if !blocks.is_empty()` and routes the empty case to the failure path, with the
comment *"returning here would leave the chain `Discovering` with no request in flight,
which nothing else can restart."* **The spec is missing that case.**

### Defect 2 — `errors` is never reset: **CONFIRMED**, and it does break liveness

`ErrorsAreConsecutive` fails in 3 steps; the harm (`NoEarlyDrop`) in 5.

```
1. Search(3, {p1})                      chain 0 Discovering(3), errors = 0
2. OnHeaders(chain 0, Err)              errors = 1;  SendHeaders(chain 0, 3)
3. OnHeaders(chain 0, Ok([3]))          REAL PROGRESS: root 3 pushed, now Discovering(2)
                                        errors stays 1  <-- nothing in the spec resets it
4. OnHeaders(chain 0, Err)              errors = 2;  SendHeaders(chain 0, 2)
5. OnHeaders(chain 0, Err)              errors = 3 > RETRY_MAX = 2  ->  Drop(chain 0)
```

The chain is dropped having failed the *current* step only twice, with a budget of two
retries per step. The already-recovered failure at step 2 ate a third of it. With the real
constants (`RETRY_MAX = 5`, a backfill walking thousands of roots) `errors` is a lifetime
counter: **any chain is dropped on its 6th failure ever, no matter how much progress it
made in between**, which for a long walk is a near-certainty.

Yes, the strengthened liveness property catches it: under `stepLive` — one honest peer that
holds the chain, present in every chain, never disconnecting, every `Ok` complete and
well-formed — `NoEarlyDrop` fails in 5 steps and the root's data is abandoned even though a
peer holding it was available the whole time.

Again the implementation already has the fix the spec lacks — `Chain::clear_errors`, called
on every successful header walk, with the comment *"Progress resets the retry budget:
`RETRY_MAX` bounds the retries of one step, not the lifetime of a chain that walks thousands
of roots."* **The spec never resets `errors` anywhere.**

---

## Further defects found

### D3 — `Drop` orphans chains anchored on the dropped chain's `Discovering` root (Inv 6)

7 steps. This one permanently strands a chain that has done nothing wrong.

```
1. Search(5, {p2})                 chain 0 Discovering(5)
2. Search(2, {p1})                 chain 1 Discovering(2)
3. OnHeaders(chain 0, Err)         errors = 1
4. OnHeaders(chain 0, Ok([5,4]))   chain 0 roots [5,4]; parent(4) = 1 unknown
                                   -> loc(1) := chain 0, Discovering(1)
5. OnHeaders(chain 1, Ok([2]))     chain 1 roots [2]; parent(2) = 1, loc(1) IS defined
                                   -> chain 1 := Anchored(1)          (Inv 6 holds here)
6. OnHeaders(chain 0, Err)         errors = 2
7. OnHeaders(chain 0, Err)         errors = 3 > RETRY_MAX -> Drop(chain 0)
```

`Drop` (L104) removes `chain 0`, its roots `{5,4}` from `loc`, **and its `Discovering(1)`
root `1` from `loc`** — then drops transitively "every `c` whose `parent` ∈ `x.roots`".
Chain 1's parent is `1`, which is *not* in `{5,4}`, so chain 1 survives.

Final state: `chain 1 = Anchored(1)` with `1 ∉ FC` and `1 ∉ dom(loc)`. **Inv 6 is false.**

Worse, chain 1 is now permanently dead. `Promote`'s `pick` requires
`parent ∈ FC ∨ loc(parent) is ForwardSync`; `1` is in neither, and nothing will ever put it
back — the chain that was going to discover it has been dropped. Nothing is in flight for
chain 1 either, so `NoStuckForest` fails too. And chain 1 cannot be rescued from outside:
`Search(2, P)` finds `loc(2) = chain 1` with `2 = c.roots[0]`, so it merely adds peers to a
chain that can never act on them. Root 2 is lost until restart.

The root cause is that `Drop` removes the `Discovering` root from `loc` but does not treat it
as a root that other chains may be anchored on. The implementation has the same gap
(`drop_chain` builds `dropped` from `chain.roots()` only, then removes the pending root
separately and never re-queues on it).

### D4 — an aborted `OnHeaders` walk leaks `loc` entries (Inv 1)

11 steps. Reduced to the part that matters, with `finalized = (4, slot 2)` already reached:

```
9.  Search(3, {p2})                 chain 0 Discovering(3), loc(3) = chain 0
10. OnHeaders(chain 0, Err)         errors = 1
11. OnHeaders(chain 0, Ok([3, 2]))
      header 3: fine. push 3. p := parent(3) = 2, unknown -> loc(2) := chain 0, continue
      header 2: slot(2) = 2 ≤ slot(finalized) = 2 and 2 ≠ root(finalized) = 4
                -> report_peer(c.peers); Drop(c)
```

At the moment of the `Drop` the chain's state is still `Discovering(3)` — the spec only
changes state via `SendHeaders`, after the walk. So `Drop` removes `c.roots = {3}` and the
`Discovering` root `3`, and **`loc(2) = chain 0` survives its chain**. `Inv 1` is false, and
root 2 is permanently unsyncable: every later `Search(2)` finds `loc(2)` defined and
operates on a chain that does not exist.

Normally the accounting works, because each `loc(p) := c` is followed by pushing `p` on the
next iteration and the final un-pushed `p` becomes `Discovering(p)`. It breaks precisely
when the walk aborts mid-way — which only the finality-conflict branch does.

### D5 — the ascent admits peers to chains that hold non-ancestors (Inv 3)

Inv 3 fails on three distinct paths. The most important one refutes the spec's own stated
justification.

**(a) `OnHeaders`' ascent across a fork — 4 steps.** This is the one that refutes L76.

```
1. Search(2, {p3})                 chain 0 Discovering(2)
2. OnHeaders(chain 0, Ok([2,1]))   roots [2,1]; parent(1) = 0 ∈ FC -> Anchored(0)
                                   Promote -> ForwardSync roots [2,1], peers {p3}
3. Search(5, {p1})                 chain 1 Discovering(5)
4. OnHeaders(chain 1, Ok([5,4]))   roots [5,4]; parent(4) = 1; loc(1) = chain 0 is defined
                                   -> chain 1 := Anchored(1)
                                   -> "ascend from 1 with c.peers", i.e. add p1 to chain 0
```

`p1` claimed only root 5. Root 1 is an ancestor of 5, fine — but **root 2 is not**: 2 and 4
are siblings on different branches. `p1` is now in the peer set of a chain containing root 2,
which it never claimed. **Inv 3 is false.**

The spec's justification at L76 — *"A peer that claimed this chain's tip holds them too"* —
does not hold, because the ascent adds peers to the chain that **owns `p`**, and `p` may be
**interior** to that chain; everything above `p` in it is on another branch. `Search`'s own
third branch (L58) gets this right — it `Split`s at `r` first and admits only to `Y`. The
ascent (L60 and L70) omits the split.

This is not cosmetic. Inv 3 is what licenses asking any single peer for *all* of `c.roots`;
once it is false, the next `SendDownload` can be served by a peer that provably lacks some
of the roots, which costs an error against the (unresettable, see D2) budget, and an
`OnProcess` `Err` then calls `report_peer` on the whole set, penalising honest peers.

**(b) `Search`'s `c.state = Discovering(r)` branch — 4 steps; this is what `base` hits
first.** `Search(4, {p2})` where
`loc(4) = c` because `c.state = Discovering(4)` takes the L57 branch `c.peers ∪= P`. But
`c.roots` are the **descendants** of 4 already walked (`[5]` in the trace); claiming 4 says
nothing about holding 5. Sound only while `c.roots = []`.

**(c) the ascent crossing a claim-ahead entry — 4 steps.** `loc(p)` being defined does not
mean the owning chain *holds* `p`: under Inv 1's second disjunct it may mean that chain is
merely *asking* for `p`. Ascending into such a chain lands the peers on that chain's roots,
which are descendants of `p`.

(a), (b) and (c) are the same underlying error: **`loc(p) ≠ ∅` is treated as "that chain's
roots are ancestors of p", and neither disjunct of Inv 1 guarantees that.**

### D6 — Inv 5 is not preserved by `Split` (the invariant is too strong)

4 steps.

```
1. Search(4, {p2})                 chain 0 Discovering(4)
2. OnHeaders(chain 0, Ok([4,1]))   roots [4,1]; parent(1) = 0 ∈ FC
                                   Promote: |roots| = 2 = B, promoted whole -> Downloading
3. OnDownload({1,4}, Ok)           Ready([1,4]);  Promote: parent 0 ∈ FC -> Processing([1,4])
4. Search(1, {p1})                 loc(1) = chain 0, 1 ≠ roots[0] = 4  ->  Split(chain 0, 1)
                                   Y = chain 0: roots [1], Processing([1])
                                   Z = chain 1: roots [4], Processing([4]), Z.parent = 1
```

Inv 5 (L114) says `Processing ⟹ parent(blocks[0]) ∈ FC`. For `Z`, `parent(4) = 1`, and 1 is
not in `FC` — it is still being processed in the very segment this half was split out of.

This is a defect in the **invariant**, not in the behaviour: `SendProcess` (L94) guards on
`c.parent ∈ FC` for the whole segment before submitting, which is where the property is
actually needed. After a split the newer half is already in flight as part of that segment.
The weakened form (`parent(blocks[0]) ∈ FC ∨ ∈ dom(loc)`) holds throughout.

Note `Promote` only ever splits `Backfill` chains, so this is reachable only through
`Search` → `Split` on a live `ForwardSync` chain.

### D7 — `owners(R)` dispatch is stale: a result reaches a chain that never issued it

6 steps, under `stepStrict`. (Random search reliably finds it from `--max-steps=8`; the
6-step trace below came from `--seed=23`.) This one breaks Inv 1 and `NoOrphanedWait` on its own.

```
1. Search(2, {p2})                 chain 0 Discovering(2)
2. OnHeaders(chain 0, Ok([2,1]))   roots [2,1], Anchored(0); Promote -> ForwardSync
                                   SendDownload -> request in flight with R = {1, 2}
3. Search(1, {p3})                 loc(1) = chain 0, 1 ≠ tip -> Split(chain 0, 1)
                                   Y = chain 0: roots [1];  Z = chain 1: roots [2]
                                   both halves await the shared R = {1,2}   (per L50)
4. Disconnect(p2)                  chain 1's peers become ∅ -> Drop(chain 1)
                                   root 2 leaves loc; R = {1,2} stays in flight for chain 0
5. Search(2, {p2})                 loc(2) now undefined -> a BRAND NEW chain 1,
                                   Backfill Discovering(2), loc(2) = chain 1
```

Now the in-flight download has `owners(R) = {loc(1) = chain 0, loc(2) = chain 1}` — and
chain 1 is an unrelated `Backfill` that has discovered nothing. When the response arrives,
L90/L92 apply it to chain 1 regardless: `Err` gives it `errors += 1` and `SendDownload(c)`,
turning a `Backfill` chain into `Downloading` **with an empty root set** and a download
request for `∅`; meanwhile its own `Discovering(2)` header request is still outstanding but
`OnHeaders`' guard `c.state = Discovering(next)` now rejects it. The chain is stuck and
`loc(2)` points at a chain that is neither holding 2 nor discovering it — **Inv 1 false**.
An `Ok` is no better: it hands the chain `Ready(blocks↾c)` — a `ForwardSync` state on a
`Backfill` chain, which the spec's own type does not admit.

**The same defect also silently destroys blocks a chain already holds.** This is the
18-step `Inv 5′` failure, and it is the most damaging manifestation:

```
   chain 0: ForwardSync roots [4,1]  ->  SendDownload, R = {1,4} in flight
   Search(1) splits it: chain 0 = [1], chain X = [4]; both await R
   chain X is dropped (its last peer disconnects); root 4 leaves loc
   Search(4) -> a new chain 1 walks to roots [5,4], downloads its OWN request,
                and is correctly Ready([4,5])
   the ORIGINAL R = {1,4} response finally arrives:
     owners(R) = { loc(1) = chain 0, loc(4) = chain 1 }
     chain 1 := Ready(blocks↾c) where blocks covers only {1,4}
             -> Ready([4])            <-- block 5 is silently discarded
```

`OnDownload` (L91) overwrites the state of every `c ∈ owners(R)` unconditionally — there is
no guard that `c` is even in `Downloading`. A chain that had already completed its own
download is knocked back to a `Ready` with a hole in it, and `Promote` will then submit that
short segment to `SendProcess` as if it were complete.

The cause is that `owners(R)` (L19) is recomputed from `loc` **at delivery time**, but `loc`
is not stable across the lifetime of a request: a root can leave the issuing chain (drop of a
split half) and be re-acquired by an unrelated new chain.

**Spec/implementation divergence here.** The implementation does *not* do what L90 says: it
stores `downloads: HashMap<Id, (ChainId, …)>` and delivers only to the recorded issuing
chain id. That avoids D7 — but it introduces the mirror bug the `owners(R)` design existed to
prevent: `Chain::split_at` gives **both** halves `Sync::Downloading` while `finish_download`
updates only the older half (which keeps `chain_id`), so **the newer half sits in
`Downloading` forever with no request in flight**, exactly the `NoOrphanedWait` failure.
Neither side is currently correct; the fix below (tag the call, let `Split` copy the tag)
fixes both.

### D8 — the `SendDownload` guarantee is load-bearing and unchecked

Under `step` (peers allowed to return fewer blocks than `R`, breaking the L88 guarantee),
Inv 5's first conjunct fails immediately: `OnDownload` (L91) does `Ready(blocks↾c)` with no
check that `blocks` covers `c.roots`, so a chain reaches `Ready` — and then `Processing` —
with a partial or empty block list. `OnProcess` `Ok` then adds **all of `R`** to `FC`,
including roots whose blocks were never fetched.

This is the one finding that requires the adversary to break a stated guarantee, so it is
lower severity than D1–D7. It is listed because the spec relies on that guarantee silently:
nothing in `OnDownload` re-checks it, and the guarantee is the sole defence.

---

## Recommended edits to `specs/tree-sync.md`

Minimal, in spec-text terms. I have **not** edited the spec.

1. **D1 — L66, `OnHeaders`.** Make the empty response a failure. Change the `Ok` case to
   split on emptiness:
   `Ok([])` → `errors += 1`; `errors > RETRY_MAX` → `Drop(c)`, else `SendHeaders(c, next)`
   — i.e. identical to the `Err` branch. (Optionally also tighten L62 to say `Ok(h)` has
   `h ≠ []`, but the transition must handle it regardless, since the peer controls this.)

2. **D2 — L66/L84.** Add one line to `OnHeaders`' `Ok` case, after the walk consumes at
   least one header: `errors := 0`. State the intent explicitly, as the implementation
   does: *`RETRY_MAX` bounds the retries of one step, not the lifetime of a chain.* Do
   **not** reset on a successful `OnDownload` — the budget must still span the
   download/process retry cycle for one batch, or a persistently bad block retries forever.

3. **D3 — L104, `Drop`.** Drop transitively on every root the chain claimed, not just
   `x.roots`: *"remove `x` and, transitively, every `c` whose `parent` ∈ `x.roots` ∪
   `{x`'s `Discovering(next)` root`}`"*.

4. **D4 — L104, `Drop`, and L71, `OnHeaders`.** Make `Drop` clear the whole `loc` preimage
   of `x`, not an enumerated list: *"`loc ∖= { r | loc(r) = x }`"*. This subsumes edit 3's
   `loc` half and fixes the leak from an aborted walk. Combined with edit 3 the two become
   one clause: *`Drop(x)` removes `x`, every `c` whose `parent` is a root `x` claimed, and
   every `loc` entry pointing at `x`.*

5. **D5 — L60 and L70, the ascent.** The ascent must `Split` before admitting. Restate as:
   *"then ascend: for each ancestor root `p` reachable by following `parent` links, if
   `loc(p) = c'` and `p ∈ c'.roots`, `Split(c', p)` and add `P` to the older half, then
   continue from its `parent`; if `p ∉ c'.roots` (`c'` is merely `Discovering(p)`), stop."*
   Also amend L57: the `c.state = Discovering(r)` branch may admit `P` only when
   `c.roots = []`; otherwise `c.roots` are `r`'s descendants and `P` has not claimed them.
   Finally, L76's justification is wrong as written and should say why the split is needed:
   the parent root may be interior to the ancestor chain, whose newer roots are on another
   branch.

6. **D6 — L114, Inv 5.** Weaken the `Processing` clause to
   `Processing ⟹ parent(blocks[0]) ∈ FC ∨ parent(blocks[0]) ∈ dom(loc)`, and note that the
   strong form is established by `SendProcess`' guard (L94) for the whole segment and is not
   preserved by `Split`, which may cut a segment that is already in flight.

7. **D7 — L19, L88, L90, L94, L96.** Give each `SendDownload`/`SendProcess` call an
   identity and dispatch on it instead of recomputing `owners(R)` from `loc`. Concretely:
   the call carries a tag; `Split` copies the tag to both halves (which is exactly what L50
   already intends — *"Both halves keep awaiting the shared in-flight call"*); `OnDownload`
   and `OnProcess` apply to the chains carrying that tag. Then delete `owners(R)` from L19
   or redefine it as *"the chains awaiting this call"*. This also removes the implementation
   divergence noted under D7.

8. **D8 — L91, `OnDownload`.** Add an explicit check rather than relying on the guarantee:
   *"`Ok(blocks)` whose roots do not cover `c.roots` exactly → `report_peer`; treat as
   `Err`."*

9. **L120, Liveness.** The stated clause is vacuous (dropping everything satisfies it).
   Replace with something falsifiable, e.g. *"with ≥1 honest peer holding the chain and
   present in `c.peers`, a chain is dropped only after `RETRY_MAX` consecutive failures of
   the same step; every other root reaches `FC`."* That is the property that catches D1,
   D2, D3 and D7.

Edits 1–5 and 7 are implemented in the model behind `const FIX` (`module fixed`), and with
them Inv 1, Inv 3, Inv 5′, Inv 6, `NoOrphanedWait`, `NoStuckForest`, `NoStaleDispatch`,
`NoEmptyDownload`, `ErrorsAreConsecutive` and `NoEarlyDrop` all pass under the same bounds
and the same adversary that breaks them on `base`. They also hold with `Prune` firing
constantly (`fixedPrune`, `ROOTS_MAX = 3`), where `basePrune` still fails Inv 1, Inv 3,
Inv 6 and `NoOrphanedWait` and surfaces nothing new.

Edit 6 changes the invariant rather than the behaviour, so it is checked as `Inv5weak`
(which `fixed` satisfies). **Edits 8 and 9 are not implemented in the model**: edit 8 is
deliberately left out so that `fixed` under the guarantee-breaking `step` relation still
shows D8, and edit 9 is a documentation change with no state-machine content.

**Non-vacuity check.** A repair that simply stops the protocol making progress would also
turn every safety property green, so `fixed` was checked for liveness in the other
direction: witness runs confirm it still drives roots on *both* branches of the fork into
`FC` (`st.fc.contains(3)` and `st.fc.contains(5)` are both reachable under `stepStrict`).
The repairs constrain who gets admitted and who gets notified; they do not stall the
pipeline.

---

## What these bounds do NOT cover

Read the `PASS` rows narrowly. In particular:

* **No `PASS` here is a proof.** All results come from randomised simulation. No
  `quint verify` run ever completed — on the full model Apalache exhausted a 4 GB heap at
  `k=1`, and on a reduced instance with 24 GB it reached step 2 and then timed out — so
  nothing here is exhaustively verified, not even for one step.
* **`Prune` is exercised only shallowly.** The `basePrune`/`fixedPrune` instances
  (`ROOTS_MAX = 3`, 6 roots) make it fire constantly, and they surface **no defect beyond
  D1–D7** — `base` fails exactly the same properties, and `fixed` passes all of them. But
  with 6 roots the "drop chains ascending by `|peers|`" ordering is barely discriminating,
  and the pathological case `Prune` exists for (a million tracked roots) is far out of
  reach.
* **`Merge` is never exercised.** The spec says no transition invokes it and it is a
  background compaction, so it is not in the transition relation at all. Its guard
  (`Z.state = Anchored(Y.roots[0]) ∧ Y.peers = Z.peers`) and the claim `Merge(Split(c,r)) = c`
  are unchecked.
* **`B = 2` barely exercises `Promote`'s split.** With 2-root chains, the "`|c.roots| > B`"
  branch fires rarely and the boundary reasoning at L86 (the `B`-th oldest root being the
  tip at `|c.roots| = B`) is only lightly covered.
* **`N = 4` means the in-flight cap is rarely the binding constraint**, so back-pressure
  behaviour under a full pipeline is essentially untested.
* **The tree has 6 roots over 4 slots and one fork.** Deep chains, multiple simultaneous
  forks, re-orgs, and long backfill walks are out of reach. D2's severity in particular
  scales with walk length, which this tree cannot show — the 5-step trace is the mechanism,
  not the magnitude.
* **`slot` and `parent_root` are functions of the root**, so a peer cannot serve a header
  that is internally inconsistent. Malformed or unhashable headers are out of scope (they
  would be rejected before reaching this state machine anyway).
* **`report_peer` is a no-op.** Peer scoring, banning and the feedback loop from
  `report_peer` back to `Disconnect` are not modelled; `Disconnect` is free and adversarial
  instead, which is a superset for safety but says nothing about whether scoring correctly
  punishes the right peer. D5's consequence — honest peers being reported — is argued, not
  model-checked.
* **Column/custody fetches, data availability and `Merge`-time peer-set equality** are not
  modelled; L30's remark about column fetches stalling on custody peers is out of scope.
* **Timing, concurrency and message reordering beyond the explicit `flight` set.** Requests
  are delivered in any order and may be arbitrarily delayed, but there is no clock and no
  duplicate delivery.
* **Traces are 12–18 steps.** Every reported failure is well within that, but a `PASS`
  says nothing about behaviours needing more steps — D4 needed 11 and D7's Inv 1 failure
  needed 18, so the depth frontier is demonstrably close.

## Reproducing

```bash
npm install -g @informalsystems/quint          # 0.32.0
cd specs/quint
quint typecheck treesync.qnt

# a failure (defect 1) -- 2 steps
quint run treesync.qnt --backend=typescript --main=base --step=stepStrict \
      --invariant=NoOrphanedWait --max-steps=2 --max-samples=6000 --verbosity=3

# the same property with the repairs applied
quint run treesync.qnt --backend=typescript --main=fixed --step=stepStrict \
      --invariant=NoOrphanedWait --max-steps=18 --max-samples=12000
```

`--backend=typescript` is required on this machine: the bundled Rust evaluator needs
`GLIBC_2.39`. Add `--out-itf=trace.json` for a machine-readable trace.
