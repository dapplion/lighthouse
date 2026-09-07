// Quint model of specs/tree-sync.md -- "tree sync": sync by block root, walk back by
// parent_root to a root fork choice knows, then import forward.
//
// The environment (peers) is modelled ADVERSARIALLY: every response may be Err, Ok with
// the full correct payload, Ok with zero items, or Ok with a short prefix/subset, and any
// peer may disconnect at any time, including while it serves an in-flight request.
//
// Encoding notes (see FINDINGS.md "What the bounds do not cover"):
//  * Chain ids are drawn from a fixed pool CHAINIDS with an `alive` set, and `loc` is a
//    total map with -1 for "undefined". This keeps everything Apalache-friendly.
//  * A block is identified with its root: in Ethereum root = hash(header), so a peer
//    cannot lie about a header's slot or parent without changing its root. `slotOf` and
//    `parentOf` are therefore static functions, not peer-supplied data.
//  * `report_peer` is a no-op here; peer scoring is not modelled. Its effect (the peer
//    going away) is covered by the always-enabled Disconnect action.
module treesync {

  // When FIX is true the model applies the repairs proposed in FINDINGS.md (edits 1-5
  // and 7), so the same invariants can be re-run against the same adversary to check
  // that those repairs are sufficient.  `module base` is the spec exactly as written.
  const FIX: bool

  // ---------------------------------------------------------------- constants (shrunk)
  pure val B         = 2   // spec: 32   roots promoted at a time
  pure val N         = 4   // spec: 256  max blocks forward syncing
  pure val RETRY_MAX = 2   // spec: 5
  // spec: 1_000_000.  A const so Prune can actually be exercised: at 6 (== |ROOTS|) it
  // never fires, at 3 it fires constantly.
  const ROOTS_MAX: int
  // chain-id pool. 6 == |ROOTS| is the natural ceiling (every chain owns at least one
  // loc entry), so the pool can never be the thing that stops a behaviour. It is a const
  // so a smaller instance can be built for symbolic checking; NoBudgetHit reports when
  // a smaller pool does bind.
  const MAXC: int

  // -------------------------------------------------------------------- the block tree
  //        0 (genesis, slot 0, in FC)
  //        |
  //        1 (slot 1)
  //       / \
  //      2   4   (slot 2)
  //      |   |
  //      3   5   (slot 3)
  pure val ROOTS: Set[int] = Set(0, 1, 2, 3, 4, 5)
  pure def parentOf(r: int): int =
    if (r == 1) 0 else if (r == 2) 1 else if (r == 3) 2
    else if (r == 4) 1 else if (r == 5) 4 else 0
  pure def slotOf(r: int): int =
    if (r == 0) 0 else if (r == 1) 1 else if (r == 2) 2
    else if (r == 3) 3 else if (r == 4) 2 else 3

  // ancestors of r, including r itself
  pure def ancestry(r: int): Set[int] =
    range(0, 6).foldl((Set(r), r), (a, _) =>
      val p = parentOf(a._2)
      (a._1.union(Set(p)), p))._1

  pure val PEERS: Set[int] = Set(1, 2, 3)
  pure val HONEST = 1                       // for the liveness configuration
  pure val CHAINIDS: Set[int] = range(0, MAXC).foldl(Set(), (a, i) => a.union(Set(i)))

  // ------------------------------------------------------------------------ list helpers
  pure def rev(l: List[int]): List[int] = l.foldl([], (acc, x) => [x].concat(acc))
  pure def setOfList(l: List[int]): Set[int] = l.foldl(Set(), (a, x) => a.union(Set(x)))
  pure def idxOf(l: List[int], x: int): int =
    l.indices().fold(-1, (a, i) => if (l[i] == x) i else a)
  pure def lastOf(l: List[int]): int = if (length(l) == 0) -1 else l[length(l) - 1]
  // the true ancestor walk of k headers starting at r (what a well-formed Ok(h) must be)
  pure def walkList(r: int, k: int): List[int] =
    range(0, k).foldl([], (l, _) =>
      if (length(l) == 0) [r] else l.append(parentOf(lastOf(l))))

  // -------------------------------------------------------------------------- the state
  // kind: "Disc"  = Backfill Discovering(target)
  //       "Anch"  = Backfill Anchored(target)
  //       "Down"  = ForwardSync Downloading      (target = parent)
  //       "Ready" = ForwardSync Ready(blocks)    (target = parent)
  //       "Proc"  = ForwardSync Processing(blocks)
  //       "Dead"  = unallocated slot
  // cerrors is a GHOST: consecutive failures of the current step, reset on any progress.
  // The spec has no such counter -- comparing it with `errors` exposes defect 2.
  type Chain = {
    roots:   List[int],     // tip first
    peers:   Set[int],
    errors:  int,
    cerrors: int,
    kind:    str,
    target:  int,
    blocks:  List[int],     // Ready/Proc payload, oldest first
    awaiting: int           // FIX: id of the download/process call this chain waits on
  }
  pure val DEAD: Chain =
    { roots: [], peers: Set(), errors: 0, cerrors: 0, kind: "Dead", target: -1,
      blocks: [], awaiting: -1 }

  // An in-flight call. rk: "H" headers (per chain), "D" download, "P" process (per root set).
  type Req = { rk: str, cid: int, tgt: int, rts: Set[int], id: int }

  type St = {
    fc:        Set[int],
    finRoot:   int,
    finSlot:   int,
    loc:       int -> int,      // total over ROOTS; -1 == undefined
    alive:     Set[int],
    chains:    int -> Chain,    // total over CHAINIDS; DEAD when not alive
    flight:    Set[Req],
    nextReq:   int,
    // ---- ghosts, for reporting only ----
    abandoned: Set[int],        // roots dropped without ever reaching FC
    searched:  Set[int],        // roots ever handed to Search
    claimed:   int -> Set[int], // per peer: the roots it actually claimed via Search
    earlyDrop: bool,            // a chain was dropped for errors>RETRY_MAX with cerrors<=RETRY_MAX
    budgetHit: bool             // the MAXC chain pool ran out (a bound, not a spec bug)
  }

  var st: St

  // ------------------------------------------------------------------ small accessors
  pure def isFwd(c: Chain): bool = c.kind == "Down" or c.kind == "Ready" or c.kind == "Proc"
  pure def hasParent(c: Chain): bool = c.kind != "Disc" and c.kind != "Dead"
  pure def rootSet(c: Chain): Set[int] = setOfList(c.roots)
  pure def oldestSlot(c: Chain): int =
    if (length(c.roots) == 0) 999 else slotOf(lastOf(c.roots))
  pure def locDom(s: St): Set[int] = ROOTS.filter(r => s.loc.get(r) != -1)
  pure def ownersOf(s: St, R: Set[int]): Set[int] =
    R.filter(r => s.loc.get(r) != -1).map(r => s.loc.get(r))
  pure def locDel(s: St, rs: Set[int]): int -> int =
    ROOTS.mapBy(r => if (r.in(rs)) -1 else s.loc.get(r))
  pure def syncingBlocks(s: St): int =
    s.alive.fold(0, (a, k) => if (isFwd(s.chains.get(k))) a + length(s.chains.get(k).roots) else a)
  // Every root that maps to cid.  Under Inv 1 this is rootSet(c) plus, if c is
  // Discovering(next), the claim-ahead entry for `next` -- but OnHeaders can leave more
  // than one such entry behind when its walk aborts, which is why FIX uses this.
  pure def ownedRoots(s: St, cid: int): Set[int] = ROOTS.filter(r => s.loc.get(r) == cid)

  pure def freeId(s: St): int =
    CHAINIDS.exclude(s.alive).fold(-1, (a, k) => if (a == -1 or k < a) k else a)

  // ------------------------------------------------------------------------ Drop(x)
  // "remove x and, transitively, every c whose parent in x.roots; loc \= x.roots, and x's
  //  Discovering(next) root if any."  Note the Discovering root is removed from loc but is
  //  NOT part of x.roots, so it does not trigger the transitive step -- see FINDINGS.
  pure def dropClosure(s: St, cid: int): Set[int] =
    range(0, MAXC).foldl(Set(cid), (acc, _) =>
      val rs = acc.fold(Set(), (a, k) =>
        if (not(k.in(s.alive))) a
        else
          val c = s.chains.get(k)
          // FIX: every root this chain claimed is about to leave loc, so a chain
          // Anchored on any of them is orphaned unless it is dropped too.
          a.union(if (FIX) ownedRoots(s, k) else rootSet(c)))
      acc.union(s.alive.filter(k =>
        hasParent(s.chains.get(k)) and s.chains.get(k).target.in(rs))))

  pure def dropChains(s: St, cids: Set[int]): St =
    val live = cids.intersect(s.alive)
    val removed = live.fold(Set(), (a, k) => a.union(rootSet(s.chains.get(k))))
    // FIX: clear the whole loc preimage.  The spec removes only c.roots and the single
    // Discovering root, so a claim-ahead `loc(p) := c` made earlier in an aborted
    // OnHeaders walk survives its chain and leaks the root forever (Inv 1).
    val pend = live.fold(Set(), (a, k) =>
      if (FIX) a.union(ownedRoots(s, k))
      else if (s.chains.get(k).kind == "Disc") a.union(Set(s.chains.get(k).target))
      else a)
    val newLoc = locDel(s, removed.union(pend))
    val newAlive = s.alive.exclude(live)
    // A request whose chain is gone becomes inert (OnHeaders guards on Discovering(next);
    // OnDownload/OnProcess dispatch via loc, so a root no longer in loc has no owner).
    val newFlight = s.flight.filter(q =>
      if (q.rk == "H") not(q.cid.in(live))
      else if (FIX) newAlive.exists(k => s.chains.get(k).awaiting == q.id)
      else q.rts.exists(r => newLoc.get(r) != -1))
    s.with("alive", newAlive)
     .with("chains", CHAINIDS.mapBy(k => if (k.in(newAlive)) s.chains.get(k) else DEAD))
     .with("loc", newLoc)
     .with("flight", newFlight)
     .with("abandoned", s.abandoned.union(removed.exclude(s.fc)))

  pure def dropChain(s: St, cid: int): St = dropChains(s, dropClosure(s, cid))

  // ------------------------------------------------------------------------ Split(c, r)
  // Y = [r .. oldest] keeps the chain id, the state and the in-flight call.
  // Z = [tip .. r+]  is new, Anchored(r) for Backfill, state restricted for ForwardSync.
  pure def splitChain(s: St, cid: int, pivot: int): St =
    val c = s.chains.get(cid)
    val i = idxOf(c.roots, pivot)
    if (i <= 0 or freeId(s) == -1)
      if (freeId(s) == -1) s.with("budgetHit", true) else s
    else
      val zid = freeId(s)
      val yRoots = c.roots.slice(i, length(c.roots))
      val zRoots = c.roots.slice(0, i)
      val ySet = setOfList(yRoots)
      val y = c.with("roots", yRoots).with("blocks", c.blocks.select(b => b.in(ySet)))
      val z =
        if (c.kind == "Disc" or c.kind == "Anch")
          c.with("roots", zRoots).with("blocks", []).with("kind", "Anch").with("target", pivot)
        else
          c.with("roots", zRoots)
           .with("blocks", c.blocks.select(b => not(b.in(ySet))))
           .with("target", pivot)
      s.with("alive", s.alive.union(Set(zid)))
       .with("chains", s.chains.put(cid, y).put(zid, z))
       .with("loc", ROOTS.mapBy(r => if (r.in(setOfList(zRoots))) zid else s.loc.get(r)))

  // ------------------------------------------------------- the ascent (Search, OnHeaders)
  // "add P to every chain holding an ancestor of r, following parent links to FC"
  pure def ascend(s: St, root: int, ps: Set[int]): St =
    range(0, MAXC + 1).foldl({ s: s, cur: root, seen: Set() }, (a, _) =>
      if (a.cur == -1) a
      else
        val cid = a.s.loc.get(a.cur)
        if (cid == -1 or cid.in(a.seen) or not(cid.in(a.s.alive))) a.with("cur", -1)
        else if (FIX and not(a.cur.in(rootSet(a.s.chains.get(cid)))))
          // FIX: loc(cur) is defined only because that chain is Discovering(cur); it does
          // not hold cur, it is asking for it.  Its roots are DESCENDANTS of cur, possibly
          // on another fork, so a peer that claimed cur has not claimed them (Inv 3).
          a.with("cur", -1)
        else
          // FIX: cur may be INTERIOR to the owner chain, whose tip is then a descendant of
          // cur on another branch -- which the peer never claimed.  Split at cur first, so
          // the peers land on cur and its ancestors only.  This is what Search's own third
          // branch already does; the ascent omitted it.
          val hd = if (length(a.s.chains.get(cid).roots) == 0) -1
                   else a.s.chains.get(cid).roots[0]
          val s0 = if (FIX and hd != -1 and hd != a.cur) splitChain(a.s, cid, a.cur) else a.s
          val c = s0.chains.get(cid)
          val c2 = c.with("peers", c.peers.union(ps))
          { s: s0.with("chains", s0.chains.put(cid, c2)),
            cur: (if (hasParent(c2)) c2.target else -1),
            seen: a.seen.union(Set(cid)) }
    ).s

  // -------------------------------------------------------------------- request senders
  pure def sendHeaders(s: St, cid: int, root: int): St =
    val c = s.chains.get(cid)
    s.with("chains", s.chains.put(cid, c.with("kind", "Disc").with("target", root)))
     .with("flight", s.flight.filter(q => not(q.rk == "H" and q.cid == cid))
                             .union(Set({ rk: "H", cid: cid, tgt: root, rts: Set(), id: -1 })))

  pure def sendDownload(s: St, cid: int): St =
    val c = s.chains.get(cid)
    s.with("chains", s.chains.put(cid,
       c.with("kind", "Down").with("blocks", []).with("awaiting", s.nextReq)))
     .with("flight", s.flight.union(Set(
       { rk: "D", cid: cid, tgt: -1, rts: rootSet(c), id: s.nextReq })))
     .with("nextReq", s.nextReq + 1)

  pure def sendProcess(s: St, cid: int): St =
    val c = s.chains.get(cid)
    s.with("chains", s.chains.put(cid, c.with("kind", "Proc").with("awaiting", s.nextReq)))
     .with("flight", s.flight.union(Set(
       { rk: "P", cid: cid, tgt: -1, rts: rootSet(c), id: s.nextReq })))
     .with("nextReq", s.nextReq + 1)

  // Who a download/process result is delivered to.  The spec says owners(R), recomputed
  // from `loc` at delivery time.  FIX instead tags the call and delivers to the chains
  // that actually descend from it -- Split copies `awaiting` to both halves, so both
  // still receive it, which is what owners(R) was there to achieve.
  pure def dispatchOf(s: St, q: Req): Set[int] =
    if (FIX) s.alive.filter(k => s.chains.get(k).awaiting == q.id)
    else ownersOf(s, q.rts)

  // ------------------------------------------------------------------------ Prune
  pure def minPeersChain(s: St): int =
    s.alive.fold(-1, (a, k) =>
      if (a == -1) k
      else if (size(s.chains.get(k).peers) < size(s.chains.get(a).peers)) k
      else a)
  pure def pruneAll(s: St): St =
    range(0, MAXC).foldl(s, (a, _) =>
      if (size(locDom(a)) <= ROOTS_MAX or a.alive == Set()) a
      else dropChain(a, minPeersChain(a)))

  // ------------------------------------------------------------------------ Promote
  pure def readyProcessable(s: St): Set[int] =
    s.alive.filter(k => s.chains.get(k).kind == "Ready" and s.chains.get(k).target.in(s.fc))

  pure def eligible(s: St): Set[int] =
    s.alive.filter(k =>
      val c = s.chains.get(k)
      and {
        c.kind == "Anch",
        length(c.roots) > 0,       // defensive; the spec's `pick` states neither guard
        c.peers != Set(),
        c.target.in(s.fc) or
          (s.loc.get(c.target) != -1 and isFwd(s.chains.get(s.loc.get(c.target))))
      })

  pure def pickOne(s: St): int =
    eligible(s).fold(-1, (best, k) =>
      if (best == -1) k
      else if (oldestSlot(s.chains.get(k)) < oldestSlot(s.chains.get(best))) k
      else if (oldestSlot(s.chains.get(k)) == oldestSlot(s.chains.get(best)) and k < best) k
      else best)

  pure def promoteOne(s: St): St =
    if (syncingBlocks(s) >= N) s
    else
      val cid = pickOne(s)
      if (cid == -1) s
      else
        val c = s.chains.get(cid)
        val s1 = if (length(c.roots) > B) splitChain(s, cid, c.roots[length(c.roots) - B]) else s
        val y = s1.chains.get(cid)
        sendDownload(s1.with("chains",
          s1.chains.put(cid, y.with("errors", 0).with("cerrors", 0))), cid)

  pure def promote(s: St): St =
    range(0, MAXC).foldl(s, (a, _) =>
      val a1 = readyProcessable(a).fold(a, (x, k) => sendProcess(x, k))
      promoteOne(a1))

  // ================================================================== Search(r, {p})
  pure def doSearch(s0: St, r: int, p: int): St =
    val s = s0.with("searched", s0.searched.union(Set(r)))
              .with("claimed", s0.claimed.put(p, s0.claimed.get(p).union(Set(r))))
    if (r.in(s.fc) or slotOf(r) <= s.finSlot) s0
    else
      val cid = s.loc.get(r)
      val sA =
        if (cid == -1)
          val nid = freeId(s)
          if (nid == -1) s.with("budgetHit", true)
          else
            sendHeaders(
              s.with("alive", s.alive.union(Set(nid)))
               .with("chains", s.chains.put(nid,
                 { roots: [], peers: Set(p), errors: 0, cerrors: 0,
                   kind: "Disc", target: r, blocks: [], awaiting: -1 }))
               .with("loc", s.loc.put(r, nid)),
              nid, r)
        else
          val c = s.chains.get(cid)
          if (length(c.roots) > 0 and c.roots[0] == r)
            s.with("chains", s.chains.put(cid, c.with("peers", c.peers.union(Set(p)))))
          else if (c.kind == "Disc" and c.target == r)
            // FIX: c.roots are DESCENDANTS of r. Claiming r says nothing about holding
            // them, so admitting p here breaks Inv 3. Safe only while c.roots is empty.
            if (FIX and length(c.roots) > 0) s
            else s.with("chains", s.chains.put(cid, c.with("peers", c.peers.union(Set(p)))))
          else
            // Split(c, r); Y (== cid) keeps [r .. oldest] and takes the new peer
            val s1 = splitChain(s, cid, r)
            val y = s1.chains.get(cid)
            s1.with("chains", s1.chains.put(cid, y.with("peers", y.peers.union(Set(p)))))
      // then ascend: the peer that claimed r holds every ancestor of r
      val owner = sA.loc.get(r)
      val sB =
        if (owner == -1 or not(owner.in(sA.alive))) sA
        else
          val c = sA.chains.get(owner)
          if (hasParent(c)) ascend(sA, c.target, Set(p)) else sA
      promote(pruneAll(sB))

  // ============================================================ OnHeaders(c, result)
  type HAcc = { s: St, cid: int, halted: bool, dropped: bool, unres: int }

  pure def hStep(a: HAcc, h: int): HAcc =
    if (a.halted or a.dropped or not(a.cid.in(a.s.alive))) a
    else
      val s = a.s
      if (slotOf(h) <= s.finSlot and h != s.finRoot)
        // conflicts with finality: report_peer(c.peers); Drop(c)
        { s: dropChain(s, a.cid), cid: a.cid, halted: true, dropped: true, unres: -1 }
      else
        val c = s.chains.get(a.cid)
        // push (header.root, header.slot).  cerrors (ghost) resets: this is real progress.
        val c2 = c.with("roots", c.roots.append(h))
                  .with("cerrors", 0)
                  .with("errors", if (FIX) 0 else c.errors)
        val s1 = s.with("chains", s.chains.put(a.cid, c2)).with("loc", s.loc.put(h, a.cid))
        val p = parentOf(h)
        if (p.in(s1.fc))
          { s: s1.with("chains", s1.chains.put(a.cid, c2.with("kind", "Anch").with("target", p))),
            cid: a.cid, halted: true, dropped: false, unres: -1 }
        else if (s1.loc.get(p) != -1)
          val c3 = c2.with("kind", "Anch").with("target", p)
          val s2 = s1.with("chains", s1.chains.put(a.cid, c3))
          { s: ascend(s2, p, c3.peers), cid: a.cid, halted: true, dropped: false, unres: -1 }
        else
          { s: s1.with("loc", s1.loc.put(p, a.cid)),
            cid: a.cid, halted: false, dropped: false, unres: p }

  pure def onHeadersOk(s0: St, cid: int, headers: List[int]): St =
    if (FIX and length(headers) == 0) onHeadersErr(s0, cid) else
    val s = s0.with("flight", s0.flight.filter(q => not(q.rk == "H" and q.cid == cid)))
    val a = headers.foldl({ s: s, cid: cid, halted: false, dropped: false, unres: -1 }, (acc, h) => hStep(acc, h))
    val sEnd =
      if (a.dropped) a.s
      else if (a.unres != -1) sendHeaders(a.s, cid, a.unres)
      // NOTE: headers == [] lands here -- no halt, no unresolved parent, so nothing is
      // re-sent and the chain stays Discovering with no request in flight.  Defect 1.
      else a.s
    promote(pruneAll(sEnd))

  pure def bumpAndRetryHeaders(s: St, cid: int): St =
    val c = s.chains.get(cid)
    val e = c.errors + 1
    val ce = c.cerrors + 1
    if (e > RETRY_MAX)
      dropChain(if (ce <= RETRY_MAX) s.with("earlyDrop", true) else s, cid)
    else
      sendHeaders(s.with("chains", s.chains.put(cid, c.with("errors", e).with("cerrors", ce))),
                  cid, c.target)

  pure def onHeadersErr(s0: St, cid: int): St =
    val s = s0.with("flight", s0.flight.filter(q => not(q.rk == "H" and q.cid == cid)))
    promote(bumpAndRetryHeaders(s, cid))

  // ========================================================== OnDownload(R, result)
  pure def bumpAndRetryDownload(s: St, cid: int): St =
    val c = s.chains.get(cid)
    val e = c.errors + 1
    val ce = c.cerrors + 1
    if (e > RETRY_MAX)
      dropChain(if (ce <= RETRY_MAX) s.with("earlyDrop", true) else s, cid)
    else
      sendDownload(s.with("chains", s.chains.put(cid, c.with("errors", e).with("cerrors", ce))), cid)

  pure def onDownloadErr(s0: St, req: Req): St
    = val tgts = dispatchOf(s0, req)
      val s = s0.with("flight", s0.flight.filter(q => not(q.rk == "D" and q.id == req.id)))
      promote(tgts.fold(s, (acc, cid) =>
        if (not(cid.in(acc.alive))) acc else bumpAndRetryDownload(acc, cid)))

  // `got` is the set of roots the peer actually returned; got == R is the well-behaved case.
  pure def onDownloadOk(s0: St, req: Req, got: Set[int]): St =
    val tgts = dispatchOf(s0, req)
    val s = s0.with("flight", s0.flight.filter(q => not(q.rk == "D" and q.id == req.id)))
    promote(tgts.fold(s, (acc, cid) =>
      if (not(cid.in(acc.alive)) or not(isFwd(acc.chains.get(cid)))) acc
      else
        val c = acc.chains.get(cid)
        acc.with("chains", acc.chains.put(cid,
          c.with("kind", "Ready")
           .with("blocks", rev(c.roots).select(b => b.in(got)))))))

  // =========================================================== OnProcess(R, result)
  pure def onProcessOk(s0: St, req: Req): St =
    val owners = dispatchOf(s0, req)
    val s = s0.with("flight", s0.flight.filter(q => not(q.rk == "P" and q.id == req.id)))
    val sEnd = owners.fold(s.with("fc", s.fc.union(req.rts)), (acc, cid) =>
      if (not(cid.in(acc.alive))) acc
      else
        // plain removal, not Drop: the descendants are now eligible, not dead
        val rs = rootSet(acc.chains.get(cid))
        acc.with("alive", acc.alive.exclude(Set(cid)))
           .with("chains", acc.chains.put(cid, DEAD))
           .with("loc", locDel(acc, rs)))
    promote(sEnd)

  pure def onProcessErr(s0: St, req: Req): St =
    val tgts = dispatchOf(s0, req)
    val s = s0.with("flight", s0.flight.filter(q => not(q.rk == "P" and q.id == req.id)))
    promote(tgts.fold(s, (acc, cid) =>
      if (not(cid.in(acc.alive))) acc else bumpAndRetryDownload(acc, cid)))

  // ============================================================== Disconnect(p)
  pure def doDisconnect(s: St, p: int): St =
    val s1 = s.with("chains", CHAINIDS.mapBy(k =>
      val c = s.chains.get(k)
      c.with("peers", c.peers.exclude(Set(p)))))
    val orphaned = s1.alive.filter(k => s1.chains.get(k).peers == Set())
    promote(orphaned.fold(s1, (a, k) => if (k.in(a.alive)) dropChain(a, k) else a))

  // ==================================================================== transitions
  action init = all {
    st' = {
      fc: Set(0), finRoot: 0, finSlot: 0,
      loc: ROOTS.mapBy(r => -1),
      alive: Set(),
      chains: CHAINIDS.mapBy(k => DEAD),
      flight: Set(),
      nextReq: 0,
      abandoned: Set(), searched: Set(),
      claimed: PEERS.mapBy(p => Set()),
      earlyDrop: false, budgetHit: false
    }
  }

  action aSearch = {
    nondet r = ROOTS.exclude(Set(0)).oneOf()
    nondet p = PEERS.oneOf()
    st' = doSearch(st, r, p)
  }

  // Adversarial header response.  A well-formed Ok(h) must satisfy h[0].root = root and
  // h[i].root = h[i-1].parent_root, so it is exactly a prefix of the true ancestor walk;
  // k = 0 is the empty answer, which the spec's guarantee permits vacuously.
  action aOnHeadersOk = {
    nondet q = st.flight.filter(f => f.rk == "H").oneOf()
    nondet k = Set(0, 1, 2, 3).oneOf()
    all {
      st.flight.exists(f => f.rk == "H"),
      q.cid.in(st.alive),
      st.chains.get(q.cid).kind == "Disc",
      st.chains.get(q.cid).target == q.tgt,
      st' = onHeadersOk(st, q.cid, walkList(q.tgt, k))
    }
  }
  action aOnHeadersErr = {
    nondet q = st.flight.filter(f => f.rk == "H").oneOf()
    all {
      st.flight.exists(f => f.rk == "H"),
      q.cid.in(st.alive),
      st.chains.get(q.cid).kind == "Disc",
      st' = onHeadersErr(st, q.cid)
    }
  }

  // SendDownload guarantees Ok(blocks) "covers exactly the roots of R as a set".
  action aOnDownloadOk = {
    nondet q = st.flight.filter(f => f.rk == "D").oneOf()
    all { st.flight.exists(f => f.rk == "D"), st' = onDownloadOk(st, q, q.rts) }
  }
  // ... and here the peer breaks that guarantee: a short or empty block set.
  action aOnDownloadShort = {
    nondet q = st.flight.filter(f => f.rk == "D").oneOf()
    nondet g = q.rts.powerset().oneOf()
    all { st.flight.exists(f => f.rk == "D"), g != q.rts, st' = onDownloadOk(st, q, g) }
  }
  action aOnDownloadErr = {
    nondet q = st.flight.filter(f => f.rk == "D").oneOf()
    all { st.flight.exists(f => f.rk == "D"), st' = onDownloadErr(st, q) }
  }

  action aOnProcessOk = {
    nondet q = st.flight.filter(f => f.rk == "P").oneOf()
    all { st.flight.exists(f => f.rk == "P"), st' = onProcessOk(st, q) }
  }
  action aOnProcessErr = {
    nondet q = st.flight.filter(f => f.rk == "P").oneOf()
    all { st.flight.exists(f => f.rk == "P"), st' = onProcessErr(st, q) }
  }

  action aDisconnect = {
    nondet p = PEERS.oneOf()
    st' = doDisconnect(st, p)
  }
  action aDisconnectAdv = {
    nondet p = PEERS.exclude(Set(HONEST)).oneOf()
    st' = doDisconnect(st, p)
  }

  // finalized is external and grows only; it can only advance to a root in fork choice
  action aFinalize = {
    nondet r = st.fc.oneOf()
    all {
      st.fc.exists(x => slotOf(x) > st.finSlot),
      slotOf(r) > st.finSlot,
      st' = st.with("finRoot", r).with("finSlot", slotOf(r))
    }
  }

  action aStutter = { st' = st }

  // The full adversary.
  action step = any {
    aSearch, aOnHeadersOk, aOnHeadersErr,
    aOnDownloadOk, aOnDownloadShort, aOnDownloadErr,
    aOnProcessOk, aOnProcessErr,
    aDisconnect, aFinalize, aStutter
  }

  // Peers keep the guarantees the spec writes down (downloads cover R exactly).
  // Empty header responses stay in: the spec's guarantee admits them vacuously.
  action stepStrict = any {
    aSearch, aOnHeadersOk, aOnHeadersErr,
    aOnDownloadOk, aOnDownloadErr,
    aOnProcessOk, aOnProcessErr,
    aDisconnect, aFinalize, aStutter
  }

  // As stepStrict, but peers never answer a header request with nothing -- used to show
  // which failures are independent of defect 1.
  action aOnHeadersOkNonEmpty = {
    nondet q = st.flight.filter(f => f.rk == "H").oneOf()
    nondet k = Set(1, 2, 3).oneOf()
    all {
      st.flight.exists(f => f.rk == "H"),
      q.cid.in(st.alive),
      st.chains.get(q.cid).kind == "Disc",
      st.chains.get(q.cid).target == q.tgt,
      st' = onHeadersOk(st, q.cid, walkList(q.tgt, k))
    }
  }
  action stepNoEmptyHeaders = any {
    aSearch, aOnHeadersOkNonEmpty, aOnHeadersErr,
    aOnDownloadOk, aOnDownloadErr,
    aOnProcessOk, aOnProcessErr,
    aDisconnect, aFinalize, aStutter
  }

  // Liveness configuration: one honest peer that holds the chain and never disconnects,
  // every response well-formed and complete, but requests may still fail intermittently.
  action stepHonest = any {
    aSearch, aOnHeadersOkNonEmpty, aOnHeadersErr,
    aOnDownloadOk, aOnDownloadErr,
    aOnProcessOk, aOnProcessErr,
    aDisconnectAdv, aFinalize, aStutter
  }

  // ==================================================================== invariants
  // Inv 1. loc(r) = c  <=>  r in c.roots or c.state = Discovering(r)
  val Inv1 = and {
    locDom(st).forall(r =>
      val cid = st.loc.get(r)
      and { cid.in(st.alive),
            r.in(rootSet(st.chains.get(cid)))
              or (st.chains.get(cid).kind == "Disc" and st.chains.get(cid).target == r) }),
    st.alive.forall(k =>
      val c = st.chains.get(k)
      and { rootSet(c).forall(r => st.loc.get(r) == k),
            c.kind != "Disc" or st.loc.get(c.target) == k })
  }

  // Inv 2. c.roots contiguous by parent_root, tip first
  val Inv2 = st.alive.forall(k =>
    val l = st.chains.get(k).roots
    if (length(l) <= 1) true
    else range(0, length(l) - 1).foldl(true, (a, i) => a and parentOf(l[i]) == l[i + 1]))

  // Inv 3. p in c.peers => p claimed every root in c.roots.  Checked against what peers
  // actually claimed via Search, closed under "holding r implies holding its ancestors".
  val Inv3 = st.alive.forall(k =>
    val c = st.chains.get(k)
    c.peers.forall(p =>
      rootSet(c).forall(r => st.claimed.get(p).exists(q => r.in(ancestry(q))))))

  // Inv 4. slot strictly decreases along c.roots
  val Inv4 = st.alive.forall(k =>
    val l = st.chains.get(k).roots
    if (length(l) <= 1) true
    else range(0, length(l) - 1).foldl(true, (a, i) => a and slotOf(l[i]) > slotOf(l[i + 1])))

  // Inv 5. Ready/Processing => blocks is c.roots reversed, one block per root, chained;
  //        Processing also => parent(blocks[0]) in FC.
  val Inv5 = st.alive.forall(k =>
    val c = st.chains.get(k)
    and {
      c.kind != "Ready" and c.kind != "Proc" or c.blocks == rev(c.roots),
      c.kind != "Proc" or (length(c.blocks) > 0 and parentOf(c.blocks[0]).in(st.fc))
    })

  // Inv 5 with the Processing clause weakened to what Split actually preserves.
  val Inv5weak = st.alive.forall(k =>
    val c = st.chains.get(k)
    and {
      c.kind != "Ready" and c.kind != "Proc" or c.blocks == rev(c.roots),
      c.kind != "Proc" or (length(c.blocks) > 0 and
        (parentOf(c.blocks[0]).in(st.fc) or st.loc.get(parentOf(c.blocks[0])) != -1))
    })

  // Inv 6. Anchored(p) => p in FC or p in dom(loc)
  val Inv6 = st.alive.forall(k =>
    val c = st.chains.get(k)
    c.kind != "Anch" or c.target.in(st.fc) or st.loc.get(c.target) != -1)

  // NoOrphanedWait (not in the spec): a chain in Discovering / Downloading / Processing
  // always has a request in flight that can still reach it.
  val NoOrphanedWait = st.alive.forall(k =>
    val c = st.chains.get(k)
    if (c.kind == "Disc")
      st.flight.exists(q => q.rk == "H" and q.cid == k)
    else if (c.kind == "Down")
      st.flight.exists(q => q.rk == "D" and dispatchOf(st, q).contains(k))
    else if (c.kind == "Proc")
      st.flight.exists(q => q.rk == "P" and dispatchOf(st, q).contains(k))
    else true)

  // Bounded liveness: no state in which the forest is non-empty but nothing can advance it.
  val Stuck = and {
    st.alive != Set(),
    st.flight == Set(),
    readyProcessable(st) == Set(),
    eligible(st) == Set()
  }
  val NoStuckForest = not(Stuck)

  // Defect 2 probe: `errors` should bound the retries of one step, not the lifetime of a
  // chain.  cerrors is the per-step count; they diverge exactly when progress fails to
  // reset the budget.
  val ErrorsAreConsecutive = st.alive.forall(k => st.chains.get(k).errors == st.chains.get(k).cerrors)
  // ... and this is the harm: a chain dropped while its per-step budget was still intact.
  val NoEarlyDrop = not(st.earlyDrop)

  // Sanity/bound probes
  val NoBudgetHit = not(st.budgetHit)
  val AnchoredHasRoots = st.alive.forall(k =>
    val c = st.chains.get(k)
    c.kind == "Disc" or length(c.roots) > 0)

  // OnDownload/OnProcess dispatch per root via `loc`, with no check that the owner is the
  // chain the request was issued for.  If a root leaves the issuing chain and is later
  // re-claimed by an unrelated Search, the stale response is delivered to a Backfill chain.
  val NoStaleDispatch = st.flight.forall(q =>
    q.rk == "H" or dispatchOf(st, q).forall(k =>
      val c = st.chains.get(k)
      (if (q.rk == "D") c.kind == "Down" else c.kind == "Proc") and rootSet(c).subseteq(q.rts)))

  val NoEmptyDownload = st.alive.forall(k =>
    val c = st.chains.get(k)
    c.kind != "Down" or length(c.roots) > 0)

  val AllInvs = and { Inv1, Inv2, Inv3, Inv4, Inv5, Inv6 }
  val Everything = and { AllInvs, NoOrphanedWait, NoStuckForest }

  // ==================================================================== liveness
  // Strengthened liveness (the spec's own "every root reaches FC or is dropped" is
  // vacuous -- dropping everything satisfies it).  Here every chain always holds one
  // honest peer that holds the whole chain and never disconnects; requests may still
  // fail transiently, which is exactly what RETRY_MAX exists for.  Under fairness
  // (retries eventually succeed) every searched root must reach FC, so:
  //   * no root may ever be abandoned, and
  //   * no reachable state may be stuck (nothing in flight, nothing promotable).
  action aSearchHonest = {
    nondet r = ROOTS.exclude(Set(0)).oneOf()
    st' = doSearch(st, r, HONEST)
  }
  action stepLive = any {
    aSearchHonest, aOnHeadersOk, aOnHeadersErr,
    aOnDownloadOk, aOnDownloadErr, aOnProcessOk, aOnProcessErr,
    aFinalize, aStutter
  }
  val NothingAbandoned = st.abandoned == Set()
  val Live = and { NothingAbandoned, NoStuckForest }
}

module base  { import treesync(FIX = false, MAXC = 6, ROOTS_MAX = 6).* }
module fixed { import treesync(FIX = true,  MAXC = 6, ROOTS_MAX = 6).* }
// Small instances, for symbolic checking with Apalache.
module base3  { import treesync(FIX = false, MAXC = 3, ROOTS_MAX = 6).* }
module fixed3 { import treesync(FIX = true,  MAXC = 3, ROOTS_MAX = 6).* }
// Prune-exercising instances: ROOTS_MAX = 3 with 6 roots, so Prune fires constantly.
module basePrune  { import treesync(FIX = false, MAXC = 6, ROOTS_MAX = 3).* }
module fixedPrune { import treesync(FIX = true,  MAXC = 6, ROOTS_MAX = 3).* }
