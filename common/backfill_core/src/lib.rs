//! The decision core of backfill sync, addressed by root instead of by slot range.
//!
//! Backfill walks backwards from the anchor one run of ancestors at a time, over
//! `BlocksByHead` (consensus-specs #5181): a request names a block root, and the response is
//! that block's parent chain in descending slot order. Verifying it needs nothing but the
//! response and the frontier we already hold — the run must start at the root we asked for
//! and hash-link down from it — so a response is accepted or rejected the instant it
//! arrives, and the peer that sent it is the only suspect.
//!
//! That is the whole reason this module is small. Addressing history by slot range makes a
//! response unverifiable on arrival: a batch can only be checked once the batch above it has
//! been imported, so faults surface late, with several suspects, and the machine grows a
//! window, a per-batch state machine, seam reconciliation and a retro-scoring pass to work
//! out who lied. None of that has anything to answer here.
//!
//! # Properties
//!
//! This file is extracted to Lean by Charon and Aeneas — `proofs/` next to it, `extract.sh`
//! to regenerate — and these are proved about it, not about a model of it:
//!
//! - **S** every `Store` carries a run hash-linked from the frontier, with strictly
//!   decreasing slots, and the staged frontier is its oldest header.
//! - **A** every `Penalize` names the peer that served the run being judged.
//! - **P** a measure strictly decreases on every event but `PeerJoined`, or the state is
//!   unchanged and no action is emitted.
//! - **R** `from_anchor` re-establishes the invariant from `AnchorInfo` alone.
//!
//! Totality is part of every proof, which is what covers the bare indexing in `check_run`:
//! the extracted model is shown never to reach `fail`, so the index cannot go out of bounds.
//!
//! # Subset
//!
//! Kept to what Charon and Aeneas accept, which costs nothing here and is worth stating as
//! style: no generics, no traits, no borrows held across returns, no `Arc`, no async, no
//! clock, no maps. `Hash256` is a `u64` because only equality is ever used on roots, and
//! `PeerId` is an index into a table the adapter owns, so the core cannot do peer policy.

pub type Slot = u64;
pub type PeerIdx = u32;

/// A `Hash256` as four words. Only equality is ever used on a root, but it has to be
/// equality of all 256 bits: a 64-bit stand-in would be a collision away from accepting a
/// fabricated ancestor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Root {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub d: u64,
}

/// Non-short-circuiting `&` again, so this is one expression rather than a branch tree.
pub fn root_eq(x: Root, y: Root) -> bool {
    ((x.a == y.a) & (x.b == y.b)) & ((x.c == y.c) & (x.d == y.d))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub root: Root,
    pub parent_root: Root,
    pub slot: Slot,
}

#[derive(Clone, Copy)]
pub struct Config {
    /// Ancestors asked for per request, capped by `MAX_REQUEST_BLOCKS` in the adapter.
    pub run_len: u64,
    /// Consecutive failures tolerated before parking. Refilled only by a run that imports,
    /// so a budget that is spent can only be earned back by progress.
    pub max_attempts: u8,
}

/// What the machine is waiting for. Every variant names the event that resolves it, so
/// there is no state from which nothing can happen: `Idle` waits on `Tick`, `Pending` on
/// `Run` or `Fail`, `Importing` on `Imported` or `Rejected`, `Parked` on `PeerJoined`.
#[derive(Clone, Copy)]
pub enum Wait {
    Idle,
    Pending,
    /// A verified run is with the store. `staged` becomes the frontier once the store
    /// confirms, and `peer` is who served it — the one to penalise if the store rejects it.
    Importing {
        staged: Header,
        peer: PeerIdx,
    },
    Parked,
}

pub struct Backfill {
    pub cfg: Config,
    /// Oldest header the store holds. Its parent is what we ask for next.
    pub frontier: Header,
    /// Backfill is complete once the frontier reaches this slot.
    pub target_slot: Slot,
    pub attempts: u8,
    pub wait: Wait,
    /// Last peer to fail us on the current anchor, passed out so the adapter can avoid it.
    pub last_bad: Option<PeerIdx>,
    pub done: bool,
}

/// The adapter owns the RPC, the clock and the peer table, so a timeout, an RPC error and a
/// disconnect all arrive here as `Fail`. Every `Request` produces exactly one `Run` or
/// `Fail`, and every `Store` exactly one `Imported`, `Rejected` or `Abandoned`.
pub enum Event {
    Tick,
    Run {
        peer: PeerIdx,
        headers: Vec<Header>,
    },
    /// The request produced nothing. `None` when it could not be sent at all, so there is no
    /// peer to avoid next time.
    Fail {
        peer: Option<PeerIdx>,
    },
    Imported,
    /// The store refused the run, so the peer that served it is at fault.
    Rejected,
    /// The run could not be made durable for a reason that is not its server's fault — the
    /// sidecars it needs could not be fetched, the processor could not take it. Retry, but
    /// do not blame the peer that served the blocks for what a different peer owed us.
    Abandoned,
    PeerJoined,
}

pub enum Action {
    Request {
        anchor: Root,
        count: u64,
        avoid: Option<PeerIdx>,
    },
    Store {
        headers: Vec<Header>,
    },
    Penalize {
        peer: PeerIdx,
    },
    Complete,
}

/// Accepts `headers` as the ancestors of `expected`, newest first, all older than `bound`.
/// Returns the oldest header of the run, which is staged to become the frontier.
///
/// This is the entire verification story of a response: `expected` is a root the store has
/// already committed to, so a run that starts there and links internally is proved by the
/// response alone, against no external state and no other peer's work.
// `&Vec` rather than `&[Header]` on purpose: the extraction models a `Vec` directly, and a
// slice would change the model this file's proofs are written against for no gain here.
#[allow(clippy::ptr_arg)]
pub fn check_run(expected: Root, bound: Slot, headers: &Vec<Header>) -> Option<Header> {
    let mut linked = true;
    let mut want = expected;
    let mut limit = bound;
    let mut last: Option<Header> = None;
    let mut i: usize = 0;
    while i < headers.len() {
        let header = headers[i];
        // Branch-free, so the body is one expression rather than a pair of conditional
        // assignments: that is what the run has to satisfy, said once.
        linked = linked & root_eq(header.root, want) & (header.slot < limit);
        want = header.parent_root;
        limit = header.slot;
        last = Some(header);
        i += 1;
    }
    if linked { last } else { None }
}

/// Spend one attempt. At zero the machine parks rather than failing the sync: production
/// fails the whole sync here and then sits dead until a peer arrives, which is a state the
/// machine cannot leave on its own.
pub fn retry(bf: &mut Backfill) {
    if bf.attempts > 1 {
        bf.attempts -= 1;
        bf.wait = Wait::Idle;
    } else {
        bf.attempts = 0;
        bf.wait = Wait::Parked;
    }
}

pub fn on_tick(bf: &mut Backfill) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Pending => {}
        Wait::Importing { staged: _, peer: _ } => {}
        Wait::Parked => {}
        Wait::Idle => {
            if bf.done {
            } else {
                out.push(Action::Request {
                    anchor: bf.frontier.parent_root,
                    count: bf.cfg.run_len,
                    avoid: bf.last_bad,
                });
                bf.wait = Wait::Pending;
            }
        }
    }
    out
}

pub fn on_run(bf: &mut Backfill, peer: PeerIdx, headers: Vec<Header>) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Idle => {}
        Wait::Importing { staged: _, peer: _ } => {}
        Wait::Parked => {}
        Wait::Pending => {
            let checked = check_run(bf.frontier.parent_root, bf.frontier.slot, &headers);
            match checked {
                None => {
                    out.push(Action::Penalize { peer });
                    bf.last_bad = Some(peer);
                    retry(bf);
                }
                Some(oldest) => {
                    bf.wait = Wait::Importing {
                        staged: oldest,
                        peer,
                    };
                    out.push(Action::Store { headers });
                }
            }
        }
    }
    out
}

/// The store has the run. It is the arbiter of everything the headers do not cover —
/// proposer signatures, Gloas envelopes, blobs and columns — so the frontier moves here and
/// not when the response arrived.
pub fn on_imported(bf: &mut Backfill) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Idle => {}
        Wait::Pending => {}
        Wait::Parked => {}
        Wait::Importing { staged, peer: _ } => {
            bf.frontier = staged;
            bf.attempts = bf.cfg.max_attempts;
            bf.last_bad = None;
            bf.wait = Wait::Idle;
            if staged.slot <= bf.target_slot {
                bf.done = true;
                out.push(Action::Complete);
            }
        }
    }
    out
}

/// The store rejected a run that was hash-linked, so the fault is in a part of the block
/// the root does not commit to. The peer that served it is named by the state, not guessed
/// from a batch's peer set.
pub fn on_rejected(bf: &mut Backfill) -> Vec<Action> {
    let mut out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Idle => {}
        Wait::Pending => {}
        Wait::Parked => {}
        Wait::Importing { staged: _, peer } => {
            out.push(Action::Penalize { peer });
            bf.last_bad = Some(peer);
            retry(bf);
        }
    }
    out
}

/// The run is gone for a reason nobody is provably to blame for, so retry it elsewhere and
/// spend an attempt, but penalise no one.
pub fn on_abandoned(bf: &mut Backfill) -> Vec<Action> {
    let out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Idle => {}
        Wait::Pending => {}
        Wait::Parked => {}
        Wait::Importing { staged: _, peer } => {
            bf.last_bad = Some(peer);
            retry(bf);
        }
    }
    out
}

pub fn on_fail(bf: &mut Backfill, peer: Option<PeerIdx>) -> Vec<Action> {
    let out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Idle => {}
        Wait::Importing { staged: _, peer: _ } => {}
        Wait::Parked => {}
        Wait::Pending => {
            bf.last_bad = peer;
            retry(bf);
        }
    }
    out
}

pub fn on_peer_joined(bf: &mut Backfill) -> Vec<Action> {
    let out: Vec<Action> = Vec::new();
    match bf.wait {
        Wait::Idle => {}
        Wait::Pending => {}
        Wait::Importing { staged: _, peer: _ } => {}
        Wait::Parked => {
            bf.attempts = bf.cfg.max_attempts;
            bf.last_bad = None;
            bf.wait = Wait::Idle;
        }
    }
    out
}

pub fn step(bf: &mut Backfill, ev: Event) -> Vec<Action> {
    match ev {
        Event::Tick => on_tick(bf),
        Event::Run { peer, headers } => on_run(bf, peer, headers),
        Event::Fail { peer } => on_fail(bf, peer),
        Event::Imported => on_imported(bf),
        Event::Rejected => on_rejected(bf),
        Event::Abandoned => on_abandoned(bf),
        Event::PeerJoined => on_peer_joined(bf),
    }
}

/// The whole persisted state is the frontier — `AnchorInfo`'s `oldest_block_parent` and
/// `oldest_block_slot`. Everything else is rebuilt here, so a restart is not a special case
/// and there is nothing to drift.
pub fn from_anchor(cfg: Config, oldest: Header, target_slot: Slot) -> Backfill {
    Backfill {
        cfg,
        frontier: oldest,
        target_slot,
        attempts: cfg.max_attempts,
        wait: Wait::Idle,
        last_bad: None,
        done: oldest.slot <= target_slot,
    }
}
