//! The decision core of backfill sync, addressed by root instead of by slot range.
//!
//! Backfill walks backwards from the anchor one run of ancestors at a time over `BlocksByHead`
//! (consensus-specs #5181): a request names a block root, and the response is that block's
//! parent chain in descending slot order. Verifying it needs only the response and the frontier
//! we already hold, so a run is accepted or rejected on arrival and the peer that sent it is
//! the only suspect. By slot range a response cannot be checked until the range above it has
//! been imported, which is where the window, the per-batch state machine, the seam
//! reconciliation and the retro-scoring pass all come from. None of that applies here.
//!
//! # Properties
//!
//! Charon and Aeneas extract this file to Lean (`proofs/`, regenerate with `extract.sh`), and
//! these are proved about it rather than about a model of it:
//!
//! - **S** every `Store` carries a run hash-linked from the frontier, slots strictly
//!   decreasing, sent by the peer the state then records, and the staged frontier is its
//!   oldest header. Its converse holds too: every honest run is accepted, so the core cannot
//!   satisfy the rest by rejecting everything.
//! - **A** every `Penalize` names the peer that served the run being judged.
//! - **P** every event but `PeerJoined` strictly decreases a measure, or changes nothing and
//!   emits nothing.
//! - **R** `from_anchor` re-establishes the invariant from `AnchorInfo` alone.
//!
//! Each is a total-correctness statement, so `step` is also proved never to fail — which is
//! what licenses the bare indexing in `check_run`.
//!
//! # Subset
//!
//! Only what Charon and Aeneas accept: no generics, traits, iterators, borrows held across
//! returns, `Arc`, async, clock or maps. A `PeerId` is an index into a table the adapter owns,
//! so the core cannot do peer policy.

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

/// The properties above are proved in Lean, which CI does not run. These are the same claims in
/// Rust, so an edit here that breaks one fails the test suite too.
#[cfg(test)]
mod tests {
    use super::*;

    fn root_of(n: u64) -> Root {
        Root {
            a: n,
            b: 0,
            c: 0,
            d: 0,
        }
    }

    fn header(root: u64, parent: u64, slot: u64) -> Header {
        Header {
            root: root_of(root),
            parent_root: root_of(parent),
            slot,
        }
    }

    /// `Header` carries no derives it does not need, so runs are compared by their fields.
    fn oldest(checked: Option<Header>) -> Option<(u64, u64)> {
        checked.map(|header| (header.slot, header.root.a))
    }

    fn penalized(actions: &[Action]) -> Vec<PeerIdx> {
        let mut peers = vec![];
        for action in actions {
            match action {
                Action::Penalize { peer } => peers.push(*peer),
                Action::Request { .. } | Action::Store { .. } | Action::Complete => {}
            }
        }
        peers
    }

    fn machine(max_attempts: u8) -> Backfill {
        from_anchor(
            Config {
                run_len: 64,
                max_attempts,
            },
            header(9, 8, 30),
            0,
        )
    }

    /// `store_is_verified_descent`: what reaches the store starts at the root we asked for and
    /// links down from it.
    #[test]
    fn a_run_is_only_accepted_when_it_links_to_the_frontier() {
        let run = vec![header(9, 8, 30), header(8, 7, 29), header(7, 6, 27)];

        assert_eq!(
            oldest(check_run(root_of(9), 31, &run)),
            Some((27, 7)),
            "a linked run is accepted and its oldest header becomes the frontier"
        );
        assert_eq!(
            oldest(check_run(root_of(5), 31, &run)),
            None,
            "wrong anchor"
        );
        assert_eq!(
            oldest(check_run(root_of(9), 30, &run)),
            None,
            "not older than the frontier"
        );
        assert_eq!(
            oldest(check_run(root_of(9), 31, &vec![])),
            None,
            "an empty run is no progress, so it is not a link"
        );
        assert_eq!(
            oldest(check_run(
                root_of(9),
                31,
                &vec![header(9, 8, 30), header(4, 3, 29)]
            )),
            None,
            "a break in the middle"
        );
        assert_eq!(
            oldest(check_run(
                root_of(9),
                31,
                &vec![header(9, 8, 30), header(8, 7, 30)]
            )),
            None,
            "slots that do not descend"
        );
    }

    /// The sequence the adapter implements: ask, verify, stage, import.
    #[test]
    fn a_landed_run_advances_the_frontier_and_refills_the_budget() {
        let mut bf = machine(3);

        let actions = step(&mut bf, Event::Tick);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Request { anchor, .. } => assert!(root_eq(*anchor, root_of(8))),
            _ => panic!("a tick on an idle machine asks for the frontier's parent"),
        }

        // A run that does not link is the sender's fault, and costs an attempt.
        let actions = step(
            &mut bf,
            Event::Run {
                peer: 1,
                headers: vec![header(4, 3, 29)],
            },
        );
        assert_eq!(penalized(&actions), vec![1]);
        assert_eq!(bf.attempts, 2);
        assert_eq!(bf.frontier.slot, 30);

        // A run that links is staged, and the frontier moves only once the store confirms.
        let _ = step(&mut bf, Event::Tick);
        let actions = step(
            &mut bf,
            Event::Run {
                peer: 2,
                headers: vec![header(8, 7, 29), header(7, 6, 27)],
            },
        );
        match &actions[0] {
            Action::Store { .. } => {}
            _ => panic!("a linked run is handed to the store"),
        }
        assert_eq!(bf.frontier.slot, 30);

        assert!(step(&mut bf, Event::Imported).is_empty());
        assert_eq!(bf.frontier.slot, 27);
        assert_eq!(bf.attempts, 3);
    }

    /// `penalize_names_the_server`: a store rejection names the peer that served the run.
    #[test]
    fn a_rejected_run_is_charged_to_the_peer_that_served_it() {
        let mut bf = machine(3);
        let _ = step(&mut bf, Event::Tick);
        let _ = step(
            &mut bf,
            Event::Run {
                peer: 7,
                headers: vec![header(8, 7, 29)],
            },
        );
        assert_eq!(penalized(&step(&mut bf, Event::Rejected)), vec![7]);

        // Whereas a run that could not be made durable blames no one.
        let _ = step(&mut bf, Event::Tick);
        let _ = step(
            &mut bf,
            Event::Run {
                peer: 7,
                headers: vec![header(8, 7, 29)],
            },
        );
        assert!(step(&mut bf, Event::Abandoned).is_empty());
    }

    /// `progress`: out of attempts the machine parks and waits, rather than spinning or dying.
    #[test]
    fn exhausted_attempts_park_until_a_peer_joins() {
        let mut bf = machine(2);

        for _ in 0..2 {
            let _ = step(&mut bf, Event::Tick);
            let _ = step(&mut bf, Event::Fail { peer: Some(1) });
        }
        assert_eq!(bf.attempts, 0);
        match bf.wait {
            Wait::Parked => {}
            Wait::Idle | Wait::Pending | Wait::Importing { .. } => panic!("expected to park"),
        }
        assert!(step(&mut bf, Event::Tick).is_empty());

        let _ = step(&mut bf, Event::PeerJoined);
        assert_eq!(bf.attempts, 2);
        assert_eq!(step(&mut bf, Event::Tick).len(), 1);
    }
}
