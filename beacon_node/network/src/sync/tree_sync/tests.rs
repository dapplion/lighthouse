//! Tests drive [`TreeSync`] against a ground-truth block tree, playing the network and beacon
//! processor roles: every `Send*` action is queued and later answered per its guarantee (or
//! failed), and the spec invariants are asserted after every transition.

use super::*;
use fixed_bytes::FixedBytesExtended;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use types::{Hash256, Slot};

const FINALIZED_SLOT: u64 = 10;

/// Ground-truth block; `root` is assigned, not hashed, since tests never hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TestBlock {
    root: Hash256,
    parent_root: Hash256,
    slot: Slot,
}

impl TreeSyncBlock for TestBlock {
    fn root(&self) -> Hash256 {
        self.root
    }
}

impl TestBlock {
    fn header(&self) -> HeaderInfo {
        HeaderInfo {
            root: self.root,
            parent_root: self.parent_root,
            slot: self.slot,
        }
    }
}

struct TestForkChoice {
    known: HashSet<Hash256>,
    finalized: (Hash256, Slot),
}

impl ForkChoiceView for TestForkChoice {
    fn contains_block(&self, block_root: &Hash256) -> bool {
        self.known.contains(block_root)
    }
    fn finalized(&self) -> (Hash256, Slot) {
        self.finalized
    }
}

fn root_hash(id: u64) -> Hash256 {
    // Offset so `Hash256::ZERO` is never a valid root.
    Hash256::from_low_u64_be(id + 1)
}

fn peer() -> PeerId {
    PeerId::random()
}

fn config(
    promote_batch_roots: usize,
    max_forward_sync_roots: usize,
    max_retries: u8,
    max_tracked_roots: usize,
) -> Config {
    Config {
        promote_batch_roots,
        max_forward_sync_roots,
        max_retries,
        max_tracked_roots,
    }
}

/// A config that never promotes, keeping chains in their backfill states.
fn backfill_only_config() -> Config {
    config(3, 0, 2, 1000)
}

struct Harness {
    tree: TreeSync<TestBlock>,
    fc: TestForkChoice,
    truth: HashMap<Hash256, TestBlock>,
    /// In-flight requests: `Send*` actions awaiting a response.
    pending: Vec<Action<TestBlock>>,
    reports: Vec<(Vec<PeerId>, &'static str)>,
    finalized: TestBlock,
    next_id: u64,
}

impl Harness {
    fn new(config: Config) -> Self {
        let finalized = TestBlock {
            root: root_hash(0),
            parent_root: Hash256::ZERO,
            slot: Slot::new(FINALIZED_SLOT),
        };
        Self {
            tree: TreeSync::new(config),
            fc: TestForkChoice {
                known: HashSet::from([finalized.root]),
                finalized: (finalized.root, finalized.slot),
            },
            truth: HashMap::from([(finalized.root, finalized)]),
            pending: Vec::new(),
            reports: Vec::new(),
            finalized,
            next_id: 1,
        }
    }

    /// Extends the ground truth with `count` blocks on top of `parent_root`, one slot apart.
    fn extend(&mut self, parent_root: Hash256, count: usize) -> Vec<TestBlock> {
        let mut parent = *self.truth.get(&parent_root).expect("parent must exist");
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let block = TestBlock {
                root: root_hash(self.next_id),
                parent_root: parent.root,
                slot: parent.slot + 1,
            };
            self.next_id += 1;
            self.truth.insert(block.root, block);
            blocks.push(block);
            parent = block;
        }
        blocks
    }

    /// A block on an unknown parent below the finalized slot: chains built on it conflict with
    /// finality.
    fn block_below_finality(&mut self) -> TestBlock {
        let block = TestBlock {
            root: root_hash(self.next_id),
            parent_root: Hash256::repeat_byte(0xff),
            slot: self.finalized.slot - 1,
        };
        self.next_id += 1;
        self.truth.insert(block.root, block);
        block
    }

    fn ingest(&mut self, actions: Vec<Action<TestBlock>>) {
        for action in actions {
            match action {
                Action::ReportPeers { peers, reason } => self.reports.push((peers, reason)),
                request => self.pending.push(request),
            }
        }
    }

    fn search(&mut self, block: &TestBlock, peer: PeerId) {
        let actions = self.tree.search(block.root, block.slot, peer, &self.fc);
        self.ingest(actions);
        self.assert_invariants();
    }

    fn serve_headers(&self, start_root: Hash256, max: usize) -> Vec<HeaderInfo> {
        let mut headers = Vec::new();
        let mut root = start_root;
        while headers.len() < max {
            let Some(block) = self.truth.get(&root) else {
                break;
            };
            headers.push(block.header());
            root = block.parent_root;
        }
        headers
    }

    /// Answers the pending request at `index` per its `Send*` guarantee. Headers requests serve at
    /// most `max_headers` per response.
    fn respond(&mut self, index: usize, max_headers: usize) {
        let actions = match self.pending.remove(index) {
            Action::SendHeaders { start_root, .. } => {
                let headers = self.serve_headers(start_root, max_headers);
                let result = if headers.is_empty() {
                    // No peer can serve a verified header for a root that does not exist.
                    Err("unknown root")
                } else {
                    Ok(headers)
                };
                self.tree.on_headers(start_root, result, &self.fc)
            }
            Action::SendDownload { roots, .. } => {
                let blocks: Vec<TestBlock> = roots
                    .iter()
                    .map(|root| *self.truth.get(root).expect("downloaded root must exist"))
                    .collect();
                self.tree
                    .on_download(&roots, Ok::<_, &str>(blocks), &self.fc)
            }
            Action::SendProcess { roots, blocks } => {
                // Assert the SendProcess guarantee before "importing".
                let first = blocks.first().expect("processed chains are never empty");
                assert!(
                    self.fc.known.contains(&first.parent_root),
                    "SendProcess guarantee: parent of the first block must be in fork choice"
                );
                for (block, root) in blocks.iter().zip(&roots) {
                    assert_eq!(block.root, *root, "SendProcess roots must match blocks");
                }
                for pair in blocks.windows(2) {
                    assert_eq!(pair[1].parent_root, pair[0].root, "blocks must be a chain");
                }
                for block in &blocks {
                    self.fc.known.insert(block.root);
                }
                self.tree.on_process(&roots, Ok::<_, &str>(()), &self.fc)
            }
            Action::ReportPeers { .. } => unreachable!("reports are not pending requests"),
        };
        self.ingest(actions);
        self.assert_invariants();
    }

    /// Fails the pending request at `index`.
    fn fail(&mut self, index: usize) {
        let actions = match self.pending.remove(index) {
            Action::SendHeaders { start_root, .. } => {
                self.tree
                    .on_headers(start_root, Err::<Vec<HeaderInfo>, _>("simulated"), &self.fc)
            }
            Action::SendDownload { roots, .. } => {
                self.tree
                    .on_download(&roots, Err::<Vec<TestBlock>, _>("simulated"), &self.fc)
            }
            Action::SendProcess { roots, .. } => {
                self.tree
                    .on_process(&roots, Err::<(), _>("simulated"), &self.fc)
            }
            Action::ReportPeers { .. } => unreachable!("reports are not pending requests"),
        };
        self.ingest(actions);
        self.assert_invariants();
    }

    fn disconnect(&mut self, peer: &PeerId) {
        let actions = self.tree.peer_disconnected(peer, &self.fc);
        self.ingest(actions);
        self.assert_invariants();
    }

    /// Answers all requests, first-in first-out, until quiescence.
    fn respond_all(&mut self, max_headers: usize) {
        for _ in 0..1000 {
            if self.pending.is_empty() {
                return;
            }
            self.respond(0, max_headers);
        }
        panic!("requests never drained: {:?}", self.pending);
    }

    /// Asserts the spec invariants (1, 2, 4, 5, 6 and structural properties) hold, checking
    /// contiguity against the ground truth. Inv 3 (peers claimed every root) is aspirational: the
    /// spec's eager peer admission trades it for availability.
    fn assert_invariants(&self) {
        let tree = &self.tree;

        // Inv 1: loc(r) = c ⟺ r ∈ c.roots ∨ c.state = Discovering(r), uniquely.
        let mut expected_loc: HashMap<Hash256, ChainId> = HashMap::new();
        for (id, chain) in &tree.chains {
            for (root, _) in &chain.roots {
                assert!(
                    expected_loc.insert(*root, *id).is_none(),
                    "root {root} tracked by two chains"
                );
            }
            if let ChainState::Discovering { next } = &chain.state {
                assert!(
                    expected_loc.insert(*next, *id).is_none(),
                    "discovery target {next} tracked by two chains"
                );
            }
        }
        assert_eq!(expected_loc, tree.loc, "Inv 1: loc must mirror the chains");

        let mut forward_sync_roots = 0;
        for (id, chain) in &tree.chains {
            assert!(!chain.peers.is_empty(), "chain {id} has no peers");
            if !matches!(chain.state, ChainState::Discovering { .. }) {
                assert!(!chain.roots.is_empty(), "chain {id} has no roots");
            }
            if chain.is_forward_sync() {
                forward_sync_roots += chain.roots.len();
            }
            assert!(
                chain.errors <= tree.config.max_retries,
                "chain {id} exceeded max retries without being dropped"
            );

            // Inv 2 + 4: contiguous by parent_root, slots strictly decreasing, tip first.
            for pair in chain.roots.windows(2) {
                let (child, parent) = (pair[0], pair[1]);
                let child_block = self.truth.get(&child.0).expect("tracked root in truth");
                assert_eq!(child_block.parent_root, parent.0, "Inv 2: chain {id}");
                assert_eq!(child_block.slot, child.1, "chain {id} stores wrong slot");
                assert!(parent.1 < child.1, "Inv 4: chain {id}");
            }
            // The link below the oldest root matches the ground truth.
            if let Some((oldest, _)) = chain.roots.last() {
                let true_parent = self
                    .truth
                    .get(oldest)
                    .expect("tracked root in truth")
                    .parent_root;
                match &chain.state {
                    ChainState::Discovering { next } => {
                        assert_eq!(
                            *next, true_parent,
                            "chain {id} discovering the wrong parent"
                        )
                    }
                    _ => assert_eq!(
                        chain.parent_link(),
                        Some(true_parent),
                        "chain {id} linked to the wrong parent"
                    ),
                }
            }

            // Inv 6: parents of anchored chains are reachable.
            if let Some(parent) = chain.parent_link() {
                assert!(
                    self.fc.known.contains(&parent) || tree.loc.contains_key(&parent),
                    "Inv 6: chain {id} parent {parent} is unreachable"
                );
            }

            // Inv 5: blocks are the roots reversed, one each.
            if let ChainState::Ready { blocks, .. } | ChainState::Processing { blocks, .. } =
                &chain.state
            {
                assert_eq!(blocks.len(), chain.roots.len(), "Inv 5: chain {id}");
                for (block, (root, _)) in blocks.iter().zip(chain.roots.iter().rev()) {
                    assert_eq!(block.root, *root, "Inv 5: chain {id} blocks out of order");
                }
            }
            // Inv 5, Processing clause, relaxed for splits: the parent is imported or being
            // imported by the shared in-flight request.
            if let ChainState::Processing { parent, .. } = &chain.state {
                let parent_processing = tree
                    .loc
                    .get(parent)
                    .and_then(|parent_id| tree.chains.get(parent_id))
                    .is_some_and(|c| matches!(c.state, ChainState::Processing { .. }));
                assert!(
                    self.fc.known.contains(parent) || parent_processing,
                    "chain {id} processing without an importable parent"
                );
            }
        }
        assert!(
            forward_sync_roots
                < tree.config.max_forward_sync_roots + tree.config.promote_batch_roots,
            "forward sync roots exceed the budget"
        );
        assert!(
            tree.loc.len() <= tree.config.max_tracked_roots,
            "tracked roots exceed the maximum"
        );
    }
}

#[test]
fn search_unknown_root_starts_discovery() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 5);
    let tip = chain[4];
    let peer_a = peer();
    harness.search(&tip, peer_a);
    assert!(matches!(
        &harness.pending[..],
        [Action::SendHeaders { start_root, peers }] if *start_root == tip.root && *peers == vec![peer_a]
    ));
    assert_eq!(harness.tree.chain_count(), 1);
    assert_eq!(harness.tree.tracked_root_count(), 1);
}

#[test]
fn search_skips_known_and_finalized_roots() {
    let mut harness = Harness::new(backfill_only_config());
    let finalized = harness.finalized;
    harness.search(&finalized, peer());
    let old = TestBlock {
        root: root_hash(77),
        parent_root: Hash256::ZERO,
        slot: finalized.slot - 5,
    };
    harness.truth.insert(old.root, old);
    harness.search(&old, peer());
    assert!(harness.pending.is_empty());
    assert!(harness.tree.is_empty());
}

#[test]
fn search_same_root_pools_peers_without_new_requests() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 3);
    harness.search(&chain[2], peer());
    harness.search(&chain[2], peer());
    assert_eq!(harness.pending.len(), 1, "one in-flight headers request");
    assert_eq!(harness.tree.chain_count(), 1);
    let chain = harness.tree.chains.values().next().expect("one chain");
    assert_eq!(chain.peers.len(), 2);
}

#[test]
fn search_discovery_target_pools_peers() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 5);
    harness.search(&chain[4], peer());
    // Partial walk: two headers leave the chain discovering chain[2].
    harness.respond(0, 2);
    assert_eq!(harness.pending.len(), 1);
    harness.search(&chain[2], peer());
    assert_eq!(
        harness.tree.chain_count(),
        1,
        "no split on the discovery target"
    );
    let tracked = harness.tree.chains.values().next().expect("one chain");
    assert_eq!(tracked.peers.len(), 2);
}

#[test]
fn headers_walk_continues_until_anchored() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 5);
    harness.search(&chain[4], peer());
    // 2 headers per response: 5 blocks need 3 responses to reach the finalized parent.
    harness.respond(0, 2);
    assert_eq!(
        harness.pending.len(),
        1,
        "walk unresolved, one follow-up request"
    );
    harness.respond(0, 2);
    harness.respond(0, 2);
    assert!(
        harness.pending.is_empty(),
        "anchored, and promotion is disabled"
    );
    let tracked = harness.tree.chains.values().next().expect("one chain");
    assert!(matches!(tracked.state, ChainState::Anchored { parent } if parent == root_hash(0)));
    assert_eq!(tracked.roots.len(), 5);
}

#[test]
fn headers_conflicting_with_finality_report_and_drop() {
    let mut harness = Harness::new(backfill_only_config());
    let below = harness.block_below_finality();
    let fork = harness.extend(below.root, 3);
    let peer_a = peer();
    harness.search(&fork[2], peer_a);
    harness.respond_all(10);
    assert!(harness.tree.is_empty(), "conflicting chain must be dropped");
    assert_eq!(harness.reports.len(), 1);
    let (peers, reason) = &harness.reports[0];
    assert_eq!(*peers, vec![peer_a]);
    assert!(reason.contains("finality"));
}

#[test]
fn headers_failures_retry_then_drop() {
    // Root unknown to the ground truth: every response fails.
    let mut harness = Harness::new(backfill_only_config());
    let ghost = TestBlock {
        root: root_hash(500),
        parent_root: Hash256::repeat_byte(0xaa),
        slot: harness.finalized.slot + 5,
    };
    harness.search(&ghost, peer());
    for _ in 0..2 {
        harness.fail(0);
        assert_eq!(harness.pending.len(), 1, "failure below the limit retries");
    }
    harness.fail(0);
    assert!(harness.pending.is_empty(), "no retry past max_retries");
    assert!(harness.tree.is_empty());
}

#[test]
fn invalid_headers_response_counts_as_failure() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 3);
    let other = harness.extend(root_hash(0), 1);
    harness.search(&chain[2], peer());
    let Some(Action::SendHeaders { start_root, .. }) = harness.pending.pop() else {
        panic!("expected a headers request");
    };
    // Verified headers for the wrong root break the SendHeaders guarantee.
    let bad = vec![other[0].header()];
    let actions = harness
        .tree
        .on_headers(start_root, Ok::<_, &str>(bad), &harness.fc);
    harness.ingest(actions);
    harness.assert_invariants();
    assert!(
        matches!(&harness.pending[..], [Action::SendHeaders { start_root: retry, .. }] if *retry == chain[2].root),
        "a broken response is retried like a failure"
    );
    let tracked = harness.tree.chains.values().next().expect("one chain");
    assert_eq!(tracked.errors, 1);
    assert!(
        tracked.roots.is_empty(),
        "nothing from the response is consumed"
    );
}

#[test]
fn full_sync_downloads_and_imports_in_batches() {
    // B = 3, N = 9: a 5 block chain becomes two forward sync chains.
    let mut harness = Harness::new(config(3, 9, 2, 1000));
    let chain = harness.extend(root_hash(0), 5);
    harness.search(&chain[4], peer());
    harness.respond(0, 10);
    // Anchored and promoted: the 3 oldest roots and the 2 newest, downloading concurrently.
    let downloads: Vec<&Action<TestBlock>> = harness.pending.iter().collect();
    assert_eq!(downloads.len(), 2);
    assert!(matches!(
        downloads[0],
        Action::SendDownload { roots, .. } if *roots == vec![chain[0].root, chain[1].root, chain[2].root]
    ));
    assert!(matches!(
        downloads[1],
        Action::SendDownload { roots, .. } if *roots == vec![chain[3].root, chain[4].root]
    ));
    harness.respond_all(10);
    assert!(harness.tree.is_empty(), "everything imported");
    assert!(
        chain
            .iter()
            .all(|block| harness.fc.known.contains(&block.root))
    );
    assert!(harness.reports.is_empty());
}

#[test]
fn promotion_respects_the_forward_sync_budget() {
    // B = 3, N = 4: only two batches (3 + 3 > 4 stops the second) may sync at once.
    let mut harness = Harness::new(config(3, 4, 2, 1000));
    let chain = harness.extend(root_hash(0), 8);
    harness.search(&chain[7], peer());
    harness.respond(0, 10);
    assert_eq!(harness.pending.len(), 2, "two downloads in flight");
    let backfill_roots: usize = harness
        .tree
        .chains
        .values()
        .filter(|chain| !chain.is_forward_sync())
        .map(|chain| chain.roots.len())
        .sum();
    assert_eq!(backfill_roots, 2, "the rest awaits promotion capacity");
    harness.respond_all(10);
    assert!(harness.tree.is_empty());
    assert!(
        chain
            .iter()
            .all(|block| harness.fc.known.contains(&block.root))
    );
}

#[test]
fn search_mid_chain_splits_and_pools_peers_on_the_older_half() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 5);
    let peer_a = peer();
    let peer_b = peer();
    harness.search(&chain[4], peer_a);
    harness.respond_all(10);
    harness.search(&chain[1], peer_b);
    assert_eq!(harness.tree.chain_count(), 2);
    let older = harness
        .tree
        .chains
        .values()
        .find(|c| c.tip() == Some(chain[1].root))
        .expect("older half tipped at the searched root");
    assert_eq!(older.roots.len(), 2);
    assert_eq!(older.peers.len(), 2, "searcher admitted to the older half");
    let newer = harness
        .tree
        .chains
        .values()
        .find(|c| c.tip() == Some(chain[4].root))
        .expect("newer half keeps the original tip");
    assert_eq!(newer.roots.len(), 3);
    assert_eq!(
        newer.peers.len(),
        1,
        "the searcher did not claim the newer half"
    );
    assert!(matches!(newer.state, ChainState::Anchored { parent } if parent == chain[1].root));
}

#[test]
fn anchoring_into_a_chain_admits_peers_to_ancestors() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 6);
    let peer_a = peer();
    let peer_b = peer();
    harness.search(&chain[2], peer_a);
    harness.respond_all(10);
    harness.search(&chain[5], peer_b);
    harness.respond_all(10);
    assert_eq!(harness.tree.chain_count(), 2);
    let ancestor = harness
        .tree
        .chains
        .values()
        .find(|c| c.tip() == Some(chain[2].root))
        .expect("ancestor chain");
    assert!(
        ancestor.peers.contains(&peer_b),
        "peers of a descendant chain hold its ancestors too"
    );
}

#[test]
fn split_during_download_shares_the_in_flight_response() {
    let mut harness = Harness::new(config(6, 100, 2, 1000));
    let chain = harness.extend(root_hash(0), 4);
    harness.search(&chain[3], peer());
    harness.respond(0, 10);
    let Some(Action::SendDownload { roots, .. }) = harness.pending.pop() else {
        panic!("expected a download request");
    };
    assert_eq!(roots.len(), 4);
    // Split while the download is in flight.
    harness.search(&chain[1], peer());
    assert_eq!(harness.tree.chain_count(), 2);
    // The single response feeds both halves.
    let blocks: Vec<TestBlock> = roots.iter().map(|root| harness.truth[root]).collect();
    let actions = harness
        .tree
        .on_download(&roots, Ok::<_, &str>(blocks), &harness.fc);
    harness.ingest(actions);
    harness.assert_invariants();
    // The older half has an imported parent: sent straight to processing.
    assert!(
        matches!(&harness.pending[..], [Action::SendProcess { roots, .. }] if roots.len() == 2)
    );
    harness.respond_all(10);
    assert!(harness.tree.is_empty());
    assert!(
        chain
            .iter()
            .all(|block| harness.fc.known.contains(&block.root))
    );
}

#[test]
fn processing_failure_reports_reforwards_and_recovers() {
    let mut harness = Harness::new(config(8, 100, 2, 1000));
    let chain = harness.extend(root_hash(0), 3);
    let peer_a = peer();
    harness.search(&chain[2], peer_a);
    harness.respond(0, 10); // headers -> anchored -> downloading
    harness.respond(0, 10); // download -> ready -> processing
    assert!(matches!(&harness.pending[..], [Action::SendProcess { .. }]));
    harness.fail(0);
    assert_eq!(harness.reports.len(), 1, "the serving peers are reported");
    assert_eq!(harness.reports[0].0, vec![peer_a]);
    assert!(
        matches!(&harness.pending[..], [Action::SendDownload { .. }]),
        "failed imports re-download, the blocks may be bad"
    );
    harness.respond_all(10);
    assert!(harness.tree.is_empty());
    assert!(
        chain
            .iter()
            .all(|block| harness.fc.known.contains(&block.root))
    );
}

#[test]
fn download_failures_retry_then_drop_with_descendants() {
    let mut harness = Harness::new(config(3, 100, 1, 1000));
    let chain = harness.extend(root_hash(0), 5);
    harness.search(&chain[4], peer());
    harness.respond(0, 10);
    assert_eq!(harness.pending.len(), 2, "two downloads in flight");
    // Fail the oldest batch to death: retry once (max_retries = 1), then drop.
    harness.fail(0);
    assert_eq!(harness.pending.len(), 2);
    harness.fail(1); // the retry sits at the back of the queue
    // The newer forward sync chain is anchored into the dropped one: the cascade removes it, and
    // its own in-flight download becomes stale.
    assert!(harness.tree.is_empty());
    let Some(Action::SendDownload { roots, .. }) = harness.pending.pop() else {
        panic!("expected the stale download");
    };
    let actions = harness
        .tree
        .on_download(&roots, Ok::<_, &str>(vec![]), &harness.fc);
    assert!(actions.is_empty(), "stale responses are ignored");
    harness.assert_invariants();
}

#[test]
fn dropping_a_chain_cascades_through_its_discovery_target() {
    let mut harness = Harness::new(backfill_only_config());
    let main = harness.extend(root_hash(0), 5);
    let branch = harness.extend(main[2].root, 2);
    // X walks back partially: discovering main[2].
    harness.search(&main[4], peer());
    harness.respond(0, 2);
    // Y anchors into X's discovery target (X's own follow-up request stays at index 0).
    harness.search(&branch[1], peer());
    harness.respond(1, 10);
    assert_eq!(harness.tree.chain_count(), 2);
    // Fail X's discovery to death (max_retries = 2): Y is anchored into a root only X was
    // discovering, so it must be dropped too.
    harness.fail(0);
    harness.fail(0);
    harness.fail(0);
    assert!(
        harness.tree.is_empty(),
        "the cascade must include the discovery target"
    );
    assert!(harness.pending.is_empty());
}

#[test]
fn disconnecting_the_last_peer_drops_the_chain() {
    let mut harness = Harness::new(backfill_only_config());
    let chain = harness.extend(root_hash(0), 3);
    let peer_a = peer();
    let peer_b = peer();
    harness.search(&chain[2], peer_a);
    harness.search(&chain[2], peer_b);
    harness.disconnect(&peer_a);
    assert_eq!(harness.tree.chain_count(), 1, "a peer remains");
    harness.disconnect(&peer_b);
    assert!(harness.tree.is_empty());
}

#[test]
fn prune_drops_the_least_attested_chain() {
    let mut harness = Harness::new(config(3, 0, 2, 4));
    let popular = harness.extend(root_hash(0), 3);
    let unpopular = harness.extend(root_hash(0), 3);
    harness.search(&popular[2], peer());
    harness.search(&popular[2], peer());
    harness.respond_all(10);
    assert_eq!(harness.tree.tracked_root_count(), 3);
    // Walking the second chain exceeds max_tracked_roots = 4: its single peer loses.
    harness.search(&unpopular[2], peer());
    harness.respond_all(10);
    assert_eq!(harness.tree.chain_count(), 1);
    let survivor = harness.tree.chains.values().next().expect("one chain");
    assert_eq!(survivor.tip(), Some(popular[2].root));
}

#[test]
fn stale_responses_are_ignored() {
    let mut harness = Harness::new(backfill_only_config());
    let actions = harness
        .tree
        .on_headers(root_hash(123), Ok::<_, &str>(vec![]), &harness.fc);
    assert!(actions.is_empty());
    let actions = harness.tree.on_download(
        &[root_hash(1), root_hash(2)],
        Ok::<_, &str>(vec![]),
        &harness.fc,
    );
    assert!(actions.is_empty());
    let actions = harness
        .tree
        .on_process(&[root_hash(3)], Ok::<_, &str>(()), &harness.fc);
    assert!(actions.is_empty());
    assert!(harness.tree.is_empty());
}

/// Randomized end-to-end runs: random block trees (including a fork conflicting with finality),
/// random response order and sizes, failures, extra searches and disconnects. Invariants are
/// asserted after every transition, every run must reach quiescence with an empty machine, and
/// failure-free runs must import every viable claimed chain.
#[test]
fn randomized_runs_reach_quiescence_with_invariants() {
    for seed in 0..30u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let failure_free = seed % 3 == 0;
        // Pruning legitimately forgets viable chains (peers re-trigger searches in reality, but
        // not reliably in this run), so only lossy runs get a tight budget.
        let max_tracked_roots = if failure_free || seed % 2 == 0 {
            10_000
        } else {
            25
        };
        let mut harness = Harness::new(config(3, 12, 3, max_tracked_roots));

        let main = harness.extend(root_hash(0), rng.random_range(10..40));
        let mut tips = vec![main[main.len() - 1]];
        for _ in 0..rng.random_range(1..4) {
            let branch_point = main[rng.random_range(0..main.len())].root;
            let branch = harness.extend(branch_point, rng.random_range(2..10));
            tips.push(branch[branch.len() - 1]);
        }
        let viable_tips = tips.clone();
        let below = harness.block_below_finality();
        let bad_fork = harness.extend(below.root, rng.random_range(2..6));
        tips.push(bad_fork[bad_fork.len() - 1]);

        let peers: Vec<PeerId> = (0..rng.random_range(2..5)).map(|_| peer()).collect();
        for tip in &tips {
            harness.search(tip, peers[rng.random_range(0..peers.len())]);
        }

        let all_blocks: Vec<TestBlock> = harness.truth.values().copied().collect();
        let mut steps = 0;
        while !harness.pending.is_empty() {
            steps += 1;
            assert!(
                steps < 5000,
                "seed {seed}: not quiescent, pending {:?}\nchains {:#?}",
                harness.pending,
                harness.tree.chains
            );
            if rng.random_bool(0.1) {
                let block = all_blocks[rng.random_range(0..all_blocks.len())];
                harness.search(&block, peers[rng.random_range(0..peers.len())]);
            }
            if !failure_free && rng.random_bool(0.02) {
                harness.disconnect(&peers[rng.random_range(0..peers.len())]);
            }
            if harness.pending.is_empty() {
                break;
            }
            let index = rng.random_range(0..harness.pending.len());
            if !failure_free && rng.random_bool(0.15) {
                harness.fail(index);
            } else {
                harness.respond(index, rng.random_range(1..6));
            }
        }

        assert!(
            harness.tree.is_empty(),
            "seed {seed}: quiescent machine must be empty\nchains {:#?}",
            harness.tree.chains
        );
        if failure_free {
            for tip in &viable_tips {
                assert!(
                    harness.fc.known.contains(&tip.root),
                    "seed {seed}: viable claimed chain {} not imported",
                    tip.root
                );
            }
        }
    }
}
