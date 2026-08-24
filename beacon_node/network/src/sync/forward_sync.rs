//! Forward sync — implementation of `specs/tree-sync.md`.
//!
//! Sync by root: walk back by `parent_root` to a block fork choice knows, then import
//! forward. Issues no `*_by_range` request. Peers are adversarial.
//!
//! State is a forest of [`Chain`]s over block roots, indexed by
//! [`ForwardSync::block_to_chain`]. A chain is a run of ancestors sharing one peer set,
//! tip first. Every peer in the set has claimed every root in the chain (Inv 3), which is
//! what licenses asking any one of them for all of `roots`; a peer covering only part of
//! a chain forces a split.

use beacon_chain::block_verification_types::RangeSyncBlock;
use lighthouse_network::PeerId;
use std::collections::{HashMap, HashSet, VecDeque};
use types::{BeaconBlockHeader, EthSpec, Hash256, Slot};

/// Roots promoted at a time. Protocol cap is 128. Spec: `B`.
pub const BATCH_SIZE: usize = 32;
/// Max blocks forward syncing — 8 chains in flight. Spec: `N`.
pub const MAX_SYNCING_BLOCKS: usize = 256;
pub const RETRY_MAX: u8 = 5;
/// Tracked roots before pruning.
pub const ROOTS_MAX: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId(pub u32);

/// Everything outside the state machine. Each `download_*` / `process_*` guarantees the
/// matching `on_*` is called, with `Ok` already validated as the spec requires.
pub trait Env<E: EthSpec> {
    /// Is `root` in fork choice?
    fn is_known(&self, root: &Hash256) -> bool;
    fn finalized(&self) -> (Hash256, Slot);
    fn report_peer(&mut self, peer: &PeerId);
    /// Guarantees `on_headers(chain_id, _)`. `Ok(headers)` has `headers[0].root = root`,
    /// `headers[i].root = headers[i - 1].parent_root`, and strictly decreasing slots.
    fn download_headers(&mut self, chain_id: ChainId, root: Hash256, peers: &HashSet<PeerId>);
    /// Guarantees `on_download(roots, _)`. `Ok(blocks)` covers exactly `roots`.
    fn download_blocks(&mut self, roots: Vec<Hash256>, peers: &HashSet<PeerId>);
    /// Guarantees `on_process(roots, _)`. `Ok` means all `blocks` are in fork choice.
    fn process_blocks(&mut self, roots: Vec<Hash256>, blocks: Vec<RangeSyncBlock<E>>);
}

/// Discovery phase: walking back for ancestors.
pub enum Backfill {
    /// A header request for this root is in flight.
    Discovering(Hash256),
    /// Discovery done; parent is in fork choice or owned by another chain (Inv 6).
    Anchored(Hash256),
}

/// Import phase.
pub enum Sync<E: EthSpec> {
    /// A block request for `roots` is in flight.
    Downloading,
    /// Blocks held, waiting for `parent` to be imported.
    Ready(Vec<RangeSyncBlock<E>>),
    /// Submitted to the processor.
    Processing(Vec<RangeSyncBlock<E>>),
}

impl<E: EthSpec> Sync<E> {
    /// Hands each half of a split the blocks for the roots it kept.
    fn partition(self, kept_by_older: &HashSet<Hash256>) -> (Self, Self) {
        let split = |blocks: Vec<RangeSyncBlock<E>>| {
            blocks
                .into_iter()
                .partition(|block| kept_by_older.contains(&block.block_root()))
        };
        match self {
            Sync::Downloading => (Sync::Downloading, Sync::Downloading),
            Sync::Ready(blocks) => {
                let (older, newer) = split(blocks);
                (Sync::Ready(older), Sync::Ready(newer))
            }
            Sync::Processing(blocks) => {
                let (older, newer) = split(blocks);
                (Sync::Processing(older), Sync::Processing(newer))
            }
        }
    }
}

pub enum Chain<E: EthSpec> {
    Backfill {
        /// Tip first; `slot` strictly decreases (Inv 4).
        roots: VecDeque<(Hash256, Slot)>,
        /// Each has claimed every root (Inv 3).
        peers: HashSet<PeerId>,
        errors: u8,
        state: Backfill,
    },
    ForwardSync {
        roots: VecDeque<(Hash256, Slot)>,
        peers: HashSet<PeerId>,
        parent: Hash256,
        errors: u8,
        state: Sync<E>,
    },
}

impl<E: EthSpec> Chain<E> {
    fn roots(&self) -> &VecDeque<(Hash256, Slot)> {
        match self {
            Chain::Backfill { roots, .. } | Chain::ForwardSync { roots, .. } => roots,
        }
    }

    fn roots_mut(&mut self) -> &mut VecDeque<(Hash256, Slot)> {
        match self {
            Chain::Backfill { roots, .. } | Chain::ForwardSync { roots, .. } => roots,
        }
    }

    fn peers(&self) -> &HashSet<PeerId> {
        match self {
            Chain::Backfill { peers, .. } | Chain::ForwardSync { peers, .. } => peers,
        }
    }

    fn peers_mut(&mut self) -> &mut HashSet<PeerId> {
        match self {
            Chain::Backfill { peers, .. } | Chain::ForwardSync { peers, .. } => peers,
        }
    }

    /// Returns true once the retry budget is spent.
    fn bump_errors(&mut self) -> bool {
        let errors = match self {
            Chain::Backfill { errors, .. } | Chain::ForwardSync { errors, .. } => errors,
        };
        *errors = errors.saturating_add(1);
        *errors > RETRY_MAX
    }

    /// Newest root.
    fn tip(&self) -> Option<Hash256> {
        self.roots().front().map(|(root, _)| *root)
    }

    fn oldest_slot(&self) -> Option<Slot> {
        self.roots().back().map(|(_, slot)| *slot)
    }

    /// The root this chain waits on. `None` while still discovering.
    fn parent(&self) -> Option<Hash256> {
        match self {
            Chain::Backfill {
                state: Backfill::Anchored(parent),
                ..
            } => Some(*parent),
            Chain::ForwardSync { parent, .. } => Some(*parent),
            Chain::Backfill { .. } => None,
        }
    }

    fn is_forward_sync(&self) -> bool {
        matches!(self, Chain::ForwardSync { .. })
    }

    /// The root a header request is outstanding for.
    fn discovering(&self) -> Option<Hash256> {
        match self {
            Chain::Backfill {
                state: Backfill::Discovering(next),
                ..
            } => Some(*next),
            _ => None,
        }
    }

    /// Builds both halves of a split outright. `roots` is cut at `index`, `peers` is
    /// copied to each, and held blocks are partitioned by which half kept their root.
    /// The older half is `[pivot … oldest]`; the newer is `[tip … pivot⁺]` and waits on
    /// `pivot`.
    fn split_at(self, index: usize, pivot: Hash256) -> (Self, Self) {
        match self {
            Chain::Backfill {
                mut roots,
                peers,
                errors,
                state,
            } => {
                // `roots` is tip first, so [index..] is the pivot and everything older.
                let older_roots = roots.split_off(index);
                (
                    Chain::Backfill {
                        roots: older_roots,
                        peers: peers.clone(),
                        errors,
                        state,
                    },
                    Chain::Backfill {
                        roots,
                        peers,
                        errors,
                        state: Backfill::Anchored(pivot),
                    },
                )
            }
            Chain::ForwardSync {
                mut roots,
                peers,
                parent,
                errors,
                state,
            } => {
                let older_roots = roots.split_off(index);
                let kept_by_older: HashSet<Hash256> =
                    older_roots.iter().map(|(root, _)| *root).collect();
                let (older_state, newer_state) = state.partition(&kept_by_older);
                (
                    Chain::ForwardSync {
                        roots: older_roots,
                        peers: peers.clone(),
                        parent,
                        errors,
                        state: older_state,
                    },
                    Chain::ForwardSync {
                        roots,
                        peers,
                        parent: pivot,
                        errors,
                        state: newer_state,
                    },
                )
            }
        }
    }
}

pub struct ForwardSync<E: EthSpec> {
    /// Which chain owns each root we intend to sync (Inv 1).
    block_to_chain: HashMap<Hash256, ChainId>,
    chains: HashMap<ChainId, Chain<E>>,
    next_id: u32,
}

impl<E: EthSpec> Default for ForwardSync<E> {
    fn default() -> Self {
        Self {
            block_to_chain: HashMap::new(),
            chains: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<E: EthSpec> ForwardSync<E> {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc(&mut self) -> ChainId {
        let chain_id = ChainId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        chain_id
    }

    /// `owners(R)` — chains currently holding any of `roots`, oldest first.
    fn owners(&self, roots: &[Hash256]) -> Vec<ChainId> {
        let mut chain_ids: Vec<ChainId> = roots
            .iter()
            .filter_map(|root| self.block_to_chain.get(root).copied())
            .collect();
        chain_ids.sort_unstable();
        chain_ids.dedup();
        chain_ids.sort_by_key(|chain_id| {
            self.chains
                .get(chain_id)
                .and_then(|chain| chain.oldest_slot())
                .unwrap_or_else(|| Slot::new(u64::MAX))
        });
        chain_ids
    }

    fn syncing_blocks(&self) -> usize {
        self.chains
            .values()
            .filter(|chain| chain.is_forward_sync())
            .map(|chain| chain.roots().len())
            .sum()
    }

    fn slot_of(&self, root: &Hash256) -> Option<Slot> {
        let chain = self.chains.get(self.block_to_chain.get(root)?)?;
        chain
            .roots()
            .iter()
            .find(|(candidate, _)| candidate == root)
            .map(|(_, slot)| *slot)
    }

    /// `Split(chain, root)` — the older half keeps `chain_id`, its state, its parent and
    /// any call in flight. Returns the newer half's id, or `None` when `root` is already
    /// the tip and there is nothing to split.
    fn split(&mut self, chain_id: ChainId, root: Hash256) -> Option<ChainId> {
        let index = self
            .chains
            .get(&chain_id)?
            .roots()
            .iter()
            .position(|(candidate, _)| *candidate == root)?;
        if index == 0 {
            return None;
        }
        let newer_id = self.alloc();
        let (older, newer) = self.chains.remove(&chain_id)?.split_at(index, root);

        for (block_root, _) in newer.roots() {
            self.block_to_chain.insert(*block_root, newer_id);
        }
        self.chains.insert(chain_id, older);
        self.chains.insert(newer_id, newer);
        Some(newer_id)
    }

    /// `Search(root, peers)` — a peer set claims `root`.
    pub fn search(&mut self, root: Hash256, peers: &HashSet<PeerId>, env: &mut impl Env<E>) {
        if env.is_known(&root) {
            return;
        }
        // The slot is only known for a root we already track; elsewhere this guard is
        // best-effort and `on_headers` is authoritative once a header is in hand.
        let (_, finalized_slot) = env.finalized();
        if self
            .slot_of(&root)
            .is_some_and(|slot| slot <= finalized_slot)
        {
            return;
        }

        match self.block_to_chain.get(&root).copied() {
            None => {
                let chain_id = self.alloc();
                self.chains.insert(
                    chain_id,
                    Chain::Backfill {
                        roots: VecDeque::new(),
                        peers: peers.clone(),
                        errors: 0,
                        state: Backfill::Discovering(root),
                    },
                );
                self.block_to_chain.insert(root, chain_id);
                env.download_headers(chain_id, root, peers);
            }
            Some(chain_id) => {
                // Split unless the peer set already covers the whole chain.
                if self.chains.get(&chain_id).and_then(|chain| chain.tip()) != Some(root) {
                    self.split(chain_id, root);
                }
                if let Some(chain) = self.chains.get_mut(&chain_id) {
                    chain.peers_mut().extend(peers.iter().copied());
                }
            }
        }

        // A peer holding `root` holds every ancestor, so admit it all the way down.
        if let Some(parent) = self
            .block_to_chain
            .get(&root)
            .and_then(|chain_id| self.chains.get(chain_id))
            .and_then(|chain| chain.parent())
        {
            self.admit_ancestors(parent, peers);
        }
        self.prune();
        self.promote(env);
    }

    /// Adds `peers` to the chain owning `root` and to every chain below it. A peer that
    /// claimed a root has claimed its ancestors, so this is sound at every level.
    fn admit_ancestors(&mut self, root: Hash256, peers: &HashSet<PeerId>) {
        let mut visited: HashSet<ChainId> = HashSet::new();
        let mut next = Some(root);
        while let Some(root) = next {
            let Some(chain_id) = self.block_to_chain.get(&root).copied() else {
                return;
            };
            if !visited.insert(chain_id) {
                return;
            }
            let Some(chain) = self.chains.get_mut(&chain_id) else {
                return;
            };
            chain.peers_mut().extend(peers.iter().copied());
            next = chain.parent();
        }
    }

    /// `SendHeaders(chain, root)`.
    fn send_headers(&mut self, chain_id: ChainId, root: Hash256, env: &mut impl Env<E>) {
        let Some(Chain::Backfill { state, peers, .. }) = self.chains.get_mut(&chain_id) else {
            return;
        };
        *state = Backfill::Discovering(root);
        let peers = peers.clone();
        env.download_headers(chain_id, root, &peers);
    }

    /// `OnHeaders(chain, result)`.
    pub fn on_headers(
        &mut self,
        chain_id: ChainId,
        result: Result<Vec<BeaconBlockHeader>, ()>,
        env: &mut impl Env<E>,
    ) {
        let Some(next) = self
            .chains
            .get(&chain_id)
            .and_then(|chain| chain.discovering())
        else {
            return;
        };

        let headers = match result {
            Err(()) => {
                if self
                    .chains
                    .get_mut(&chain_id)
                    .is_some_and(|chain| chain.bump_errors())
                {
                    self.drop_chain(chain_id);
                } else {
                    self.send_headers(chain_id, next, env);
                }
                return self.promote(env);
            }
            Ok(headers) => headers,
        };

        let (finalized_root, finalized_slot) = env.finalized();
        let mut unresolved: Option<Hash256> = None;
        for header in headers {
            let root = header.canonical_root();
            if header.slot <= finalized_slot && root != finalized_root {
                let peers: Vec<PeerId> = self
                    .chains
                    .get(&chain_id)
                    .map(|chain| chain.peers().iter().copied().collect())
                    .unwrap_or_default();
                for peer in &peers {
                    env.report_peer(peer);
                }
                self.drop_chain(chain_id);
                return self.promote(env);
            }

            let Some(chain) = self.chains.get_mut(&chain_id) else {
                return;
            };
            chain.roots_mut().push_back((root, header.slot));
            let parent = header.parent_root;

            if env.is_known(&parent) {
                if let Chain::Backfill { state, .. } = chain {
                    *state = Backfill::Anchored(parent);
                }
                unresolved = None;
                break;
            }

            match self.block_to_chain.get(&parent).copied() {
                Some(owner) if owner != chain_id => {
                    if let Some(chain) = self.chains.get_mut(&chain_id) {
                        if let Chain::Backfill { state, .. } = chain {
                            *state = Backfill::Anchored(parent);
                        }
                    }
                    // The peers that claimed this chain's tip hold the ancestors too, and
                    // `Search`'s ascent could not reach them: they did not exist yet.
                    let peers: HashSet<PeerId> = self
                        .chains
                        .get(&chain_id)
                        .map(|chain| chain.peers().clone())
                        .unwrap_or_default();
                    self.admit_ancestors(parent, &peers);
                    unresolved = None;
                    break;
                }
                _ => {}
            }
            // Claim `parent` before it is in `roots`, so a second search cannot spawn a
            // duplicate chain for it (Inv 1).
            self.block_to_chain.insert(parent, chain_id);
            unresolved = Some(parent);
        }

        // One request for the whole response. Sending one per intermediate parent would
        // re-request headers already in hand and leave several responses racing for a
        // single `Discovering(next)`.
        if let Some(parent) = unresolved {
            self.send_headers(chain_id, parent, env);
        }

        self.prune();
        self.promote(env);
    }

    /// `Promote` — runs after every transition.
    fn promote(&mut self, env: &mut impl Env<E>) {
        let ready: Vec<ChainId> = self
            .chains
            .iter()
            .filter(|(_, chain)| match chain {
                Chain::ForwardSync {
                    state: Sync::Ready(_),
                    parent,
                    ..
                } => env.is_known(parent),
                _ => false,
            })
            .map(|(chain_id, _)| *chain_id)
            .collect();
        for chain_id in ready {
            self.send_process(chain_id, env);
        }

        while self.syncing_blocks() < MAX_SYNCING_BLOCKS {
            let Some(chain_id) = self.pick(env) else {
                break;
            };
            let length = self
                .chains
                .get(&chain_id)
                .map_or(0, |chain| chain.roots().len());
            if length > BATCH_SIZE {
                // The BATCH_SIZE-th oldest root; the older half takes it and below.
                let pivot = self
                    .chains
                    .get(&chain_id)
                    .and_then(|chain| chain.roots().get(length - BATCH_SIZE))
                    .map(|(root, _)| *root);
                if let Some(pivot) = pivot {
                    self.split(chain_id, pivot);
                }
            }

            let parent = match self.chains.get(&chain_id) {
                Some(Chain::Backfill {
                    state: Backfill::Anchored(parent),
                    ..
                }) => *parent,
                _ => break,
            };
            let (roots, peers) = match self.chains.remove(&chain_id) {
                Some(Chain::Backfill { roots, peers, .. }) => (roots, peers),
                Some(other) => {
                    self.chains.insert(chain_id, other);
                    break;
                }
                None => break,
            };
            self.chains.insert(
                chain_id,
                Chain::ForwardSync {
                    roots,
                    peers,
                    parent,
                    errors: 0,
                    state: Sync::Downloading,
                },
            );
            self.send_download(chain_id, env);
        }
    }

    /// A `Backfill` chain whose parent is imported or already forward syncing, closest to
    /// the import frontier first.
    fn pick(&self, env: &impl Env<E>) -> Option<ChainId> {
        self.chains
            .iter()
            .filter(|(_, chain)| {
                let Chain::Backfill {
                    state: Backfill::Anchored(parent),
                    peers,
                    roots,
                    ..
                } = chain
                else {
                    return false;
                };
                if peers.is_empty() || roots.is_empty() {
                    return false;
                }
                env.is_known(parent)
                    || self
                        .block_to_chain
                        .get(parent)
                        .and_then(|chain_id| self.chains.get(chain_id))
                        .is_some_and(|owner| owner.is_forward_sync())
            })
            .min_by_key(|(_, chain)| chain.oldest_slot().unwrap_or_else(|| Slot::new(u64::MAX)))
            .map(|(chain_id, _)| *chain_id)
    }

    /// `SendDownload(chain)`.
    fn send_download(&mut self, chain_id: ChainId, env: &mut impl Env<E>) {
        let Some(chain) = self.chains.get_mut(&chain_id) else {
            return;
        };
        if let Chain::ForwardSync { state, .. } = chain {
            *state = Sync::Downloading;
        }
        let roots = chain.roots().iter().map(|(root, _)| *root).collect();
        let peers = chain.peers().clone();
        env.download_blocks(roots, &peers);
    }

    /// `OnDownload(R, result)` — dispatched per owning chain, since `roots` may have been
    /// split across several since the request went out.
    pub fn on_download(
        &mut self,
        roots: &[Hash256],
        result: Result<Vec<RangeSyncBlock<E>>, ()>,
        env: &mut impl Env<E>,
    ) {
        for chain_id in self.owners(roots) {
            match &result {
                Ok(blocks) => {
                    let Some(chain) = self.chains.get_mut(&chain_id) else {
                        continue;
                    };
                    // `roots` is tip first, so reversing gives import order.
                    let ordered: Vec<RangeSyncBlock<E>> = chain
                        .roots()
                        .iter()
                        .rev()
                        .filter_map(|(root, _)| {
                            blocks
                                .iter()
                                .find(|block| block.block_root() == *root)
                                .cloned()
                        })
                        .collect();
                    if let Chain::ForwardSync { state, .. } = chain {
                        *state = Sync::Ready(ordered);
                    }
                }
                Err(()) => {
                    if self
                        .chains
                        .get_mut(&chain_id)
                        .is_some_and(|chain| chain.bump_errors())
                    {
                        self.drop_chain(chain_id);
                    } else {
                        self.send_download(chain_id, env);
                    }
                }
            }
        }
        self.promote(env);
    }

    /// `SendProcess(chain)`.
    fn send_process(&mut self, chain_id: ChainId, env: &mut impl Env<E>) {
        let Some(Chain::ForwardSync {
            state,
            parent,
            roots,
            ..
        }) = self.chains.get_mut(&chain_id)
        else {
            return;
        };
        if !env.is_known(parent) {
            return;
        }
        let Sync::Ready(blocks) = state else {
            return;
        };
        let blocks = std::mem::take(blocks);
        let roots = roots.iter().map(|(root, _)| *root).collect();
        *state = Sync::Processing(blocks.clone());
        env.process_blocks(roots, blocks);
    }

    /// `OnProcess(R, result)`.
    pub fn on_process(&mut self, roots: &[Hash256], result: Result<(), ()>, env: &mut impl Env<E>) {
        let owners = self.owners(roots);
        if result.is_err() {
            // Oldest only: import stops at the first bad block, and split halves share a
            // peer set, so blaming each would double count.
            let peers: Vec<PeerId> = owners
                .first()
                .and_then(|chain_id| self.chains.get(chain_id))
                .map(|chain| chain.peers().iter().copied().collect())
                .unwrap_or_default();
            for peer in &peers {
                env.report_peer(peer);
            }
        }

        for chain_id in owners {
            match result {
                Ok(()) => {
                    // Every root is in fork choice, so this is a clean removal — the
                    // descendants are now eligible, not dead.
                    if let Some(chain) = self.chains.remove(&chain_id) {
                        for (root, _) in chain.roots() {
                            self.block_to_chain.remove(root);
                        }
                    }
                }
                Err(()) => {
                    if self
                        .chains
                        .get_mut(&chain_id)
                        .is_some_and(|chain| chain.bump_errors())
                    {
                        self.drop_chain(chain_id);
                    } else {
                        self.send_download(chain_id, env);
                    }
                }
            }
        }
        self.promote(env);
    }

    /// `Disconnect(peer)`.
    pub fn disconnect(&mut self, peer: &PeerId, env: &mut impl Env<E>) {
        let mut orphaned = Vec::new();
        for (chain_id, chain) in self.chains.iter_mut() {
            chain.peers_mut().remove(peer);
            if chain.peers().is_empty() {
                orphaned.push(*chain_id);
            }
        }
        for chain_id in orphaned {
            self.drop_chain(chain_id);
        }
        self.promote(env);
    }

    /// `Drop(chain)` — the chain and, transitively, every chain anchored on one of its
    /// roots.
    fn drop_chain(&mut self, chain_id: ChainId) {
        let mut queue = vec![chain_id];
        while let Some(next_id) = queue.pop() {
            let Some(chain) = self.chains.remove(&next_id) else {
                continue;
            };
            let dropped: HashSet<Hash256> = chain.roots().iter().map(|(root, _)| *root).collect();
            for root in &dropped {
                self.block_to_chain.remove(root);
            }
            // The claimed-but-unfetched root, which is in the index but not in `roots`.
            if let Some(pending) = chain.discovering() {
                self.block_to_chain.remove(&pending);
            }
            for (child_id, child) in self.chains.iter() {
                if child
                    .parent()
                    .is_some_and(|parent| dropped.contains(&parent))
                {
                    queue.push(*child_id);
                }
            }
        }
    }

    /// `Prune` — after any insertion into the index.
    fn prune(&mut self) {
        while self.block_to_chain.len() > ROOTS_MAX {
            // Least corroborated first: one peer is a fork nobody else has, or an
            // adversary; many peers is probably the real chain.
            let Some(chain_id) = self
                .chains
                .iter()
                .min_by_key(|(_, chain)| chain.peers().len())
                .map(|(chain_id, _)| *chain_id)
            else {
                return;
            };
            self.drop_chain(chain_id);
        }
    }
}
