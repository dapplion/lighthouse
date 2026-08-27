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

use super::manager::BatchProcessResult;
use super::network_context::block_components_by_root::{
    BlockComponentsByRootRequest, Error as ComponentsError,
};
use super::network_context::{RpcResponseResult, SyncNetworkContext};
use crate::network_beacon_processor::ChainSegmentProcessId;
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::RangeSyncBlock;
use lighthouse_network::service::api_types::{Id, SingleLookupReqId};
use lighthouse_network::{PeerAction, PeerId};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::debug;
use types::{DataColumnSidecarList, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Roots promoted at a time. Protocol cap is 128. Spec: `B`.
pub const BATCH_SIZE: usize = 32;
/// Max blocks forward syncing — 8 chains in flight. Spec: `N`.
pub const MAX_SYNCING_BLOCKS: usize = 256;
pub const RETRY_MAX: u8 = 5;
/// Tracked roots before pruning.
pub const ROOTS_MAX: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId(pub u32);

/// Peers claiming a chain. Shared so a peer admitted mid-flight is usable by a request
/// already outstanding, which is what the spec means by `peers` being live.
type Peers = Arc<RwLock<HashSet<PeerId>>>;

/// Discovery phase: walking back for ancestors.
pub enum Backfill {
    /// A header request for this root is in flight.
    Discovering(Hash256),
    /// Discovery done; parent is in fork choice or owned by another chain (Inv 6).
    Anchored(Hash256),
}

/// Import phase.
pub enum Sync<E: EthSpec> {
    /// A coupled block request for `roots` is in flight.
    Downloading,
    /// Blocks held, waiting for `parent` to be imported.
    Ready(Vec<RangeSyncBlock<E>>),
    /// Submitted to the processor.
    Processing,
}

pub enum Chain<E: EthSpec> {
    Backfill {
        /// Tip first; `slot` strictly decreases (Inv 4).
        roots: VecDeque<(Hash256, Slot)>,
        /// Each has claimed every root (Inv 3).
        peers: Peers,
        errors: u8,
        state: Backfill,
    },
    ForwardSync {
        roots: VecDeque<(Hash256, Slot)>,
        peers: Peers,
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

    fn peers(&self) -> &Peers {
        match self {
            Chain::Backfill { peers, .. } | Chain::ForwardSync { peers, .. } => peers,
        }
    }

    fn admit(&self, new_peers: &HashSet<PeerId>) {
        self.peers().write().extend(new_peers.iter().copied());
    }

    fn peer_count(&self) -> usize {
        self.peers().read().len()
    }

    /// Returns true once the retry budget is spent.
    fn bump_errors(&mut self) -> bool {
        let errors = match self {
            Chain::Backfill { errors, .. } | Chain::ForwardSync { errors, .. } => errors,
        };
        *errors = errors.saturating_add(1);
        *errors > RETRY_MAX
    }

    /// Progress resets the retry budget: `RETRY_MAX` bounds the retries of one step, not
    /// the lifetime of a chain that walks thousands of roots.
    fn clear_errors(&mut self) {
        match self {
            Chain::Backfill { errors, .. } | Chain::ForwardSync { errors, .. } => *errors = 0,
        }
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

    /// Builds both halves of a split outright. `roots` is cut at `index`; each half gets
    /// its own copy of the peer set, and held blocks go to whichever half kept their root.
    /// The older half is `[pivot … oldest]`; the newer is `[tip … pivot⁺]`, waiting on
    /// `pivot`.
    fn split_at(self, index: usize, pivot: Hash256) -> (Self, Self) {
        let copy_peers = |peers: &Peers| Arc::new(RwLock::new(peers.read().clone()));
        match self {
            Chain::Backfill {
                mut roots,
                peers,
                errors,
                state,
            } => {
                // `roots` is tip first, so [index..] is the pivot and everything older.
                let older_roots = roots.split_off(index);
                let newer_peers = copy_peers(&peers);
                (
                    Chain::Backfill {
                        roots: older_roots,
                        peers,
                        errors,
                        state,
                    },
                    Chain::Backfill {
                        roots,
                        peers: newer_peers,
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
                let kept: HashSet<Hash256> = older_roots.iter().map(|(root, _)| *root).collect();
                let (older_state, newer_state) = state.partition(&kept);
                let newer_peers = copy_peers(&peers);
                (
                    Chain::ForwardSync {
                        roots: older_roots,
                        peers,
                        parent,
                        errors,
                        state: older_state,
                    },
                    Chain::ForwardSync {
                        roots,
                        peers: newer_peers,
                        parent: pivot,
                        errors,
                        state: newer_state,
                    },
                )
            }
        }
    }
}

impl<E: EthSpec> Sync<E> {
    /// Hands each half of a split the blocks for the roots it kept.
    fn partition(self, kept_by_older: &HashSet<Hash256>) -> (Self, Self) {
        match self {
            Sync::Downloading => (Sync::Downloading, Sync::Downloading),
            Sync::Processing => (Sync::Processing, Sync::Processing),
            Sync::Ready(blocks) => {
                let (older, newer) = blocks
                    .into_iter()
                    .partition(|block| kept_by_older.contains(&block.block_root()));
                (Sync::Ready(older), Sync::Ready(newer))
            }
        }
    }
}

pub struct ForwardSync<T: BeaconChainTypes> {
    /// Which chain owns each root we intend to sync (Inv 1).
    block_to_chain: HashMap<Hash256, ChainId>,
    chains: HashMap<ChainId, Chain<T::EthSpec>>,
    /// Outstanding header walks, by request id.
    header_requests: HashMap<Id, ChainId>,
    /// Outstanding coupled downloads, by request id.
    downloads: HashMap<Id, (ChainId, BlockComponentsByRootRequest<T>)>,
    next_id: u32,
}

impl<T: BeaconChainTypes> Default for ForwardSync<T> {
    fn default() -> Self {
        Self {
            block_to_chain: HashMap::new(),
            chains: HashMap::new(),
            header_requests: HashMap::new(),
            downloads: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<T: BeaconChainTypes> ForwardSync<T> {
    pub fn new() -> Self {
        Self::default()
    }

    fn alloc(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        id
    }

    fn is_known(cx: &SyncNetworkContext<T>, root: &Hash256) -> bool {
        cx.chain.block_is_known_to_fork_choice(root)
    }

    fn finalized(cx: &SyncNetworkContext<T>) -> (Hash256, Slot) {
        let checkpoint = cx.chain.canonical_head.cached_head().finalized_checkpoint();
        (
            checkpoint.root,
            checkpoint
                .epoch
                .start_slot(<T::EthSpec as EthSpec>::slots_per_epoch()),
        )
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
        let newer_id = ChainId(self.alloc());
        let (older, newer) = self.chains.remove(&chain_id)?.split_at(index, root);

        for (block_root, _) in newer.roots() {
            self.block_to_chain.insert(*block_root, newer_id);
        }
        self.chains.insert(chain_id, older);
        self.chains.insert(newer_id, newer);
        Some(newer_id)
    }

    /// `Search(root, peers)` — a peer set claims `root`.
    pub fn search(
        &mut self,
        root: Hash256,
        peers: &HashSet<PeerId>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if Self::is_known(cx, &root) {
            return;
        }
        // The slot is only known for a root we already track; elsewhere this guard is
        // best-effort and `on_headers` is authoritative once a header is in hand.
        let (_, finalized_slot) = Self::finalized(cx);
        if self
            .slot_of(&root)
            .is_some_and(|slot| slot <= finalized_slot)
        {
            return;
        }

        match self.block_to_chain.get(&root).copied() {
            None => {
                let chain_id = ChainId(self.alloc());
                self.chains.insert(
                    chain_id,
                    Chain::Backfill {
                        roots: VecDeque::new(),
                        peers: Arc::new(RwLock::new(peers.clone())),
                        errors: 0,
                        state: Backfill::Discovering(root),
                    },
                );
                self.block_to_chain.insert(root, chain_id);
                self.send_headers(chain_id, root, cx, &HashSet::new());
            }
            Some(chain_id) => {
                // Split unless the peer set already covers the whole chain.
                if self.chains.get(&chain_id).and_then(|chain| chain.tip()) != Some(root) {
                    self.split(chain_id, root);
                }
                if let Some(chain) = self.chains.get(&chain_id) {
                    chain.admit(peers);
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
        self.promote(cx);
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
            // Only `root` and its ancestors were claimed. Whatever descends from `root`
            // inside this chain may be on another branch, so split it off first rather
            // than admitting peers to roots they never claimed (Inv 3). `split` leaves the
            // older half — `root` and below — under `chain_id`.
            if self.chains.get(&chain_id).and_then(|chain| chain.tip()) != Some(root) {
                self.split(chain_id, root);
            }
            let Some(chain) = self.chains.get(&chain_id) else {
                return;
            };
            chain.admit(peers);
            next = chain.parent();
        }
    }

    /// `SendHeaders(chain, root)`. No `HeadersByRoot` RPC exists, so this asks for the
    /// block and takes its header.
    fn send_headers(
        &mut self,
        chain_id: ChainId,
        root: Hash256,
        cx: &mut SyncNetworkContext<T>,
        failed_peers: &HashSet<PeerId>,
    ) {
        let Some(chain) = self.chains.get_mut(&chain_id) else {
            return;
        };
        let peers = chain.peers().clone();
        if let Chain::Backfill { state, .. } = chain {
            *state = Backfill::Discovering(root);
        }
        match cx.blocks_by_root_batch_request(chain_id.0, vec![root], peers, failed_peers) {
            Ok(id) => {
                self.header_requests.insert(id.lookup_id, chain_id);
            }
            Err(e) => {
                debug!(?e, chain = chain_id.0, "Forward sync header request failed");
                self.drop_chain(chain_id);
            }
        }
    }

    /// True if `id` was issued by forward sync. On disconnect `peer_disconnected` labels
    /// every `blocks_by_root` request `SingleBlock` — it cannot see which map an id came
    /// from — so the manager asks here before routing the injected error.
    pub fn owns_request(&self, id: &SingleLookupReqId) -> bool {
        self.header_requests.contains_key(&id.lookup_id)
            || self.downloads.contains_key(&id.lookup_id)
    }

    /// Routes a batched `BlocksByRoot` response to whichever request issued it.
    pub fn on_blocks_by_root_batch(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        result: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if let Some(chain_id) = self.header_requests.remove(&id.lookup_id) {
            self.on_headers(chain_id, peer_id, result, cx);
        } else if self.downloads.contains_key(&id.lookup_id) {
            self.on_download_blocks(id, peer_id, result, cx);
        }
    }

    /// `OnHeaders(chain, result)`.
    fn on_headers(
        &mut self,
        chain_id: ChainId,
        peer_id: PeerId,
        result: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(next) = self
            .chains
            .get(&chain_id)
            .and_then(|chain| chain.discovering())
        else {
            return;
        };

        let blocks = match result {
            Ok(blocks) if !blocks.is_empty() => blocks,
            // A peer answering with nothing for a root it claimed leaves the walk exactly
            // where it was. Retry on another peer: returning here would leave the chain
            // `Discovering` with no request in flight, which nothing else can restart.
            _ => {
                if self
                    .chains
                    .get_mut(&chain_id)
                    .is_some_and(|chain| chain.bump_errors())
                {
                    self.drop_chain(chain_id);
                } else {
                    self.send_headers(chain_id, next, cx, &HashSet::from([peer_id]));
                }
                return self.promote(cx);
            }
        };

        if let Some(chain) = self.chains.get_mut(&chain_id) {
            chain.clear_errors();
        }

        let (finalized_root, finalized_slot) = Self::finalized(cx);
        let mut unresolved: Option<Hash256> = None;
        for block in blocks {
            let header = block.message().block_header();
            let root = header.canonical_root();
            if header.slot <= finalized_slot && root != finalized_root {
                self.report_chain(chain_id, cx);
                self.drop_chain(chain_id);
                return self.promote(cx);
            }

            let Some(chain) = self.chains.get_mut(&chain_id) else {
                return;
            };
            chain.roots_mut().push_back((root, header.slot));
            let parent = header.parent_root;

            if Self::is_known(cx, &parent) {
                if let Chain::Backfill { state, .. } = chain {
                    *state = Backfill::Anchored(parent);
                }
                unresolved = None;
                break;
            }

            match self.block_to_chain.get(&parent).copied() {
                Some(owner) if owner != chain_id => {
                    let peers = self
                        .chains
                        .get_mut(&chain_id)
                        .map(|chain| {
                            if let Chain::Backfill { state, .. } = chain {
                                *state = Backfill::Anchored(parent);
                            }
                            chain.peers().read().clone()
                        })
                        .unwrap_or_default();
                    // The peers that claimed this chain's tip hold the ancestors too, and
                    // `Search`'s ascent could not reach them: they did not exist yet.
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
            self.send_headers(chain_id, parent, cx, &HashSet::new());
        }

        self.prune();
        self.promote(cx);
    }

    /// `Promote` — runs after every transition.
    fn promote(&mut self, cx: &mut SyncNetworkContext<T>) {
        let ready: Vec<ChainId> = self
            .chains
            .iter()
            .filter(|(_, chain)| match chain {
                Chain::ForwardSync {
                    state: Sync::Ready(_),
                    parent,
                    ..
                } => Self::is_known(cx, parent),
                _ => false,
            })
            .map(|(chain_id, _)| *chain_id)
            .collect();
        for chain_id in ready {
            self.send_process(chain_id, cx);
        }

        while self.syncing_blocks() < MAX_SYNCING_BLOCKS {
            let Some(chain_id) = self.pick(cx) else {
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
            self.send_download(chain_id, cx);
        }
    }

    /// A `Backfill` chain whose parent is imported or already forward syncing, closest to
    /// the import frontier first.
    fn pick(&self, cx: &SyncNetworkContext<T>) -> Option<ChainId> {
        self.chains
            .iter()
            .filter(|(_, chain)| {
                let Chain::Backfill {
                    state: Backfill::Anchored(parent),
                    roots,
                    ..
                } = chain
                else {
                    return false;
                };
                if chain.peer_count() == 0 || roots.is_empty() {
                    return false;
                }
                Self::is_known(cx, parent)
                    || self
                        .block_to_chain
                        .get(parent)
                        .and_then(|chain_id| self.chains.get(chain_id))
                        .is_some_and(|owner| owner.is_forward_sync())
            })
            .min_by_key(|(_, chain)| chain.oldest_slot().unwrap_or_else(|| Slot::new(u64::MAX)))
            .map(|(chain_id, _)| *chain_id)
    }

    /// `SendDownload(chain)` — one coupled request for the chain's whole root set.
    fn send_download(&mut self, chain_id: ChainId, cx: &mut SyncNetworkContext<T>) {
        let Some(chain) = self.chains.get(&chain_id) else {
            return;
        };
        let roots: Vec<Hash256> = chain.roots().iter().rev().map(|(root, _)| *root).collect();
        let Some(oldest_slot) = chain.oldest_slot() else {
            return;
        };
        let peers = chain.peers().clone();
        let request_id = self.alloc();
        match BlockComponentsByRootRequest::new(
            request_id,
            roots,
            oldest_slot.epoch(<T::EthSpec as EthSpec>::slots_per_epoch()),
            peers,
            cx,
        ) {
            Ok(request) => {
                self.downloads.insert(request_id, (chain_id, request));
            }
            Err(e) => {
                debug!(?e, chain = chain_id.0, "Forward sync block request failed");
                self.on_download_failed(chain_id, cx);
            }
        }
    }

    fn on_download_blocks(
        &mut self,
        id: SingleLookupReqId,
        peer_id: PeerId,
        result: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some((chain_id, mut request)) = self.downloads.remove(&id.lookup_id) else {
            return;
        };
        let outcome = request.on_blocks_response(id, peer_id, result, cx);
        self.finish_download(id.lookup_id, chain_id, request, outcome, cx);
    }

    /// Routes a custody result for a coupled download.
    pub fn on_custody_result(
        &mut self,
        requester: Id,
        result: Result<DataColumnSidecarList<T::EthSpec>, super::network_context::RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some((chain_id, mut request)) = self.downloads.remove(&requester) else {
            return;
        };
        let outcome = request.on_custody_response(result, cx);
        self.finish_download(requester, chain_id, request, outcome, cx);
    }

    fn finish_download(
        &mut self,
        requester: Id,
        chain_id: ChainId,
        request: BlockComponentsByRootRequest<T>,
        outcome: Option<Result<Vec<RangeSyncBlock<T::EthSpec>>, ComponentsError>>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match outcome {
            // Still in flight.
            None => {
                self.downloads.insert(requester, (chain_id, request));
            }
            Some(Ok(blocks)) => {
                self.deliver_blocks(blocks);
                self.promote(cx);
            }
            Some(Err(e)) => {
                debug!(%e, chain = chain_id.0, "Forward sync download failed");
                for owner in self.owners(request.roots()) {
                    self.on_download_failed(owner, cx);
                }
            }
        }
    }

    /// `owners(R)` — the chains now holding these roots, deduped. A `Split` while the
    /// request was in flight moves some of `R` to a chain that never issued one, so the
    /// issuing id alone is not who the result belongs to.
    fn owners(&self, roots: &[Hash256]) -> Vec<ChainId> {
        let mut owners = Vec::new();
        for root in roots {
            if let Some(owner) = self.block_to_chain.get(root).copied()
                && !owners.contains(&owner)
            {
                owners.push(owner);
            }
        }
        owners
    }

    /// Hands each owner the blocks for the roots it holds. A chain takes them only if they
    /// cover it whole, so a root re-claimed by an unrelated chain cannot leave a partial
    /// `Ready` behind (Inv 5).
    fn deliver_blocks(&mut self, blocks: Vec<RangeSyncBlock<T::EthSpec>>) {
        let mut by_owner: HashMap<ChainId, Vec<RangeSyncBlock<T::EthSpec>>> = HashMap::new();
        for block in blocks {
            if let Some(owner) = self.block_to_chain.get(&block.block_root()).copied() {
                by_owner.entry(owner).or_default().push(block);
            }
        }
        for (owner, owned) in by_owner {
            let Some(Chain::ForwardSync { roots, state, .. }) = self.chains.get_mut(&owner) else {
                continue;
            };
            if matches!(state, Sync::Downloading) && owned.len() == roots.len() {
                *state = Sync::Ready(owned);
            }
        }
    }

    fn on_download_failed(&mut self, chain_id: ChainId, cx: &mut SyncNetworkContext<T>) {
        if self
            .chains
            .get_mut(&chain_id)
            .is_some_and(|chain| chain.bump_errors())
        {
            self.drop_chain(chain_id);
        } else {
            self.send_download(chain_id, cx);
        }
        self.promote(cx);
    }

    /// `SendProcess(chain)`.
    fn send_process(&mut self, chain_id: ChainId, cx: &mut SyncNetworkContext<T>) {
        let Some(Chain::ForwardSync { state, parent, .. }) = self.chains.get_mut(&chain_id) else {
            return;
        };
        if !cx.chain.block_is_known_to_fork_choice(parent) {
            return;
        }
        let Sync::Ready(blocks) = state else {
            return;
        };
        let blocks = std::mem::take(blocks);
        *state = Sync::Processing;

        let Some(processor) = cx.beacon_processor_if_enabled() else {
            return;
        };
        if let Err(e) =
            processor.send_chain_segment(ChainSegmentProcessId::ForwardSync(chain_id.0), blocks)
        {
            debug!(?e, chain = chain_id.0, "Forward sync process send failed");
            self.drop_chain(chain_id);
        }
    }

    /// `OnProcess(chain, result)`.
    pub fn on_process_result(
        &mut self,
        chain_id: ChainId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match result {
            BatchProcessResult::Success { .. } => {
                // Every root is in fork choice, so this is a clean removal — the
                // descendants are now eligible, not dead.
                if let Some(chain) = self.chains.remove(&chain_id) {
                    for (root, _) in chain.roots() {
                        self.block_to_chain.remove(root);
                    }
                }
            }
            BatchProcessResult::FaultyFailure { .. } => {
                self.report_chain(chain_id, cx);
                self.on_download_failed(chain_id, cx);
            }
            BatchProcessResult::NonFaultyFailure => {
                self.on_download_failed(chain_id, cx);
            }
        }
        self.promote(cx);
    }

    fn report_chain(&self, chain_id: ChainId, cx: &SyncNetworkContext<T>) {
        let Some(chain) = self.chains.get(&chain_id) else {
            return;
        };
        for peer in chain.peers().read().iter() {
            cx.report_peer(*peer, PeerAction::LowToleranceError, "forward_sync");
        }
    }

    /// `Disconnect(peer)`.
    pub fn disconnect(&mut self, peer: &PeerId, cx: &mut SyncNetworkContext<T>) {
        let mut orphaned = Vec::new();
        for (chain_id, chain) in self.chains.iter() {
            chain.peers().write().remove(peer);
            if chain.peer_count() == 0 {
                orphaned.push(*chain_id);
            }
        }
        for chain_id in orphaned {
            self.drop_chain(chain_id);
        }
        self.promote(cx);
    }

    /// `Drop(chain)` — the chain and, transitively, every chain anchored on one of its
    /// roots.
    fn drop_chain(&mut self, chain_id: ChainId) {
        let mut queue = vec![chain_id];
        while let Some(next_id) = queue.pop() {
            let Some(chain) = self.chains.remove(&next_id) else {
                continue;
            };
            self.header_requests.retain(|_, owner| *owner != next_id);
            self.downloads.retain(|_, (owner, _)| *owner != next_id);

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
                .min_by_key(|(_, chain)| chain.peer_count())
                .map(|(chain_id, _)| *chain_id)
            else {
                return;
            };
            self.drop_chain(chain_id);
        }
    }
}
