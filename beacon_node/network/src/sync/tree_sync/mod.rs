//! Tree sync: walk back from a peer's claimed head by parent root until reaching a block we
//! know, then import the discovered blocks forward.
//!
//! Goals, in order:
//!
//! 1. Never stall: every chain state names the event that resolves it; a broken invariant
//!    drops the whole forest, and sync rebuilds from peers' head advertisements.
//! 2. Never lose a peer: a peer claiming a root joins every chain it can serve, even
//!    mid-import — hence chains may split at any time and batch results route by root.
//! 3. Ask a peer only for roots it claimed, and hold it to them: a claimed root is fetched
//!    regardless of the peer's earliest available slot.
//!
//! Invariants:
//!
//! 1. Every root known to tree sync is owned by exactly one chain (`block_to_chain`).
//! 2. Every peer of a chain has claimed every root of the chain.

use super::manager::BatchProcessResult;
use super::network_context::components_by_root::BlockSummary;
use super::network_context::components_by_root::Error as ComponentsError;
use super::network_context::{
    BlockRootsRequest, DownloadError, LookupRequestResult, RpcResponseResult, SyncNetworkContext,
};
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::network_context::DownloadRequest;
use beacon_chain::BeaconChainTypes;
use beacon_chain::block_verification_types::RangeSyncBlock;
use lighthouse_network::service::api_types::{
    BeaconBlocksByRootRequestId, BeaconBlocksByRootRequester, ComponentsByRootRequestId,
};
use lighthouse_network::{PeerAction, PeerId};
use parking_lot::RwLock;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, instrument, warn};
use types::{EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Tuning for the forest. Injectable so tests can reach the batch, budget and pruning
/// boundaries without building thousand-block chains.
#[derive(Clone, Copy, Debug)]
pub struct TreeSyncConfig {
    /// Roots imported at a time. Below the by-root cap of 128. Spec: `B`.
    pub batch_size: usize,
    /// Maximum blocks in the import pipeline across all chains. Spec: `N`.
    pub max_syncing_blocks: usize,
    /// Roots are untrusted peer claims, so bound how many we hold.
    pub roots_max: usize,
    /// How long a chain may go without moving before it is assumed stuck. Long enough never
    /// to fire while a walk is making round trips, short enough to unstick a node without a
    /// restart.
    pub chain_stuck_timeout: Duration,
}

impl Default for TreeSyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            max_syncing_blocks: 256,
            roots_max: 1_000_000,
            chain_stuck_timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId(pub u32);

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Shared with the chain's custody requests, which read it live to pick retry peers.
type Peers = Arc<RwLock<HashSet<PeerId>>>;

/// Discovery walks headers; the roots land in `Chain::roots`, not here.
type DiscoveryRequest = DownloadRequest<(), BeaconBlocksByRootRequestId>;
/// Blocks with their columns and payloads. They land in `AwaitingProcessing`, not here.
type ImportRequest = DownloadRequest<(), ComponentsByRootRequestId>;

/// Why a chain is dropped.
#[derive(Debug)]
enum DropReason {
    HeadersRequest(#[allow(dead_code)] DownloadError),
    BlocksRequest(#[allow(dead_code)] DownloadError),
    /// The beacon processor did not accept the batch.
    Processor(#[allow(dead_code)] String),
    /// Discovery reached a block at or below finality that is not the finalized root.
    FinalityConflict,
    /// An ancestor was served at a slot at or above the block it is the parent of.
    NonDecreasingSlot,
    /// Nothing moved it before the stuck timeout, so no event ever will.
    Stuck,
    NoPeers,
    Pruned,
}

#[derive(Clone)]
enum ChainState<E: EthSpec> {
    /// Walking back the ancestors of `next`.
    Discovering {
        next: Hash256,
        request: DiscoveryRequest,
    },
    /// Discovery done, waiting to be promoted into the import pipeline.
    Anchored(Hash256),
    /// In the import pipeline, waiting on the anchor to be imported.
    ForwardSync(Hash256, ForwardSyncState<E>),
}

/// Where a chain is in the import pipeline.
#[derive(Clone)]
enum ForwardSyncState<E: EthSpec> {
    /// Downloading the blocks of the chain's whole root set.
    Downloading(ImportRequest),
    /// Blocks in hand, waiting for the anchor to be imported.
    AwaitingProcessing(Vec<RangeSyncBlock<E>>),
    /// Blocks submitted to the beacon processor.
    Processing,
}

/// A run of ancestor roots sharing one peer set.
struct Chain<E: EthSpec> {
    /// Tip first.
    roots: VecDeque<BlockSummary>,
    /// Each has claimed every root (Inv 2).
    peers: Peers,
    state: ChainState<E>,
    /// When the chain last moved. Only `set_state` writes it, so a transition cannot
    /// forget to, and a chain that stops moving is dropped by `drop_stuck_chains`.
    last_progress: Instant,
}

impl<E: EthSpec> Chain<E> {
    /// Moves the chain on and records that it did.
    fn set_state(&mut self, state: ChainState<E>) {
        self.state = state;
        self.last_progress = Instant::now();
    }

    /// The parent root this chain waits on. `None` while still discovering.
    fn parent(&self) -> Option<Hash256> {
        match self.state {
            ChainState::Discovering { .. } => None,
            ChainState::Anchored(anchor) | ChainState::ForwardSync(anchor, _) => Some(anchor),
        }
    }

    /// A new chain discovering the ancestors of `root`, claimed by `peers`.
    fn new(root: Hash256, peers: &[PeerId]) -> Self {
        Self {
            roots: VecDeque::new(),
            peers: Arc::new(RwLock::new(peers.iter().copied().collect())),
            state: ChainState::Discovering {
                next: root,
                request: DownloadRequest::new(),
            },
            last_progress: Instant::now(),
        }
    }

    fn add_peers(&self, peers: &[PeerId]) {
        self.peers.write().extend(peers.iter().copied());
    }

    /// Penalizes every peer: each one claimed every root of this chain (Inv 2).
    fn report_peers<T: BeaconChainTypes<EthSpec = E>>(&self, cx: &SyncNetworkContext<T>) {
        for peer in self.peers.read().iter() {
            cx.report_peer(*peer, PeerAction::LowToleranceError, "tree_sync");
        }
    }

    /// Newest root.
    fn oldest_slot(&self) -> Option<Slot> {
        self.roots.back().map(|block| block.slot)
    }

    fn is_importing(&self) -> bool {
        match self.state {
            ChainState::Discovering { .. } | ChainState::Anchored(_) => false,
            ChainState::ForwardSync(..) => true,
        }
    }

    /// Every root this chain owns in the index: its roots, plus the unfetched one (Inv 1).
    fn claimed_roots(&self) -> HashSet<Hash256> {
        let mut claimed: HashSet<Hash256> =
            self.roots.iter().map(|block| block.block_root).collect();
        claimed.extend(self.discovering());
        claimed
    }

    /// The root the walk is currently after, claimed in the index but not yet in `roots`.
    fn discovering(&self) -> Option<Hash256> {
        match self.state {
            ChainState::Discovering { next, .. } => Some(next),
            ChainState::Anchored(_) | ChainState::ForwardSync(..) => None,
        }
    }

    /// Issues the request this state waits on, or submits blocks once the anchor is in.
    /// `Err` is the reason to drop the chain.
    fn continue_requests<T: BeaconChainTypes<EthSpec = E>>(
        &mut self,
        chain_id: ChainId,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), DropReason> {
        // An arm holds `&mut self.state`, so a transition it decides on is applied once
        // that borrow ends — which keeps it going through `set_state`.
        let mut next_state = None;
        let result = match &mut self.state {
            ChainState::Discovering { next, request } => {
                let root = *next;
                // A fresh chain has no roots yet; its tip-to-be is the search target
                let tip = self.roots.front().map_or(root, |block| block.block_root);
                let peers = self.peers.clone();
                request
                    .maybe_start_downloading(|failed_peers| {
                        match cx.send_blocks_by_root_request(
                            BlockRootsRequest::new(root),
                            BeaconBlocksByRootRequester::TreeSyncHeaders(tip),
                            &peers,
                            failed_peers,
                            true,
                        )? {
                            Some(id) => Ok(LookupRequestResult::RequestSent(id)),
                            None => Ok(LookupRequestResult::Pending("no peers")),
                        }
                    })
                    .map_err(DropReason::HeadersRequest)
            }
            // Waiting to be promoted by `advance`
            ChainState::Anchored(_) => Ok(()),
            ChainState::ForwardSync(anchor, forward_sync) => match forward_sync {
                ForwardSyncState::Downloading(download) => {
                    let peers = self.peers.clone();
                    let roots = &self.roots;
                    download
                        .maybe_start_downloading(|_failed_peers| {
                            let blocks: Vec<BlockSummary> = roots.iter().rev().cloned().collect();
                            cx.components_by_root_request(chain_id.0, &blocks, peers.clone())
                                .map(LookupRequestResult::RequestSent)
                        })
                        .map_err(DropReason::BlocksRequest)
                }
                ForwardSyncState::AwaitingProcessing(blocks) => {
                    if cx.block_is_known_to_fork_choice(anchor) {
                        // As in lookup sync, an offline engine drops the work rather
                        // than holding it
                        let processor = cx
                            .beacon_processor_if_enabled()
                            .cloned()
                            .ok_or(DropReason::Processor("processor offline".to_string()))?;
                        let roots = blocks.iter().map(|block| block.block_root()).collect();
                        processor
                            .send_chain_segment(
                                ChainSegmentProcessId::TreeSync(roots),
                                blocks.clone(),
                            )
                            .map_err(|e| DropReason::Processor(format!("{e:?}")))?;
                        next_state = Some(ChainState::ForwardSync(
                            *anchor,
                            ForwardSyncState::Processing,
                        ));
                    }
                    Ok(())
                }
                // Waiting on the beacon processor
                ForwardSyncState::Processing => Ok(()),
            },
        };
        if let Some(state) = next_state {
            self.set_state(state);
        }
        result
    }

    /// Keeps `[pivot..oldest]` and returns the newer `[tip..]` half, which waits on
    /// `pivot`. `None` when there is nothing to cut off.
    fn split_at(&mut self, pivot: Hash256) -> Result<Option<Self>, InternalError> {
        let newer_roots = if let ChainState::Discovering { next, .. } = self.state
            && next == pivot
        {
            // Everything held descends from the unfetched `pivot`: hand those roots
            // over, and keep the walk here for a peer that claimed `pivot` to join
            if self.roots.is_empty() {
                return Ok(None);
            }
            std::mem::take(&mut self.roots)
        } else {
            let index = self
                .roots
                .iter()
                .position(|block| block.block_root == pivot)
                .ok_or(InternalError::from("chain does not contain a root it owns"))?;
            if index == 0 {
                // Already the tip: the chain is exactly `pivot` and below
                return Ok(None);
            }
            // `roots` is tip first, so `[index..]` is the pivot and everything older
            let older_roots = self.roots.split_off(index);
            std::mem::replace(&mut self.roots, older_roots)
        };

        // The older half keeps this chain's state as it is; only the newer half's is built
        let newer_state = match &mut self.state {
            // The tip moves to the newer half, and responses route by tip, so re-arm
            // the walk to re-issue under the tip this half keeps
            ChainState::Discovering { request, .. } => {
                *request = DownloadRequest::new();
                ChainState::Anchored(pivot)
            }
            ChainState::Anchored(_) => ChainState::Anchored(pivot),
            // Both halves stay in the same step of the pipeline, anchored on the pivot
            ChainState::ForwardSync(_, forward_sync) => {
                let newer_forward_sync = match forward_sync {
                    // Both halves are covered by the request, so both keep it
                    ForwardSyncState::Downloading(download) => {
                        ForwardSyncState::Downloading(download.clone())
                    }
                    // Held blocks follow whichever half kept their root
                    ForwardSyncState::AwaitingProcessing(blocks) => {
                        let kept: HashSet<Hash256> =
                            self.roots.iter().map(|block| block.block_root).collect();
                        let (older, newer) = std::mem::take(blocks)
                            .into_iter()
                            .partition(|block| kept.contains(&block.block_root()));
                        *blocks = older;
                        ForwardSyncState::AwaitingProcessing(newer)
                    }
                    // The batch result routes by root and resolves each half
                    ForwardSyncState::Processing => ForwardSyncState::Processing,
                };
                ChainState::ForwardSync(pivot, newer_forward_sync)
            }
        };
        Ok(Some(Chain {
            roots: newer_roots,
            peers: Arc::new(RwLock::new(self.peers.read().clone())),
            state: newer_state,
            last_progress: Instant::now(),
        }))
    }
}

/// A state the invariants forbid. Should never happen; handled by `reset`.
#[derive(Debug)]
struct InternalError(String);

impl From<&str> for InternalError {
    fn from(reason: &str) -> Self {
        InternalError(reason.to_owned())
    }
}

/// A chain id that does not resolve to a chain: the index and the forest disagree (Inv 1).
fn missing_chain(chain_id: ChainId) -> InternalError {
    InternalError(format!("chain {chain_id} is not in the forest"))
}

/// The chain forest.
pub struct TreeSync<T: BeaconChainTypes> {
    /// Which chain owns each root we intend to sync (Inv 1).
    block_to_chain: HashMap<Hash256, ChainId>,
    chains: HashMap<ChainId, Chain<T::EthSpec>>,
    next_id: u32,
    config: TreeSyncConfig,
}

impl<T: BeaconChainTypes> TreeSync<T> {
    pub fn new() -> Self {
        Self {
            block_to_chain: HashMap::new(),
            chains: HashMap::new(),
            next_id: 0,
            config: TreeSyncConfig::default(),
        }
    }

    fn chain(&self, chain_id: ChainId) -> Result<&Chain<T::EthSpec>, InternalError> {
        self.chains.get(&chain_id).ok_or(missing_chain(chain_id))
    }

    fn chain_mut(&mut self, chain_id: ChainId) -> Result<&mut Chain<T::EthSpec>, InternalError> {
        self.chains
            .get_mut(&chain_id)
            .ok_or(missing_chain(chain_id))
    }

    /* Search requests */

    /// A peer claims `root`: walk its ancestors, or join the chains already covering it.
    pub fn search(&mut self, root: Hash256, peers: &[PeerId], cx: &mut SyncNetworkContext<T>) {
        if !self.block_to_chain.contains_key(&root) {
            let chain_id = self.next_chain_id();
            self.chains.insert(chain_id, Chain::new(root, peers));
            self.block_to_chain.insert(root, chain_id);
            debug!(%chain_id, %root, peers = peers.len(), "Created tree sync chain");
        }

        // A peer that claims `root` also claims every ancestor of it (Inv 2)
        if let Err(e) = self
            .add_peers_to_ancestors(root, peers)
            .and_then(|()| self.update(cx))
        {
            self.reset(e, "search");
        }
    }

    /// Adds `peers` to the chain owning `root` and to every chain below it. They claimed
    /// `root` and its ancestors only, so each chain is split at `root` first (Inv 2).
    fn add_peers_to_ancestors(
        &mut self,
        root: Hash256,
        peers: &[PeerId],
    ) -> Result<(), InternalError> {
        let mut visited: HashSet<ChainId> = HashSet::new();
        let mut next_root = Some(root);
        while let Some(root) = next_root {
            // The first root no chain owns ends the ascent: fork-choice has it
            let Some(&chain_id) = self.block_to_chain.get(&root) else {
                break;
            };
            // Parent links run strictly older, so a chain cannot be reached twice
            if !visited.insert(chain_id) {
                return Err(InternalError::from("cycle in the chain parent links"));
            }
            // Peers join only what they claimed: `split` leaves `root` and below here
            self.split(chain_id, root)?;
            let chain = self.chain(chain_id)?;
            chain.add_peers(peers);
            next_root = chain.parent();
        }
        Ok(())
    }

    /* Network responses */

    /// Response to a chain's `Discovering` request.
    #[instrument(level = "debug", skip_all, fields(req = %request_id))]
    pub fn on_headers(
        &mut self,
        tip: Hash256,
        request_id: BeaconBlocksByRootRequestId,
        peer_id: PeerId,
        result: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let walked = match self.block_to_chain.get(&tip) {
            Some(&chain_id) => self.accept_headers(chain_id, request_id, peer_id, result, cx),
            None => {
                // The chain was dropped while the request was in flight
                debug!(%tip, "Headers for a root no chain owns");
                Ok(())
            }
        };
        if let Err(e) = walked.and_then(|()| self.update(cx)) {
            self.reset(e, "headers");
        }
    }

    /// Acts on a discovery response, if the chain is still waiting on that attempt.
    fn accept_headers(
        &mut self,
        chain_id: ChainId,
        request_id: BeaconBlocksByRootRequestId,
        peer_id: PeerId,
        result: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), InternalError> {
        let chain = self.chain_mut(chain_id)?;

        // A superseded attempt must not append roots nor spend the current one's budget
        if let ChainState::Discovering { request, .. } = &mut chain.state
            && request.is_current(&request_id)
        {
            match result {
                Ok(blocks) => self.extend_chain(chain_id, blocks, cx)?,
                Err(e) => {
                    debug!(error = ?e, "Headers request failed");
                    // Re-arm to retry away from the peer; `advance` issues it
                    request.failed(Some(peer_id));
                }
            }
        } else {
            debug!("Headers for a chain not awaiting this attempt");
        }
        Ok(())
    }

    /// One step of the walk: append the blocks, then leave the state saying what's next.
    fn extend_chain(
        &mut self,
        chain_id: ChainId,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), InternalError> {
        let chain = self
            .chains
            .get_mut(&chain_id)
            .ok_or(missing_chain(chain_id))?;

        let (finalized_root, finalized_slot) = cx.finalized();

        for block in &blocks {
            let header = block.message().block_header();
            let root = header.canonical_root();

            // Below finality off the finalized root: unimportable, and so is its subtree
            if header.slot <= finalized_slot && root != finalized_root {
                chain.report_peers(cx);
                self.drop_chain_and_children(chain_id, DropReason::FinalityConflict);
                return Ok(());
            }

            // Walking back, so slots strictly decrease (Inv 3). A peer breaking this is
            // feeding us a fabricated ancestry, which without this check walks until the
            // finality guard or the root cap stops it.
            if let Some(newest) = chain.roots.back()
                && header.slot >= newest.slot
            {
                chain.report_peers(cx);
                self.drop_chain_and_children(chain_id, DropReason::NonDecreasingSlot);
                return Ok(());
            }

            chain.roots.push_back(BlockSummary {
                block_root: root,
                slot: header.slot,
                has_data: block.num_expected_blobs() > 0,
                has_payload: cx
                    .chain
                    .spec
                    .fork_name_at_slot::<T::EthSpec>(header.slot)
                    .gloas_enabled(),
            });
            let parent = header.parent_root;

            // The parent is in fork-choice: discovery is done
            if cx.block_is_known_to_fork_choice(&parent) {
                debug!(roots = chain.roots.len(), "Chain anchored on fork-choice");
                chain.set_state(ChainState::Anchored(parent));
                return Ok(());
            }

            // Another chain owns the parent: anchor on it, and hand it our peers, who
            // claimed this tip and so its ancestors too (Inv 2)
            if let Some(&parent_chain) = self.block_to_chain.get(&parent)
                && parent_chain != chain_id
            {
                chain.set_state(ChainState::Anchored(parent));
                let peers = chain.peers.read().iter().copied().collect::<Vec<_>>();
                debug!(%parent_chain, peers = peers.len(), "Chain anchored");
                self.add_peers_to_ancestors(parent, &peers)?;
                return Ok(());
            }

            // Claim `parent` now, so a concurrent search cannot duplicate it (Inv 1)
            self.block_to_chain.insert(parent, chain_id);
        }

        // More to fetch. A step is progress, so the next request gets a full budget
        let oldest = blocks.last().ok_or(InternalError::from("empty response"))?;
        let next = oldest.message().parent_root();
        chain.set_state(ChainState::Discovering {
            next,
            request: DownloadRequest::new(),
        });
        Ok(())
    }

    /// The coupled download finished: blocks arrive with their columns already attached.
    #[instrument(level = "debug", skip_all, fields(req = %req_id))]
    pub fn on_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        result: Result<Vec<RangeSyncBlock<T::EthSpec>>, ComponentsError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let handled = match result {
            Ok(blocks) => self.on_blocks_downloaded(req_id, blocks),
            Err(e) => {
                debug!(error = ?e, "Download failed");
                // Splits duplicate the request, so every holder re-arms
                for (chain_id, chain) in self.chains.iter_mut() {
                    if let ChainState::ForwardSync(_, ForwardSyncState::Downloading(download)) =
                        &mut chain.state
                        && download.is_current(&req_id)
                    {
                        download.failed(None);
                    } else {
                        debug!(%chain_id, "Blocks for a chain not awaiting this attempt");
                    }
                }
                Ok(())
            }
        };
        if let Err(e) = handled.and_then(|()| self.update(cx)) {
            self.reset(e, "download_result");
        }
    }

    /// Hands downloaded blocks to the chains that own them now — a split may have moved
    /// them — and only to a chain they cover whole.
    fn on_blocks_downloaded(
        &mut self,
        req_id: ComponentsByRootRequestId,
        blocks: Vec<RangeSyncBlock<T::EthSpec>>,
    ) -> Result<(), InternalError> {
        let mut blocks_by_owner: HashMap<ChainId, Vec<RangeSyncBlock<T::EthSpec>>> = HashMap::new();
        let mut unowned = 0usize;
        for block in blocks {
            match self.block_to_chain.get(&block.block_root()) {
                Some(owner) => blocks_by_owner.entry(*owner).or_default().push(block),
                // The chain that wanted the block was dropped while the request was out
                None => unowned += 1,
            }
        }
        if unowned > 0 {
            debug!(
                blocks = unowned,
                "Downloaded blocks no longer owned by any chain"
            );
        }

        for (owner, blocks) in blocks_by_owner {
            let chain = self.chain_mut(owner)?;
            // Splits duplicate the request, so every holder checks the attempt itself
            if let ChainState::ForwardSync(anchor, ForwardSyncState::Downloading(request)) =
                &chain.state
                && request.is_current(&req_id)
            {
                // we assume blocks.len() == chain.roots len
                chain.state =
                    ChainState::ForwardSync(*anchor, ForwardSyncState::AwaitingProcessing(blocks));
            } else {
                debug!(chain = %owner, "Blocks for a chain not awaiting this attempt");
            }
        }
        Ok(())
    }

    /* Processing responses */

    /// Result of a batch, identified by its roots: a chain can split while processing,
    /// so each root is routed through the ownership mapping again (Inv 1).
    pub fn on_processing_result(
        &mut self,
        roots: Vec<Hash256>,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        debug!(
            ?result,
            roots = roots.len(),
            "Received batch processing result"
        );
        if let Err(e) = self
            .on_blocks_processed(roots, result, cx)
            .and_then(|()| self.update(cx))
        {
            self.reset(e, "processing_result");
        }
    }

    /// Applies the batch result to the chains it resolves: those `Processing` and covered
    /// whole, since splits partition a batch exactly. A chain that merely overlaps it
    /// re-formed after a drop and waits on its own event.
    fn on_blocks_processed(
        &mut self,
        roots: Vec<Hash256>,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), InternalError> {
        let mut covered: HashMap<ChainId, usize> = HashMap::new();
        let mut unowned = 0usize;
        for root in &roots {
            match self.block_to_chain.get(root) {
                Some(owner) => *covered.entry(*owner).or_default() += 1,
                // The chain that submitted the batch was dropped while it was processing
                None => unowned += 1,
            }
        }
        if unowned > 0 {
            debug!(roots = unowned, "Batch roots no longer owned by any chain");
        }

        for (chain_id, owned) in covered {
            let chain = self.chain(chain_id)?;
            // Splits partition a batch exactly, so its chain is `Processing` and whole
            let is_batch_chain = owned == chain.roots.len()
                && matches!(
                    chain.state,
                    ChainState::ForwardSync(_, ForwardSyncState::Processing)
                );

            if is_batch_chain {
                match &result {
                    // Every root is in fork-choice, so chains anchored on them can go
                    BatchProcessResult::Success { .. } => {
                        let chain = self
                            .chains
                            .remove(&chain_id)
                            .ok_or(missing_chain(chain_id))?;
                        debug!(%chain_id, roots = chain.roots.len(), "Chain imported");
                        for block in &chain.roots {
                            self.block_to_chain.remove(&block.block_root);
                        }
                    }
                    // The blocks went with the `Processing` state, so fetch them again.
                    // A batch also carries other peers' columns and payloads, so a fault
                    // may be theirs: downscore everyone who served it
                    BatchProcessResult::NonFaultyFailure
                    | BatchProcessResult::FaultyFailure { .. } => {
                        if matches!(result, BatchProcessResult::FaultyFailure { .. }) {
                            chain.report_peers(cx);
                        }
                        let chain = self.chain_mut(chain_id)?;
                        if let ChainState::ForwardSync(_, state) = &mut chain.state {
                            *state = ForwardSyncState::Downloading(DownloadRequest::new());
                        } else {
                            return Err(InternalError::from("not in processing state"));
                        }
                    }
                }
            } else {
                // Not this batch's chain: its own pending event resolves it
                debug!(%chain_id, "Batch overlaps an unrelated chain");
            }
        }
        Ok(())
    }

    /* Error responses */

    pub fn peer_disconnected(&mut self, peer_id: &PeerId, cx: &mut SyncNetworkContext<T>) {
        let mut orphaned = vec![]; // < buffer ids to not re-borrow &mut self on drop
        for (chain_id, chain) in self.chains.iter() {
            let mut peers = chain.peers.write();
            peers.remove(peer_id);
            if peers.is_empty() {
                orphaned.push(*chain_id);
            }
        }
        for chain_id in orphaned {
            self.drop_chain_and_children(chain_id, DropReason::NoPeers);
        }
        if let Err(e) = self.update(cx) {
            self.reset(e, "peer_disconnected");
        }
    }

    /* Helper functions */

    /// An invariant broke, so no chain can be trusted and any of them may be stuck. Drop
    /// them all: peers keep advertising their heads, so the forest rebuilds itself.
    fn reset(&mut self, error: InternalError, source: &str) {
        error!(
            source,
            reason = error.0,
            chains = self.chains.len(),
            "Tree sync invariant broken, dropping all chains"
        );
        self.chains.clear();
        self.block_to_chain.clear();
    }

    /// Re-drives the forest: prune, promote, then issue what each state waits on.
    fn update(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), InternalError> {
        self.prune();
        let promoted = self.advance(cx);
        self.continue_requests(cx);
        promoted
    }

    /// Promotes `Anchored` chains up to the block budget, so handlers need only
    /// transition states. Spec: `Promote`.
    fn advance(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), InternalError> {
        // Blocks already in the import pipeline, bounding how many more chains to promote
        let mut syncing_blocks: usize = self
            .chains
            .values()
            .filter(|chain| chain.is_importing())
            .map(|chain| chain.roots.len())
            .sum();

        while syncing_blocks < self.config.max_syncing_blocks {
            let Some(chain_id) = self.next_importable_chain(cx) else {
                break;
            };
            // Import at most `batch_size` blocks at once
            self.split_at_count(chain_id, self.config.batch_size)?;

            let chain = self.chain_mut(chain_id)?;
            let ChainState::Anchored(anchor) = &chain.state else {
                return Err(InternalError::from("promoted chain is not anchored"));
            };
            chain.set_state(ChainState::ForwardSync(
                *anchor,
                ForwardSyncState::Downloading(DownloadRequest::new()),
            ));
            syncing_blocks += chain.roots.len();
            debug!(%chain_id, roots = chain.roots.len(), "Chain started importing");
        }
        Ok(())
    }

    /// The next `Anchored` chain whose parent is imported or importing. Most corroborated
    /// first, so a lone claimer cannot starve the chain most peers agree on; ties go to
    /// the import frontier.
    ///
    /// TODO(tree-sync): enough sybil peers per chain still occupies the whole pipeline.
    /// Weight the choice by peer count instead, so every chain eventually gets a turn.
    fn next_importable_chain(&self, cx: &SyncNetworkContext<T>) -> Option<ChainId> {
        self.chains
            .iter()
            .filter_map(|(chain_id, chain)| {
                let ChainState::Anchored(parent) = &chain.state else {
                    return None;
                };
                let parent_available = cx.block_is_known_to_fork_choice(parent)
                    || self
                        .block_to_chain
                        .get(parent)
                        .and_then(|chain_id| self.chains.get(chain_id))
                        .is_some_and(|owner| owner.is_importing());
                if !parent_available {
                    return None;
                }
                // `Anchored` implies non-empty roots: anchoring appends at least one root
                Some((chain_id, chain.peers.read().len(), chain.oldest_slot()?))
            })
            .min_by_key(|&(_, peer_count, oldest_slot)| (Reverse(peer_count), oldest_slot))
            .map(|(chain_id, _, _)| *chain_id)
    }

    /// Issues what each chain waits on, and submits those whose anchor has imported.
    fn continue_requests(&mut self, cx: &mut SyncNetworkContext<T>) {
        let mut failed = vec![]; // < buffer drop reasons to not re-borrow &mut self
        for (chain_id, chain) in self.chains.iter_mut() {
            if let Err(reason) = chain.continue_requests(*chain_id, cx) {
                failed.push((*chain_id, reason));
            }
        }
        for (chain_id, reason) in failed {
            self.drop_chain_and_children(chain_id, reason);
        }
    }

    /// Splits so the oldest `n` roots stay under `chain_id`. `None` if it holds `n` or
    /// fewer.
    fn split_at_count(
        &mut self,
        chain_id: ChainId,
        n: usize,
    ) -> Result<Option<ChainId>, InternalError> {
        let chain = self.chain(chain_id)?;
        match chain.roots.iter().nth_back(n.saturating_sub(1)) {
            Some(pivot) => self.split(chain_id, pivot.block_root),
            None => Ok(None),
        }
    }

    /// The older half keeps `chain_id`, its state and any request in flight; the newer
    /// half becomes a chain anchored on `root`. `None` if `root` is already the tip.
    fn split(
        &mut self,
        chain_id: ChainId,
        root: Hash256,
    ) -> Result<Option<ChainId>, InternalError> {
        let chain = self.chain_mut(chain_id)?;
        match chain.split_at(root)? {
            None => Ok(None),
            Some(newer) => {
                let newer_id = self.next_chain_id();
                for block in &newer.roots {
                    self.block_to_chain.insert(block.block_root, newer_id);
                }
                self.chains.insert(newer_id, newer);
                Ok(Some(newer_id))
            }
        }
    }

    /// Drops chains that stopped moving, mirroring lookup sync's `drop_stuck_lookups`. The
    /// forest is event driven, so a bug anywhere upstream can leave a chain nothing will ever
    /// drive again. Dropping it lets peer status messages rebuild the walk instead of the
    /// node stalling until it restarts.
    pub fn drop_stuck_chains(&mut self, cx: &mut SyncNetworkContext<T>) {
        let timeout = self.config.chain_stuck_timeout;
        while let Some((chain_id, roots)) = self
            .chains
            .iter()
            .find(|(_, chain)| chain.last_progress.elapsed() > timeout)
            .map(|(chain_id, chain)| (*chain_id, chain.roots.len()))
        {
            warn!(%chain_id, roots, "Notify the devs a tree sync chain is stuck");
            self.drop_chain_and_children(chain_id, DropReason::Stuck);
        }
        if let Err(e) = self.update(cx) {
            self.reset(e, "drop_stuck_chains");
        }
    }

    /// Drops the chain and every chain anchored on one of its roots, which now waits on
    /// a parent that will never arrive. In-flight requests are the network context's to
    /// retire, not ours.
    // TODO(tree-sync): peers that claimed roots and never served them are not downscored
    // here, so a slow-loris occupies import budget for free.
    fn drop_chain_and_children(&mut self, initial_chain_id: ChainId, reason: DropReason) {
        let mut queue = vec![initial_chain_id];
        while let Some(chain_id) = queue.pop() {
            // A chain can be queued twice when two dropped parents both anchor it
            let Some(chain) = self.chains.remove(&chain_id) else {
                continue;
            };
            debug!(%chain_id, ?reason, "Chain dropped");
            let dropped = chain.claimed_roots();
            // Sweep by owner, not by `dropped`: an aborted walk can leave a claimed
            // root in neither `roots` nor `discovering`
            self.block_to_chain.retain(|_, owner| *owner != chain_id);
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

    /// Bounds the total roots tracked across all chains.
    fn prune(&mut self) {
        while self.block_to_chain.len() > self.config.roots_max {
            // Least corroborated first: one peer is a fork nobody else has
            let Some(chain_id) = self
                .chains
                .iter()
                .min_by_key(|(_, chain)| chain.peers.read().len())
                .map(|(chain_id, _)| *chain_id)
            else {
                return;
            };
            self.drop_chain_and_children(chain_id, DropReason::Pruned);
        }
    }

    fn next_chain_id(&mut self) -> ChainId {
        let id = ChainId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }
}
