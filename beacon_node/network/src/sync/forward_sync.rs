use super::network_context::{
    DownloadRequest, DownloadRequestError, RpcRequestSendError, RpcResponseError,
    SyncNetworkContext,
};
use crate::metrics;
use crate::sync::network_context::{BatchPeers, RpcResponseResult};
use crate::sync::sync_block::{Error as SyncBlockError, SyncBlock, SyncBlockResult};
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use itertools::Itertools;
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, ComponentsByRootRequestId, HeaderLookupId, Id,
    RangeRequestId,
};
use lighthouse_network::PeerId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::{debug, error};
use types::{BeaconBlockHeader, EthSpec, Hash256, SignedBeaconBlock, Slot};

const MAX_LOOKUP_COUNT: usize = 1_000_000;
const PRUNE_COUNT: usize = 100_000;
const BLOCK_BUFFER_SIZE: usize = 2;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
struct TipId(u32);

/// Roots are added to ForwardSync via:
/// 1. Peers referencing an unknown block root
/// 2. When fetching the next ancestor of a chain, the parent is unknown
///
/// Invariants:
/// - Each block references a single chain
/// - Each block root exists in exactly one `Chain::block_roots` list
/// - A block can change what chain it belongs to at any moment, including during an active request
///
/// Goals
/// - Download multiple blocks at once to increase download speed
pub struct ForwardSync<T: BeaconChainTypes> {
    block_to_tip: HashMap<Hash256, TipId>,
    chains: HashMap<TipId, Chain<T>>,
}

/// Chain of consecutive blocks that are imported by the same set of peers
struct Chain<T: BeaconChainTypes> {
    peers: HashSet<PeerId>,
    status: ChainStatus<T>,
}

struct ForwardSyncBlock<T: BeaconChainTypes> {
    id: HeaderLookupId,
    status: Status<T>,
}

enum ChainStatus<T: BeaconChainTypes> {
    // Recursively fetch headers until discovering a parent_root that is known, then transition
    // state to `ForwardSync`.
    BackfillHeaders {
        /// Headers descendant of `next_block_root` that are already downloaded.
        /// Sorting: tip first, oldest ancestor last
        block_roots: Vec<Hash256>,
        /// Oldest ancestor block root of this Chain.
        next_header_request: HeaderRequest,
    },
    WaitingParentChain {
        parent_root: Hash256,
        /// Sorting: tip first, oldest ancestor last
        block_roots: Vec<Hash256>,
    },
    // Sync blocks from old to new buffering some blocks
    ForwardSync {
        /// Sorting: tip first, oldest ancestor last
        block_roots: Vec<Hash256>,
        /// Sorting: oldest ancestor first
        syncing_blocks: VecDeque<SyncBlock<T>>,
    },
}

enum Status<T: BeaconChainTypes> {
    // TODO(tree-sync): Make the "waiting" completed header requests as memory cheap as possible
    BackfillHeader {
        failed_peers: HashSet<PeerId>,
        request: DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>,
    },
    ForwardSyncBlock {
        header: BeaconBlockHeader,
        request: SyncBlock<T>,
    },
}

struct HeaderRequest {
    id: HeaderLookupId,
    block_root: Hash256,
    failed_peers: HashSet<PeerId>,
    request: DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>,
}

impl HeaderRequest {
    fn new(block_root: Hash256, id: Id) -> Self {
        Self {
            id: HeaderLookupId { id, block_root },
            block_root,
            failed_peers: <_>::default(),
            request: DownloadRequest::new(),
        }
    }

    fn empty() -> Self {
        Self::new(Hash256::ZERO, 0)
    }

    fn continue_request<T: BeaconChainTypes>(
        &mut self,
        peers: &HashSet<PeerId>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        if self.request.is_awaiting_download() {
            let Some(peer) = peers
                .iter()
                .map(|peer| {
                    (
                        // If contains -> 1 (order after), not contains -> 0 (order first)
                        self.failed_peers.contains(peer),
                        // Random factor to break ties, otherwise the PeerID breaks ties
                        rand::random::<u32>(),
                        peer,
                    )
                })
                .min()
                .map(|(_, _, peer)| *peer)
            else {
                // When a peer disconnects and is removed from the SyncingChain peer set, if the set
                // reaches zero the lookup is removed
                return Err(Error::InternalError("No peers".to_owned()));
            };

            let req_id = cx.send_blocks_by_root_request(
                peer,
                self.block_root,
                BlocksByRootRequester::Header(self.id),
            )?;

            self.request.on_download_start(req_id)?;
        }
        Ok(())
    }
}

// TODO(tree-sync): Re-add the reprocessing cache, so we don't process twice a block that we got
// through gossip and sync.

impl<T: BeaconChainTypes> Chain<T> {
    fn new(block_root: Hash256, id: Id, initial_peers: &[PeerId]) -> Self {
        Self {
            peers: HashSet::from_iter(initial_peers.iter().copied()),
            status: ChainStatus::BackfillHeaders {
                block_roots: vec![],
                next_header_request: HeaderRequest::new(block_root, id),
            },
        }
    }

    /// Returns whether the value was newly inserted
    fn add_peer(&mut self, peer: PeerId) -> bool {
        self.peers.insert(peer)
    }

    /// Returns whether the value was present in the set.
    fn remove_peer(&mut self, peer: &PeerId) -> bool {
        self.peers.remove(peer)
    }

    fn get_peers(&self) -> Vec<PeerId> {
        self.peers.iter().copied().collect()
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn parent_root(&self) -> Option<Hash256> {
        match &self.status {
            ChainStatus::BackfillHeaders {
                next_header_request,
                ..
            } => Some(next_header_request.block_root),
            ChainStatus::WaitingParentChain { parent_root, .. } => Some(*parent_root),
            ChainStatus::ForwardSync { .. } => None,
        }
    }

    fn tip(&self) -> Hash256 {
        match &self.status {
            ChainStatus::BackfillHeaders {
                next_header_request,
                block_roots,
            } => block_roots
                .first()
                .copied()
                .unwrap_or(next_header_request.block_root),
            ChainStatus::WaitingParentChain { block_roots, .. } => block_roots
                .first()
                .copied()
                .expect("block roots is not empty"),
            ChainStatus::ForwardSync {
                block_roots,
                syncing_blocks,
            } => block_roots.first().copied().unwrap_or_else(|| {
                syncing_blocks
                    .back()
                    .map(|block| *block.block_root())
                    .expect("blocks are not empty")
            }),
        }
    }

    /// Split chain by `block_root` returning a new Self that includes `block_root` and all of its
    /// ancestors, and leaves `self` with only the descendants of `block_root` excluding
    /// `block_root`
    fn split_by(&mut self, block_root: Hash256) -> Result<Self, InternalError> {
        let status = match &mut self.status {
            ChainStatus::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                // Take ownership of BackfillHeaders fields without having to add a Poisoned state
                let mut block_roots = std::mem::take(block_roots);
                let next_header_request =
                    std::mem::replace(next_header_request, HeaderRequest::empty());

                let new_block_roots =
                    if let Some(idx) = block_roots.iter().position(|b| b == &block_root) {
                        // ..= to keep the block_root on the left
                        block_roots.drain(0..=idx).collect::<Vec<_>>()
                    } else {
                        // TODO(tree-sync): check that block_root is the next_root or error
                        vec![]
                    };
                self.status = ChainStatus::WaitingParentChain {
                    parent_root: block_root,
                    block_roots,
                };
                ChainStatus::BackfillHeaders {
                    block_roots: new_block_roots,
                    next_header_request,
                }
            }
            ChainStatus::WaitingParentChain {
                parent_root,
                block_roots,
            } => {
                let idx =
                    block_roots
                        .iter()
                        .position(|b| b == &block_root)
                        .ok_or(InternalError(format!(
                            "block_root {block_root:?} no in chain"
                        )))?;
                // ..= to keep the block_root on the left
                let new_block_roots = block_roots.drain(0..=idx).collect::<Vec<_>>();
                let parent_root = *parent_root;
                self.status = ChainStatus::WaitingParentChain {
                    parent_root: block_root,
                    block_roots: std::mem::take(block_roots),
                };
                ChainStatus::WaitingParentChain {
                    parent_root,
                    block_roots: new_block_roots,
                }
            }
            ChainStatus::ForwardSync { .. } => {
                todo!("How to split a chain that's already syncing?");
            }
        };

        Ok(Self {
            peers: self.peers.clone(),
            // What to set the status to??
            status,
        })
    }

    fn to_foward_sync_block(&mut self) -> Result<Hash256, InternalError> {
        todo!();
    }

    fn on_block_imported(&mut self, block_root: &Hash256) {
        match &mut self.status {
            ChainStatus::BackfillHeaders { .. } => {}
            ChainStatus::WaitingParentChain {
                block_roots,
                parent_root,
            } => {
                if block_root == parent_root {
                    self.status = ChainStatus::ForwardSync {
                        block_roots: std::mem::take(block_roots),
                        syncing_blocks: <_>::default(),
                    };
                }
            }
            ChainStatus::ForwardSync { .. } => {}
        }
    }

    fn to_forward_sync(&mut self, parent_root: Hash256) -> Result<(), InternalError> {
        match &mut self.status {
            ChainStatus::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                block_roots.push(next_header_request.block_root);
                self.status = ChainStatus::ForwardSync {
                    block_roots: std::mem::take(block_roots),
                    syncing_blocks: <_>::default(),
                };
                Ok(())
            }
            _ => Err(InternalError("Not in BackfillHeaders state".to_string())),
        }
    }

    fn block_count(&self) -> usize {
        match &self.status {
            ChainStatus::BackfillHeaders { block_roots, .. }
            | ChainStatus::WaitingParentChain { block_roots, .. } => block_roots.len(),
            ChainStatus::ForwardSync {
                block_roots,
                syncing_blocks,
            } => block_roots.len() + syncing_blocks.len(),
        }
    }

    /// Returns all block roots part of this chain
    fn iter_block_roots(&self) -> Box<dyn Iterator<Item = &Hash256> + '_> {
        match &self.status {
            ChainStatus::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                Box::new(std::iter::once(&next_header_request.block_root).chain(block_roots.iter()))
            }
            ChainStatus::WaitingParentChain { block_roots, .. } => Box::new(block_roots.iter()),
            ChainStatus::ForwardSync {
                syncing_blocks,
                block_roots,
            } => Box::new(
                syncing_blocks
                    .iter()
                    .map(|block| block.block_root())
                    .chain(block_roots.iter()),
            ),
        }
    }

    /// Returns true if this chain has no blocks
    fn is_empty(&self) -> bool {
        self.iter_block_roots().is_empty()
    }

    fn min_slot(&self) -> Option<Slot> {
        todo!();
    }

    fn max_slot(&self) -> Option<Slot> {
        todo!();
    }

    fn syncing_blocks_count(&self) -> usize {
        match &self.status {
            ChainStatus::BackfillHeaders { .. } => 0,
            ChainStatus::WaitingParentChain { .. } => 0,
            ChainStatus::ForwardSync { syncing_blocks, .. } => syncing_blocks.len(),
        }
    }

    fn header_request(
        &mut self,
    ) -> Result<&mut DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>, Error> {
        match &mut self.status {
            ChainStatus::BackfillHeaders {
                next_header_request,
                ..
            } => Ok(&mut next_header_request.request),
            _ => Err(Error::InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn add_ancestor(&mut self, parent_root: Hash256, id: Id) -> Result<(), InternalError> {
        match &mut self.status {
            ChainStatus::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                block_roots.push(next_header_request.block_root);
                *next_header_request = HeaderRequest::new(parent_root, id);
                Ok(())
            }
            _ => Err(InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn to_waiting_parent(&mut self, parent_root: Hash256) -> Result<(), Error> {
        match &mut self.status {
            ChainStatus::BackfillHeaders { block_roots, .. } => {
                self.status = ChainStatus::WaitingParentChain {
                    parent_root,
                    block_roots: std::mem::take(block_roots),
                };
                Ok(())
            }
            _ => Err(Error::InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn on_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        let (ok_to_import, block) = self.block_request(req_id.requester)?;
        block.on_download_result(req_id, result, cx)?;
        block.continue_request(cx, ok_to_import)?;
        Ok(())
    }

    fn on_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<SyncBlockResult, Error> {
        let (ok_to_import, block) = self.block_request(RangeRequestId::ForwardSync(id))?;
        match block.on_process_result(result, cx)? {
            SyncBlockResult::Done { parent_root, slot } => {
                // This block is complete, remove it from chain
                if !ok_to_import {
                    return Err(Error::InternalError(format!(
                        "Block {id} is not the first block"
                    )));
                }
                if let ChainStatus::ForwardSync { syncing_blocks, .. } = &mut self.status {
                    if let Some(block) = syncing_blocks.pop_front() {
                        debug!("Dropping syncing block {}", block.id());
                    } else {
                        return Err(Error::InternalError("syncing_blocks is empty".to_string()));
                    }
                }
                Ok(SyncBlockResult::Done { parent_root, slot })
            }
            SyncBlockResult::Wait => {
                // Not complete yet, continue requests
                block.continue_request(cx, ok_to_import)?;
                Ok(SyncBlockResult::Wait)
            }
        }
    }

    fn block_request(&mut self, id: RangeRequestId) -> Result<(bool, &mut SyncBlock<T>), Error> {
        match &mut self.status {
            ChainStatus::ForwardSync { syncing_blocks, .. } => {
                if let Some(index) = syncing_blocks.iter().position(|b| b.id() == id) {
                    let block = syncing_blocks.get_mut(index).expect("index just found");
                    return Ok((index == 0, block));
                }

                let first_ids: Vec<_> = syncing_blocks.iter().take(5).map(|b| b.id()).collect();
                Err(Error::InternalError(format!(
                    "Unknown block for {id}, first few blocks {first_ids:?}"
                )))
            }

            _ => Err(Error::InternalError(
                "Expected lookup to be in Syncing state".to_owned(),
            )),
        }
    }

    fn continue_requests(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), Error> {
        match &mut self.status {
            ChainStatus::BackfillHeaders {
                next_header_request,
                ..
            } => Ok(next_header_request.continue_request(&self.peers, cx)?),
            ChainStatus::WaitingParentChain { .. } => Ok(()),
            ChainStatus::ForwardSync {
                block_roots,
                syncing_blocks,
            } => {
                for (index, block) in syncing_blocks.iter_mut().enumerate() {
                    let ok_to_import = index == 0;
                    block.continue_request(cx, ok_to_import)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InternalError(String),
    TooManyErrors(String),
    BlockConflictsWithFinality(String),
}

#[derive(Debug)]
struct InternalError(String);

impl From<InternalError> for Error {
    fn from(e: InternalError) -> Self {
        Self::InternalError(e.0)
    }
}

impl From<DownloadRequestError> for Error {
    fn from(e: DownloadRequestError) -> Self {
        match e {
            DownloadRequestError::InternalError(e) => Self::InternalError(e),
            DownloadRequestError::TooManyErrors(e) => Self::TooManyErrors(format!("{e:?}")),
        }
    }
}

impl From<RpcRequestSendError> for Error {
    fn from(e: RpcRequestSendError) -> Self {
        match e {
            RpcRequestSendError::InternalError(e) => Self::InternalError(e),
            // TODO(tree-sync): Should we allow lookups to have zero peers
            RpcRequestSendError::NoPeers => Self::InternalError("No peers".to_string()),
        }
    }
}

impl From<SyncBlockError> for Error {
    fn from(e: SyncBlockError) -> Self {
        match e {
            SyncBlockError::InternalError(e) => Self::InternalError(e),
            SyncBlockError::TooManyErrors(e) => Self::TooManyErrors(e),
        }
    }
}

pub(crate) enum SyncState {
    Synced,
    Syncing { max_slot: Slot },
}

impl<T: BeaconChainTypes> ForwardSync<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            block_to_tip: <_>::default(),
            chains: <_>::default(),
        }
    }

    #[cfg(test)]
    pub fn block_peers(&self, block_root: &Hash256) -> Result<Option<Vec<PeerId>>, String> {
        let Some(chain) = self.block_to_tip.get(block_root) else {
            return Ok(None);
        };
        Ok(Some(
            self.chains
                .get(chain)
                .ok_or(format!("Unknown chain {chain:?}"))?
                .get_peers(),
        ))
    }

    #[cfg(test)]
    pub fn get_lookups(&self) -> Vec<Hash256> {
        self.block_to_tip.keys().copied().collect()
    }

    pub fn block_count(&self) -> usize {
        self.block_to_tip.len()
    }

    /// Returns the highest known slot that we are attempting to sync
    pub fn max_slot_to_sync(&self) -> Option<Slot> {
        // TODO(tree-sync): weak metric, who have a better heuristic for sync? Now that lookups
        // count here
        todo!();
    }

    #[cfg(test)]
    pub fn get_processing_ids(&mut self) -> Vec<HeaderLookupId> {
        let mut ids = vec![];
        for chain in self.chains.values() {
            match &chain.status {
                ChainStatus::BackfillHeaders { .. } => {}
                ChainStatus::WaitingParentChain { .. } => {}
                ChainStatus::ForwardSync { syncing_blocks, .. } => {
                    for block in syncing_blocks {
                        if block.is_processing() {
                            if let RangeRequestId::ForwardSync(id) = block.id() {
                                ids.push(id);
                            }
                        }
                    }
                }
            }
        }
        ids
    }

    pub fn pause(&mut self) {
        todo!();
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        for chain in self.chains.values_mut() {
            chain.remove_peer(&peer);
        }
    }

    pub fn search(
        &mut self,
        block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        if let Some(initial_chain_id) = self.block_to_tip.get(&block_root) {
            let mut counts = HashMap::<&PeerId, usize>::new();
            // Add peer to `block`'s entry and all its ancestors
            let mut target_block_root = block_root;
            while let Some(chain_id) = self.block_to_tip.get_mut(&target_block_root) {
                let chain = self
                    .chains
                    .get_mut(chain_id)
                    .ok_or(InternalError(format!("Unknown chain {chain_id}")))?;

                // If target_block_root is not the tip of chain, we have to split the chain
                let chain_to_add_peers = if chain.tip() != target_block_root {
                    let new_chain = chain.split_by(target_block_root)?;
                    let new_chain_id = TipId(cx.next_id());

                    // Update all block references to the new chain
                    for block_root in new_chain.iter_block_roots() {
                        *self
                            .block_to_tip
                            .get_mut(block_root)
                            .ok_or(InternalError(format!("No block {block_root:?}")))? =
                            new_chain_id;
                    }

                    self.chains.insert(new_chain_id, new_chain);
                    self.chains.get_mut(&new_chain_id).expect("key just added")
                } else {
                    chain
                };

                for peer in peers {
                    // TODO(tree-sync): If peer already in set no need to add to its ancestors
                    if chain_to_add_peers.add_peer(*peer) {
                        // TODO(tree-sync): This log can be very noisy maybe log once per peer
                        *counts.entry(peer).or_default() += 1;
                    } else {
                        // Peer already part of this lookup, therefore it must be part of the peer
                        // set of all of its ancestors: stop
                        break;
                    }
                }
                if let Some(parent_root) = chain_to_add_peers.parent_root() {
                    target_block_root = parent_root;
                } else {
                    break;
                }
            }
            for (peer, count) in counts {
                debug!(block_root = ?target_block_root, %peer, count, "Adding peer to existing header lookup and ancestors");
            }
        } else {
            if self.block_to_tip.len() > MAX_LOOKUP_COUNT {
                if let Err(e) = self.prune_least_popular_lookups() {
                    error!("Error on prune_least_popular_lookups {e:?}");
                }
            }

            let id = cx.next_id();
            let chain_id = TipId(cx.next_id());
            match peers {
                [peer] => debug!(?block_root, id, %chain_id, %peer, "Creating new header lookup"),
                _ => debug!(
                    ?block_root,
                    id,
                    %chain_id,
                    peers = peers.len(),
                    "Creating new header lookup"
                ),
            }

            let mut chain = Chain::new(block_root, id, peers);
            chain.continue_requests(cx)?;
            // Don't insert until first request is successful
            metrics::inc_counter(&metrics::SYNC_CHAINS_ADDED);
            self.chains.insert(chain_id, chain);
            self.block_to_tip.insert(block_root, chain_id);
        }
        Ok(())
    }

    pub fn on_header_download_result(
        &mut self,
        req_id: BlocksByRootRequestId,
        id: HeaderLookupId,
        response: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = id.block_root;

        let result: Result<SyncBlockResult, Error> = (|| {
            let Some(chain_id) = self.block_to_tip.get(&block_root) else {
                // TODO(tree-sync): register metric
                debug!(id = ?req_id, "Received header request for unknown block_root");
                return Ok(SyncBlockResult::Wait);
            };
            let chain = self.chains.get_mut(chain_id).ok_or(InternalError(format!(
                "block_root {block_root:?} references unknown chain {chain_id}"
            )))?;

            let response = response.and_then(|(blocks, timestamp)| {
                let block = blocks
                    .first()
                    .cloned()
                    .ok_or(RpcResponseError::InternalError(
                        "blocks_by_root response contains zero blocks".to_owned(),
                    ))?;
                Ok((block, timestamp))
            });

            // TODO(tree-sync): add some check to make sure that distinct lookups for the same
            // block root don't mess with each other. That check must happen before triggering
            // errors for bad state

            match response {
                Ok((block, received)) => {
                    debug!(%req_id, "Forward sync block header downloaded success");

                    let block_header = block.message().block_header();
                    let parent_root = block_header.parent_root;

                    chain.header_request()?.on_download_success(
                        req_id,
                        peer_id,
                        block_header.clone(),
                        received,
                    )?;

                    metrics::inc_counter(&metrics::SYNC_HEADERS_DOWNLOADED);

                    // Once we discover the parent_root of this block three things can happen
                    // 1. The parent root is a known block -> stop
                    // 2. We conflicts with finality -> reject
                    // 3. The parent root is unknown -> continue search

                    // TODO(tree-sync): should check if the block is descendant of finalized
                    // TODO(tree-sync): on finalization or every interval we should drop branches that
                    // conflict with finality
                    let finalized_checkpoint = cx.chain.head().finalized_checkpoint();

                    // TODO(tree-sync): check that the slots are decreasing, so we don't end up in
                    // an infinite loop. But note that the wrong block will be the descendant.
                    // - We get header A with parent B and slot 10
                    // - We get header B with parent C and slot 11
                    // - That makes header A invalid

                    if block_header.slot
                        <= finalized_checkpoint
                            .epoch
                            .start_slot(T::EthSpec::slots_per_epoch())
                        && block_root != finalized_checkpoint.root
                    {
                        return Err(Error::BlockConflictsWithFinality(format!(
                            "Block {:?} {} conflicts with finalized checkpoint {:?}",
                            block_root, block_header.slot, finalized_checkpoint
                        )));
                    }

                    if cx.chain.block_is_known_to_fork_choice(&parent_root) {
                        // Parent is imported, we can forward sync this chain
                        // Stop search we reached a known block
                        chain.to_forward_sync(parent_root)?;
                        debug!(%chain_id, ?parent_root, block_count = chain.block_count(), "Forward sync chain reached imported block");
                        // Trigger potential foward sync for this chain
                        self.continue_requests(cx);
                    } else if let Some(parent_chain_id) = self.block_to_tip.get(&parent_root) {
                        debug!(%chain_id, %parent_chain_id, ?parent_root, "Forward sync chain reached known block");
                        // Parent is part of another chain, stop search
                        // Stop search we reached a known block
                        chain.to_waiting_parent(parent_root)?;
                        // TODO(tree-sync): Add peers recursively to the chain_id, potentially
                        // splitting the chain when adding peers.
                    } else {
                        chain.add_ancestor(parent_root, cx.next_id())?;
                        // Add to the block_to_tip mapping to respect the invariant "Each block
                        // root exists in exactly one `Chain::block_roots` list".
                        self.block_to_tip.insert(parent_root, *chain_id);
                        // Since the block already points to `chain` we don't need to add peers.
                        // Just trigger header download for this new root.
                        self.continue_requests(cx);
                    }
                }
                Err(e) => {
                    // Request errors are logged in `SyncNetworkContext::on_rpc_response_result`
                    chain.header_request()?.on_download_error(req_id, Some(e))?;
                    // Continue this request to potentially resend the header request
                    self.continue_requests(cx);
                }
            }
            Ok(SyncBlockResult::Wait)
        })();

        // Map result Ok to Wait as completing the header request does not complete the overall
        // ForwardSyncBlock request.
        if let Err(e) = result {
            self.handle_result(id.block_root, e, cx);
        }
    }

    pub fn on_block_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        id: HeaderLookupId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(chain_id) = self.block_to_tip.get(&id.block_root) else {
            debug!(?id, "Received block process result for unknown lookup");
            return;
        };
        let Some(chain) = self.chains.get_mut(chain_id) else {
            error!(%chain_id, block_root = ?id.block_root, "Block references unknown chain");
            return;
        };

        if let Err(e) = chain.on_download_result(req_id, result, cx) {
            self.handle_result(id.block_root, e, cx);
        }
    }

    pub fn on_block_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(chain_id) = self.block_to_tip.get(&id.block_root) else {
            debug!(?id, "Received block process result for unknown lookup");
            return;
        };
        let Some(chain) = self.chains.get_mut(chain_id) else {
            error!(%chain_id, block_root = ?id.block_root, "Block references unknown chain");
            return;
        };

        match chain.on_process_result(id, result, cx) {
            Ok(SyncBlockResult::Done { .. }) => {
                metrics::inc_counter(&metrics::SYNC_BLOCKS_PROCESSED);
                self.block_to_tip.remove(&id.block_root);
                // Find all chains that are awaiting this block to process and continue them
                for other_chain in self.chains.values_mut() {
                    other_chain.on_block_imported(&id.block_root);
                }
                self.continue_requests(cx);
                // If the chain is empty, remove it
                if chain.is_empty() {
                    self.chains.remove(&chain_id);
                    metrics::inc_counter(&metrics::SYNC_CHAINS_REMOVED);
                }
            }
            // Wait for next event
            Ok(SyncBlockResult::Wait) => {}
            Err(e) => {
                self.handle_result(id.block_root, e, cx);
            }
        }
    }

    pub fn prune(&mut self) {
        // Prune blocks once imported, and once finality advances
    }

    pub fn prune_imported_block(&mut self, block_root: Hash256, _imported: bool) {
        // Recursively prune this block and all their ancestors
        todo!();
    }

    fn handle_result(&mut self, block_root: Hash256, error: Error, cx: &mut SyncNetworkContext<T>) {
        debug!(?error, ?block_root, "Dropping forward sync block lookup");
        let Some(chain_id) = self.block_to_tip.get(&block_root).copied() else {
            debug!(?block_root, "Handling error for unknown block_root");
            return;
        };
        match error {
            Error::InternalError(_) | Error::TooManyErrors(_) => {
                let block_to_children = self
                    .compute_children()
                    .expect("TODO: handle this error if it can't be avoided");
                self.drop_chain_and_children(chain_id, &block_to_children);
            }
            Error::BlockConflictsWithFinality(_e) => {
                let block_to_children = self
                    .compute_children()
                    .expect("TODO: handle this error if it can't be avoided");
                self.drop_chain_and_children(chain_id, &block_to_children);
                // TODO(tree-sync): penalize peers of this lookups
                // TODO(tree-sync): add blocks to a failed cache to prevent re-sync
            }
        }
    }

    /// Marks blocks ready for download as syncing
    /// Should be called anytime:
    /// - A new block is imported to fork-choice
    /// - A block in the header tree is advanced to Syncing
    /// - A new header is downloaded with a parent that is imported or syncing
    fn trigger_forward_sync(&mut self, cx: &mut SyncNetworkContext<T>) {
        // We want to download and import blocks whose parent is imported in our fork-choice. Also
        // to buffer we want to download children of blocks that are awaiting import.
        //
        // We may want to avoid 1M calls into fork-choice to check if a block is imported. We only
        // need to work of roots. Once a root is processed we have re-compute roots, or track
        // children.

        // TODO(tree-sync): don't build on demand, cache roots somewhere

        let mut blocks_syncing = self
            .chains
            .values()
            .map(|chain| chain.syncing_blocks_count())
            .sum::<usize>();

        // A chain can be in two states:
        // - Active backfill
        // - Oldest ancestor known

        let mut new_syncing_blocks = false;

        // Have up to 2 blocks syncing
        // Find the block range with most peers and highest slot. This is the block
        // to be used as tip of the chain of blocks to fetch.
        let mut chains_by_peer_count = self
            .chains
            .iter_mut()
            .filter_map(|(_, chain)| {
                if matches!(chain.status, ChainStatus::ForwardSync { .. }) {
                    Some((chain.peer_count(), chain))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        chains_by_peer_count.sort_by_key(|(peer_count, _)| *peer_count);

        for (_, chain) in chains_by_peer_count {
            if let ChainStatus::ForwardSync {
                block_roots,
                syncing_blocks,
            } = &mut chain.status
            {
                /// block_roots sorting: tip first, oldest ancestor last => pop
                if let Some(next_block) = block_roots.pop() {
                    syncing_blocks.push_back(SyncBlock::new(
                        RangeRequestId::ForwardSync(HeaderLookupId {
                            id: cx.next_id(),
                            block_root: next_block,
                        }),
                        next_block,
                        &chain.peers.iter().copied().collect::<Vec<_>>(),
                    ));
                    blocks_syncing += 1;
                    new_syncing_blocks = true;
                    if blocks_syncing >= BLOCK_BUFFER_SIZE {
                        break;
                    }
                }
            }
        }

        if new_syncing_blocks {
            self.continue_requests(cx);
        }
    }

    fn continue_requests(&mut self, cx: &mut SyncNetworkContext<T>) {
        // TODO(tree-sync): optimize this call to maybe not do it everytime
        self.trigger_forward_sync(cx);

        let mut chains_to_drop = vec![];

        for (chain_id, chain) in self.chains.iter_mut() {
            if let Err(_e) = chain.continue_requests(cx) {
                // TODO(tree-sync): should log error?
                chains_to_drop.push(*chain_id);
            }
        }

        let chain_to_children = self
            .compute_children()
            .expect("Handle this error if it can't be avoided");
        for chain_id in chains_to_drop {
            self.drop_chain_and_children(chain_id, &chain_to_children);
        }
    }

    /// Drop chain if it exists and all its children
    fn drop_chain_and_children(
        &mut self,
        initial_chain_id: TipId,
        chain_to_children: &HashMap<TipId, Vec<TipId>>,
    ) {
        let mut queue: VecDeque<TipId> = VecDeque::from([initial_chain_id]);

        while let Some(chain_id) = queue.pop_front() {
            // Remove the node itself.
            if let Some(chain) = self.chains.remove(&chain_id) {
                metrics::inc_counter(&metrics::SYNC_CHAINS_REMOVED);
                for block_root in chain.iter_block_roots() {
                    self.block_to_tip.remove(block_root);
                    debug!(?block_root, id = %chain_id, "Dropping forward sync block lookup");
                    metrics::inc_counter(&metrics::SYNC_LOOKUPS_DROPPED);
                }
                // Only remove children if the node still existed
                // Push its children—if any—onto the work list.
                if let Some(children) = chain_to_children.get(&chain_id) {
                    queue.extend(children.iter().cloned());
                }
            }
        }
    }

    /// Drop lookup `block_root` if it exists and all its children
    fn compute_children(&mut self) -> Result<HashMap<TipId, Vec<TipId>>, InternalError> {
        let mut chain_to_children = HashMap::<TipId, Vec<TipId>>::new();
        for (chain_id, chain) in self.chains.iter() {
            if let Some(parent_root) = chain.parent_root() {
                // TODO(tree-sync): Is this error impossible?
                let parent_chain_id = self.block_to_tip
                    .get(&parent_root)
                    .ok_or(InternalError(format!(
                        "Chain {chain_id} has a parent root that points to an unknown block {parent_root:?}"
                    )))?;

                chain_to_children
                    .entry(*parent_chain_id)
                    .or_default()
                    .push(*chain_id);
            }
        }
        Ok(chain_to_children)
    }

    /// Drop lookups with least amount of peers and slot until we pruned PRUNE_COUNT lookups
    fn prune_least_popular_lookups(&mut self) -> Result<(), InternalError> {
        let mut chains = self
            .chains
            .iter()
            // TODO: Prune only lookups that are not syncing and we know the header
            .map(|(chain_id, chain)| (chain.peer_count(), *chain_id))
            .collect::<Vec<_>>();
        chains.sort_unstable();

        let chain_to_children = self.compute_children()?;
        for (_, chain_id) in chains {
            self.drop_chain_and_children(chain_id, &chain_to_children);
            if self.block_to_tip.len() < MAX_LOOKUP_COUNT - PRUNE_COUNT {
                break;
            }
        }
        Ok(())
    }

    pub fn register_metrics(&self) {
        let (min_slot, max_slot) =
            self.chains
                .values()
                .fold((None::<Slot>, None::<Slot>), |(gmin, gmax), chain| {
                    let gmin = match (gmin, chain.min_slot()) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        (None, some @ Some(_)) => some, // first non-None wins
                        (x, None) => x,
                    };

                    let gmax = match (gmax, chain.max_slot()) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (None, some @ Some(_)) => some,
                        (x, None) => x,
                    };

                    (gmin, gmax)
                });

        if let (Some(min_slot), Some(max_slot)) = (min_slot, max_slot) {
            metrics::set_gauge(&metrics::SYNC_HEADER_MIN_SLOT, min_slot.as_u64() as i64);
            metrics::set_gauge(&metrics::SYNC_HEADER_MAX_SLOT, max_slot.as_u64() as i64);
        }

        metrics::set_gauge(&metrics::SYNC_HEADERS_COUNT, self.block_to_tip.len() as i64);
        metrics::set_gauge(&metrics::SYNC_CHAINS_COUNT, self.chains.len() as i64);

        // Min header
        // Highest known header
        // Current head
    }
}

impl std::fmt::Display for TipId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
