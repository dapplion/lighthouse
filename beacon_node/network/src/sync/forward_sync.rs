use super::network_context::{
    DownloadRequest, DownloadRequestError, RpcRequestSendError, RpcResponseError,
    SyncNetworkContext,
};
use crate::metrics;
use crate::sync::network_context::{BatchPeers, RpcResponseResult};
use crate::sync::sync_block::{Error as SyncBlockError, SyncBlock, SyncBlockResult};
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, ComponentsByRootRequestId, HeaderLookupId, Id,
    RangeRequestId,
};
use lighthouse_network::PeerId;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use strum::IntoStaticStr;
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
///
///
/// ## da_checker oracle
///
/// TODO(tree-sync): re-implement if necessary
///
///
/// ## duplicate_cache with gossip blocks
///
/// Gossip may receive and process the same block that ForwardSync attempts to process.
///
/// a. Gossip receives block X and sends to process
/// b. ForwardSync downloads block X
/// c. ForwardSync sends block X for process
///
/// Consider the order of events
/// - [a,b,c]: the gossip block is inserted in the `duplicate_cache` and the RPC block is queued.
///            Step b could be skipped, but we accept the inneficiency for simplicity.
/// - [b,a,c]: the RPC block is downloaded, gossip block into `duplicate_cache` and RPC block queued
/// - [b,c,a]: the RPC block is inserted in the `duplicate_cache` and the gossip block is queued
///
/// ## Pruning
///
/// So chose to not explicitly implement pruning for forward sync. Chains can be pruned by:
///
/// 1. Checking if the conflict with finality once finality advances: If this happens once we
///    attempt to import the first block of the chain we'll get an unknown parent error. The chain
///    will fail and be dropped = so this pruning happens by default.
/// 2. If their blocks are imported through another source: If this happens when we attempt to
///    process the block we'll get a duplicate_cache hit or a block already known error. In either
///    case the processing result for the block with be an Ok, and we'll move to the next block.
///
///
pub struct ForwardSync<T: BeaconChainTypes> {
    block_to_tip: HashMap<Hash256, TipId>,
    chains: HashMap<TipId, Chain<T>>,
}

/// Chain of consecutive blocks that are imported by the same set of peers
struct Chain<T: BeaconChainTypes> {
    peers: HashSet<PeerId>,
    status: Status<T>,
}

type PendingBlock = (Hash256, Slot, Id);

#[allow(clippy::large_enum_variant)]
enum Status<T: BeaconChainTypes> {
    /// Recursively fetch headers until discovering a parent_root that is known. Its list of
    /// block_roots can grow by appending ancestors.
    /// - Transition to `WaitingParentChain` if the parent is known but not imported
    /// - Transition to `ForwardSync` if the parent is imported
    BackfillHeaders {
        /// Headers descendant of `next_header_request.block_root` that are already downloaded.
        /// Does not include `next_header_request.block_root`.
        /// Sorting: tip first, oldest ancestor last
        block_roots: Vec<PendingBlock>,
        /// Oldest ancestor block root of this Chain.
        next_header_request: HeaderRequest,
    },
    /// Waits for a parent block in a different chain to be imported. Its block_root list does not
    /// change.
    /// - Transitions to `ForwardSync` once `parent_root` is imported.
    WaitingParentChain {
        /// Parent root of the last block_root in `block_roots`
        parent_root: Hash256,
        /// Sorting: tip first, oldest ancestor last
        block_roots: Vec<PendingBlock>,
    },
    /// Download and process block_roots from oldest ancestor to tip. Its list of block_roots does
    /// not grow, only removed block roots once processed.
    ///
    /// Note: Keeping block_roots and syncing_blocks in separate Vecs instead of a single Vec with
    /// an enum shows the following invariants:
    /// - The set of PendingBlocks is consecutive
    /// - The set of SyncBlocks is consecutive
    /// - The parent of the last item in `block_roots` is the first item in `syncing_blocks`
    ForwardSync {
        /// Sorting: tip first, oldest ancestor last
        block_roots: Vec<PendingBlock>,
        /// Sorting: oldest ancestor first
        syncing_blocks: VecDeque<SyncBlock<T>>,
    },
}

/// Tracks a request to download a BeaconBlockHeader by block root
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
            status: Status::BackfillHeaders {
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

    /// Returns a Vec of peers that have imported the blocks in this chain
    fn get_peers(&self) -> Vec<PeerId> {
        self.peers.iter().copied().collect()
    }

    /// Returns the count of peers that have imported the blocks in this chain
    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns the parent root of the oldest ancestor of this chain. Returns None if the chain is
    /// already processing = its parent has already been imported.
    fn parent_root(&self) -> Option<Hash256> {
        match &self.status {
            Status::BackfillHeaders { .. } => None,
            Status::WaitingParentChain { parent_root, .. } => Some(*parent_root),
            Status::ForwardSync { .. } => None,
        }
    }

    /// Returns the tip of this chain. Returns None if the chain is empty (should not happen)
    fn tip(&self) -> Option<Hash256> {
        match &self.status {
            Status::BackfillHeaders {
                next_header_request,
                block_roots,
            } => Some(
                block_roots
                    .first()
                    .map(|block| block.0)
                    .unwrap_or(next_header_request.block_root),
            ),
            Status::WaitingParentChain { block_roots, .. } => {
                block_roots.first().map(|block| block.0)
            }
            Status::ForwardSync {
                block_roots,
                syncing_blocks,
            } => block_roots
                .first()
                .map(|block| block.0)
                .or_else(|| syncing_blocks.back().map(|block| *block.block_root())),
        }
    }

    /// Split chain by `block_root` returning a new Self that includes `block_root` and all of its
    /// ancestors, and leaves `self` with only the descendants of `block_root` excluding
    /// `block_root`
    fn split_by(&mut self, block_root: Hash256) -> Result<Self, InternalError> {
        // TODO(tree-sync): Review this logic, it's sensitive and not trivial
        // TODO(tree-sync): write a prop test for this, check milhouse tests as inspo
        let status = match &mut self.status {
            Status::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                // Take ownership of BackfillHeaders fields without having to add a Poisoned state
                let mut block_roots = std::mem::take(block_roots);
                let next_header_request =
                    std::mem::replace(next_header_request, HeaderRequest::empty());

                let new_block_roots =
                    if let Some(idx) = block_roots.iter().position(|b| b.0 == block_root) {
                        // ..= to keep the block_root on the left
                        block_roots.drain(0..=idx).collect::<Vec<_>>()
                    } else {
                        // TODO(tree-sync): check that block_root is the next_root or error
                        vec![]
                    };
                self.status = Status::WaitingParentChain {
                    parent_root: block_root,
                    block_roots,
                };
                Status::BackfillHeaders {
                    block_roots: new_block_roots,
                    next_header_request,
                }
            }
            Status::WaitingParentChain {
                parent_root,
                block_roots,
            } => {
                let idx =
                    block_roots
                        .iter()
                        .position(|b| b.0 == block_root)
                        .ok_or(InternalError(format!(
                            "block_root {block_root:?} no in chain"
                        )))?;
                // ..= to keep the block_root on the left
                let new_block_roots = block_roots.drain(0..=idx).collect::<Vec<_>>();
                let parent_root = *parent_root;
                self.status = Status::WaitingParentChain {
                    parent_root: block_root,
                    block_roots: std::mem::take(block_roots),
                };
                Status::WaitingParentChain {
                    parent_root,
                    block_roots: new_block_roots,
                }
            }
            Status::ForwardSync {
                block_roots,
                syncing_blocks,
            } => {
                // block_root may be in `block_roots` or in `syncing_blocks`.
                let block_roots_idx = block_roots.iter().position(|b| b.0 == block_root);
                let new_block_roots = if let Some(idx) = block_roots_idx {
                    // ..= to keep the block_root on the left
                    block_roots.drain(0..=idx).collect::<Vec<_>>()
                } else {
                    // `block_root` must be in `syncing_blocks` so the new splitted chain will have
                    // no `block_roots` items.
                    vec![]
                };

                let new_syncing_blocks = if block_roots_idx.is_some() {
                    // If `block_root` is in `block_roots` all syncing_blocks go to the new chain
                    std::mem::take(syncing_blocks)
                } else {
                    // else find the position
                    let idx = syncing_blocks
                        .iter()
                        .position(|b| *b.block_root() == block_root)
                        .ok_or(InternalError(format!(
                            "block_root {block_root:?} not found in chain"
                        )))?;
                    // ..= to keep the block_root on the left
                    syncing_blocks.drain(0..=idx).collect::<VecDeque<_>>()
                };
                // This chain remains ForwardSync
                // New chain is ForwardSync with the splitted Vecs
                Status::ForwardSync {
                    block_roots: new_block_roots,
                    syncing_blocks: new_syncing_blocks,
                }
            }
        };

        Ok(Self {
            peers: self.peers.clone(),
            // What to set the status to??
            status,
        })
    }

    /// If this chain is waiting for `block_root` it transitions to forward sync.
    fn on_block_imported(&mut self, block_root: &Hash256) {
        match &mut self.status {
            Status::BackfillHeaders { .. } => {}
            Status::WaitingParentChain {
                block_roots,
                parent_root,
            } => {
                if block_root == parent_root {
                    self.status = Status::ForwardSync {
                        block_roots: std::mem::take(block_roots),
                        syncing_blocks: <_>::default(),
                    };
                }
            }
            Status::ForwardSync { .. } => {}
        }
    }

    /// Transitions to forward sync
    fn backfill_headers_to_forward_sync(
        &mut self,
        block: BeaconBlockHeader,
    ) -> Result<(), InternalError> {
        match &mut self.status {
            Status::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                block_roots.push((
                    block.canonical_root(),
                    block.slot,
                    next_header_request.id.id,
                ));
                self.status = Status::ForwardSync {
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
            Status::BackfillHeaders { block_roots, .. }
            | Status::WaitingParentChain { block_roots, .. } => block_roots.len(),
            Status::ForwardSync {
                block_roots,
                syncing_blocks,
            } => block_roots.len() + syncing_blocks.len(),
        }
    }

    /// Returns all block roots part of this chain
    fn iter_block_roots(&self) -> Box<dyn Iterator<Item = &Hash256> + '_> {
        match &self.status {
            Status::BackfillHeaders {
                block_roots,
                next_header_request,
            } => Box::new(
                std::iter::once(&next_header_request.block_root)
                    .chain(block_roots.iter().map(|(root, _, _)| root)),
            ),
            Status::WaitingParentChain { block_roots, .. } => {
                Box::new(block_roots.iter().map(|(root, _, _)| root))
            }
            Status::ForwardSync {
                syncing_blocks,
                block_roots,
            } => Box::new(
                syncing_blocks
                    .iter()
                    .map(|block| block.block_root())
                    .chain(block_roots.iter().map(|(root, _, _)| root)),
            ),
        }
    }

    /// Returns true if this chain has no blocks
    fn is_empty(&self) -> bool {
        self.iter_block_roots().next().is_none()
    }

    fn min_slot(&self) -> Option<Slot> {
        match &self.status {
            // TODO(tree-sync): include syncing_blocks for ForwardSync
            Status::BackfillHeaders { block_roots, .. }
            | Status::WaitingParentChain { block_roots, .. }
            | Status::ForwardSync { block_roots, .. } => block_roots.last().map(|b| b.1),
        }
    }

    fn max_slot(&self) -> Option<Slot> {
        match &self.status {
            // TODO(tree-sync): include syncing_blocks for ForwardSync
            Status::BackfillHeaders { block_roots, .. }
            | Status::WaitingParentChain { block_roots, .. }
            | Status::ForwardSync { block_roots, .. } => block_roots.first().map(|b| b.1),
        }
    }

    fn syncing_blocks_count(&self) -> usize {
        match &self.status {
            Status::BackfillHeaders { .. } => 0,
            Status::WaitingParentChain { .. } => 0,
            Status::ForwardSync { syncing_blocks, .. } => syncing_blocks.len(),
        }
    }

    fn header_request(
        &mut self,
    ) -> Result<&mut DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>, Error> {
        match &mut self.status {
            Status::BackfillHeaders {
                next_header_request,
                ..
            } => Ok(&mut next_header_request.request),
            _ => Err(Error::InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn add_ancestor(&mut self, block: BeaconBlockHeader, id: Id) -> Result<(), InternalError> {
        match &mut self.status {
            Status::BackfillHeaders {
                block_roots,
                next_header_request,
            } => {
                block_roots.push((
                    // Should be the same as `next_header_request.block_root`
                    block.canonical_root(),
                    block.slot,
                    // Persist the request ID of the header for better traceability
                    next_header_request.id.id,
                ));
                *next_header_request = HeaderRequest::new(block.parent_root, id);
                Ok(())
            }
            _ => Err(InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn to_waiting_parent(&mut self, parent_root: Hash256) -> Result<(), Error> {
        match &mut self.status {
            Status::BackfillHeaders { block_roots, .. } => {
                self.status = Status::WaitingParentChain {
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

    /// Handle the result of a block processing.
    fn on_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<SyncBlockResult, Error> {
        let (ok_to_import, block) = self.block_request(RangeRequestId::ForwardSync(id))?;
        match block.on_process_result(result, cx)? {
            SyncBlockResult::Done { parent_root, slot } => {
                // Sanity check: the processed block must be the oldest block in the chain
                if !ok_to_import {
                    return Err(Error::InternalError(format!(
                        "Block {id} is not the first block"
                    )));
                }
                // This block processing is complete, remove it from chain
                if let Status::ForwardSync { syncing_blocks, .. } = &mut self.status {
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
            Status::ForwardSync { syncing_blocks, .. } => {
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

    /// Continues the header or blocks requests of this chain
    fn continue_requests(&mut self, cx: &mut SyncNetworkContext<T>) -> Result<(), Error> {
        match &mut self.status {
            Status::BackfillHeaders {
                next_header_request,
                ..
            } => Ok(next_header_request.continue_request(&self.peers, cx)?),
            Status::WaitingParentChain { .. } => Ok(()),
            Status::ForwardSync { syncing_blocks, .. } => {
                for (index, block) in syncing_blocks.iter_mut().enumerate() {
                    let ok_to_import = index == 0;
                    block.continue_request(cx, ok_to_import)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, IntoStaticStr)]
pub enum Error {
    /// Unexpected and unrecoverable error
    InternalError(String),
    /// Expected and unrecoverable error
    TooManyErrors(String),
    /// Block is not descendant of the finalized checkpoint
    BlockConflictsWithFinality(String),
}

/// Unexpected and unrecoverable error
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
    pub fn new() -> Self {
        Self {
            block_to_tip: <_>::default(),
            chains: <_>::default(),
        }
    }

    /// Returns the peers that claim to have imported a specific block_root
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

    /// Get all blocks that forward sync intends to sync
    #[cfg(test)]
    pub fn get_lookups(&self) -> Vec<Hash256> {
        self.block_to_tip.keys().copied().collect()
    }

    /// Total count of blocks that forward sync intends to sync
    pub fn block_count(&self) -> usize {
        self.block_to_tip.len()
    }

    /// Returns the highest known slot that we are attempting to sync
    pub fn max_slot_to_sync(&self) -> Option<Slot> {
        // TODO(tree-sync): weak metric, who have a better heuristic for sync? Now that lookups
        // count here
        self.chains
            .values()
            .filter_map(|chain| chain.max_slot())
            .max()
    }

    /// Return all processing ids of syncing blocks
    #[cfg(test)]
    pub fn get_processing_ids(&mut self) -> Vec<HeaderLookupId> {
        let mut ids = vec![];
        for chain in self.chains.values() {
            match &chain.status {
                Status::BackfillHeaders { .. } => {}
                Status::WaitingParentChain { .. } => {}
                Status::ForwardSync { syncing_blocks, .. } => {
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
        // TODO(tree-sync): consider if we really need a pausing mechanism for when EL offline
    }

    /// Remove a disconnected peer from all chains
    pub fn remove_peer(&mut self, peer: PeerId) {
        let chains_to_remove = self
            .chains
            .iter_mut()
            .filter_map(|(chain_id, chain)| {
                chain.remove_peer(&peer);
                // TODO(tree-sync): research if it actually useful to keep chains with zero peers for
                // some time.
                if chain.peer_count() == 0 {
                    Some(*chain_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if !chains_to_remove.is_empty() {
            let chain_to_children = self.compute_children();
            for chain_id in chains_to_remove {
                self.drop_chain_and_children(chain_id, &chain_to_children, "no_peers");
            }
        }
    }

    /// A set of peers claim to have imported a block_root. Create a new lookup for it or add them
    /// to an existing one + its ancestors
    pub fn search(
        &mut self,
        block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        if let Some(_) = self.block_to_tip.get(&block_root) {
            let mut peers = HashSet::<&PeerId>::from_iter(peers);
            let mut counts = HashMap::<&PeerId, usize>::new();

            // Add peer to `block`'s entry and all its ancestors
            let mut target_block_root = block_root;
            while let Some(chain_id) = self.block_to_tip.get_mut(&target_block_root) {
                let chain = self
                    .chains
                    .get_mut(chain_id)
                    .ok_or(InternalError(format!("Unknown chain {chain_id}")))?;

                let should_split_chain = match chain.tip() {
                    // If target_block_root is not the tip of chain, we have to split the chain
                    Some(tip) => tip != target_block_root,
                    // If the chain has no tip (should not happen) don't split the chain
                    None => false,
                };
                let chain_to_add_peers = if should_split_chain {
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

                peers.retain(|peer| {
                    if chain_to_add_peers.add_peer(**peer) {
                        *counts.entry(peer).or_default() += 1;
                        // We added peer to the lookup, retain it for the next ancestor chain
                        true
                    } else {
                        // Peer already part of this lookup, therefore it must be part of the peer
                        // set of all of its ancestors: stop
                        false
                    }
                });
                // No peers need to be added to ancestors, stop
                if peers.is_empty() {
                    break;
                }

                if let Some(parent_root) = chain_to_add_peers.parent_root() {
                    target_block_root = parent_root;
                } else {
                    break;
                }
            }
            // Log once per peer, as we could add it to a very large number of lookups
            for (peer, count) in counts {
                debug!(block_root = ?target_block_root, %peer, count, "Adding peer to existing header lookup and ancestors");
            }
        } else {
            if self.block_to_tip.len() > MAX_LOOKUP_COUNT {
                self.prune_least_popular_lookups();
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
            self.chains.insert(chain_id, chain);
            self.block_to_tip.insert(block_root, chain_id);
            metrics::inc_counter(&metrics::SYNC_CHAINS_ADDED);
        }
        Ok(())
    }

    /// Handle the result of a header download.
    pub fn on_header_download_result(
        &mut self,
        req_id: BlocksByRootRequestId,
        id: HeaderLookupId,
        response: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = id.block_root;

        // Invoke a closure to use the ? operator and handle the result consistenlty
        let result: Result<(), Error> = (|| {
            let Some(chain_id) = self.block_to_tip.get(&block_root) else {
                // TODO(tree-sync): register metric
                debug!(id = ?req_id, "Received header request for unknown block_root");
                return Ok(());
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
                    let block_header = block.message().block_header();
                    let parent_root = block_header.parent_root;

                    chain.header_request()?.on_download_success(
                        req_id,
                        peer_id,
                        block_header.clone(),
                        received,
                    )?;

                    metrics::inc_counter(&metrics::SYNC_HEADERS_DOWNLOADED);
                    debug!(%req_id, %chain_id, "Forward sync block header downloaded success");

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
                        chain.backfill_headers_to_forward_sync(block_header)?;
                        debug!(%chain_id, ?parent_root, block_count = chain.block_count(), "Forward sync chain reached imported block");
                        // Trigger potential foward sync for this chain
                        self.continue_requests(cx);
                    } else if let Some(parent_chain_id) = self.block_to_tip.get(&parent_root) {
                        // Parent is part of another chain, stop search
                        // Stop search we reached a known block
                        chain.to_waiting_parent(parent_root)?;
                        debug!(%chain_id, %parent_chain_id, ?parent_root, "Forward sync chain reached known block");
                        // TODO(tree-sync): Add peers recursively to the chain_id, potentially
                        // splitting the chain when adding peers.
                    } else {
                        chain.add_ancestor(block_header, cx.next_id())?;
                        debug!(%chain_id, ?parent_root, "Forward sync chain continues fetching ancestor");
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
            Ok(())
        })();

        if let Err(e) = result {
            self.handle_error(id.block_root, e);
        }
    }

    /// Handle the result of a block download.
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
            self.handle_error(id.block_root, e);
        }
    }

    /// Handle the result of a block processing.
    pub fn on_block_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(chain_id) = self.block_to_tip.get(&id.block_root).copied() else {
            debug!(?id, "Received block process result for unknown lookup");
            return;
        };
        let Some(chain) = self.chains.get_mut(&chain_id) else {
            error!(%chain_id, block_root = ?id.block_root, "Block references unknown chain");
            return;
        };

        debug!(%id, %chain_id, ?result, "Forward sync block process result");

        match chain.on_process_result(id, result, cx) {
            Ok(SyncBlockResult::Done { .. }) => {
                metrics::inc_counter(&metrics::SYNC_BLOCKS_PROCESSED);
                self.block_to_tip.remove(&id.block_root);
                // If the chain is empty, remove it
                if chain.is_empty() {
                    self.chains.remove(&chain_id);
                    debug!(%chain_id, "Removed completed chain");
                    metrics::inc_counter_vec(&metrics::SYNC_CHAINS_REMOVED, &["completed"]);
                }

                // Find all chains that are awaiting this block to process and continue them
                for other_chain in self.chains.values_mut() {
                    other_chain.on_block_imported(&id.block_root);
                }
                self.continue_requests(cx);
            }
            // Wait for next event
            Ok(SyncBlockResult::Wait) => {}
            Err(e) => {
                self.handle_error(id.block_root, e);
            }
        }
    }

    /// Common handler for any `forward_sync::Error`. For simplicity it drops the chain that includes
    /// the block and all of its descendants.
    fn handle_error(&mut self, block_root: Hash256, error: Error) {
        debug!(?error, ?block_root, "Dropping forward sync block lookup");
        let Some(chain_id) = self.block_to_tip.get(&block_root).copied() else {
            debug!(?block_root, "Handling error for unknown block_root");
            return;
        };

        metrics::inc_counter_vec(&metrics::SYNC_CHAIN_ERROR_COUNT, &[(&error).into()]);

        let block_to_children = self.compute_children();
        // TODO(tree-sync): logging `block_to_children` for debugging
        debug!(%chain_id, ?block_root, ?error, ?block_to_children, "Dropping forward sync chain on error");
        self.drop_chain_and_children(chain_id, &block_to_children, (&error).into());

        match error {
            Error::InternalError(_) | Error::TooManyErrors(_) => {
                //
            }
            Error::BlockConflictsWithFinality(_e) => {
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
                if matches!(chain.status, Status::ForwardSync { .. }) {
                    Some((chain.peer_count(), chain))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        chains_by_peer_count.sort_by_key(|(peer_count, _)| *peer_count);

        for (_, chain) in chains_by_peer_count {
            if let Status::ForwardSync {
                block_roots,
                syncing_blocks,
            } = &mut chain.status
            {
                // block_roots sorting: tip first, oldest ancestor last => pop
                if let Some(next_block) = block_roots.pop() {
                    syncing_blocks.push_back(SyncBlock::new(
                        RangeRequestId::ForwardSync(HeaderLookupId {
                            // Reuse the request ID of the header for better traceability
                            id: next_block.2,
                            block_root: next_block.0,
                        }),
                        next_block.0,
                        next_block.1,
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

        let chains_to_drop = self
            .chains
            .iter_mut()
            .filter_map(|(chain_id, chain)| {
                if let Err(e) = chain.continue_requests(cx) {
                    // TODO(tree-sync): should log error?
                    Some((*chain_id, e))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if !chains_to_drop.is_empty() {
            let chain_to_children = self.compute_children();
            for (chain_id, e) in chains_to_drop {
                self.drop_chain_and_children(chain_id, &chain_to_children, e.into());
            }
        }
    }

    /// Drop chain if it exists and all its children
    fn drop_chain_and_children(
        &mut self,
        initial_chain_id: TipId,
        chain_to_children: &HashMap<Hash256, Vec<TipId>>,
        reason: &'static str,
    ) {
        let mut queue: VecDeque<TipId> = VecDeque::from([initial_chain_id]);

        while let Some(chain_id) = queue.pop_front() {
            // Remove the node itself.
            // Only continue if the node was removed. This prevents infinite loops even if
            // `chain_to_children` items reference themselves
            if let Some(chain) = self.chains.remove(&chain_id) {
                metrics::inc_counter_vec(&metrics::SYNC_CHAINS_REMOVED, &[reason]);
                for block_root in chain.iter_block_roots() {
                    self.block_to_tip.remove(block_root);
                    debug!(?block_root, %chain_id, %initial_chain_id, reason, "Dropping forward sync block lookup");
                    metrics::inc_counter(&metrics::SYNC_FORWARD_BLOCKS_DROPPED);
                    // Only remove children if the node still existed
                    // Push its children‚Äîif any‚Äîonto the work list.
                    if let Some(children) = chain_to_children.get(block_root) {
                        queue.extend(children.iter().cloned());
                    }
                }
            }
        }
    }

    /// Drop lookup `block_root` if it exists and all its children
    fn compute_children(&mut self) -> HashMap<Hash256, Vec<TipId>> {
        let mut parent_to_children = HashMap::<Hash256, Vec<TipId>>::new();
        for (chain_id, chain) in self.chains.iter() {
            if let Some(parent_root) = chain.parent_root() {
                parent_to_children
                    .entry(parent_root)
                    .or_default()
                    .push(*chain_id);
            }
        }
        parent_to_children
    }

    /// Drop lookups with least amount of peers and slot until we pruned PRUNE_COUNT lookups
    fn prune_least_popular_lookups(&mut self) {
        let mut chains = self
            .chains
            .iter()
            // TODO: Prune only lookups that are not syncing and we know the header
            .map(|(chain_id, chain)| (chain.peer_count(), *chain_id))
            .collect::<Vec<_>>();
        chains.sort_unstable();

        let chain_to_children = self.compute_children();
        for (_, chain_id) in chains {
            self.drop_chain_and_children(chain_id, &chain_to_children, "too_many_blocks");
            if self.block_to_tip.len() < MAX_LOOKUP_COUNT - PRUNE_COUNT {
                break;
            }
        }
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
