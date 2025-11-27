use super::network_context::{
    DownloadRequest, DownloadRequestError, RpcRequestSendError, RpcResponseError,
    SyncNetworkContext,
};
use crate::metrics;
use crate::sync::network_context::{BatchPeers, LookupVerifyError, RpcResponseResult};
use crate::sync::sync_block::{Error as SyncBlockError, OkToImport, SyncBlock, SyncBlockResult};
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, ComponentsByRootRequestId, ForwardSyncLookupId,
    HeaderChainId, HeaderLookupId, Id, RangeRequestId,
};
use lighthouse_network::PeerId;
use std::collections::{HashMap, HashSet, VecDeque};
use strum::IntoStaticStr;
use tracing::{debug, error};
use types::{BeaconBlockHeader, EthSpec, Hash256, Slot};

const MAX_LOOKUP_COUNT: usize = 1_000_000;
const PRUNE_COUNT: usize = 100_000;
const BLOCK_BUFFER_SIZE: usize = 4;

#[derive(Debug, Copy, Clone)]
enum BlockPointer {
    HeaderChain(HeaderChainId),
    SyncBlock(Hash256),
}

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
    block_to_tip: HashMap<Hash256, BlockPointer>,
    header_chains: HashMap<HeaderChainId, HeaderChain>,
    syncing_blocks: HashMap<Hash256, SyncBlock<T>>,
}

/// Chain of consecutive blocks that are imported by the same set of peers
struct Chain<T: BeaconChainTypes> {
    status: Status<T>,
}

type PendingBlock = (Hash256, Slot);

#[derive(Copy, Clone, Debug)]
pub struct PeerStatusSummary {
    pub max_slot: Slot,
    pub min_slot: Slot,
}

struct HeaderChain {
    id: HeaderChainId,
    /// Headers descendant of `next_header_request.block_root` that are already downloaded.
    /// Does not include `next_header_request.block_root`.
    /// Sorting: tip first, oldest ancestor last
    block_roots: VecDeque<PendingBlock>,
    status: HeaderChainStatus,
    /// Peers that claim to have imported the oldest ancestor of this chain
    peers: HashMap<PeerId, PeerStatusSummary>,
}

enum HeaderChainStatus {
    Backfill {
        /// Oldest ancestor block root of this Chain.
        next_request: HeaderRequest,
    },
    WaitingParent {
        /// Parent root of the last block_root in `block_roots`
        parent_root: Hash256,
        /// True if the oldest ancestor can start downloading
        ready_to_sync: bool,
    },
}

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
        /// True if the oldest ancestor can start downloading
        ready_to_sync: bool,
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
        block: SyncBlock<T>,
        /// The parent root of `block`. Note that it may point to a block that is already imported,
        /// and is not in the sync headers DAG.
        parent_root: Hash256,
    },
}

/// Tracks a request to download a BeaconBlockHeader by block root
struct HeaderRequest {
    id: Option<Id>,
    chain_id: HeaderChainId,
    block_root: Hash256,
    failed_peers: HashSet<PeerId>,
    request: DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>,
}

impl HeaderRequest {
    fn new(block_root: Hash256, chain_id: HeaderChainId) -> Self {
        Self {
            id: None,
            chain_id,
            block_root,
            failed_peers: <_>::default(),
            request: DownloadRequest::new(),
        }
    }

    fn empty() -> Self {
        Self::new(Hash256::ZERO, HeaderChainId(0))
    }

    fn continue_request<T, I>(
        &mut self,
        peers: I,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error>
    where
        T: BeaconChainTypes,
        I: Iterator<Item = &'_ PeerId>,
    {
        if self.request.is_awaiting_download() {
            let Some(peer) = peers
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

            let id = self.id.get_or_insert_with(|| cx.next_id()).clone();

            // TODO(tree-sync): send headers_by_root request if available
            let req_id = cx.send_blocks_by_root_request(
                peer,
                self.block_root,
                BlocksByRootRequester::Header(HeaderLookupId {
                    id,
                    chain_id: self.chain_id,
                }),
            )?;

            self.request.on_download_start(req_id)?;
        }
        Ok(())
    }
}

impl HeaderChain {
    fn new(
        initial_block_root: Hash256,
        id: HeaderChainId,
        initial_peers: &[(PeerId, PeerStatusSummary)],
    ) -> Self {
        Self {
            id,
            block_roots: <_>::default(),
            status: HeaderChainStatus::Backfill {
                next_request: HeaderRequest::new(initial_block_root, id),
            },
            peers: HashMap::from_iter(initial_peers.iter().copied()),
        }
    }

    /// Continues the header or blocks requests of this chain
    fn continue_requests<T: BeaconChainTypes>(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        match &mut self.status {
            HeaderChainStatus::Backfill { next_request } => {
                Ok(next_request.continue_request(self.peers.keys(), cx)?)
            }
            _ => Ok(()),
        }
    }

    fn add_ancestor(&mut self, header: BeaconBlockHeader) -> Result<(), InternalError> {
        match &mut self.status {
            HeaderChainStatus::Backfill { next_request, .. } => {
                self.block_roots
                    .push_back((next_request.block_root, header.slot));
                *next_request = HeaderRequest::new(header.parent_root, self.id);
                Ok(())
            }
            _ => Err(InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn extend_with_children(&mut self, mut child_chain: Self) {
        while let Some(block) = child_chain.block_roots.pop_back() {
            // pop_back gives oldest first, pushing to front restores tip-first
            self.block_roots.push_front(block);
        }

        // All the peers of the child chain have imported the ancestors
        self.peers.extend(child_chain.peers.drain());
    }

    fn to_waiting_parent(
        &mut self,
        parent_root: Hash256,
        ready_to_sync: bool,
    ) -> Result<(), Error> {
        self.status = HeaderChainStatus::WaitingParent {
            parent_root,
            ready_to_sync,
        };
        Ok(())
    }

    fn parent_root(&self) -> Option<Hash256> {
        match &self.status {
            HeaderChainStatus::Backfill { .. } => None,
            HeaderChainStatus::WaitingParent { parent_root, .. } => Some(*parent_root),
        }
    }

    /// Returns true if the peer has been added to the map
    fn add_peer(&mut self, peer: PeerId, status: PeerStatusSummary) -> bool {
        let contains_key = self.peers.contains_key(&peer);
        self.peers.insert(peer, status);
        !contains_key
    }

    /// Returns true if a peer was removed from the map
    fn remove_peer(&mut self, peer: &PeerId) -> bool {
        self.peers.remove(peer).is_some()
    }

    fn pop_oldest_ancestor(&mut self) -> Option<PendingBlock> {
        match &mut self.status {
            HeaderChainStatus::WaitingParent {
                parent_root,
                ready_to_sync,
            } => {
                if !*ready_to_sync {
                    return None;
                }
                if let Some((block_root, block_slot)) = self.block_roots.pop_back() {
                    *parent_root = block_root;
                    Some((block_root, block_slot))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn peers_of_block_slot(&self, block_slot: Slot) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, status)| block_slot >= status.min_slot && block_slot < status.max_slot)
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Returns true if this chain transitioned into ready to sync
    fn on_parent_imported(&mut self, imported_block_root: &Hash256) -> bool {
        match &mut self.status {
            HeaderChainStatus::WaitingParent {
                parent_root,
                ready_to_sync,
            } => {
                if parent_root == imported_block_root && !*ready_to_sync {
                    *ready_to_sync = true;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn block_count(&self) -> usize {
        self.block_roots.len()
    }

    fn min_slot(&self) -> Option<Slot> {
        self.block_roots.back().map(|b| b.1)
    }

    fn max_slot(&self) -> Option<Slot> {
        self.block_roots.front().map(|b| b.1)
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

// TODO(tree-sync): Re-add the reprocessing cache, so we don't process twice a block that we got
// through gossip and sync.

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
            header_chains: <_>::default(),
            syncing_blocks: <_>::default(),
        }
    }

    /// Returns the peers that claim to have imported a specific block_root
    #[cfg(test)]
    pub fn block_peers(&self, block_root: &Hash256) -> Result<Option<Vec<PeerId>>, String> {
        let Some(block_ptr) = self.block_to_tip.get(block_root) else {
            return Ok(None);
        };
        match block_ptr {
            BlockPointer::HeaderChain(id) => Err(format!("Block {id} is a header chain")),
            BlockPointer::SyncBlock(id) => Ok(Some(
                self.syncing_blocks
                    .get(id)
                    .ok_or(format!("Unknown chain {id}"))?
                    .get_peers(),
            )),
        }
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
        self.header_chains
            .values()
            .filter_map(|chain| chain.max_slot())
            .max()
    }

    /// Return all processing ids of syncing blocks
    #[cfg(test)]
    pub fn get_processing_ids(&mut self) -> Vec<ForwardSyncLookupId> {
        let mut ids = vec![];
        for block in self.syncing_blocks.values() {
            if block.is_processing() {
                if let RangeRequestId::ForwardSync(id) = block.id() {
                    ids.push(id);
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
            .header_chains
            .iter_mut()
            .filter_map(|(chain_id, chain)| {
                chain.remove_peer(&peer);
                // TODO(tree-sync): research if it actually useful to keep chains with zero peers for
                // some time.
                if chain.peer_count() == 0 {
                    Some((*chain_id).into())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (id, block) in self.syncing_blocks.iter_mut() {
            block.remove_peer(&peer);
        }

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
        peers: &[(PeerId, PeerStatusSummary)],
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        if let Some(_) = self.block_to_tip.get(&block_root) {
            debug!(block_root = ?block_root, ?peers, "Adding peer to existing header lookup and ancestors");
            self.add_peers_recursively(block_root, peers)?;
        } else {
            if self.block_to_tip.len() > MAX_LOOKUP_COUNT {
                self.prune_least_popular_lookups();
            }

            let chain_id = HeaderChainId(cx.next_id());
            match peers {
                [peer] => debug!(?block_root, %chain_id, ?peer, "Creating new header lookup"),
                _ => debug!(
                    ?block_root,
                    %chain_id,
                    peers = peers.len(),
                    "Creating new header lookup"
                ),
            }

            let mut chain = HeaderChain::new(block_root, chain_id, peers);
            chain.continue_requests(cx)?;
            // Don't insert until first request is successful
            self.header_chains.insert(chain_id, chain);
            self.block_to_tip
                .insert(block_root, BlockPointer::HeaderChain(chain_id));
            metrics::inc_counter(&metrics::SYNC_CHAINS_ADDED);
        }
        Ok(())
    }

    /// Handle the result of a header download.
    pub fn on_headers_download_result(
        &mut self,
        req_id: BlocksByRootRequestId,
        id: HeaderLookupId,
        response: RpcResponseResult<Vec<BeaconBlockHeader>>,
        _peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        // Invoke a closure to use the ? operator and handle the result consistenlty
        let result: Result<(), Error> = (|| {
            let chain_id = id.chain_id;
            let chain = self
                .header_chains
                .get_mut(&chain_id)
                .ok_or(InternalError(format!("Request for unknown chain {id}")))?;

            let response = response.and_then(|(blocks, timestamp)| {
                if blocks.is_empty() {
                    Err(RpcResponseError::VerifyError(
                        LookupVerifyError::NotEnoughResponsesReturned { actual: 0 },
                    ))
                } else {
                    Ok((blocks, timestamp))
                }
            });

            let header_request = match &mut chain.status {
                HeaderChainStatus::Backfill { next_request, .. } => next_request,
                HeaderChainStatus::WaitingParent { .. } => {
                    debug!(%req_id, %chain_id, "Unexpected request for header chain waiting parent");
                    return Ok(());
                }
            };

            // TODO(tree-sync): add some check to make sure that distinct lookups for the same
            // block root don't mess with each other. That check must happen before triggering
            // errors for bad state

            match response {
                Ok((headers, received)) => {
                    header_request.request.on_download_success(
                        req_id,
                        PeerId::random(),
                        BeaconBlockHeader::empty(),
                        received,
                    )?;
                    debug!(%req_id, %chain_id, "Forward sync block header downloaded success");

                    // TODO(tree-sync): should check if the block is descendant of finalized
                    // TODO(tree-sync): on finalization or every interval we should drop branches that
                    // conflict with finality
                    let finalized_checkpoint = cx.chain.head().finalized_checkpoint();

                    for header in headers {
                        let parent_root = header.parent_root;
                        let block_root = header.canonical_root();
                        chain.add_ancestor(header.clone())?;

                        metrics::inc_counter(&metrics::SYNC_HEADERS_DOWNLOADED);

                        // Once we discover the parent_root of this block three things can happen
                        // 1. The parent root is a known block -> stop
                        // 2. We conflicts with finality -> reject
                        // 3. The parent root is unknown -> continue search

                        // TODO(tree-sync): check that the slots are decreasing, so we don't end up in
                        // an infinite loop. But note that the wrong block will be the descendant.
                        // - We get header A with parent B and slot 10
                        // - We get header B with parent C and slot 11
                        // - That makes header A invalid

                        if header.slot
                            <= finalized_checkpoint
                                .epoch
                                .start_slot(T::EthSpec::slots_per_epoch())
                            && block_root != finalized_checkpoint.root
                        {
                            return Err(Error::BlockConflictsWithFinality(format!(
                                "Block {:?} {} conflicts with finalized checkpoint {:?}",
                                block_root, header.slot, finalized_checkpoint
                            )));
                        }

                        if cx.chain.block_is_known_to_fork_choice(&parent_root) {
                            // Parent is imported, we can forward sync this chain
                            // Stop search we reached a known block
                            chain.to_waiting_parent(parent_root, true)?;
                            debug!(%chain_id, ?parent_root, block_count = chain.block_count(), "Forward sync chain reached imported block");
                            // Trigger potential foward sync for this chain
                            self.continue_requests(cx);
                            break;
                        } else if let Some(parent_chain_ptr) =
                            self.block_to_tip.get(&parent_root).copied()
                        {
                            // Parent is part of another chain, stop search
                            // Stop search we reached a known block
                            debug!(%chain_id, ?parent_chain_ptr, ?parent_root, "Forward sync chain reached known block");

                            // If this is the only child of `parent_root` we can insert the block
                            // in the parent chain, and "merge" them. This is the common case in
                            // single fork chains. The main chain keeps producing new blocks while
                            // we backfill headers.
                            if match self.compute_children().get(&parent_root) {
                                Some(children) => children.is_empty(),
                                None => false,
                            } {
                                if let BlockPointer::HeaderChain(parent_chain_id) = parent_chain_ptr
                                {
                                    // Add new tip to `parent_chain`
                                    let chain = self.header_chains.remove(&chain_id).ok_or(
                                        InternalError(format!("missing chain {chain_id}")),
                                    )?;

                                    let parent_chain = self
                                        .header_chains
                                        .get_mut(&parent_chain_id)
                                        .ok_or(InternalError(format!(
                                            "missing chain {parent_chain_id}"
                                        )))?;

                                    for (block_root, _) in &chain.block_roots {
                                        self.block_to_tip.insert(*block_root, parent_chain_ptr);
                                    }
                                    parent_chain.extend_with_children(chain);
                                }
                            } else {
                                let chain = self
                                    .header_chains
                                    .get_mut(&chain_id)
                                    .ok_or(InternalError(format!("missing chain {chain_id}")))?;

                                // `parent_root` has multiple children, keep `chain` as a fork and
                                // mark it awaiting parent
                                chain.to_waiting_parent(parent_root, false)?;
                            }

                            // The rest of headers of this response are known, ignore
                            break;
                        } else {
                            debug!(%chain_id, ?parent_root, "Forward sync chain continues fetching ancestor");
                            // Add to the block_to_tip mapping to respect the invariant "Each block
                            // root exists in exactly one `Chain::block_roots` list".
                            self.block_to_tip.insert(parent_root, chain_id.into());
                            // Since the block already points to `chain` we don't need to add peers.
                            // Just trigger header download for this new root.
                        }
                    }
                }
                Err(e) => {
                    // Request errors are logged in `SyncNetworkContext::on_rpc_response_result`
                    header_request.request.on_download_error(req_id, Some(e))?;
                    // Continue this request to potentially resend the header request
                }
            }
            self.continue_requests(cx);
            Ok(())
        })();

        if let Err(e) = result {
            self.handle_error(id.chain_id.into(), e);
        }
    }

    /// Handle the result of a block download.
    pub fn on_block_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        id: ForwardSyncLookupId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = id.block_root;
        let Some(block) = self.syncing_blocks.get_mut(&block_root) else {
            error!(?block_root, "Unknown forward sync block");
            return;
        };

        let result: Result<(), Error> = (|| {
            // let block = self.block_request(req_id.requester)?;
            debug!(%id, ?block_root, result = render_result(&result), "Forward sync block download result");
            block.on_download_result(req_id, result, cx)?;
            block.continue_request(cx, OkToImport::IfParentImported)?;
            Ok(())
        })();

        if let Err(e) = result {
            self.handle_error(block_root.into(), e);
            // Some syncing blocks may have been dropped so there's space for new chains to sync
            self.continue_requests(cx);
        }
    }

    /// Handle the result of a block processing.
    /// We known this block's parent is imported, so we don't explicitly handle a ParentUnknown error.
    pub fn on_block_process_result(
        &mut self,
        id: ForwardSyncLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let result: Result<(), Error> = (|| {
            let block_root = id.block_root;
            let Some(block) = self.syncing_blocks.get_mut(&block_root) else {
                error!(?block_root, "Unknown forward sync block");
                return Ok(());
            };

            debug!(%id, ?block_root, ?result, "Forward sync block process result");

            // TODO(tree-sync): use id to ensure results for other roots don't mix up
            match block.on_process_result(result, cx)? {
                SyncBlockResult::Done { .. } => {
                    metrics::inc_counter(&metrics::SYNC_BLOCKS_PROCESSED);
                    self.block_to_tip.remove(&block_root);
                    // ForwardSync chains have a single block, remove them on Done
                    self.syncing_blocks.remove(&block_root);
                    debug!(%id, ?block_root, "Removed completed forward sync block");
                    metrics::inc_counter_vec(&metrics::SYNC_CHAINS_REMOVED, &["completed"]);

                    // Find all chains that are awaiting this block to process and continue them
                    for (chain_id, other_chain) in self.header_chains.iter_mut() {
                        if other_chain.on_parent_imported(&id.block_root) {
                            debug!(
                                %chain_id,
                                parent_root = ?id.block_root,
                                "Forward sync marked chain as ready to sync"
                            );
                        }
                    }
                    self.continue_requests(cx);
                }
                // Not complete yet, continue requests
                SyncBlockResult::Wait => {
                    block.continue_request(cx, OkToImport::IfParentImported)?;
                }
            }
            Ok(())
        })();

        if let Err(e) = result {
            self.handle_error(id.block_root.into(), e);
            // Some syncing blocks may have been dropped so there's space for new chains to sync
            self.continue_requests(cx);
        }
    }

    pub fn prune(&mut self) {
        // TODO(tree-sync): should prune? Based on finality and expired head chains
    }

    /// Common handler for any `forward_sync::Error`. For simplicity it drops the chain that includes
    /// the block and all of its descendants.
    fn handle_error(&mut self, chain_id: BlockPointer, error: Error) {
        debug!(?error, ?chain_id, "Dropping forward sync block lookup");

        metrics::inc_counter_vec(&metrics::SYNC_CHAIN_ERROR_COUNT, &[(&error).into()]);

        let block_to_children = self.compute_children();
        // TODO(tree-sync): logging `block_to_children` for debugging
        debug!(%chain_id, ?chain_id, ?error, ?block_to_children, "Dropping forward sync chain on error");
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

        if self.syncing_blocks.len() > BLOCK_BUFFER_SIZE {
            return;
        }

        // A chain can be in two states:
        // - Active backfill
        // - Oldest ancestor known

        // Find the block range with most peers and highest slot. This is the block
        // to be used as tip of the chain of blocks to fetch.
        let mut chains_by_peer_count = self
            .header_chains
            .iter_mut()
            .filter_map(|(_, chain)| {
                if chain.parent_root().is_some() {
                    Some((chain.peers.len(), chain))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        chains_by_peer_count.sort_by_key(|(peer_count, _)| *peer_count);

        let mut blocks_to_add = vec![];

        'o: for (chain_id, chain) in chains_by_peer_count {
            while let Some((block_root, block_slot)) = chain.pop_oldest_ancestor() {
                let block_peers = chain.peers_of_block_slot(block_slot);
                blocks_to_add.push((block_root, block_slot, block_peers));
                debug!(%chain_id, ?block_root, %block_slot, "Transitioned block to forward sync");
                if blocks_to_add.len() + self.syncing_blocks.len() > BLOCK_BUFFER_SIZE {
                    break 'o;
                }
            }
        }

        let should_continue_requests = !blocks_to_add.is_empty();
        for (block_root, block_slot, block_peers) in blocks_to_add {
            // Need to compute the peer of the block here since header chains only track peers
            // that have imported the oldest ancestor.

            let block = SyncBlock::new(
                // Reuse the request ID of the header for better traceability
                RangeRequestId::ForwardSync(ForwardSyncLookupId {
                    id: cx.next_id(),
                    block_root,
                }),
                block_root,
                block_slot,
                &block_peers,
            );
            // Update all block references to the new chain
            self.block_to_tip
                .insert(block_root, BlockPointer::SyncBlock(block_root));
            self.syncing_blocks.insert(block_root, block);
        }

        // Prune chains that become empty after pop_next_block_to_sync
        self.header_chains
            .retain(|_, chain| !chain.block_roots.is_empty());

        if should_continue_requests {
            self.continue_requests(cx);
        }
    }

    fn continue_requests(&mut self, cx: &mut SyncNetworkContext<T>) {
        // TODO(tree-sync): optimize this call to maybe not do it everytime
        self.trigger_forward_sync(cx);

        let mut chains_to_drop = vec![];

        for (chain_id, block) in self.syncing_blocks.iter_mut() {
            if let Err(e) = block.continue_request(cx, OkToImport::IfParentImported) {
                // TODO(tree-sync): should log error?
                chains_to_drop.push(((*chain_id).into(), e.into()));
            }
        }

        for (chain_id, chain) in self.header_chains.iter_mut() {
            if let Err(e) = chain.continue_requests(cx) {
                // TODO(tree-sync): should log error?
                chains_to_drop.push(((*chain_id).into(), e));
            }
        }

        if !chains_to_drop.is_empty() {
            let chain_to_children = self.compute_children();
            for (chain_id, e) in chains_to_drop {
                self.drop_chain_and_children(chain_id, &chain_to_children, e.into());
            }
        }
    }

    fn add_peers_recursively(
        &mut self,
        block_root: Hash256,
        peers: &[(PeerId, PeerStatusSummary)],
    ) -> Result<(), Error> {
        let Some(id) = self.block_to_tip.get(&block_root) else {
            return Ok(());
        };
        match id {
            BlockPointer::HeaderChain(chain_id) => {
                // The peer claims to have imported some block in this header chain. Header
                // chain requests always the oldest ancestor. So we can guarantee that this peer
                // has imported the oldest ancestor of the chain.
                let chain = self
                    .header_chains
                    .get_mut(chain_id)
                    .ok_or(InternalError(format!("Unknown chain {chain_id}")))?;
                for (peer, status) in peers {
                    chain.add_peer(*peer, *status);
                }
                if let Some(parent_root) = chain.parent_root() {
                    self.add_peers_recursively(parent_root, peers)?;
                }
                Ok(())
            }
            BlockPointer::SyncBlock(id) => {
                let block = self
                    .syncing_blocks
                    .get_mut(id)
                    .ok_or(InternalError(format!("Unknown syncing block {id:?}")))?;
                for (peer, _) in peers {
                    block.add_peer(*peer);
                }
                if let Some(parent_root) = block.parent_root() {
                    self.add_peers_recursively(parent_root, peers)?;
                }
                Ok(())
            }
        }
    }

    /// Drop chain if it exists and all its children
    fn drop_chain_and_children(
        &mut self,
        initial_chain_id: BlockPointer,
        chain_to_children: &HashMap<Hash256, Vec<BlockPointer>>,
        reason: &'static str,
    ) {
        let mut queue: VecDeque<BlockPointer> = VecDeque::from([initial_chain_id]);

        while let Some(block_ptr) = queue.pop_front() {
            // Remove the node itself.
            // Only continue if the node was removed. This prevents infinite loops even if
            // `chain_to_children` items reference themselves
            match block_ptr {
                BlockPointer::HeaderChain(chain_id) => {
                    if let Some(chain) = self.header_chains.remove(&chain_id) {
                        debug!(%chain_id, %initial_chain_id, reason, "Dropping forward sync chain");
                        metrics::inc_counter_vec(&metrics::SYNC_CHAINS_REMOVED, &[reason]);

                        for (block_root, _) in chain.block_roots {
                            self.block_to_tip.remove(&block_root);
                            debug!(?block_root, %chain_id, %initial_chain_id, reason, "Dropping forward sync block");
                            metrics::inc_counter(&metrics::SYNC_FORWARD_BLOCKS_DROPPED);

                            // Only remove children if the node still existed
                            // Push its children‚ if any‚ onto the work list.
                            if let Some(children) = chain_to_children.get(&block_root) {
                                queue.extend(children.iter().cloned());
                            }
                        }
                    }
                }
                BlockPointer::SyncBlock(id) => {
                    if let Some(block) = self.syncing_blocks.remove(&id) {
                        if let Some(children) = chain_to_children.get(&id) {
                            queue.extend(children.iter().cloned());
                        }
                    }
                }
            }
        }
    }

    /// Compute the map of block_roots -> chain IDs
    fn compute_children(&self) -> HashMap<Hash256, Vec<BlockPointer>> {
        let mut parent_to_children = HashMap::<Hash256, Vec<BlockPointer>>::new();
        for (chain_id, chain) in self.header_chains.iter() {
            if let Some(parent_root) = chain.parent_root() {
                parent_to_children
                    .entry(parent_root)
                    .or_default()
                    .push(BlockPointer::HeaderChain(*chain_id));
            }
        }
        for (chain_id, chain) in self.syncing_blocks.iter() {
            if let Some(parent_root) = chain.parent_root() {
                parent_to_children
                    .entry(parent_root)
                    .or_default()
                    .push(BlockPointer::SyncBlock(*chain_id));
            }
        }
        parent_to_children
    }

    /// Drop lookups with least amount of peers and slot until we pruned PRUNE_COUNT lookups
    fn prune_least_popular_lookups(&mut self) {
        let mut chains = self
            .header_chains
            .iter()
            // TODO: Prune only lookups that are not syncing and we know the header
            .map(|(chain_id, chain)| (chain.peer_count(), *chain_id))
            .collect::<Vec<_>>();
        chains.sort_unstable();

        let chain_to_children = self.compute_children();
        for (_, chain_id) in chains {
            self.drop_chain_and_children(chain_id.into(), &chain_to_children, "too_many_blocks");
            if self.block_to_tip.len() < MAX_LOOKUP_COUNT - PRUNE_COUNT {
                break;
            }
        }
    }

    pub fn register_metrics(&self) {
        let (min_slot, max_slot) = self.header_chains.values().fold(
            (None::<Slot>, None::<Slot>),
            |(gmin, gmax), chain| {
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
            },
        );

        if let (Some(min_slot), Some(max_slot)) = (min_slot, max_slot) {
            metrics::set_gauge(&metrics::SYNC_HEADER_MIN_SLOT, min_slot.as_u64() as i64);
            metrics::set_gauge(&metrics::SYNC_HEADER_MAX_SLOT, max_slot.as_u64() as i64);
        }

        metrics::set_gauge(&metrics::SYNC_HEADERS_COUNT, self.block_to_tip.len() as i64);
        metrics::set_gauge(
            &metrics::SYNC_HEADER_CHAINS_COUNT,
            self.header_chains.len() as i64,
        );
        metrics::set_gauge(
            &metrics::SYNC_FORWARD_SYNC_BLOCKS_COUNT,
            self.syncing_blocks.len() as i64,
        );

        for (chain_id, chain) in &self.header_chains {
            let status = match &chain.status {
                HeaderChainStatus::Backfill { next_request, .. } => {
                    format!(
                        "BackfillHeaders block_roots {:?} next_header_request {:?} {} {}",
                        chain.block_roots,
                        next_request.id,
                        next_request.block_root,
                        next_request.request.status_str()
                    )
                }
                HeaderChainStatus::WaitingParent {
                    parent_root,
                    ready_to_sync,
                } => {
                    format!("WaitingParentChain ready_to_sync {ready_to_sync} parent_root {parent_root:?} block_roots {:?}",chain.block_roots)
                }
            };

            let recursive_parent_chain = (|| {
                let mut next_chain_id = *chain_id;
                loop {
                    let Some(next_chain) = self.header_chains.get(&next_chain_id) else {
                        return Err(format!("Unknown chain {next_chain_id}"));
                    };
                    if let HeaderChainStatus::WaitingParent { parent_root, .. } = next_chain.status
                    {
                        let Some(parent_ptr_id) = self.block_to_tip.get(&parent_root) else {
                            return Err(format!("{next_chain_id} Unknown block {parent_root:?}"));
                        };
                        let parent_chain_id = match parent_ptr_id {
                            BlockPointer::HeaderChain(id) => id,
                            BlockPointer::SyncBlock(id) => {
                                return Err(format!("{next_chain_id} unknown/imported"));
                            }
                        };
                        next_chain_id = *parent_chain_id;
                    } else if next_chain_id == *chain_id {
                        return Ok(format!("itself"));
                    } else {
                        return Ok(format!("{next_chain_id}"));
                    }
                }
            })();

            debug!(%chain_id, status, ?recursive_parent_chain, "DEBUG chain");
        }

        for (block_root, chain_id) in &self.block_to_tip {
            if !match chain_id {
                BlockPointer::HeaderChain(id) => self.header_chains.contains_key(id),
                BlockPointer::SyncBlock(id) => self.syncing_blocks.contains_key(id),
            } {
                debug!("DEBUG block {block_root} points to unknown chain {chain_id}");
            }
        }

        // Min header
        // Highest known header
        // Current head
    }
}

impl std::fmt::Display for BlockPointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderChain(id) => write!(f, "Header/{id}"),
            Self::SyncBlock(id) => write!(f, "Block/{id:?}"),
        }
    }
}

impl From<HeaderChainId> for BlockPointer {
    fn from(id: HeaderChainId) -> Self {
        Self::HeaderChain(id)
    }
}

impl From<Hash256> for BlockPointer {
    fn from(id: Hash256) -> Self {
        Self::SyncBlock(id)
    }
}

fn render_result<T, E: std::fmt::Debug>(result: &Result<T, E>) -> String {
    match result {
        Ok(_) => format!("Ok"),
        Err(e) => format!("Err({e:?})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::builder::Witness;
    use beacon_chain::eth1_chain::CachingEth1Backend;
    use slot_clock::ManualSlotClock;
    use store::MemoryStore;
    use types::FixedBytesExtended;
    use types::MinimalEthSpec as E;

    type T = Witness<ManualSlotClock, CachingEth1Backend<E>, E, MemoryStore<E>, MemoryStore<E>>;

    fn to_roots(input: &[u64]) -> Vec<Hash256> {
        input.iter().map(to_root).collect()
    }

    fn to_root(u: &u64) -> Hash256 {
        Hash256::from_low_u64_le(*u)
    }

    fn from_root(r: &Hash256) -> u64 {
        r.to_low_u64_le()
    }

    fn to_block(u: &u64) -> PendingBlock {
        (
            HeaderLookupId {
                id: *u as u32,
                block_root: to_root(u),
            },
            Slot::new(*u),
        )
    }

    fn get_roots<T: BeaconChainTypes>(chain: &Chain<T>) -> Vec<u64> {
        chain.iter_block_roots().map(from_root).collect()
    }

    fn test_split_by(input: &[u64], split: u64, roots_new: &[u64], roots_initial: &[u64]) {
        let mut initial_chain = {
            /// input sorting: tip first, oldest ancestor last
            let (last, rest) = input.split_last().unwrap();
            Chain::<T> {
                peers: <_>::default(),
                status: Status::BackfillHeaders {
                    block_roots: rest.iter().map(to_block).collect::<Vec<_>>(),
                    next_header_request: HeaderRequest::new(to_root(&last), 0),
                },
            }
        };
        let new_chain = initial_chain
            .split_by(to_root(&split))
            .expect("error spliting backfill headers");

        assert_eq!(get_roots(&new_chain), roots_new, "new backfill");
        assert_eq!(get_roots(&initial_chain), roots_initial, "initial backfill");

        let mut initial_chain = Chain::<T> {
            peers: <_>::default(),
            status: Status::WaitingParentChain {
                parent_root: to_root(&0),
                block_roots: input.iter().map(to_block).collect::<Vec<_>>(),
                ready_to_sync: false,
            },
        };
        let new_chain = initial_chain
            .split_by(to_root(&split))
            .expect("error spliting backfill headers");

        assert_eq!(get_roots(&new_chain), roots_new, "new waiting");
        assert_eq!(get_roots(&initial_chain), roots_initial, "initial waiting");
        assert_eq!(
            from_root(&initial_chain.parent_root().unwrap()),
            // The tip of the new chain is the parent of the initial chain
            *roots_new.first().unwrap(),
            "parent_initial"
        );
    }

    fn test_merge(left: &[u64], right: &[u64], expected_merged: &[u64]) {
        let peers = HashSet::from_iter([PeerId::random()]);
        // Left chain has descendant roots of right
        let mut left_chain = Chain::<T> {
            peers: peers.clone(),
            status: Status::WaitingParentChain {
                parent_root: to_root(right.first().unwrap()),
                block_roots: left.iter().map(to_block).collect::<Vec<_>>(),
                ready_to_sync: false,
            },
        };
        // Right chain has no known parent, so set it to 0xff
        let mut right_chain = Chain::<T> {
            peers: peers.clone(),
            status: Status::WaitingParentChain {
                parent_root: to_root(&0xff), // rand root to not have conflicts
                block_roots: right.iter().map(to_block).collect::<Vec<_>>(),
                ready_to_sync: false,
            },
        };
        let mut sync = ForwardSync {
            block_to_tip: <_>::default(),
            chains: HashMap::from_iter([(HeaderChainId(0), left_chain), (TipId(1), right_chain)]),
        };
        sync.merge_chains();
        assert_eq!(sync.chains.len(), 1, "Should merge 2 chains into 1");
        let merged_chain = sync.chains.values().next().unwrap();
        assert_eq!(get_roots(merged_chain), expected_merged, "merged roots");
    }

    #[test]
    fn split_by_only_elem_a() {
        // input [0,1] sorted by tip first
        test_split_by(&[1, 0], 0, &[0], &[1]);
    }

    #[test]
    fn split_by_only_elem_b() {
        test_split_by(&[1, 0], 1, &[1, 0], &[]);
    }

    #[test]
    fn split_by_first() {
        test_split_by(&[3, 2, 1, 0], 0, &[0], &[3, 2, 1]);
    }

    #[test]
    fn split_by_last() {
        test_split_by(&[3, 2, 1, 0], 3, &[3, 2, 1, 0], &[]);
    }

    #[test]
    fn split_by_middle_a() {
        test_split_by(&[3, 2, 1, 0], 1, &[1, 0], &[3, 2]);
    }
    #[test]
    fn split_by_middle_b() {
        test_split_by(&[3, 2, 1, 0], 2, &[2, 1, 0], &[3]);
    }
    #[test]
    fn split_by_middle_c() {
        test_split_by(&[2, 1, 0], 1, &[1, 0], &[2]);
    }

    #[test]
    fn merge_left_long() {
        test_merge(&[2, 1], &[0], &[2, 1, 0]);
    }

    #[test]
    fn merge_right_long() {
        test_merge(&[2], &[1, 0], &[2, 1, 0]);
    }

    #[test]
    fn merge_same() {
        test_merge(&[3, 2], &[1, 0], &[3, 2, 1, 0]);
    }
}
