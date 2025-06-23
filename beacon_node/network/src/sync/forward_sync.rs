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
use tracing::{debug, error, warn};
use types::{BeaconBlockHeader, EthSpec, Hash256, SignedBeaconBlock, Slot};

const MAX_LOOKUP_COUNT: usize = 1_000_000;
const PRUNE_COUNT: usize = 100_000;
const BLOCK_BUFFER_SIZE: usize = 2;

pub struct ForwardSync<T: BeaconChainTypes> {
    blocks: HashMap<Hash256, ForwardSyncBlock<T>>,
    chain: Arc<BeaconChain<T>>,
}

struct ForwardSyncBlock<T: BeaconChainTypes> {
    id: HeaderLookupId,
    status: Status<T>,
}

enum Status<T: BeaconChainTypes> {
    // TODO(tree-sync): Make the "waiting" completed header requests as memory cheap as possible
    BackfillHeader {
        peers: HashSet<PeerId>,
        failed_peers: HashSet<PeerId>,
        request: DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>,
    },
    ForwardSyncBlock {
        header: BeaconBlockHeader,
        request: SyncBlock<T>,
    },
}

// TODO(tree-sync): Re-add the reprocessing cache, so we don't process twice a block that we got
// through gossip and sync.

impl<T: BeaconChainTypes> ForwardSyncBlock<T> {
    fn new(block_root: Hash256, id: Id, peers: &[PeerId]) -> Self {
        Self {
            id: HeaderLookupId { id, block_root },
            status: Status::BackfillHeader {
                peers: HashSet::from_iter(peers.iter().copied()),
                failed_peers: <_>::default(),
                request: DownloadRequest::new(),
            },
        }
    }

    /// Returns whether the value was newly inserted
    fn add_peer(&mut self, peer: PeerId) -> bool {
        match &mut self.status {
            Status::BackfillHeader { peers, .. } => peers.insert(peer),
            Status::ForwardSyncBlock { request, .. } => request.add_peer(peer),
        }
    }

    fn remove_peer(&mut self, peer: &PeerId) {
        match &mut self.status {
            Status::BackfillHeader { peers, .. } => {
                peers.remove(peer);
            }
            Status::ForwardSyncBlock { request, .. } => {
                request.remove_peer(peer);
            }
        }
    }

    fn peer_count(&self) -> usize {
        match &self.status {
            Status::BackfillHeader { peers, .. } => peers.len(),
            Status::ForwardSyncBlock { request, .. } => request.peer_count(),
        }
    }

    fn get_peers(&self) -> Vec<PeerId> {
        match &self.status {
            Status::BackfillHeader { peers, .. } => peers.iter().copied().collect(),
            Status::ForwardSyncBlock { request, .. } => {
                request.clone_peers().iter().copied().collect()
            }
        }
    }

    fn is_syncing(&self) -> bool {
        match self.status {
            Status::BackfillHeader { .. } => false,
            Status::ForwardSyncBlock { .. } => true,
        }
    }

    fn parent_root(&self) -> Option<Hash256> {
        match &self.status {
            Status::BackfillHeader { request, .. } => {
                request.is_complete().map(|header| header.parent_root)
            }
            Status::ForwardSyncBlock { header, .. } => Some(header.parent_root),
        }
    }

    fn header_request(
        &mut self,
    ) -> Result<&mut DownloadRequest<BlocksByRootRequestId, BeaconBlockHeader>, Error> {
        match &mut self.status {
            Status::BackfillHeader { request, .. } => Ok(request),
            _ => Err(Error::InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn block_request(&mut self) -> Result<&mut SyncBlock<T>, Error> {
        match &mut self.status {
            Status::ForwardSyncBlock { request, .. } => Ok(request),
            _ => Err(Error::InternalError(
                "Expected lookup to be in Syncing state".to_owned(),
            )),
        }
    }

    fn assert_expected_lookup_id(&self, lookup_id: HeaderLookupId) -> Result<(), Error> {
        if self.id == lookup_id {
            Ok(())
        } else {
            Err(Error::InternalError(format!(
                "Unexpected lookup ID {} != {}",
                self.id, lookup_id
            )))
        }
    }

    fn to_foward_sync_block(&mut self, block_root: Hash256) -> Result<(), Error> {
        let (peers, request) = match &mut self.status {
            Status::BackfillHeader { peers, request, .. } => (peers, request),
            _ => {
                return Err(Error::InternalError(
                    "Expected lookup to be in DownloadingHeader state".to_owned(),
                ))
            }
        };

        let header = match request.is_complete() {
            Some(header) => header.clone(),
            None => {
                return Err(Error::InternalError(
                    "Expected request to be complete".to_owned(),
                ))
            }
        };

        // We are replacing the `status` field below, so peers will never be read again
        let initial_peers = std::mem::take(peers).into_iter().collect::<Vec<_>>();

        self.status = Status::ForwardSyncBlock {
            header,
            request: SyncBlock::new(
                RangeRequestId::ForwardSync(self.id),
                block_root,
                &initial_peers,
            ),
        };
        Ok(())
    }

    fn send_block_header_request(
        &mut self,
        block_root: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        let (peers, failed_peers, request) = match &mut self.status {
            Status::BackfillHeader {
                peers,
                failed_peers,
                request,
            } => (peers, failed_peers, request),
            Status::ForwardSyncBlock { .. } => {
                return Err(Error::InternalError(
                    "Lookup not in forward sync block status".to_owned(),
                ))
            }
        };

        let Some(peer) = peers
            .iter()
            .map(|peer| {
                (
                    // If contains -> 1 (order after), not contains -> 0 (order first)
                    failed_peers.contains(peer),
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
            block_root,
            BlocksByRootRequester::Header(self.id),
        )?;

        request.on_download_start(req_id)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InternalError(String),
    TooManyErrors(String),
    BlockConflictsWithFinality(String),
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
            RpcRequestSendError::NoPeers => Self::InternalError(format!("No peers")),
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
            blocks: <_>::default(),
            chain,
        }
    }

    #[cfg(test)]
    pub fn block_peers(&self, block_root: &Hash256) -> Option<Vec<PeerId>> {
        self.blocks.get(block_root).map(|block| block.get_peers())
    }

    #[cfg(test)]
    pub fn get_lookups(&self) -> Vec<Hash256> {
        self.blocks.keys().copied().collect()
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn max_slot_to_sync(&self) -> Option<Slot> {
        // TODO(tree-sync): weak metric, who have a better heuristic for sync? Now that lookups
        // count here
        self.blocks
            .values()
            .filter_map(|block| match &block.status {
                Status::BackfillHeader { request, .. } => {
                    request.is_complete().map(|header| header.slot)
                }
                Status::ForwardSyncBlock { .. } => None,
            })
            .max()
    }

    #[cfg(test)]
    pub fn get_processing_ids(&mut self) -> Vec<HeaderLookupId> {
        let mut ids = vec![];
        for block in self.blocks.values_mut() {
            if block
                .block_request()
                .ok()
                .map(|request| request.is_processing())
                .unwrap_or(false)
            {
                ids.push(block.id);
            }
        }
        ids
    }

    pub fn pause(&mut self) {
        todo!();
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        for block in self.blocks.values_mut() {
            block.remove_peer(&peer);
        }
    }

    pub fn search(
        &mut self,
        block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) {
        if self.blocks.contains_key(&block_root) {
            let mut counts = HashMap::<&PeerId, usize>::new();
            // Add peer to `block`'s entry and all its ancestors
            let mut target_block_root = block_root;
            while let Some(lookup) = self.blocks.get_mut(&target_block_root) {
                for peer in peers {
                    // TODO(tree-sync): If peer already in set no need to add to its ancestors
                    if lookup.add_peer(*peer) {
                        // TODO(tree-sync): This log can be very noisy maybe log once per peer
                        *counts.entry(peer).or_default() += 1;
                    } else {
                        // Peer already part of this lookup, therefore it must be part of the peer
                        // set of all of its ancestors: stop
                        break;
                    }
                }
                if let Some(parent_root) = lookup.parent_root() {
                    target_block_root = parent_root;
                } else {
                    break;
                }
            }
            for (peer, count) in counts {
                debug!(block_root = ?target_block_root, %peer, count, "Adding peer to existing header lookup and ancestors");
            }
        } else {
            if self.blocks.len() > MAX_LOOKUP_COUNT {
                self.prune_least_popular_lookups();
            }

            let id = cx.next_id();
            match peers {
                [peer] => debug!(?block_root, id, %peer, "Creating new header lookup"),
                _ => debug!(
                    ?block_root,
                    id,
                    peers = peers.len(),
                    "Creating new header lookup"
                ),
            }

            let mut lookup = ForwardSyncBlock::new(block_root, id, peers);
            match lookup.send_block_header_request(block_root, cx) {
                Ok(_) => {
                    self.blocks.insert(block_root, lookup);
                    metrics::inc_counter(&metrics::SYNC_LOOKUPS_CREATED);
                }
                Err(e) => {
                    warn!(id = ?lookup.id, error = ?e, "Error sending initial lookup request");
                }
            }
        }
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
            let Some(lookup) = self.blocks.get_mut(&block_root) else {
                // TODO(tree-sync): register metric
                debug!(id = ?req_id, "Received header request for unknown lookup");
                return Ok(SyncBlockResult::Wait);
            };
            lookup.assert_expected_lookup_id(id)?;

            let response = response.and_then(|(blocks, timestamp)| {
                let block = blocks
                    .first()
                    .cloned()
                    .ok_or(RpcResponseError::InternalError(
                        "blocks_by_root response contains zero blocks".to_owned(),
                    ))?;
                Ok((block, timestamp))
            });

            match response {
                Ok((block, received)) => {
                    debug!(%req_id, "Forward sync block header downloaded success");

                    let block_header = block.message().block_header();
                    let parent_root = block_header.parent_root;

                    lookup.header_request()?.on_download_success(
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
                    let parent_imported = self.chain.block_is_known_to_fork_choice(&parent_root);
                    let finalized_checkpoint = self.chain.head().finalized_checkpoint();
                    let parent_known = self.blocks.contains_key(&parent_root);

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
                    if parent_imported || parent_known {
                        // Stop search we reached a known block
                        self.trigger_forward_sync(cx);
                    } else {
                        let lookup = self.blocks.get_mut(&block_root).expect("lookup exists");
                        let peers = lookup.get_peers();
                        self.search(parent_root, &peers, cx);
                    }
                }
                Err(e) => {
                    // Request errors are logged in `SyncNetworkContext::on_rpc_response_result`
                    lookup
                        .header_request()?
                        .on_download_error(req_id, Some(e))?;
                    lookup.send_block_header_request(block_root, cx)?;
                }
            }
            Ok(SyncBlockResult::Wait)
        })();

        // Map result Ok to Wait as completing the header request does not complete the overall
        // ForwardSyncBlock request.
        self.handle_result(id.block_root, result.map(|_| SyncBlockResult::Wait), cx);
    }

    pub fn on_block_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        id: HeaderLookupId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(lookup) = self.blocks.get_mut(&id.block_root) else {
            // TODO(tree-sync): register metric
            debug!(?id, "Received block request for unknown lookup");
            return;
        };
        if let Err(e) = lookup.assert_expected_lookup_id(id) {
            debug!(?id, "Unexpected lookup ID");
            return;
        }

        let outcome = lookup
            .block_request()
            .and_then(|block| Ok(block.on_download_result(req_id, result, cx)?));
        self.handle_result(id.block_root, outcome, cx);
    }

    pub fn on_block_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(lookup) = self.blocks.get_mut(&id.block_root) else {
            debug!(?id, "Received block process result for unknown lookup");
            return;
        };
        if let Err(e) = lookup.assert_expected_lookup_id(id) {
            debug!(?id, "Unexpected lookup ID");
            return;
        }

        let outcome = lookup
            .block_request()
            .and_then(|block| Ok(block.on_process_result(result, cx)?));
        self.handle_result(id.block_root, outcome, cx);
    }

    pub fn prune(&mut self) {
        // Prune blocks once imported, and once finality advances
    }

    pub fn prune_imported_block(&mut self, block_root: Hash256, _imported: bool) {
        let mut block_to_delete = block_root;
        while let Some(block) = self.blocks.remove(&block_root) {
            debug!(?block_root, "Deleted imported block lookup");
            if let Some(parent_root) = block.parent_root() {
                block_to_delete = parent_root;
            } else {
                break;
            }
        }
    }

    fn handle_result(
        &mut self,
        block_root: Hash256,
        result: Result<SyncBlockResult, Error>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match result {
            Ok(SyncBlockResult::Done { .. }) => {
                metrics::inc_counter(&metrics::SYNC_BLOCKS_PROCESSED);
                self.blocks.remove(&block_root);
                self.trigger_forward_sync(cx);
            }
            // Wait for next event
            Ok(SyncBlockResult::Wait) => {}
            Err(e) => {
                debug!(error = ?e, ?block_root, "Dropping forward sync block lookup");
                match e {
                    Error::InternalError(_) | Error::TooManyErrors(_) => {
                        let block_to_children = self.compute_children();
                        self.drop_lookup_and_children(block_root, &block_to_children);
                    }
                    Error::BlockConflictsWithFinality(_e) => {
                        let block_to_children = self.compute_children();
                        self.drop_lookup_and_children(block_root, &block_to_children);
                        // TODO(tree-sync): penalize peers of this lookups
                        // TODO(tree-sync): add blocks to a failed cache to prevent re-sync
                    }
                }
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

        let blocks_syncing = self
            .blocks
            .values()
            .filter(|block| block.is_syncing())
            .count();
        let mut new_syncing_blocks = false;

        // Have up to 2 blocks syncing
        for _ in blocks_syncing..BLOCK_BUFFER_SIZE {
            // Find the block range with most peers and highest slot. This is the block
            // to be used as tip of the chain of blocks to fetch.
            let Some(block_root) = self
                .blocks
                .iter()
                .filter_map(|(root, block)| {
                    let header = match &block.status {
                        // Ignore blocks that are still downloading
                        Status::BackfillHeader { request, .. } => match request.is_complete() {
                            Some(header) => header,
                            None => return None,
                        },
                        // Ignore blocks already syncing
                        Status::ForwardSyncBlock { .. } => return None,
                    };
                    // Check if the parent is known in the header tree
                    let is_candidate = if let Some(parent) = self.blocks.get(&header.parent_root) {
                        parent.is_syncing()
                    } else {
                        // TODO(tree-sync): cache this calls in the struct
                        cx.chain.block_is_known_to_fork_choice(&header.parent_root)
                    };

                    if is_candidate {
                        Some((block.peer_count(), Slot::new(u64::MAX) - header.slot, root))
                    } else {
                        None
                    }
                })
                .max()
                .map(|(_, _, root)| *root)
            else {
                break;
            };

            // Start syncing `block_root`
            match self
                .blocks
                .get_mut(&block_root)
                .ok_or(Error::InternalError(format!(
                    "self.blocks must contain an entry with {block_root}"
                )))
                .and_then(|block| {
                    block.to_foward_sync_block(block_root)?;
                    Ok(block.id)
                }) {
                Ok(id) => debug!(?id, "Starting forward sync of block"),
                // Should never error
                Err(e) => error!("Unable to transition header to forward sync block: {e:?}"),
            }

            new_syncing_blocks = true;
        }

        if new_syncing_blocks {
            self.continue_syncing_blocks(cx);
        }
    }

    fn continue_syncing_blocks(&mut self, cx: &mut SyncNetworkContext<T>) {
        let mut lookups_to_drop = vec![];

        for (block_root, lookup) in self.blocks.iter_mut() {
            let result = match &mut lookup.status {
                Status::BackfillHeader { .. } => continue,
                Status::ForwardSyncBlock { request, .. } => request.continue_request(cx),
            };

            if let Err(_e) = result {
                // TODO(tree-sync): should log error?
                lookups_to_drop.push(*block_root);
            }
        }

        let block_to_children = self.compute_children();
        for block_root in lookups_to_drop {
            self.drop_lookup_and_children(block_root, &block_to_children);
        }
    }

    /// Drop lookup `block_root` if it exists and all its children
    fn drop_lookup_and_children(
        &mut self,
        initial_block_root: Hash256,
        block_to_children: &HashMap<Hash256, Vec<Hash256>>,
    ) {
        let mut queue: VecDeque<Hash256> = VecDeque::from([initial_block_root]);

        while let Some(block_root) = queue.pop_front() {
            // Remove the node itself.
            if let Some(block) = self.blocks.remove(&block_root) {
                debug!(?block_root, id = %block.id, "Dropping forward sync block lookup");
                metrics::inc_counter(&metrics::SYNC_LOOKUPS_DROPPED);
                // Only remove children if the node still existed
                // Push its children—if any—onto the work list.
                if let Some(children) = block_to_children.get(&block_root) {
                    queue.extend(children.iter().cloned());
                }
            }
        }
    }

    /// Drop lookup `block_root` if it exists and all its children
    fn compute_children(&mut self) -> HashMap<Hash256, Vec<Hash256>> {
        let mut block_to_children = HashMap::<Hash256, Vec<Hash256>>::new();
        for (block_root, block) in self.blocks.iter() {
            if let Some(parent_root) = block.parent_root() {
                block_to_children
                    .entry(parent_root)
                    .or_default()
                    .push(*block_root);
            }
        }
        block_to_children
    }

    /// Drop lookups with least amount of peers and slot until we pruned PRUNE_COUNT lookups
    fn prune_least_popular_lookups(&mut self) {
        let mut blocks = self
            .blocks
            .iter()
            .filter_map(|(block_root, block)| match &block.status {
                // Prune only lookups that are not syncing and we know the header
                Status::BackfillHeader { peers, request, .. } => request
                    .is_complete()
                    .map(|header| (block.peer_count(), header.slot, *block_root)),
                Status::ForwardSyncBlock { .. } => None,
            })
            .collect::<Vec<_>>();
        blocks.sort_unstable();

        let block_to_children = self.compute_children();
        for (_, _, block_root) in blocks {
            self.drop_lookup_and_children(block_root, &block_to_children);
            if self.blocks.len() < MAX_LOOKUP_COUNT - PRUNE_COUNT {
                break;
            }
        }
    }

    pub fn register_metrics(&self) {
        if let Some((min_slot, max_slot)) = self
            .blocks
            .values()
            .filter_map(|lookup| {
                if let Status::BackfillHeader { request, .. } = &lookup.status {
                    request.is_complete().map(|header| header.slot)
                } else {
                    None
                }
            })
            .minmax()
            .into_option()
        {
            metrics::set_gauge(&metrics::SYNC_HEADER_MIN_SLOT, min_slot.as_u64() as i64);
            metrics::set_gauge(&metrics::SYNC_HEADER_MAX_SLOT, max_slot.as_u64() as i64);
        }

        // Min header
        // Highest known header
        // Current head
    }
}
