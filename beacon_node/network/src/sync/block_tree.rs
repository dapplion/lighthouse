use super::network_context::{RpcRequestSendError, RpcResponseError, SyncNetworkContext};
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::network_context::custody_by_root::{ColumnRequest, Error as ColumnRequestError};
use crate::sync::network_context::{BatchPeers, RpcResponseResult};
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, HeaderLookupId, Id, RangeRequestId,
};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use tracing::{debug, warn};
use types::{BeaconBlockHeader, EthSpec, Hash256, SignedBeaconBlock, Slot};

const MAX_LOOKUP_COUNT: usize = 1_000_000;
const PRUNE_COUNT: usize = 100_000;

pub struct BlockTree<T: BeaconChainTypes> {
    blocks: HashMap<Hash256, ForwardSyncBlock<T>>,
    chain: Arc<BeaconChain<T>>,
}

struct ForwardSyncBlock<T: BeaconChainTypes> {
    id: HeaderLookupId,
    status: Status<T>,
}

enum Status<T: BeaconChainTypes> {
    BackfillHeader {
        peers: HashSet<PeerId>,
        request: ColumnRequest<BlocksByRootRequestId, BeaconBlockHeader>,
    },
    ForwardSyncBlock {
        header: BeaconBlockHeader,
        request: SyncBlock<T>,
    },
}

// TODO(tree-sync): have the peer set inside here when syncing add dedup logic
// TODO(tree-sync): for backfill sync use the sync state to check the peers have this block or not
pub struct SyncBlock<T: BeaconChainTypes> {
    id: RangeRequestId,
    block_root: Hash256,
    failed_peers: HashSet<PeerId>,
    peers: Arc<RwLock<HashSet<PeerId>>>,
    request: SyncingStatus<T::EthSpec>,
}

pub enum SyncBlockResult {
    Done { parent_root: Hash256, slot: Slot },
    Wait,
}

impl<T: BeaconChainTypes> SyncBlock<T> {
    pub fn new(id: RangeRequestId, block_root: Hash256, initial_peers: &[PeerId]) -> Self {
        Self {
            id,
            block_root,
            failed_peers: <_>::default(),
            peers: Arc::new(RwLock::new(HashSet::from_iter(initial_peers))),
            request: SyncingStatus::AwaitingDownload,
        }
    }

    pub fn on_download_result(
        &mut self,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<SyncBlockResult, Error> {
        match &mut self.request {
            SyncingStatus::Downloading(_) => match result {
                // TODO(tree-sync): check that the request ID matches
                Ok((block, peers)) => {
                    debug!(id = %self.id, "Sync block downloaded");
                    self.request = SyncingStatus::AwaitingProcessing(block, peers);
                    self.continue_request(cx)
                }
                Err(e) => {
                    // TODO(tree-sync): increase error counter
                    debug!(id = %self.id, error = ?e, "Sync block download error");
                    self.request = SyncingStatus::AwaitingDownload;
                    self.continue_request(cx)
                }
            },
            _ => Err(Error::InternalError(
                "Lookup not in expected state Downloading".to_owned(),
            )),
        }
    }

    pub fn on_process_result(
        &mut self,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<SyncBlockResult, Error> {
        match &mut self.request {
            SyncingStatus::Processing(peers) => match result {
                BatchProcessResult::Success => {
                    debug!(id = %self.id, "Sync block process success");
                    Ok(SyncBlockResult::Done)
                }
                BatchProcessResult::Failure { peer_action, error } => {
                    debug!(id = %self.id, "Sync block process error");

                    if let Some(peer_action) = peer_action {
                        for (peer, penalty) in peers.blame(peer_action) {
                            cx.report_peer(peer, penalty, "faulty_batch");
                        }
                    }

                    self.request = SyncingStatus::AwaitingDownload;
                    self.continue_request(cx)
                }
            },
            _ => Err(Error::InternalError(
                "Lookup not in expected state Processing".to_owned(),
            )),
        }
    }

    pub fn continue_request(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<SyncBlockResult, Error> {
        match &mut self.request {
            SyncingStatus::AwaitingDownload => {
                match cx.block_components_by_range_request(
                    self.block_root,
                    self.id,
                    &self.peers,
                    &self.failed_peers,
                ) {
                    Ok(req_id) => {
                        self.request = SyncingStatus::Downloading(req_id);
                        Ok(SyncBlockResult::Wait)
                    }
                    Err(e) => match e {
                        RpcRequestSendError::NoPeers | RpcRequestSendError::InternalError(_) => {
                            Err(Error::InternalError(format!(
                                "Error sending block components request: {e:?}"
                            )))
                        }
                    },
                }
            }
            SyncingStatus::Downloading(_) => Ok(SyncBlockResult::Wait),
            SyncingStatus::AwaitingProcessing(block, peers) => {
                // No need to check if block is already imported here, we'll get an error
                // from the beacon processor anyway. No need to add more code to handle this
                // edge case faster.

                let expect_parent_to_be_imported = false;
                if expect_parent_to_be_imported
                    && !cx
                        .chain
                        .block_is_known_to_fork_choice(&block.as_block().parent_root())
                {
                    return Ok(SyncBlockResult::Wait);
                }

                if let Some(beacon_processor) = cx.beacon_processor_if_enabled() {
                    let id = match self.id {
                        RangeRequestId::ForwardSync(id) => ChainSegmentProcessId::ForwardSync(id),
                        RangeRequestId::BackfillSync(id) => ChainSegmentProcessId::BackfillSync(id),
                    };

                    if let Err(e) = beacon_processor.send_chain_segment(id, vec![block.clone()]) {
                        Err(Error::InternalError(format!(
                            "Error sending block to processor: {e:?}"
                        )))
                    } else {
                        self.request = SyncingStatus::Processing(peers.clone());
                        Ok(SyncBlockResult::Wait)
                    }
                } else {
                    // TODO(tree-sync): This error will cause the full chain of headers to
                    // be dropped if the beacon processor goes offline. When can that
                    // happen?
                    Err(Error::InternalError(
                        "Beacon processor is disabled".to_owned(),
                    ))
                }
            }
            SyncingStatus::Processing(_) => Ok(SyncBlockResult::Wait),
        }
    }

    pub fn is_processing(&self) -> bool {
        matches!(self.request, SyncingStatus::Processing(_))
    }
}

enum SyncingStatus<E: EthSpec> {
    AwaitingDownload,
    Downloading(Id),
    AwaitingProcessing(RpcBlock<E>, BatchPeers),
    Processing(BatchPeers),
}

// TODO(tree-sync): Re-add the reprocessing cache, so we don't process twice a block that we got
// through gossip and sync.

impl<T: BeaconChainTypes> ForwardSyncBlock<T> {
    fn new(block_root: Hash256, id: Id, peers: &[PeerId]) -> Self {
        Self {
            id: HeaderLookupId(block_root, id),
            status: Status::BackfillHeader {
                peers: HashSet::from_iter(peers.iter().copied()),
                request: ColumnRequest::new(),
            },
        }
    }

    fn add_peer(&mut self, peer: PeerId) {
        match &mut self.status {
            Status::BackfillHeader { peers, .. } => {
                peers.insert(peer);
            }
            Status::ForwardSyncBlock { request, .. } => {
                request.peers.write().insert(peer);
            }
        }
    }

    fn remove_peer(&mut self, peer: &PeerId) {
        match &mut self.status {
            Status::BackfillHeader { peers, .. } => {
                peers.remove(peer);
            }
            Status::ForwardSyncBlock { request, .. } => {
                request.peers.write().remove(peer);
            }
        }
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
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
    ) -> Result<&mut ColumnRequest<BlocksByRootRequestId, BeaconBlockHeader>, Error> {
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

    fn send_block_header_request(
        lookup: &mut ForwardSyncBlock<T>,
        block_root: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        // TODO(tree-sync): have good peer selection
        let Some(peer) = lookup.peers.iter().next() else {
            return Err(Error::InternalError("No peers".to_owned()));
        };

        let req_id = cx.send_blocks_by_root_request(
            *peer,
            block_root,
            BlocksByRootRequester::Header(lookup.id),
        )?;

        lookup.header_request()?.on_download_start(req_id)?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InternalError(String),
    BlockConflictsWithFinality(String),
}

impl From<ColumnRequestError> for Error {
    fn from(_e: ColumnRequestError) -> Self {
        todo!();
    }
}

impl From<RpcRequestSendError> for Error {
    fn from(_e: RpcRequestSendError) -> Self {
        todo!();
    }
}

pub(crate) enum SyncState {
    Synced,
    Syncing { max_slot: Slot },
}

impl<T: BeaconChainTypes> BlockTree<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            blocks: <_>::default(),
            chain,
        }
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
    pub fn get_processing_ids(&self) -> Vec<HeaderLookupId> {
        self.blocks
            .values()
            .filter(|block| {
                block
                    .header_request()
                    .ok()
                    .map(|request| request.is_processing())
                    .unwrap_or(false)
            })
            .map(|block| block.id)
            .collect()
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
            // Add peer to `block`'s entry and all its ancestors
            let mut target_block_root = block_root;
            while let Some(lookup) = self.blocks.get_mut(&target_block_root) {
                for peer in peers {
                    // TODO(tree-sync): If peer already in set no need to add to its ancestors
                    lookup.add_peer(*peer);
                    // TODO(tree-sync): This log can be very noisy maybe log once per peer
                    debug!(block_root = ?target_block_root, ?peer, "Adding peer to existing header lookup");
                }
                if let Some(parent_root) = lookup.parent_root() {
                    target_block_root = parent_root;
                } else {
                    break;
                }
            }
        } else {
            if self.blocks.len() > MAX_LOOKUP_COUNT {
                self.prune_least_popular_lookups();
            }

            debug!(?block_root, ?peers, "Creating new header lookup");

            let mut lookup = ForwardSyncBlock::new(block_root, cx.next_id(), peers);
            match Self::send_block_header_request(&mut lookup, block_root, cx) {
                Ok(_) => {
                    self.blocks.insert(block_root, lookup);
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
        let block_root = id.0;

        let result = (|| {
            let Some(lookup) = self.blocks.get_mut(&block_root) else {
                // TODO(tree-sync): register metric
                debug!(id = ?req_id, "Received header request for unknown lookup");
                return Ok(());
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
                    lookup.status = Status::Header(block_header.clone());

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
                        let peers = lookup.peers.iter().copied().collect::<Vec<_>>();
                        self.search(parent_root, &peers, cx);
                    }
                }
                Err(e) => {
                    debug!(%req_id, error = ?e, "Forward sync block header downloaded error");
                    lookup.header_request()?.on_download_error(req_id)?;
                    Self::send_block_header_request(lookup, block_root, cx)?;
                }
            }
            Ok(())
        })();
        self.handle_result(id.0, result);
    }

    pub fn on_block_download_result(
        &mut self,
        id: HeaderLookupId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let result = (|| {
            // TODO(tree-sync): attach an ID to the block entry to make sure we are querying the right
            // one, while still indexing by block_root only
            let Some(lookup) = self.blocks.get_mut(&id.0) else {
                // TODO(tree-sync): register metric
                debug!(?id, "Received block request for unknown lookup");
                return Ok(());
            };
            lookup.assert_expected_lookup_id(id)?;

            let request = lookup.block_request()?;
            request.on_download_result(result, cx)?;
            Ok(())
        })();
        self.handle_result(id.0, result);

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    pub fn on_block_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let result = (|| {
            let Some(lookup) = self.blocks.get_mut(&id.0) else {
                debug!(?id, "Received block process result for unknown lookup");
                return Ok(());
            };
            lookup.assert_expected_lookup_id(id)?;

            let request = lookup.block_request()?;
            match request.on_process_result(result, cx) {
                Ok(SyncBlockResult::Done { .. }) => {
                    self.blocks.remove(&id.0);
                    self.trigger_forward_sync(cx);
                }
                Ok(SyncBlockResult::Continue) => {
                    // continue same block
                }
                _ => {}
            }
            todo!();
        })();
        self.handle_result(id.0, result);

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    pub fn prune(&mut self) {
        // Prune blocks once imported, and once finality advances
    }

    pub fn prune_root(&mut self, _block_root: Hash256, _imported: bool) {
        todo!();
    }

    fn handle_result(&mut self, block_root: Hash256, result: Result<(), Error>) {
        match result {
            Ok(_) => {}
            Err(e) => {
                debug!(error = ?e, "Dropping forward sync block header lookup");
                match e {
                    Error::InternalError(_e) => {
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
        for _ in blocks_syncing..2 {
            // Find the block range with most peers and highest slot. This is the block
            // to be used as tip of the chain of blocks to fetch.
            let Some((block_root, header)) = self
                .blocks
                .iter()
                .filter_map(|(root, block)| {
                    let header = match &block.status {
                        // Ignore blocks that are still downloading
                        Status::DownloadingHeader(_) => return None,
                        Status::Header(header) => header,
                        // Ignore blocks already syncing
                        Status::Syncing { .. } => return None,
                    };
                    // Check if the parent is known in the header tree
                    let is_candidate = if let Some(parent) = self.blocks.get(&header.parent_root) {
                        parent.is_syncing()
                    } else {
                        // TODO(tree-sync): cache this calls in the struct
                        cx.chain.block_is_known_to_fork_choice(&header.parent_root)
                    };

                    if is_candidate {
                        Some((block.peer_count(), root, header))
                    } else {
                        None
                    }
                })
                .max_by_key(|(peer_count, _, header)| {
                    // Find highest peer count, then min slot
                    (*peer_count, Slot::new(u64::MAX) - header.slot)
                })
                .map(|(_, root, header)| (*root, header.clone()))
            else {
                break;
            };

            // Start syncing `block_root`
            let block_to_sync = self
                .blocks
                .get_mut(&block_root)
                .expect("block_root is a key of self.blocks");

            // The code above ensures that `block_to_sync` is in `Status::Header` status
            block_to_sync.status = Status::Syncing(
                header,
                SyncBlock::new(RangeRequestId::ForwardSync(block_to_sync.id), block_root),
            );

            debug!(id = %block_to_sync.id, "Starting forwards sync of block");

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
                Status::DownloadingHeader(..) => continue,
                Status::Header(_) => continue,
                Status::Syncing(_, syncing_block) => {
                    syncing_block.continue_request(&lookup.peers, cx)
                }
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
        block_root: Hash256,
        block_to_children: &HashMap<Hash256, Vec<Hash256>>,
    ) {
        // Change to `Vec::new()` if you want depth-first order.
        let mut queue: VecDeque<Hash256> = VecDeque::from([block_root]);

        while let Some(node) = queue.pop_front() {
            // Remove the node itself.
            if self.blocks.remove(&node).is_some() {
                // Only remove children if the node still existed
                // Push its children—if any—onto the work list.
                if let Some(children) = block_to_children.get(&node) {
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
                Status::DownloadingHeader(..) => None,
                Status::Header(header) => Some((block.peer_count(), header.slot, *block_root)),
                Status::Syncing { .. } => None,
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

    fn send_block_header_request(
        lookup: &mut ForwardSyncBlock<T>,
        block_root: Hash256,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        // TODO(tree-sync): have good peer selection
        let Some(peer) = lookup.peers.iter().next() else {
            return Err(Error::InternalError("No peers".to_owned()));
        };

        let req_id = cx.send_blocks_by_root_request(
            *peer,
            block_root,
            BlocksByRootRequester::Header(lookup.id),
        )?;

        lookup.header_request()?.on_download_start(req_id)?;
        Ok(())
    }
}
