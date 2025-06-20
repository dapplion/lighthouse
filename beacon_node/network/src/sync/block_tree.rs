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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, warn};
use types::{BeaconBlockHeader, EthSpec, Hash256, SignedBeaconBlock, Slot};

pub struct BlockTree<T: BeaconChainTypes> {
    blocks: HashMap<Hash256, Block<T::EthSpec>>,
    chain: Arc<BeaconChain<T>>,
}

struct Block<E: EthSpec> {
    id: HeaderLookupId,
    peers: HashSet<PeerId>,
    status: Status<E>,
}

enum Status<E: EthSpec> {
    DownloadingHeader(ColumnRequest<BlocksByRootRequestId, BeaconBlockHeader>),
    Header(BeaconBlockHeader),
    Syncing {
        block_root: Hash256,
        parent_root: Hash256,
        request: SyncingStatus<E>,
    },
}

enum SyncingStatus<E: EthSpec> {
    AwaitingDownload,
    Downloading(Id),
    AwaitingProcessing(RpcBlock<E>, BatchPeers),
    Processing(BatchPeers),
}

// TODO(tree-sync): Re-add the reprocessing cache, so we don't process twice a block that we got
// through gossip and sync.

impl<E: EthSpec> Block<E> {
    fn new(block_root: Hash256, id: Id, peers: &[PeerId]) -> Self {
        Self {
            id: HeaderLookupId(block_root, id),
            peers: HashSet::from_iter(peers.iter().copied()),
            status: Status::DownloadingHeader(ColumnRequest::new()),
        }
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn is_syncing(&self) -> bool {
        match self.status {
            Status::DownloadingHeader(..) => false,
            Status::Header(..) => false,
            Status::Syncing { .. } => true,
        }
    }

    fn parent_root(&self) -> Option<Hash256> {
        match &self.status {
            Status::DownloadingHeader(..) => None,
            Status::Header(header) => Some(header.parent_root),
            Status::Syncing { parent_root, .. } => Some(*parent_root),
        }
    }

    fn header_request(
        &mut self,
    ) -> Result<&mut ColumnRequest<BlocksByRootRequestId, BeaconBlockHeader>, Error> {
        match &mut self.status {
            Status::DownloadingHeader(request) => Ok(request),
            _ => Err(Error::InternalError(
                "Expected lookup to be in DownloadingHeader state".to_owned(),
            )),
        }
    }

    fn block_request(&mut self) -> Result<&mut SyncingStatus<E>, Error> {
        match &mut self.status {
            Status::Syncing { request, .. } => Ok(request),
            _ => Err(Error::InternalError(
                "Expected lookup to be in Syncing state".to_owned(),
            )),
        }
    }
}

#[derive(Debug)]
enum Error {
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

impl<T: BeaconChainTypes> BlockTree<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            blocks: <_>::default(),
            chain,
        }
    }

    #[cfg(test)]
    pub fn get_processing_ids(&self) -> Vec<HeaderLookupId> {
        self.blocks
            .values()
            .filter(|block| {
                matches!(
                    block.status,
                    Status::Syncing(_, SyncingStatus::Processing(_)),
                )
            })
            .map(|block| block.id)
            .collect()
    }

    pub fn pause(&mut self) {
        todo!();
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        for block in self.blocks.values_mut() {
            block.peers.remove(&peer);
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
                    lookup.peers.insert(*peer);
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
            debug!(?block_root, ?peers, "Creating new header lookup");

            let mut lookup = Block::new(block_root, cx.next_id(), peers);
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

    pub fn on_block_header(
        &mut self,
        req_id: BlocksByRootRequestId,
        lookup_id: HeaderLookupId,
        response: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        peer_id: PeerId,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let block_root = lookup_id.0;

        let result = (|| {
            let Some(mut lookup) = self.blocks.get_mut(&block_root) else {
                // TODO(tree-sync): register metric
                debug!(id = ?req_id, "Received header request for unknown lookup");
                return Ok(());
            };

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

        if let Err(e) = result {
            debug!(error = ?e, "Dropping forward sync block header lookup");
            self.drop_lookup_and_children(block_root);
        }
    }

    pub fn prune(&mut self) {
        // Prune blocks once imported, and once finality advances
    }

    pub fn prune_root(&mut self, _block_root: Hash256, _imported: bool) {
        todo!();
    }

    fn mark_descendants_as_rooted(&mut self, _block_root: Hash256) {
        // TODO: iterate all blocks and mark descendants of `block_root` as rooted
    }

    fn mark_as_syncing(&mut self, _blocks: &[Hash256]) {
        // TODO: mark all this block entries as syncing
    }

    fn collect_ancestors(&self, mut block_root: Hash256) -> Vec<Hash256> {
        let mut ancestors = vec![];
        while let Some(block) = self.blocks.get(&block_root) {
            ancestors.push(block_root);
            if let Some(parent_root) = block.parent_root() {
                block_root = parent_root;
            } else {
                break;
            }
        }
        ancestors
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
            let Some((block_root, parent_root)) = self
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
                        // Find highest peer count, then min slot
                        Some((
                            block.peer_count(),
                            Slot::new(u64::MAX) - header.slot,
                            root,
                            &header.parent_root,
                        ))
                    } else {
                        None
                    }
                })
                .max()
                .map(|(_, _, root, parent_root)| (*root, *parent_root))
            else {
                break;
            };

            // Start syncing `block_root`
            let block_to_sync = self
                .blocks
                .get_mut(&block_root)
                .expect("block_root is a key of self.blocks");

            // The code above ensures that `block_to_sync` is in `Status::Header` status
            block_to_sync.status = Status::Syncing {
                block_root,
                parent_root,
                request: SyncingStatus::AwaitingDownload,
            };

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
                Status::Syncing { request, .. } => match request {
                    SyncingStatus::AwaitingDownload => {
                        let requester = RangeRequestId::RangeSync(lookup.id);
                        // TODO(tree-sync) use RwLock or manually add to active request
                        let peers = Arc::new(RwLock::new(HashSet::from_iter(
                            lookup.peers.iter().copied(),
                        )));
                        let failed_peers = HashSet::new();

                        match cx.block_components_by_range_request(
                            *block_root,
                            requester,
                            peers,
                            &failed_peers,
                        ) {
                            Ok(req_id) => {
                                *request = SyncingStatus::Downloading(req_id);
                                Ok(())
                            }
                            Err(e) => match e {
                                RpcRequestSendError::NoPeers
                                | RpcRequestSendError::InternalError(_) => {
                                    Err(format!("Error sending block components request: {e:?}"))
                                }
                            },
                        }
                    }
                    SyncingStatus::Downloading(_) => Ok(()), // wait for event
                    SyncingStatus::AwaitingProcessing(block, peers) => {
                        if let Some(beacon_processor) = cx.beacon_processor_if_enabled() {
                            if let Err(e) = beacon_processor.send_chain_segment(
                                ChainSegmentProcessId::RangeBatchId(lookup.id),
                                vec![block.clone()],
                            ) {
                                Err(format!("Error sending block to processor: {e:?}"))
                            } else {
                                *request = SyncingStatus::Processing(peers.clone());
                                Ok(())
                            }
                        } else {
                            // TODO(tree-sync): This error will cause the full chain of headers to
                            // be dropped if the beacon processor goes offline. When can that
                            // happen?
                            Err("Beacon processor is disabled".to_owned())
                        }
                    }
                    SyncingStatus::Processing(_) => Ok(()), // wait for event
                },
            };

            if let Err(_e) = result {
                // TODO(tree-sync): should log error?
                lookups_to_drop.push(*block_root);
            }
        }

        for block_root in lookups_to_drop {
            self.drop_lookup_and_children(block_root);
        }
    }

    pub fn on_block_response(
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

            let request = lookup.block_request()?;
            match request {
                SyncingStatus::Downloading(_) => match result {
                    Ok((block, peers)) => {
                        debug!(%id, "Sync block downloaded");
                        *request = SyncingStatus::AwaitingProcessing(block, peers);
                        Ok(())
                    }
                    Err(e) => {
                        // TODO(tree-sync): increase error counter
                        debug!(%id, error = ?e, "Sync block download error");
                        *request = SyncingStatus::AwaitingDownload;
                        Ok(())
                    }
                },
                _ => Err(Error::InternalError(
                    "Lookup not in expected state Downloading".to_owned(),
                )),
            }
        })();

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    pub fn handle_block_process_result(
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

            let request = lookup.block_request()?;
            match request {
                SyncingStatus::Processing(peers) => match result {
                    BatchProcessResult::Success => {
                        debug!(%id, "Sync block process success");
                        self.blocks.remove(&id.0);
                        self.trigger_forward_sync(cx);
                        Ok(())
                    }
                    BatchProcessResult::Failure { peer_action, error } => {
                        debug!(%id, "Sync block process error");

                        if let Some(peer_action) = peer_action {
                            for (peer, penalty) in peers.blame(peer_action) {
                                cx.report_peer(peer, penalty, "faulty_batch");
                            }
                        }

                        *request = SyncingStatus::AwaitingDownload;

                        Ok(())
                    }
                },
                _ => Err(Error::InternalError(
                    "Lookup not in expected state Processing".to_owned(),
                )),
            }
        })();

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    fn drop_lookup_and_children(&mut self, _block_root: Hash256) {
        todo!();
    }

    fn send_block_header_request(
        lookup: &mut Block<T::EthSpec>,
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
