use super::network_context::{LookupRequestResult, RpcResponseError, SyncNetworkContext};
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::network_context::custody_by_root::ColumnRequest;
use crate::sync::network_context::{
    BlocksByRootSameForkRequest, RpcResponseBatchResult, RpcResponseResult,
};
use crate::sync::range_sync::{BatchInfo, BatchPeers};
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::rpc::BlocksByRootRequest;
use lighthouse_network::service::api_types::{
    BlocksByRootRequestId, BlocksByRootRequester, HeaderLookupId, Id, RangeRequestId,
};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::debug;
use types::{BeaconBlockHeader, Epoch, EthSpec, ForkName, Hash256, SignedBeaconBlock, Slot};

pub struct BlockTree<T: BeaconChainTypes> {
    blocks: HashMap<Hash256, Block<T::EthSpec>>,
    batches: HashMap<Id, BatchInfo<T::EthSpec>>,
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
    Syncing(BeaconBlockHeader, SyncingStatus<E>),
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

    fn start<T: BeaconChainTypes>(&mut self, cx: &mut SyncNetworkContext<T>) {}

    fn on_error(&mut self, _e: RpcResponseError) {
        todo!();
    }

    fn root(&self) -> Hash256 {
        todo!();
    }

    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn is_syncing(&self) -> bool {
        match self.status {
            Status::DownloadingHeader(..) => false,
            Status::Header(..) => false,
            Status::Syncing(..) => true,
        }
    }

    fn header(&self) -> Option<&BeaconBlockHeader> {
        match &self.status {
            Status::DownloadingHeader(..) => None,
            Status::Header(header) => Some(header),
            Status::Syncing(header, _) => Some(header),
        }
    }

    fn parent_root(&self) -> Option<Hash256> {
        self.header().map(|header| header.parent_root)
    }

    fn parent_root_and_slot(&self) -> Option<(Hash256, Slot)> {
        self.header()
            .map(|header| (header.parent_root, header.slot))
    }

    fn header_request(
        &mut self,
    ) -> Result<&mut ColumnRequest<BlocksByRootRequestId, BeaconBlockHeader>, String> {
        match &mut self.status {
            Status::DownloadingHeader(request) => Ok(request),
            _ => Err("Expected lookup to be in DownloadingHeader state".to_owned()),
        }
    }

    fn syncing(&mut self) -> Option<(&mut BeaconBlockHeader, &mut SyncingStatus<E>)> {
        match &mut self.status {
            Status::Syncing(header, request) => Some((header, request)),
            _ => None,
        }
    }

    fn block_request(&mut self) -> Result<&mut SyncingStatus<E>, String> {
        match &mut self.status {
            Status::Syncing(_, request) => Ok(request),
            _ => Err("Expected lookup to be in Syncing state".to_owned()),
        }
    }
}

enum Error {
    A,
}

impl<T: BeaconChainTypes> BlockTree<T> {
    pub fn new(chain: Arc<BeaconChain<T>>) -> Self {
        Self {
            blocks: <_>::default(),
            batches: <_>::default(),
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
        todo!()
    }

    pub fn remove_peer(&mut self, _peer: PeerId) {
        todo!();
    }

    pub fn search(
        &mut self,
        block_root: Hash256,
        peers: &[PeerId],
        cx: &mut SyncNetworkContext<T>,
    ) -> bool {
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

            true
        } else {
            debug!(?block_root, ?peers, "Creating new header lookup");

            let mut lookup = Block::new(block_root, cx.next_id(), peers);

            // TODO(tree-sync): have good peer selection
            let Some(peer) = lookup.peers.iter().next() else {
                todo!("no peer");
            };

            let req_id = cx
                .send_blocks_by_root_request(
                    *peer,
                    BlocksByRootRequest::new(vec![block_root], cx.spec(), ForkName::Fulu),
                    BlocksByRootRequester::Header(lookup.id),
                )
                .unwrap();

            lookup
                .header_request()
                .expect("A new lookup is in DownloadingHeader request state")
                .on_download_start(req_id)
                .expect("A new request is in AwaitingDownload state");

            self.blocks.insert(block_root, lookup);
            true
        }
    }

    fn oldest_known_ancestor(&self, mut block_root: Hash256) -> Hash256 {
        let Some(mut parent_root) = self
            .blocks
            .get(&block_root)
            .and_then(|lookup| lookup.parent_root())
        else {
            return block_root;
        };

        loop {
            if let Some(lookup) = self.blocks.get(&parent_root) {
                if let Some(next_parent_root) = lookup.parent_root() {
                    // Continue iterating the parent chain
                    block_root = parent_root;
                    parent_root = next_parent_root;
                } else {
                    // There's an entry for parent_root but it's not downloaded yet
                    return parent_root;
                }
            } else {
                // There's no entry in the DAG for parent_root, thus block_root is the root node
                return block_root;
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
    ) -> Result<(), String> {
        let block_root = lookup_id.0;
        let Some(lookup) = self.blocks.get_mut(&block_root) else {
            return Err(format!("No header lookup for root {block_root}"));
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
                let block_header = block.message().block_header();
                let parent_root = block_header.parent_root;

                lookup
                    .header_request()?
                    .on_download_success(req_id, peer_id, block_header.clone(), received)
                    .unwrap();
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
                    panic!(
                        "Block {:?} {} conflicts with finalized checkpoint {:?}",
                        block_root, block_header.slot, finalized_checkpoint
                    );
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
                lookup.header_request()?.on_download_error(req_id).unwrap();

                // TODO(tree-sync): have good peer selection
                let Some(peer) = lookup.peers.iter().next() else {
                    todo!("no peer");
                };

                let req_id = cx
                    .send_blocks_by_root_request(
                        *peer,
                        BlocksByRootRequest::new(vec![block_root], cx.spec(), ForkName::Fulu),
                        BlocksByRootRequester::Header(lookup.id),
                    )
                    .unwrap();

                lookup
                    .header_request()
                    .expect("A new lookup is in DownloadingHeader request state")
                    .on_download_start(req_id)
                    .expect("A new request is in AwaitingDownload state");

                todo!("error {e:?}");
            }
        }
        Ok(())
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
            let Some(block_root) = self
                .blocks
                .iter()
                .filter_map(|(root, block)| {
                    // Ignore blocks that are already being forward synced
                    if block.is_syncing() {
                        return None;
                    }
                    // Ignore block roots which header is not downloaded yet
                    let Some((parent_root, slot)) = block.parent_root_and_slot() else {
                        return None;
                    };
                    // Check if the parent is known in the header tree
                    let is_candidate = if let Some(parent) = self.blocks.get(&parent_root) {
                        parent.is_syncing()
                    } else {
                        // TODO(tree-sync): cache this calls in the struct
                        cx.chain.block_is_known_to_fork_choice(&parent_root)
                    };

                    if is_candidate {
                        // Find highest peer count, then min slot
                        Some((block.peer_count(), Slot::new(u64::MAX) - slot, root))
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
            let block_to_sync = self
                .blocks
                .get_mut(&block_root)
                .expect("Block should exist");

            match &mut block_to_sync.status {
                Status::Header(header) => {
                    block_to_sync.status =
                        Status::Syncing(header.clone(), SyncingStatus::AwaitingDownload);
                }
                _ => panic!("Unpected state"),
            }
            debug!(id = %block_to_sync.id, "Starting forwards sync of block");

            new_syncing_blocks = true;
        }

        if new_syncing_blocks {
            self.continue_syncing_blocks(cx);
        }
    }

    fn continue_syncing_blocks(&mut self, cx: &mut SyncNetworkContext<T>) {
        for lookup in self.blocks.values_mut().filter(|block| block.is_syncing()) {
            match &mut lookup.status {
                Status::Syncing(header, syncing_status) => match syncing_status {
                    SyncingStatus::AwaitingDownload => {
                        let request = BlocksByRootSameForkRequest {
                            // TODO(tree-sync): cache block root
                            block_roots: vec![header.canonical_root()],
                            fork: cx.spec().fork_name_at_slot::<T::EthSpec>(header.slot),
                        };

                        // TODO
                        let chain_id = cx.next_id();
                        let requester = RangeRequestId::RangeSync(lookup.id);
                        let peers = Arc::new(RwLock::new(HashSet::from_iter(
                            lookup.peers.iter().copied(),
                        )));
                        let failed_peers = HashSet::new();

                        match cx.block_components_by_range_request(
                            request,
                            requester,
                            peers,
                            &failed_peers,
                        ) {
                            Ok(req_id) => {
                                *syncing_status = SyncingStatus::Downloading(req_id);
                            }
                            Err(e) => {
                                // Log failed chain, mark blocks as not syncing
                            }
                        };
                    }
                    SyncingStatus::Downloading(_) => {} // wait for event
                    SyncingStatus::AwaitingProcessing(block, peers) => {
                        let Some(beacon_processor) = cx.beacon_processor_if_enabled() else {
                            todo!("processor disabled");
                        };
                        if let Err(e) = beacon_processor.send_chain_segment(
                            ChainSegmentProcessId::RangeBatchId(lookup.id),
                            vec![block.clone()],
                        ) {
                            todo!("error sending");
                        }
                        *syncing_status = SyncingStatus::Processing(peers.clone());
                    }
                    SyncingStatus::Processing(_) => {} // wait for event
                },
                _ => panic!("bad state"),
            }
        }
    }

    pub fn on_blocks_response(
        &mut self,
        id: HeaderLookupId,
        result: Result<(Vec<RpcBlock<T::EthSpec>>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        // TODO(tree-sync): attach an ID to the block entry to make sure we are querying the right
        // one, while still indexing by block_root only
        let Some(lookup) = self.blocks.get_mut(&id.0) else {
            panic!("Unknown batch id {id}");
        };

        let result = result.and_then(|(blocks, peers)| {
            let block = blocks
                .first()
                .cloned()
                .ok_or(RpcResponseError::InternalError(
                    "blocks_by_root response contains zero blocks".to_owned(),
                ))?;
            Ok((block, peers))
        });

        let request = lookup.block_request().unwrap();
        match request {
            SyncingStatus::Downloading(_) => match result {
                Ok((block, peers)) => {
                    debug!(%id, "Sync block downloaded");
                    *request = SyncingStatus::AwaitingProcessing(block, peers);
                }
                Err(e) => {
                    debug!(%id, "Sync block download error");
                    *request = SyncingStatus::AwaitingDownload;
                }
            },
            _ => panic!("Bad state"),
        }

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    pub fn handle_block_process_result(
        &mut self,
        id: HeaderLookupId,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let Some(lookup) = self.blocks.get_mut(&id.0) else {
            panic!("Unknown batch id {id}");
        };

        let request = lookup.block_request().unwrap();
        match request {
            SyncingStatus::Processing(peers) => match result {
                BatchProcessResult::Success { .. } => {
                    debug!(%id, "Sync block process success");
                    self.blocks.remove(&id.0);
                    self.trigger_forward_sync(cx);
                }
                BatchProcessResult::FaultyFailure { .. } | BatchProcessResult::NonFaultyFailure => {
                    debug!(%id, "Sync block process error");
                    *request = SyncingStatus::AwaitingDownload;
                    // TODO(tree-sync): add peer to failed peers and downscore
                }
            },
            _ => panic!("Bad state"),
        }
    }
}
