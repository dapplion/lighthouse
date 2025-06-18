use super::*;
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::status::ToStatusMessage;
use crate::sync::manager::SLOT_IMPORT_TOLERANCE;
use crate::sync::network_context::{BlockComponentsByRangeRequestStep, RangeRequestId};
use crate::sync::range_sync::{BatchId, BatchState, RangeSyncType};
use crate::sync::tests::lookups::TestOptions;
use crate::sync::{ChainId, SyncMessage};
use beacon_chain::data_column_verification::CustodyDataColumn;
use beacon_chain::test_utils::{AttestationStrategy, BlockStrategy};
use beacon_chain::{block_verification_types::RpcBlock, EngineState, NotifyExecutionLayer};
use beacon_processor::WorkType;
use lighthouse_network::rpc::methods::{
    BlobsByRangeRequest, BlocksByRootRequest, DataColumnsByRangeRequest, DataColumnsByRootRequest,
    OldBlocksByRangeRequest,
};
use lighthouse_network::rpc::{RequestType, StatusMessage};
use lighthouse_network::service::api_types::{
    AppRequestId, BlobsByRangeRequestId, BlocksByRangeRequestId, BlocksByRootRequestId,
    BlocksByRootRequester, ComponentsByRangeRequestId, DataColumnsByRangeRequestId,
    DataColumnsByRootRequestId, HeaderLookupId, SyncRequestId,
};
use lighthouse_network::types::SyncState;
use lighthouse_network::{PeerId, SyncInfo};
use std::collections::HashSet;
use std::time::Duration;
use types::{
    BeaconBlock, BlobSidecarList, BlockImportSource, ColumnIndex, DataColumnSidecar, Epoch,
    EthSpec, Hash256, KzgCommitment, MinimalEthSpec as E, Signature, SignedBeaconBlock,
    SignedBeaconBlockHash, Slot, VariableList,
};

const D: Duration = Duration::new(0, 0);

pub(crate) enum DataSidecars<E: EthSpec> {
    Blobs(BlobSidecarList<E>),
    DataColumns(Vec<CustodyDataColumn<E>>),
}

enum ByRangeDataRequestIds {
    PreDeneb,
    PrePeerDAS(BlobsByRangeRequestId, PeerId, BlobsByRangeRequest),
    PostPeerDAS(
        Vec<(
            DataColumnsByRangeRequestId,
            PeerId,
            DataColumnsByRangeRequest,
        )>,
    ),
}

impl ByRangeDataRequestIds {
    /// If there's a single active request, returns its peer, else panics
    fn peer(&self) -> PeerId {
        match self {
            Self::PreDeneb => panic!("no requests PreDeneb"),
            Self::PrePeerDAS(_, peer, _) => *peer,
            Self::PostPeerDAS(reqs) => {
                if reqs.len() != 1 {
                    panic!("Should have 1 PostPeerDAS request");
                }
                reqs.first().expect("no PostPeerDAS requests").1
            }
        }
    }
}

struct Config {
    peers: PeersConfig,
}

type BlocksByRangeRequestData = (BlocksByRangeRequestId, PeerId, OldBlocksByRangeRequest);

type BlocksByRootRequestData = (BlocksByRootRequestId, PeerId, BlocksByRootRequest);

type DataColumnsByRangeRequestData = (
    DataColumnsByRangeRequestId,
    PeerId,
    DataColumnsByRangeRequest,
);

type DataColumnsByRootRequestData = (DataColumnsByRootRequestId, PeerId, DataColumnsByRootRequest);

/// Sync tests are usually written in the form:
/// - Do some action
/// - Expect a request to be sent
/// - Complete the above request
///
/// To make writting tests succint, the machinery in this testing rig automatically identifies
/// _which_ request to complete. Picking the right request is critical for tests to pass, so this
/// filter allows better expressivity on the criteria to identify the right request.
#[derive(Default, Debug, Clone, Copy)]
struct RequestFilter {
    peer: Option<PeerId>,
    epoch: Option<u64>,
    column_index: Option<u64>,
}

const NO_FILTER: RequestFilter = RequestFilter {
    peer: None,
    epoch: None,
    column_index: None,
};

impl RequestFilter {
    fn peer(mut self, peer: PeerId) -> Self {
        self.peer = Some(peer);
        self
    }

    fn epoch(mut self, epoch: u64) -> Self {
        self.epoch = Some(epoch);
        self
    }

    fn column_index(mut self, index: u64) -> Self {
        self.column_index = Some(index);
        self
    }

    fn blocks_by_range_requests<E: EthSpec>(
        &self,
        ev: &NetworkMessage<E>,
    ) -> Option<BlocksByRangeRequestData> {
        match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlocksByRange(req),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlocksByRange(id)),
            } if self.matches_blocks_by_range(peer_id, req) => Some((*id, *peer_id, req.clone())),
            _ => None,
        }
    }

    fn blocks_by_root_requests<E: EthSpec>(
        &self,
        ev: &NetworkMessage<E>,
    ) -> Option<BlocksByRootRequestData> {
        match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::BlocksByRoot(req),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlocksByRoot(id)),
            } if self.matches_blocks_by_root(peer_id, req) => Some((*id, *peer_id, req.clone())),
            _ => None,
        }
    }

    fn data_columns_by_range_requests<E: EthSpec>(
        &self,
        ev: &NetworkMessage<E>,
    ) -> Option<DataColumnsByRangeRequestData> {
        match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::DataColumnsByRange(req),
                app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRange(id)),
            } if self.matches_data_columns_by_range(peer_id, req) => {
                Some((*id, *peer_id, req.clone()))
            }
            _ => None,
        }
    }

    fn data_columns_by_root_requests<E: EthSpec>(
        &self,
        ev: &NetworkMessage<E>,
    ) -> Option<DataColumnsByRootRequestData> {
        match ev {
            NetworkMessage::SendRequest {
                peer_id,
                request: RequestType::DataColumnsByRoot(req),
                app_request_id: AppRequestId::Sync(SyncRequestId::DataColumnsByRoot(id)),
            } if self.matches_data_columns_by_root(peer_id, req) => {
                Some((*id, *peer_id, req.clone()))
            }
            _ => None,
        }
    }

    fn matches_blocks_by_root(&self, peer: &PeerId, _req: &BlocksByRootRequest) -> bool {
        self.matches_peer(peer)
    }

    fn matches_blocks_by_range(&self, peer: &PeerId, req: &OldBlocksByRangeRequest) -> bool {
        self.matches_common(peer, *req.start_slot())
    }

    fn matches_blobs_by_range(&self, peer: &PeerId, req: &BlobsByRangeRequest) -> bool {
        self.matches_common(peer, req.start_slot)
    }

    fn matches_data_columns_by_range(
        &self,
        peer: &PeerId,
        req: &DataColumnsByRangeRequest,
    ) -> bool {
        if let Some(index) = self.column_index {
            if !req.columns.contains(&index) {
                return false;
            }
        }
        self.matches_common(peer, req.start_slot)
    }

    fn matches_data_columns_by_root(&self, peer: &PeerId, req: &DataColumnsByRootRequest) -> bool {
        if let Some(index) = self.column_index {
            if !req
                .data_column_ids
                .iter()
                .any(|id| id.columns.iter().any(|i| *i == index))
            {
                return false;
            }
        }
        self.matches_peer(peer)
    }

    fn matches_common(&self, peer: &PeerId, start_slot: u64) -> bool {
        if let Some(expected_epoch) = self.epoch {
            let epoch = Slot::new(start_slot).epoch(E::slots_per_epoch()).as_u64();
            if epoch != expected_epoch {
                return false;
            }
        }
        self.matches_peer(peer)
    }

    fn matches_peer(&self, peer: &PeerId) -> bool {
        if let Some(expected_peer) = self.peer {
            if *peer != expected_peer {
                return false;
            }
        }
        true
    }
}

fn filter() -> RequestFilter {
    RequestFilter::default()
}

/// Instruct the testing rig how to complete requests for _by_range requests
#[derive(Debug, Clone, Copy)]
struct CompleteConfig {
    block_count: usize,
    with_data: bool,
    custody_failure_at_index: Option<u64>,
}

impl CompleteConfig {
    fn custody_failure_at_index(mut self, index: u64) -> Self {
        self.custody_failure_at_index = Some(index);
        self
    }
}

fn complete() -> CompleteConfig {
    CompleteConfig {
        block_count: 1,
        with_data: true,
        custody_failure_at_index: None,
    }
}

impl TestRig {
    fn our_custody_indices(&self) -> Vec<ColumnIndex> {
        self.network_globals
            .sampling_columns()
            .iter()
            .copied()
            .collect()
    }

    /// Produce a head peer with an advanced head
    fn add_head_peer(&mut self) -> PeerId {
        self.add_head_peer_with_root(Hash256::random())
    }

    /// Produce a head peer with an advanced head
    fn add_head_peer_with_root(&mut self, head_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        self.add_connected_sync_random_peer(SyncInfo {
            head_root,
            head_slot: local_info.head_slot + 1 + Slot::new(SLOT_IMPORT_TOLERANCE as u64),
            ..local_info
        })
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer(&mut self) -> PeerId {
        self.add_finalized_peer_with_root(Hash256::random())
    }

    // Produce a finalized peer with an advanced finalized epoch
    fn add_finalized_peer_with_root(&mut self, finalized_root: Hash256) -> PeerId {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + 2;
        self.add_connected_sync_random_peer(SyncInfo {
            finalized_epoch,
            finalized_root,
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
        })
    }

    fn finalized_remote_info_advanced_by(&self, advanced_epochs: Epoch) -> SyncInfo {
        let local_info = self.local_info();
        let finalized_epoch = local_info.finalized_epoch + advanced_epochs;
        SyncInfo {
            finalized_epoch,
            finalized_root: Hash256::random(),
            head_slot: finalized_epoch.start_slot(E::slots_per_epoch()),
            head_root: Hash256::random(),
        }
    }

    fn local_info(&self) -> SyncInfo {
        let StatusMessage {
            fork_digest: _,
            finalized_root,
            finalized_epoch,
            head_root,
            head_slot,
        } = self.harness.chain.status_message();
        SyncInfo {
            head_slot,
            head_root,
            finalized_epoch,
            finalized_root,
        }
    }

    fn add_connected_sync_peer_not_supernode(&mut self, remote_info: SyncInfo) -> PeerId {
        self.add_sync_peer(false, remote_info)
    }

    fn add_connected_sync_random_peer(&mut self, remote_info: SyncInfo) -> PeerId {
        // Create valid peer known to network globals
        // TODO(fulu): Using supernode peers to ensure we have peer across all column
        // subnets for syncing. Should add tests connecting to full node peers.
        self.add_sync_peer(true, remote_info)
    }

    fn assert_state(&mut self, state: RangeSyncType) {
        assert_eq!(
            self.sync_manager
                .range_sync()
                .state()
                .expect("State is ok")
                .expect("Range should be syncing, there are no chains")
                .0,
            state,
            "not expected range sync state"
        );
    }

    fn get_sync_state(&mut self) -> SyncState {
        self.sync_manager.network().network_globals().sync_state()
    }

    fn get_batch_states(&mut self) -> Vec<(ChainId, BatchId, &BatchState<E>)> {
        self.sync_manager.range_sync().batches_state()
    }

    fn assert_sync_state(&mut self, expected_state: SyncState) {
        let current_state = self.sync_manager.network().network_globals().sync_state();
        assert_eq!(current_state, expected_state);
    }

    fn assert_syncing_finalized(&mut self) {
        self.assert_sync_state(SyncState::SyncingFinalized {
            start_slot: Slot::new(0),
            target_slot: Slot::new(0),
        });
    }

    fn assert_no_chains_exist(&mut self) {
        if let Some(chain) = self.sync_manager.range_sync().state().unwrap() {
            panic!("There still exists a chain {chain:?}");
        }
    }

    fn assert_no_failed_chains(&mut self) {
        assert_eq!(
            self.sync_manager.range_sync().failed_chains(),
            Vec::<Hash256>::new(),
            "Expected no failed chains"
        )
    }

    #[track_caller]
    fn expect_chain_segments(&mut self, count: usize) {
        for i in 0..count {
            self.pop_received_processor_event(|ev| {
                (ev.work_type() == beacon_processor::WorkType::ChainSegment).then_some(())
            })
            .unwrap_or_else(|e| panic!("Expect ChainSegment work event count {i}: {e:?}"));
        }
    }

    fn expect_no_data_columns_by_range_requests(&mut self, request_filter: RequestFilter) {
        let events = self
            .filter_received_network_events(|ev| request_filter.data_columns_by_range_requests(ev));
        if !events.is_empty() {
            panic!("Expected to not find data_columns_by_range requests {request_filter:?} by found {events:?}")
        }
    }

    fn expect_active_block_components_by_range_request_on_custody_step(&mut self) {
        let requests = self
            .sync_manager
            .network()
            .active_block_components_by_range_requests();
        if requests.is_empty() {
            panic!("No active block_components_by_range requests");
        }
        for (id, step) in requests {
            if !matches!(step, BlockComponentsByRangeRequestStep::CustodyRequest) {
                panic!("block_components_by_range request {id} is not on CustodyRequest step: {step:?}");
            }
        }
    }

    fn expect_no_active_block_components_by_range_requests(&mut self) {
        let requests = self
            .sync_manager
            .network()
            .active_block_components_by_range_requests();
        if !requests.is_empty() {
            panic!("Still active block_components_by_range requests {requests:?}");
        }
    }

    fn expect_no_active_rpc_requests(&mut self) {
        let requests = self
            .sync_manager
            .network()
            .active_requests()
            .collect::<Vec<_>>();
        if !requests.is_empty() {
            panic!("There are still active RPC requests {requests:?}");
        }
    }

    fn expect_all_batches_in_state<F: Fn(&BatchState<E>) -> bool>(
        &mut self,
        predicate: F,
        expected_state: &'static str,
    ) {
        let batches = self.get_batch_states();
        if batches.is_empty() {
            panic!("no batches");
        }
        for (chain_id, batch_id, state) in &batches {
            if !predicate(state) {
                panic!("batch {chain_id} {batch_id} not in state {expected_state}, {state}");
            }
        }
    }

    fn expect_all_batches_downloading(&mut self) {
        self.expect_all_batches_in_state(
            |state| matches!(state, BatchState::Downloading { .. }),
            "Downloading",
        );
    }

    fn expect_all_batches_processing_or_awaiting(&mut self) {
        self.expect_all_batches_in_state(
            |state| {
                matches!(
                    state,
                    BatchState::Processing { .. } | BatchState::AwaitingProcessing { .. }
                )
            },
            "Processing or AwaitingProcessing",
        );
    }

    fn update_execution_engine_state(&mut self, state: EngineState) {
        self.log(&format!("execution engine state updated: {state:?}"));
        self.sync_manager.update_execution_engine_state(state);
    }

    fn zero_block_at_slot(&mut self, slot: Slot, with_data: bool) -> SignedBeaconBlock<E> {
        let mut block = BeaconBlock::empty(&self.spec);
        if with_data {
            if let Ok(blob_kzg_commitments) = block.body_mut().blob_kzg_commitments_mut() {
                blob_kzg_commitments
                    .push(KzgCommitment([0; 48]))
                    .expect("pushed to empty kzg commitments");
            }
        }
        *block.slot_mut() = slot;
        SignedBeaconBlock::from_block(block, Signature::empty())
    }

    fn create_parent_chain(&mut self) -> (Hash256, Slot) {
        let current_head = self.harness.chain.head();
        let mut parent_root = current_head.head_block_root();
        let mut slot = current_head.head_slot();
        for _ in 0..64 {
            let mut block = self.zero_block_at_slot(slot, true);
            *block.message_mut().parent_root_mut() = parent_root;
            *block.message_mut().slot_mut() = slot;
            let block_root = block.canonical_root();
            self.blocks_by_root.insert(block_root, block.into());

            parent_root = block_root;
            slot = slot + Slot::new(1);
        }
        (parent_root, slot)
    }

    fn last_sent_blocks_by_range(
        &mut self,
        id: ComponentsByRangeRequestId,
    ) -> Vec<Arc<SignedBeaconBlock<E>>> {
        self.sent_blocks_by_range
            .get(&id)
            .cloned()
            .unwrap_or_else(|| panic!("No blocks for ComponentsByRangeRequestId {id}"))
    }

    fn send_blocks_by_range_response(
        &mut self,
        req_id: BlocksByRangeRequestId,
        peer_id: PeerId,
        blocks: &[Arc<SignedBeaconBlock<E>>],
    ) {
        let slots = blocks.iter().map(|block| block.slot()).collect::<Vec<_>>();
        self.log(&format!(
            "Completing BlocksByRange request {req_id} to {peer_id} with blocks {slots:?}"
        ));

        for block in blocks {
            self.send_sync_message(SyncMessage::RpcBlock {
                sync_request_id: SyncRequestId::BlocksByRange(req_id),
                peer_id,
                beacon_block: Some(block.clone()),
                seen_timestamp: D,
            });
        }
        self.send_sync_message(SyncMessage::RpcBlock {
            sync_request_id: SyncRequestId::BlocksByRange(req_id),
            peer_id,
            beacon_block: None,
            seen_timestamp: D,
        });

        if self
            .sent_blocks_by_range
            .insert(req_id.parent_request_id, blocks.to_vec())
            .is_some()
        {
            panic!("Sent two blocks_by_range requests in the same epoch. We need better tracking");
        }
    }

    fn send_blocks_by_root_response(
        &mut self,
        req_id: BlocksByRootRequestId,
        peer_id: PeerId,
        blocks: &[Arc<SignedBeaconBlock<E>>],
    ) {
        let slots = blocks.iter().map(|block| block.slot()).collect::<Vec<_>>();
        self.log(&format!(
            "Completing BlocksByRoot request {req_id} to {peer_id} with blocks {slots:?}"
        ));

        for block in blocks {
            self.send_sync_message(SyncMessage::RpcBlock {
                sync_request_id: SyncRequestId::BlocksByRoot(req_id),
                peer_id,
                beacon_block: Some(block.clone()),
                seen_timestamp: D,
            });
        }
        self.send_sync_message(SyncMessage::RpcBlock {
            sync_request_id: SyncRequestId::BlocksByRoot(req_id),
            peer_id,
            beacon_block: None,
            seen_timestamp: D,
        });
    }

    fn send_data_columns_by_range_response(
        &mut self,
        id: DataColumnsByRangeRequestId,
        peer_id: PeerId,
        data_columns: &[Arc<DataColumnSidecar<E>>],
    ) {
        let mut ids = data_columns
            .iter()
            .map(|d| (d.slot().as_u64(), d.index))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        self.log(&format!(
            "Completing DataColumnsByRange request {id} to {peer_id} with data_columns {ids:?}"
        ));

        for data_column in data_columns {
            self.send_sync_message(SyncMessage::RpcDataColumn {
                sync_request_id: SyncRequestId::DataColumnsByRange(id),
                peer_id,
                data_column: Some(data_column.clone()),
                seen_timestamp: D,
            });
        }
        self.send_sync_message(SyncMessage::RpcDataColumn {
            sync_request_id: SyncRequestId::DataColumnsByRange(id),
            peer_id,
            data_column: None,
            seen_timestamp: D,
        });
    }

    fn send_data_columns_by_root_response(
        &mut self,
        id: DataColumnsByRootRequestId,
        peer_id: PeerId,
        data_columns: &[Arc<DataColumnSidecar<E>>],
    ) {
        let mut ids = data_columns
            .iter()
            .map(|d| (d.slot().as_u64(), d.index))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        self.log(&format!(
            "Completing DataColumnsByRange request {id} to {peer_id} with data_columns {ids:?}"
        ));

        for data_column in data_columns {
            self.send_sync_message(SyncMessage::RpcDataColumn {
                sync_request_id: SyncRequestId::DataColumnsByRoot(id),
                peer_id,
                data_column: Some(data_column.clone()),
                seen_timestamp: D,
            });
        }
        self.send_sync_message(SyncMessage::RpcDataColumn {
            sync_request_id: SyncRequestId::DataColumnsByRoot(id),
            peer_id,
            data_column: None,
            seen_timestamp: D,
        });
    }

    fn pop_blocks_by_range_request(
        &mut self,
        request_filter: RequestFilter,
    ) -> (BlocksByRangeRequestId, PeerId, OldBlocksByRangeRequest) {
        self.pop_received_network_event(|ev| request_filter.blocks_by_range_requests(ev))
            .unwrap_or_else(|e| {
                panic!("Should have a BlocksByRange request, filter {request_filter:?}: {e:?}")
            })
    }

    fn pop_data_columns_by_range_requests(
        &mut self,
        request_filter: RequestFilter,
    ) -> Vec<(
        DataColumnsByRangeRequestId,
        PeerId,
        DataColumnsByRangeRequest,
    )> {
        let mut data_columns_requests = vec![];
        while let Ok(data_columns_request) =
            self.pop_received_network_event(|ev| request_filter.data_columns_by_range_requests(ev))
        {
            data_columns_requests.push(data_columns_request);
        }
        data_columns_requests
    }

    fn find_data_by_range_request(
        &mut self,
        request_filter: RequestFilter,
    ) -> ByRangeDataRequestIds {
        if self.after_fulu() {
            let data_columns_requests = self.pop_data_columns_by_range_requests(request_filter);
            if data_columns_requests.is_empty() {
                panic!("Found zero DataColumnsByRange requests, filter {request_filter:?}");
            }
            ByRangeDataRequestIds::PostPeerDAS(data_columns_requests)
        } else if self.after_deneb() {
            let (id, peer, req) = self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id,
                        request: RequestType::BlobsByRange(req),
                        app_request_id: AppRequestId::Sync(SyncRequestId::BlobsByRange(id)),
                    } if request_filter.matches_blobs_by_range(peer_id, req) => {
                        Some((*id, *peer_id, req.clone()))
                    }
                    _ => None,
                })
                .unwrap_or_else(|e| {
                    panic!("Should have a blobs by range request, filter {request_filter:?}: {e:?}")
                });
            ByRangeDataRequestIds::PrePeerDAS(id, peer, req)
        } else {
            ByRangeDataRequestIds::PreDeneb
        }
    }

    fn find_and_complete_block_components_by_range_request(
        &mut self,
        request_filter: RequestFilter,
        complete_config: CompleteConfig,
    ) -> RangeRequestId {
        let id = self.find_and_complete_blocks_by_range_request(request_filter, complete_config);
        self.find_and_complete_data_by_range_request(request_filter, complete_config);
        id
    }

    fn find_and_complete_blocks_by_range_request(
        &mut self,
        request_filter: RequestFilter,
        complete_config: CompleteConfig,
    ) -> RangeRequestId {
        let (blocks_req_id, block_peer, blocks_req) =
            self.pop_blocks_by_range_request(request_filter);

        let start_slot = Slot::new(*blocks_req.start_slot());
        let blocks = (0..complete_config.block_count)
            .map(|i| {
                self.zero_block_at_slot(start_slot + Slot::new(i as u64), complete_config.with_data)
                    .into()
            })
            .collect::<Vec<_>>();
        self.send_blocks_by_range_response(blocks_req_id, block_peer, &blocks);

        blocks_req_id.parent_request_id.requester
    }

    fn complete_blocks_by_range_request(
        &mut self,
        request: BlocksByRangeRequestData,
        complete_config: CompleteConfig,
    ) -> RangeRequestId {
        let (blocks_req_id, block_peer, blocks_req) = request;
        let start_slot = Slot::new(*blocks_req.start_slot());
        let blocks = (0..complete_config.block_count)
            .map(|i| {
                self.zero_block_at_slot(start_slot + Slot::new(i as u64), complete_config.with_data)
                    .into()
            })
            .collect::<Vec<_>>();
        self.send_blocks_by_range_response(blocks_req_id, block_peer, &blocks);

        blocks_req_id.parent_request_id.requester
    }

    fn complete_blocks_by_root_request(
        &mut self,
        request: BlocksByRootRequestData,
        complete_config: CompleteConfig,
    ) -> BlocksByRootRequester {
        let (blocks_req_id, block_peer, blocks_req) = request;

        let blocks = blocks_req
            .block_roots()
            .iter()
            .map(|block_root| {
                self.blocks_by_root
                    .get(block_root)
                    .expect("Test consumer requested unknown block")
                    .clone()
            })
            .collect::<Vec<_>>();

        self.send_blocks_by_root_response(blocks_req_id, block_peer, &blocks);

        blocks_req_id.parent_request_id
    }

    fn complete_data_columns_by_range_request(
        &mut self,
        (id, peer_id, req): DataColumnsByRangeRequestData,
        complete_config: CompleteConfig,
    ) {
        // To reply with a valid DataColumnsByRange we need to construct
        // DataColumnsByRange for the block root that we requested the block peer, plus
        // figure out which exact columns we requested this peer

        let components_by_range_req_id = id.parent_request_id.parent_request_id;
        let blocks = self.last_sent_blocks_by_range(components_by_range_req_id);

        let data_columns = blocks
            .iter()
            .flat_map(|block| {
                let kzg_commitments_inclusion_proof = block
                    .message()
                    .body()
                    .kzg_commitments_merkle_proof()
                    .unwrap();
                let kzg_commitments = block
                    .message()
                    .body()
                    .blob_kzg_commitments()
                    .unwrap()
                    .clone();
                let signed_block_header = block.signed_block_header();

                req.columns.iter().filter_map(move |index| {
                    // Skip column generation if index is marked as failure
                    if complete_config.custody_failure_at_index == Some(*index) {
                        return None;
                    }

                    // We need to produce a DataColumn with valid inclusion proof, but can
                    // be with random KZG proof and data as we won't send it for processing
                    Some(Arc::new(DataColumnSidecar {
                        index: *index,
                        column: VariableList::empty(),
                        kzg_commitments: kzg_commitments.clone(),
                        kzg_proofs: VariableList::from(vec![]),
                        signed_block_header: signed_block_header.clone(),
                        kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
                    }))
                })
            })
            .collect::<Vec<_>>();

        // Need to log here because I can't capture &mut self inside the columns iter
        if !blocks.is_empty() {
            if let Some(index) = complete_config.custody_failure_at_index {
                self.log(&format!(
                    "Forced custody failure at request {id} for peer {peer_id} index {index:?}"
                ));
            }
        }

        self.send_data_columns_by_range_response(id, peer_id, &data_columns);
    }

    fn complete_data_columns_by_root_request_range_sync(
        &mut self,
        (id, peer_id, req): DataColumnsByRootRequestData,
        complete_config: CompleteConfig,
    ) {
        // To reply with a valid DataColumnsByRange we need to construct
        // DataColumnsByRange for the block root that we requested the block peer, plus
        // figure out which exact columns we requested this peer
        let mut triggered_custody_failure = false;

        let data_columns = req
            .data_column_ids
            .iter()
            .flat_map(|column_id| {
                let block = self
                    .blocks_by_root
                    .get(&column_id.block_root)
                    .expect("Test consumer requested unknown block")
                    .clone();

                let kzg_commitments_inclusion_proof = block
                    .message()
                    .body()
                    .kzg_commitments_merkle_proof()
                    .unwrap();
                let kzg_commitments = block
                    .message()
                    .body()
                    .blob_kzg_commitments()
                    .unwrap()
                    .clone();
                let signed_block_header = block.signed_block_header();

                column_id.columns.iter().filter_map(move |index| {
                    // Skip column generation if index is marked as failure
                    if complete_config.custody_failure_at_index == Some(*index) {
                        triggered_custody_failure = true;
                        return None;
                    }

                    // We need to produce a DataColumn with valid inclusion proof, but can
                    // be with random KZG proof and data as we won't send it for processing
                    Some(Arc::new(DataColumnSidecar {
                        index: *index,
                        column: VariableList::empty(),
                        kzg_commitments: kzg_commitments.clone(),
                        kzg_proofs: VariableList::from(vec![]),
                        signed_block_header: signed_block_header.clone(),
                        kzg_commitments_inclusion_proof: kzg_commitments_inclusion_proof.clone(),
                    }))
                })
            })
            .collect::<Vec<_>>();

        // Need to log here because I can't capture &mut self inside the columns iter
        if triggered_custody_failure {
            if let Some(index) = complete_config.custody_failure_at_index {
                self.log(&format!(
                    "Forced custody failure at request {id} for peer {peer_id} index {index:?}"
                ));
            }
        }

        self.send_data_columns_by_root_response(id, peer_id, &data_columns);
    }

    fn find_and_complete_data_by_range_request(
        &mut self,
        request_filter: RequestFilter,
        complete_config: CompleteConfig,
    ) {
        let by_range_data_request_ids = self.find_data_by_range_request(request_filter);
        self.complete_data_by_range_request(by_range_data_request_ids, complete_config);
    }

    fn complete_data_by_range_request(
        &mut self,
        by_range_data_request_ids: ByRangeDataRequestIds,
        complete_config: CompleteConfig,
    ) {
        match by_range_data_request_ids {
            ByRangeDataRequestIds::PreDeneb => {}
            ByRangeDataRequestIds::PrePeerDAS(id, peer_id, req) => {
                // Complete the request with a single stream termination
                self.log(&format!(
                    "Completing BlobsByRange request {id} {req:?} with empty stream"
                ));
                self.send_sync_message(SyncMessage::RpcBlob {
                    sync_request_id: SyncRequestId::BlobsByRange(id),
                    peer_id,
                    blob_sidecar: None,
                    seen_timestamp: D,
                });
            }
            ByRangeDataRequestIds::PostPeerDAS(data_column_req_ids) => {
                // Complete the request with a single stream termination
                for (id, peer_id, req) in data_column_req_ids {
                    // To reply with a valid DataColumnsByRange we need to construct
                    // DataColumnsByRange for the block root that we requested the block peer, plus
                    // figure out which exact columns we requested this peer

                    let components_by_range_req_id = id.parent_request_id.parent_request_id;
                    let blocks = self.last_sent_blocks_by_range(components_by_range_req_id);

                    let data_columns = blocks
                        .iter()
                        .flat_map(|block| {
                            let kzg_commitments_inclusion_proof = block
                                .message()
                                .body()
                                .kzg_commitments_merkle_proof()
                                .unwrap();
                            let kzg_commitments = block
                                .message()
                                .body()
                                .blob_kzg_commitments()
                                .unwrap()
                                .clone();
                            let signed_block_header = block.signed_block_header();

                            req.columns.iter().filter_map(move |index| {
                                // Skip column generation if index is marked as failure
                                if complete_config.custody_failure_at_index == Some(*index) {
                                    return None;
                                }

                                // We need to produce a DataColumn with valid inclusion proof, but can
                                // be with random KZG proof and data as we won't send it for processing
                                Some(Arc::new(DataColumnSidecar {
                                    index: *index,
                                    column: VariableList::empty(),
                                    kzg_commitments: kzg_commitments.clone(),
                                    kzg_proofs: VariableList::from(vec![]),
                                    signed_block_header: signed_block_header.clone(),
                                    kzg_commitments_inclusion_proof:
                                        kzg_commitments_inclusion_proof.clone(),
                                }))
                            })
                        })
                        .collect::<Vec<_>>();

                    // Need to log here because I can't capture &mut self inside the columns iter
                    if !blocks.is_empty() {
                        if let Some(index) = complete_config.custody_failure_at_index {
                            self.log(&format!("Forced custody failure at request {id} for peer {peer_id} index {index:?}"));
                        }
                    }

                    self.send_data_columns_by_range_response(id, peer_id, &data_columns);
                }
            }
        }
    }

    fn progress_until_no_events(
        &mut self,
        request_filter: RequestFilter,
        complete_config: CompleteConfig,
    ) {
        loop {
            if let Ok(request) =
                self.pop_received_network_event(|ev| request_filter.blocks_by_range_requests(ev))
            {
                self.complete_blocks_by_range_request(request, complete_config);
                continue;
            }

            if let Ok(request) =
                self.pop_received_network_event(|ev| request_filter.blocks_by_root_requests(ev))
            {
                self.complete_blocks_by_root_request(request, complete_config);
                continue;
            }

            if let Ok(request) = self
                .pop_received_network_event(|ev| request_filter.data_columns_by_range_requests(ev))
            {
                self.complete_data_columns_by_range_request(request, complete_config);
                continue;
            }

            if let Ok(request) = self
                .pop_received_network_event(|ev| request_filter.data_columns_by_root_requests(ev))
            {
                self.complete_data_columns_by_root_request_range_sync(request, complete_config);
                continue;
            }

            let sync_state = self.get_sync_state();
            self.log(&format!("Progressed sync, current state: {:?}", sync_state,));

            return;
        }
    }

    fn find_and_complete_processing_chain_segment(&mut self, id: ChainSegmentProcessId) {
        self.pop_received_processor_event(|ev| {
            (ev.work_type() == WorkType::ChainSegment).then_some(())
        })
        .unwrap_or_else(|e| panic!("Expected chain segment work event: {e}"));

        self.log(&format!(
            "Completing ChainSegment processing work {id:?} with success"
        ));
        self.send_sync_message(SyncMessage::BatchProcessed {
            sync_type: id,
            result: crate::sync::BatchProcessResult::Success {
                sent_blocks: 8,
                imported_blocks: 8,
            },
        });
    }

    fn complete_and_process_range_sync_until(
        &mut self,
        last_epoch: u64,
        request_filter: RequestFilter,
        complete_config: CompleteConfig,
    ) {
        for epoch in 0..last_epoch {
            // Note: In this test we can't predict the block peer
            let id = self.find_and_complete_block_components_by_range_request(
                request_filter.epoch(epoch),
                complete_config,
            );
            if let RangeRequestId::RangeSync { batch_id, .. } = id {
                assert_eq!(batch_id.as_u64(), epoch, "Unexpected batch_id");
            } else {
                panic!("unexpected RangeRequestId {id}");
            }

            let id = match id {
                RangeRequestId::RangeSync { chain_id, batch_id } => {
                    ChainSegmentProcessId::RangeBatchId(chain_id, batch_id)
                }
                RangeRequestId::BackfillSync { batch_id } => {
                    ChainSegmentProcessId::BackSyncBatchId(batch_id)
                }
            };

            self.find_and_complete_processing_chain_segment(id);
            if epoch < last_epoch - 1 {
                self.assert_state(RangeSyncType::Finalized);
            } else {
                self.assert_no_chains_exist();
                self.assert_no_failed_chains();
            }
        }
    }

    async fn create_canonical_block(&mut self) -> (SignedBeaconBlock<E>, Option<DataSidecars<E>>) {
        self.harness.advance_slot();

        let block_root = self
            .harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        let store = &self.harness.chain.store;
        let block = store.get_full_block(&block_root).unwrap().unwrap();
        let fork = block.fork_name_unchecked();

        let data_sidecars = if fork.fulu_enabled() {
            store
                .get_data_columns(&block_root)
                .unwrap()
                .map(|columns| {
                    columns
                        .into_iter()
                        .map(CustodyDataColumn::from_asserted_custody)
                        .collect()
                })
                .map(DataSidecars::DataColumns)
        } else if fork.deneb_enabled() {
            store
                .get_blobs(&block_root)
                .unwrap()
                .blobs()
                .map(DataSidecars::Blobs)
        } else {
            None
        };

        (block, data_sidecars)
    }

    async fn remember_block(
        &mut self,
        (block, data_sidecars): (SignedBeaconBlock<E>, Option<DataSidecars<E>>),
    ) {
        // This code is kind of duplicated from Harness::process_block, but takes sidecars directly.
        let block_root = block.canonical_root();
        self.harness.set_current_slot(block.slot());
        let _: SignedBeaconBlockHash = self
            .harness
            .chain
            .process_block(
                block_root,
                build_rpc_block(block.into(), &data_sidecars, &self.spec),
                NotifyExecutionLayer::Yes,
                BlockImportSource::RangeSync,
                || Ok(()),
            )
            .await
            .unwrap()
            .try_into()
            .unwrap();
        self.harness.chain.recompute_head_at_current_slot().await;
    }
}

fn build_rpc_block(
    block: Arc<SignedBeaconBlock<E>>,
    data_sidecars: &Option<DataSidecars<E>>,
    spec: &ChainSpec,
) -> RpcBlock<E> {
    match data_sidecars {
        Some(DataSidecars::Blobs(blobs)) => {
            RpcBlock::new(None, block, Some(blobs.clone())).unwrap()
        }
        Some(DataSidecars::DataColumns(columns)) => {
            RpcBlock::new_with_custody_columns(None, block, columns.clone(), spec).unwrap()
        }
        // Block has no data, expects zero columns
        None => RpcBlock::new_without_blobs(None, block),
    }
}

#[test]
fn head_chain_removed_while_finalized_syncing() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2821
    let mut rig = TestRig::test_setup();

    // Get a peer with an advanced head
    let head_peer = rig.add_head_peer();
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.pop_blocks_by_range_request(filter().peer(head_peer));

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer();
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.pop_blocks_by_range_request(filter().peer(finalized_peer));

    // Fail the head chain by disconnecting the peer.
    rig.peer_disconnected(head_peer);
    rig.assert_state(RangeSyncType::Finalized);
}

#[tokio::test]
async fn state_update_while_purging() {
    // NOTE: this is a regression test.
    // Added in PR https://github.com/sigp/lighthouse/pull/2827
    let mut rig = TestRig::test_setup();

    // Create blocks on a separate harness
    let mut rig_2 = TestRig::test_setup();
    // Need to create blocks that can be inserted into the fork-choice and fit the "known
    // conditions" below.
    let head_peer_block = rig_2.create_canonical_block().await;
    let head_peer_root = head_peer_block.0.canonical_root();
    let finalized_peer_block = rig_2.create_canonical_block().await;
    let finalized_peer_root = finalized_peer_block.0.canonical_root();

    // Get a peer with an advanced head
    let head_peer = rig.add_head_peer_with_root(head_peer_root);
    rig.assert_state(RangeSyncType::Head);

    // Sync should have requested a batch, grab the request.
    let _ = rig.pop_blocks_by_range_request(filter().peer(head_peer));

    // Now get a peer with an advanced finalized epoch.
    let finalized_peer = rig.add_finalized_peer_with_root(finalized_peer_root);
    rig.assert_state(RangeSyncType::Finalized);

    // Sync should have requested a batch, grab the request
    let _ = rig.pop_blocks_by_range_request(filter().peer(finalized_peer));

    // Now the chain knows both chains target roots.
    rig.remember_block(head_peer_block).await;
    rig.remember_block(finalized_peer_block).await;

    // Add an additional peer to the second chain to make range update it's status
    rig.add_finalized_peer();
}

#[test]
fn pause_and_resume_on_ee_offline() {
    let mut rig = TestRig::test_setup();

    // add some peers
    let peer1 = rig.add_head_peer();
    // make the ee offline
    rig.update_execution_engine_state(EngineState::Offline);
    // send the response to the request
    rig.find_and_complete_block_components_by_range_request(
        filter().peer(peer1).epoch(0),
        complete(),
    );
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();

    // while the ee is offline, more peers might arrive. Add a new finalized peer.
    let _peer2 = rig.add_finalized_peer();

    // send the response to the request
    // Don't filter requests and the columns requests may be sent to peer1 or peer2
    // We need to filter by epoch, because the previous batch eagerly sent requests for the next
    // epoch for the other batch. So we can either filter by epoch of by sync type.
    rig.find_and_complete_block_components_by_range_request(filter().epoch(0), complete());
    // the beacon processor shouldn't have received any work
    rig.expect_empty_processor();
    // make the beacon processor available again.
    // update_execution_engine_state implicitly calls resume
    // now resume range, we should have two processing requests in the beacon processor.
    rig.update_execution_engine_state(EngineState::Online);

    // The head chain and finalized chain (2) should be in the processing queue
    rig.expect_chain_segments(2);
}

/// To attempt to finalize the peer's status finalized checkpoint we synced to its finalized epoch +
/// 2 epochs + 1 slot.
const EXTRA_SYNCED_EPOCHS: u64 = 2 + 1;

#[test]
fn finalized_sync_enough_global_custody_peers_few_chain_peers() {
    // Run for all forks
    let mut r = TestRig::test_setup();
    // This test creates enough global custody peers to satisfy column queries but only adds few
    // peers to the chain
    r.new_connected_peers_for_peerdas();

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Current priorization only sends batches to idle peers, so we need enough peers for each batch
    // TODO: Test this with a single peer in the chain, it should still work
    r.add_sync_peer(false, remote_info);
    r.assert_state(RangeSyncType::Finalized);

    let last_epoch = advanced_epochs + EXTRA_SYNCED_EPOCHS;
    r.complete_and_process_range_sync_until(last_epoch, filter(), complete());
}

// Same test with different types of peers:
// - 100 peers
// - 1 supernode
// - perfectly distributed peer ids

#[test]
fn finalized_sync_not_enough_custody_peers_on_start_supernode_only() {
    finalized_sync_not_enough_custody_peers_on_start(Config {
        peers: PeersConfig::SupernodeOnly,
    });
}

#[test]
fn finalized_sync_not_enough_custody_peers_on_start_supernode_and_random() {
    finalized_sync_not_enough_custody_peers_on_start(Config {
        peers: PeersConfig::SupernodeAndRandom,
    });
}

fn finalized_sync_not_enough_custody_peers_on_start(config: Config) {
    let mut r = TestRig::test_setup_as_supernode();
    // Only run post-PeerDAS
    if !r.fork_name.fulu_enabled() {
        return;
    }

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());

    // Unikely that the single peer we added has enough columns for us. Tests are determinstic and
    // this error should never be hit
    r.add_connected_sync_peer_not_supernode(remote_info.clone());
    r.assert_syncing_finalized();

    // The SyncingChain has a single peer, so it can issue blocks_by_range requests. However, it
    // doesn't have enough peers to cover all columns
    r.progress_until_no_events(NO_FILTER, complete());
    r.expect_no_active_rpc_requests();

    // Here we have a batch with partially completed block_components_by_range requests. The batch
    // should not have failed, we are still syncing, and there are no downscoring events.
    r.expect_no_penalty_for_anyone();
    r.expect_active_block_components_by_range_request_on_custody_step();

    // Generate enough peers and supernodes to cover all custody columns
    r.add_sync_peers(config.peers, remote_info.clone());
    // Note: not necessary to add this peers to the chain, as we draw from the global pool
    // We still need to add enough peers to trigger batch downloads with idle peers. Same issue as
    // the test above.

    r.progress_until_no_events(NO_FILTER, complete());
    r.expect_no_active_rpc_requests();
    r.expect_no_active_block_components_by_range_requests();
    // TOOD(das): For now this tests don't complete sync. We can't track beacon processor Work
    // events from here easily. What we pop from the beacon processor queue is an opaque closure
    // wihtout any information. We don't know what batch it is for.
}

#[test]
fn finalized_sync_single_custody_peer_failure() {
    let mut r = TestRig::test_setup();
    // Only run post-PeerDAS
    if !r.fork_name.fulu_enabled() {
        return;
    }

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());
    let column_index_to_fail = r.our_custody_indices().first().copied().unwrap();

    r.add_sync_peer(true, remote_info.clone());
    r.assert_state(RangeSyncType::Finalized);

    // Progress all blocks_by_range and columns_by_range requests but respond empty for a single
    // column index
    r.progress_until_no_events(
        NO_FILTER,
        complete().custody_failure_at_index(column_index_to_fail),
    );
    r.expect_penalties("custody_failure");

    // Some peer had a custody failure, but since there's a single peer in the batch we won't issue
    // another request yet.
    r.expect_no_active_rpc_requests();
    // Ensure that the block components by range request have not failed
    r.expect_active_block_components_by_range_request_on_custody_step();
    r.expect_all_batches_downloading();

    // After adding a new peer we will try to fetch from it
    r.add_sync_peer(true, remote_info.clone());
    r.progress_until_no_events(
        // Find the requests first to assert that this is the only request that exists
        filter().column_index(column_index_to_fail),
        // complete this one request without the custody failure now
        complete(),
    );

    r.expect_no_active_rpc_requests();
    r.expect_no_active_block_components_by_range_requests();
    r.expect_all_batches_processing_or_awaiting();
}

#[test]
fn finalized_sync_permanent_custody_peer_failure() {
    let mut r = TestRig::test_setup_with_options(TestOptions {
        is_supernode: false,
        // The default buffer size is 5, but we want to manually complete only the batch for epoch
        // 0. By setting this buffer to 1 sync will create a single batch until it completes. We can
        // do better assertions of state assuming there's only one batch and logs are cleaner.
        batch_buffer_size: 1,
    });
    // Only run post-PeerDAS
    if !r.fork_name.fulu_enabled() {
        return;
    }

    let advanced_epochs: u64 = 2;
    let remote_info = r.finalized_remote_info_advanced_by(advanced_epochs.into());
    let column_index_to_fail = r.our_custody_indices().first().copied().unwrap();
    const PEERS_IN_BATCH: usize = 4;

    for _ in 0..PEERS_IN_BATCH {
        r.add_connected_sync_random_peer(remote_info.clone());
    }
    r.assert_state(RangeSyncType::Finalized);

    // Some peer had a costudy failure at `column_index` so sync should do a single extra request
    // for that index and epoch.
    r.find_and_complete_block_components_by_range_request(
        filter().epoch(0),
        complete().custody_failure_at_index(column_index_to_fail),
    );

    let mut requested_peers = HashSet::new();

    for i in 0..PEERS_IN_BATCH - 1 {
        r.log(&format!("Loop {i} of custody failure round"));

        // Some peer had a costudy failure at `column_index` so sync should do a single extra request
        // for that index and epoch. We want to make sure that the request goes to different peer
        // than the attempted before.
        let reqs =
            r.find_data_by_range_request(filter().epoch(0).column_index(column_index_to_fail));
        let req_peer = reqs.peer();
        if requested_peers.contains(&req_peer) {
            panic!("Re-requested the same peer {req_peer} again after a custody failure");
        }
        requested_peers.insert(req_peer);

        // Find the requests first to assert that this is the only request that exists
        r.expect_no_data_columns_by_range_requests(filter().epoch(0));
        r.complete_data_by_range_request(
            reqs,
            complete().custody_failure_at_index(column_index_to_fail),
        );
    }

    // custody_by_range request is still active waiting for a new peer to connect
    r.expect_active_block_components_by_range_request_on_custody_step();
}

#[tokio::test]
async fn tree_sync_happy_path() {
    let mut r = TestRig::test_setup();
    let (head_root, head_slot) = r.create_parent_chain();
    let remote_info = SyncInfo {
        finalized_epoch: Epoch::new(0),
        finalized_root: Hash256::ZERO,
        head_slot,
        head_root,
    };
    r.add_sync_peer(false, remote_info.clone());
    r.progress_until_no_events(NO_FILTER, complete());
    r.add_sync_peer(true, remote_info);
    r.progress_until_no_events(NO_FILTER, complete());
    r.expect_empty_network();
}
