use super::range::{complete, filter, NO_FILTER};
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::sync::{
    manager::{BlockProcessingResult, SyncManager},
    peer_sampling::SamplingConfig,
    SamplingId, SyncMessage,
};
use crate::NetworkMessage;
use std::sync::Arc;
use std::time::Duration;

use super::*;

use beacon_chain::observed_data_sidecars::Observe;
use beacon_chain::{
    blob_verification::GossipVerifiedBlob,
    block_verification_types::{AsBlock, BlockImportData},
    data_availability_checker::Availability,
    test_utils::{
        generate_rand_block_and_blobs, generate_rand_block_and_data_columns, test_spec,
        BeaconChainHarness, EphemeralHarnessType, NumBlobs,
    },
    validator_monitor::timestamp_now,
    AvailabilityPendingExecutedBlock, AvailabilityProcessingStatus, BlockError,
    PayloadVerificationOutcome, PayloadVerificationStatus,
};
use beacon_processor::WorkEvent;
use lighthouse_network::discovery::CombinedKey;
use lighthouse_network::{
    rpc::{RPCError, RequestType, RpcErrorResponse},
    service::api_types::{
        AppRequestId, DataColumnsByRootRequestId, DataColumnsByRootRequester, Id,
        SamplingRequester, SingleLookupReqId, SyncRequestId,
    },
    types::SyncState,
    NetworkConfig, NetworkGlobals, PeerId, SyncInfo,
};
use slot_clock::{SlotClock, TestingSlotClock};
use tokio::sync::mpsc;
use tracing::info;
use types::{
    data_column_sidecar::ColumnIndex,
    test_utils::{SeedableRng, TestRandom, XorShiftRng},
    BeaconState, BeaconStateBase, BlobSidecar, DataColumnSidecar, DataColumnSidecarList, EthSpec,
    ForkContext, ForkName, Hash256, MinimalEthSpec as E, SignedBeaconBlock, Slot,
};

const D: Duration = Duration::new(0, 0);
const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 5;
const PARENT_FAIL_TOLERANCE: u8 = SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS;
const PARENT_DEPTH_TOLERANCE: usize = 32;
const SAMPLING_REQUIRED_SUCCESSES: usize = 2;
type DCByRootIds = Vec<DCByRootId>;
type DCByRootId = (SyncRequestId, Vec<ColumnIndex>);

pub enum PeersConfig {
    SupernodeAndRandom,
    SupernodeOnly,
}

pub enum ResponseType {
    Block,
    Blob,
    CustodyColumn,
}

struct BlockLookupSummary {}

pub struct TestOptions {
    /// If the node created by this test harness is a supernode
    pub is_supernode: bool,
}

impl TestRig {
    pub fn test_setup() -> Self {
        Self::test_setup_with_options(TestOptions {
            is_supernode: false,
        })
    }

    pub fn test_setup_as_supernode() -> Self {
        Self::test_setup_with_options(TestOptions { is_supernode: true })
    }

    pub fn test_setup_with_options(options: TestOptions) -> Self {
        // Use `fork_from_env` logic to set correct fork epochs
        let spec = test_spec::<E>();

        // Initialise a new beacon chain
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E)
            .spec(Arc::new(spec))
            .deterministic_keypairs(1)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .testing_slot_clock(TestingSlotClock::new(
                Slot::new(0),
                Duration::from_secs(0),
                Duration::from_secs(12),
            ))
            .build();

        let chain = harness.chain.clone();
        let fork_context = Arc::new(ForkContext::new::<E>(
            Slot::new(0),
            chain.genesis_validators_root,
            &chain.spec,
        ));

        let (network_tx, network_rx) = mpsc::unbounded_channel();
        let (sync_tx, sync_rx) = mpsc::unbounded_channel::<SyncMessage<E>>();
        // TODO(das): make the generation of the ENR use the deterministic rng to have consistent
        // column assignments
        let network_config = Arc::new(NetworkConfig::default());
        let globals = Arc::new(NetworkGlobals::new_test_globals_as_supernode(
            Vec::new(),
            network_config,
            chain.spec.clone(),
            options.is_supernode,
        ));
        let (beacon_processor, beacon_processor_rx) = NetworkBeaconProcessor::null_for_testing(
            globals,
            sync_tx,
            chain.clone(),
            harness.runtime.task_executor.clone(),
        );

        let fork_name = chain.spec.fork_name_at_slot::<E>(chain.slot().unwrap());

        // All current tests expect synced and EL online state
        beacon_processor
            .network_globals
            .set_sync_state(SyncState::Synced);

        let spec = chain.spec.clone();

        // deterministic seed
        let rng = ChaCha20Rng::from_seed([0u8; 32]);

        init_tracing();

        TestRig {
            beacon_processor_rx,
            beacon_processor_rx_queue: vec![],
            network_rx,
            network_rx_queue: vec![],
            sync_rx,
            blocks_by_root: <_>::default(),
            rng,
            network_globals: beacon_processor.network_globals.clone(),
            sync_manager: SyncManager::new(
                chain,
                network_tx,
                beacon_processor.into(),
                // Pass empty recv not tied to any tx
                mpsc::unbounded_channel().1,
                SamplingConfig::Custom {
                    required_successes: vec![SAMPLING_REQUIRED_SUCCESSES],
                },
                fork_context,
            ),
            harness,
            fork_name,
            spec,
        }
    }

    fn test_setup_after_deneb_before_fulu() -> Option<Self> {
        let r = Self::test_setup();
        if r.after_deneb() && !r.fork_name.fulu_enabled() {
            Some(r)
        } else {
            None
        }
    }

    pub fn test_setup_after_fulu() -> Option<Self> {
        let r = Self::test_setup();
        if r.fork_name.fulu_enabled() {
            Some(r)
        } else {
            None
        }
    }

    pub fn log(&self, msg: &str) {
        info!(msg, "TEST_RIG");
    }

    pub fn after_deneb(&self) -> bool {
        self.fork_name.deneb_enabled()
    }

    pub fn after_fulu(&self) -> bool {
        self.fork_name.fulu_enabled()
    }

    fn trigger_unknown_parent_block(&mut self, peer_id: PeerId, block: Arc<SignedBeaconBlock<E>>) {
        let block_root = block.canonical_root();
        self.send_sync_message(SyncMessage::UnknownParentBlock(peer_id, block, block_root))
    }

    fn trigger_unknown_parent_blob(&mut self, peer_id: PeerId, blob: BlobSidecar<E>) {
        self.send_sync_message(SyncMessage::UnknownParentBlob(peer_id, blob.into()));
    }

    fn trigger_unknown_block_from_attestation(&mut self, block_root: Hash256, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::UnknownBlockHashFromAttestation(
            peer_id, block_root,
        ));
    }

    fn trigger_sample_block(&mut self, block_root: Hash256, block_slot: Slot) {
        self.send_sync_message(SyncMessage::SampleBlock(block_root, block_slot))
    }

    /// Drain all sync messages in the sync_rx attached to the beacon processor
    fn drain_sync_rx(&mut self) {
        while let Ok(sync_message) = self.sync_rx.try_recv() {
            self.send_sync_message(sync_message);
        }
    }

    pub fn rand_block(&mut self) -> SignedBeaconBlock<E> {
        self.rand_block_and_blobs(NumBlobs::None).0
    }

    fn rand_block_and_blobs(
        &mut self,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let fork_name = self.fork_name;
        let rng = &mut self.rng;
        generate_rand_block_and_blobs::<E>(fork_name, num_blobs, rng, &self.spec)
    }

    fn rand_block_and_data_columns(&mut self) -> (SignedBeaconBlock<E>, DataColumnSidecarList<E>) {
        let num_blobs = NumBlobs::Number(1);
        generate_rand_block_and_data_columns::<E>(
            self.fork_name,
            num_blobs,
            &mut self.rng,
            &self.harness.spec,
        )
    }

    pub fn rand_block_and_parent(
        &mut self,
    ) -> (SignedBeaconBlock<E>, SignedBeaconBlock<E>, Hash256, Hash256) {
        let parent = self.rand_block();
        let parent_root = parent.canonical_root();
        let mut block = self.rand_block();
        *block.message_mut().parent_root_mut() = parent_root;
        let block_root = block.canonical_root();
        (parent, block, parent_root, block_root)
    }

    pub fn send_sync_message(&mut self, sync_message: SyncMessage<E>) {
        self.sync_manager.handle_message(sync_message);
    }

    fn assert_active_lookup(&self, block_root: Hash256) {
        todo!();
    }

    fn expect_no_active_sampling(&mut self) {
        assert_eq!(
            self.sync_manager.active_sampling_requests(),
            Vec::<Hash256>::new(),
            "expected no active sampling"
        );
    }

    fn expect_active_sampling(&mut self, block_root: &Hash256) {
        assert!(self
            .sync_manager
            .active_sampling_requests()
            .contains(block_root));
    }

    fn expect_clean_finished_sampling(&mut self) {
        self.expect_empty_network();
        self.expect_sampling_result_work();
        self.expect_no_active_sampling();
    }

    fn assert_lookup_peers(&self, block_root: Hash256, expected_peers: &[PeerId]) {
        todo!();
    }

    fn insert_failed_chain(&mut self, block_root: Hash256) {
        todo!();
    }

    fn assert_not_failed_chain(&mut self, chain_hash: Hash256) {
        let failed_chains = self.get_failed_chains();
        if failed_chains.contains(&chain_hash) {
            panic!("failed chains contain {chain_hash:?}: {failed_chains:?}");
        }
    }

    fn get_failed_chains(&mut self) -> Vec<Hash256> {
        todo!();
    }

    fn assert_failed_chain(&mut self, chain_hash: Hash256) {
        let failed_chains = self.get_failed_chains();
        if !failed_chains.contains(&chain_hash) {
            panic!("expected failed chains to contain {chain_hash:?}: {failed_chains:?}");
        }
    }

    fn find_single_lookup_for(&self, block_root: Hash256) -> Id {
        todo!();
    }

    #[track_caller]
    fn expect_no_active_lookups(&self) {
        todo!();
    }

    fn expect_no_active_lookups_empty_network(&mut self) {
        self.expect_no_active_lookups();
        self.expect_empty_network();
    }

    // Note: prefer to use `add_connected_peer_testing_only`. This is currently extensively used in
    // lookup tests. We should consolidate this "add peer" methods in a future refactor
    fn new_connected_peer(&mut self) -> PeerId {
        self.add_connected_peer_testing_only(false)
    }

    // Note: prefer to use `add_connected_peer_testing_only`. This is currently extensively used in
    // lookup tests. We should consolidate this "add peer" methods in a future refactor
    fn new_connected_supernode_peer(&mut self) -> PeerId {
        self.add_connected_peer_testing_only(true)
    }

    /// Add a random connected peer that is not known by the sync module
    pub fn add_connected_peer_testing_only(&mut self, supernode: bool) -> PeerId {
        let key = self.determinstic_key();
        let peer_id = self
            .network_globals
            .peers
            .write()
            .__add_connected_peer_testing_only(supernode, &self.harness.spec, key);
        let mut peer_custody_subnets = self
            .network_globals
            .peers
            .read()
            .peer_info(&peer_id)
            .expect("peer was just added")
            .custody_subnets_iter()
            .map(|subnet| **subnet)
            .collect::<Vec<_>>();
        peer_custody_subnets.sort_unstable();
        self.log(&format!(
            "Added new peer for testing {peer_id:?} custody subnets {peer_custody_subnets:?}"
        ));
        peer_id
    }

    /// Add a random connected peer + add it to sync with a specific remote Status
    pub fn add_sync_peer(&mut self, supernode: bool, remote_info: SyncInfo) -> PeerId {
        let peer_id = self.add_connected_peer_testing_only(supernode);
        self.send_sync_message(SyncMessage::AddPeer(peer_id, remote_info));
        peer_id
    }

    fn determinstic_key(&mut self) -> CombinedKey {
        k256::ecdsa::SigningKey::random(&mut self.rng).into()
    }

    pub fn add_sync_peers(&mut self, config: PeersConfig, remote_info: SyncInfo) {
        match config {
            PeersConfig::SupernodeAndRandom => {
                for _ in 0..100 {
                    self.add_sync_peer(false, remote_info.clone());
                }
                self.add_sync_peer(true, remote_info);
            }
            PeersConfig::SupernodeOnly => {
                self.add_sync_peer(true, remote_info);
            }
        }
    }

    pub fn new_connected_peers_for_peerdas(&mut self) {
        // Enough sampling peers with few columns
        for _ in 0..100 {
            self.new_connected_peer();
        }
        // One supernode peer to ensure all columns have at least one peer
        self.new_connected_supernode_peer();
    }

    fn return_empty_sampling_requests(&mut self, ids: DCByRootIds) {
        for id in ids {
            self.log(&format!("return empty data column for {id:?}"));
            self.return_empty_sampling_request(id)
        }
    }

    fn return_empty_sampling_request(&mut self, (sync_request_id, _): DCByRootId) {
        let peer_id = PeerId::random();
        // Send stream termination
        self.send_sync_message(SyncMessage::RpcDataColumn {
            sync_request_id,
            peer_id,
            data_column: None,
            seen_timestamp: timestamp_now(),
        });
    }

    fn sampling_requests_failed(
        &mut self,
        sampling_ids: DCByRootIds,
        peer_id: PeerId,
        error: RPCError,
    ) {
        for (sync_request_id, _) in sampling_ids {
            self.send_sync_message(SyncMessage::RpcError {
                peer_id,
                sync_request_id,
                error: error.clone(),
            })
        }
    }

    fn complete_valid_sampling_column_requests(
        &mut self,
        ids: DCByRootIds,
        data_columns: DataColumnSidecarList<E>,
    ) {
        for id in ids {
            self.log(&format!("return valid data column for {id:?}"));
            let indices = &id.1;
            let columns_to_send = indices
                .iter()
                .map(|&i| data_columns[i as usize].clone())
                .collect::<Vec<_>>();
            self.complete_valid_sampling_column_request(id, &columns_to_send);
        }
    }

    fn complete_valid_sampling_column_request(
        &mut self,
        id: DCByRootId,
        data_columns: &[Arc<DataColumnSidecar<E>>],
    ) {
        let first_dc = data_columns.first().unwrap();
        let block_root = first_dc.block_root();
        let sampling_request_id = match id.0 {
            SyncRequestId::DataColumnsByRoot(DataColumnsByRootRequestId {
                parent_request_id: DataColumnsByRootRequester::Sampling(sampling_id),
                ..
            }) => sampling_id.sampling_request_id,
            _ => unreachable!(),
        };
        self.complete_data_columns_by_root_request(id, data_columns);

        // Expect work event
        self.expect_rpc_sample_verify_work_event();

        // Respond with valid result
        self.send_sync_message(SyncMessage::SampleVerified {
            id: SamplingId {
                id: SamplingRequester::ImportedBlock(block_root),
                sampling_request_id,
            },
            result: Ok(()),
        })
    }

    fn complete_data_columns_by_root_request(
        &mut self,
        (sync_request_id, _): DCByRootId,
        data_columns: &[Arc<DataColumnSidecar<E>>],
    ) {
        let peer_id = PeerId::random();
        for data_column in data_columns {
            // Send chunks
            self.send_sync_message(SyncMessage::RpcDataColumn {
                sync_request_id,
                peer_id,
                data_column: Some(data_column.clone()),
                seen_timestamp: timestamp_now(),
            });
        }
        // Send stream termination
        self.send_sync_message(SyncMessage::RpcDataColumn {
            sync_request_id,
            peer_id,
            data_column: None,
            seen_timestamp: timestamp_now(),
        });
    }

    /// Return RPCErrors for all active requests of peer
    fn rpc_error_all_active_requests(&mut self, disconnected_peer_id: PeerId) {
        self.drain_network_rx();
        while let Ok(sync_request_id) = self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id,
                app_request_id: AppRequestId::Sync(id),
                ..
            } if *peer_id == disconnected_peer_id => Some(*id),
            _ => None,
        }) {
            self.send_sync_message(SyncMessage::RpcError {
                peer_id: disconnected_peer_id,
                sync_request_id,
                error: RPCError::Disconnected,
            });
        }
    }

    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        self.send_sync_message(SyncMessage::Disconnect(peer_id));
    }

    fn drain_network_rx(&mut self) {
        while let Ok(event) = self.network_rx.try_recv() {
            self.network_rx_queue.push(event);
        }
    }

    fn drain_processor_rx(&mut self) {
        while let Ok(event) = self.beacon_processor_rx.try_recv() {
            self.beacon_processor_rx_queue.push(event);
        }
    }

    pub fn pop_received_network_event<T, F: Fn(&NetworkMessage<E>) -> Option<T>>(
        &mut self,
        predicate_transform: F,
    ) -> Result<T, String> {
        self.drain_network_rx();

        if let Some(index) = self
            .network_rx_queue
            .iter()
            .position(|x| predicate_transform(x).is_some())
        {
            // Transform the item, knowing that it won't be None because we checked it in the position predicate.
            let transformed = predicate_transform(&self.network_rx_queue[index]).unwrap();
            self.network_rx_queue.remove(index);
            Ok(transformed)
        } else {
            Err(format!("current network messages {:?}", self.network_rx_queue).to_string())
        }
    }

    /// Similar to `pop_received_network_events` but finds matching events without removing them.
    pub fn filter_received_network_events<T, F: Fn(&NetworkMessage<E>) -> Option<T>>(
        &mut self,
        predicate_transform: F,
    ) -> Vec<T> {
        self.drain_network_rx();

        self.network_rx_queue
            .iter()
            .filter_map(predicate_transform)
            .collect()
    }

    pub fn pop_received_processor_event<T, F: Fn(&WorkEvent<E>) -> Option<T>>(
        &mut self,
        predicate_transform: F,
    ) -> Result<T, String> {
        self.drain_processor_rx();

        if let Some(index) = self
            .beacon_processor_rx_queue
            .iter()
            .position(|x| predicate_transform(x).is_some())
        {
            // Transform the item, knowing that it won't be None because we checked it in the position predicate.
            let transformed = predicate_transform(&self.beacon_processor_rx_queue[index]).unwrap();
            self.beacon_processor_rx_queue.remove(index);
            Ok(transformed)
        } else {
            Err(format!(
                "current processor messages {:?}",
                self.beacon_processor_rx_queue
            )
            .to_string())
        }
    }

    pub fn expect_empty_processor(&mut self) {
        self.drain_processor_rx();
        if !self.beacon_processor_rx_queue.is_empty() {
            panic!(
                "Expected processor to be empty, but has events: {:?}",
                self.beacon_processor_rx_queue
            );
        }
    }

    fn find_block_lookup_request(
        &mut self,
        _for_block: Hash256,
    ) -> Result<SingleLookupReqId, String> {
        todo!();
    }

    #[track_caller]
    fn expect_block_lookup_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.find_block_lookup_request(for_block)
            .unwrap_or_else(|e| panic!("Expected block request for {for_block:?}: {e}"))
    }

    fn find_blob_lookup_request(
        &mut self,
        for_block: Hash256,
    ) -> Result<SingleLookupReqId, String> {
        self.pop_received_network_event(|ev| match ev {
            NetworkMessage::SendRequest {
                peer_id: _,
                request: RequestType::BlobsByRoot(request),
                app_request_id: AppRequestId::Sync(SyncRequestId::BlobsByRoot(id)),
            } if request
                .blob_ids
                .to_vec()
                .iter()
                .any(|r| r.block_root == for_block) =>
            {
                todo!();
            }
            _ => None,
        })
    }

    #[track_caller]
    fn expect_blob_lookup_request(&mut self, for_block: Hash256) -> SingleLookupReqId {
        self.find_blob_lookup_request(for_block)
            .unwrap_or_else(|e| panic!("Expected blob request for {for_block:?}: {e}"))
    }

    #[track_caller]
    fn expect_block_parent_request(&mut self, _for_block: Hash256) -> SingleLookupReqId {
        todo!();
    }

    fn expect_no_requests_for(&mut self, block_root: Hash256) {
        if let Ok(request) = self.find_block_lookup_request(block_root) {
            panic!("Expected no block request for {block_root:?} found {request:?}");
        }
        if let Ok(request) = self.find_blob_lookup_request(block_root) {
            panic!("Expected no blob request for {block_root:?} found {request:?}");
        }
    }

    /// Retrieves an unknown number of requests for data columns of `block_root`. Because peer ENRs
    /// are random, and peer selection is random, the total number of batched requests is unknown.
    fn expect_data_columns_by_root_requests(
        &mut self,
        block_root: Hash256,
        count: usize,
    ) -> DCByRootIds {
        let mut requests: DCByRootIds = vec![];
        loop {
            let req = self
                .pop_received_network_event(|ev| match ev {
                    NetworkMessage::SendRequest {
                        peer_id: _,
                        request: RequestType::DataColumnsByRoot(request),
                        app_request_id:
                            AppRequestId::Sync(id @ SyncRequestId::DataColumnsByRoot { .. }),
                    } => {
                        let matching = request
                            .data_column_ids
                            .iter()
                            .find(|id| id.block_root == block_root)?;

                        let indices = matching.columns.iter().copied().collect();
                        Some((*id, indices))
                    }
                    _ => None,
                })
                .unwrap_or_else(|e| {
                    panic!("Expected more DataColumnsByRoot requests for {block_root:?}: {e}")
                });
            requests.push(req);

            // Should never infinite loop because sync does not send requests for 0 columns
            if requests.iter().map(|r| r.1.len()).sum::<usize>() >= count {
                return requests;
            }
        }
    }

    fn expect_only_data_columns_by_root_requests(
        &mut self,
        for_block: Hash256,
        count: usize,
    ) -> DCByRootIds {
        let ids = self.expect_data_columns_by_root_requests(for_block, count);
        self.expect_empty_network();
        ids
    }

    #[track_caller]
    fn expect_block_process(&mut self, response_type: ResponseType) {
        match response_type {
            ResponseType::Block => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::WorkType::RpcBlock).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected block work event: {e}")),
            ResponseType::Blob => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::WorkType::RpcBlobs).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected blobs work event: {e}")),
            ResponseType::CustodyColumn => self
                .pop_received_processor_event(|ev| {
                    (ev.work_type() == beacon_processor::WorkType::RpcCustodyColumn).then_some(())
                })
                .unwrap_or_else(|e| panic!("Expected column work event: {e}")),
        }
    }

    fn expect_rpc_custody_column_work_event(&mut self) {
        self.pop_received_processor_event(|ev| {
            if ev.work_type() == beacon_processor::WorkType::RpcCustodyColumn {
                Some(())
            } else {
                None
            }
        })
        .unwrap_or_else(|e| panic!("Expected RPC custody column work: {e}"))
    }

    fn expect_rpc_sample_verify_work_event(&mut self) {
        self.pop_received_processor_event(|ev| {
            if ev.work_type() == beacon_processor::WorkType::RpcVerifyDataColumn {
                Some(())
            } else {
                None
            }
        })
        .unwrap_or_else(|e| panic!("Expected sample verify work: {e}"))
    }

    fn expect_sampling_result_work(&mut self) {
        self.pop_received_processor_event(|ev| {
            if ev.work_type() == beacon_processor::WorkType::SamplingResult {
                Some(())
            } else {
                None
            }
        })
        .unwrap_or_else(|e| panic!("Expected sampling result work: {e}"))
    }

    fn expect_no_work_event(&mut self) {
        self.drain_processor_rx();
        assert!(self.network_rx_queue.is_empty());
    }

    fn expect_no_penalty_for(&mut self, peer_id: PeerId) {
        self.drain_network_rx();
        let downscore_events = self
            .network_rx_queue
            .iter()
            .filter_map(|ev| match ev {
                NetworkMessage::ReportPeer {
                    peer_id: p_id, msg, ..
                } if p_id == &peer_id => Some(msg),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !downscore_events.is_empty() {
            panic!("Some downscore events for {peer_id}: {downscore_events:?}");
        }
    }

    pub fn expect_no_penalty_for_anyone(&mut self) {
        let downscore_events = self.filter_received_network_events(|ev| match ev {
            NetworkMessage::ReportPeer { peer_id, msg, .. } => Some((*peer_id, *msg)),
            _ => None,
        });
        if !downscore_events.is_empty() {
            panic!("Expected no downscoring events but found: {downscore_events:?}");
        }
    }

    #[track_caller]
    fn expect_parent_chain_process(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Ok(work) => {
                // Parent chain sends blocks one by one
                assert_eq!(work.work_type(), beacon_processor::WorkType::RpcBlock);
            }
            other => panic!(
                "Expected rpc_block from chain segment process, found {:?}",
                other
            ),
        }
    }

    #[track_caller]
    pub fn expect_empty_network(&mut self) {
        self.drain_network_rx();
        if !self.network_rx_queue.is_empty() {
            let n = self.network_rx_queue.len();
            panic!(
                "expected no network events but got {n} events, displaying first 2: {:#?}",
                self.network_rx_queue[..n.min(2)].iter().collect::<Vec<_>>()
            );
        }
    }

    #[track_caller]
    fn expect_empty_beacon_processor(&mut self) {
        match self.beacon_processor_rx.try_recv() {
            Err(mpsc::error::TryRecvError::Empty) => {} // ok
            Ok(event) => panic!("expected empty beacon processor: {:?}", event),
            other => panic!("unexpected err {:?}", other),
        }
    }

    #[track_caller]
    fn expect_empty_network_fully_synced(&mut self) {
        self.expect_empty_network();
        self.expect_no_active_lookups();
    }

    #[track_caller]
    pub fn expect_penalties(&mut self, expected_penalty_msg: &'static str) {
        let all_penalties = self.filter_received_network_events(|ev| match ev {
            NetworkMessage::ReportPeer { peer_id, msg, .. } => Some((*peer_id, *msg)),
            _ => None,
        });
        if all_penalties
            .iter()
            .any(|(_, msg)| *msg != expected_penalty_msg)
        {
            panic!(
                "Expected penalties only of {expected_penalty_msg}, but found {all_penalties:?}"
            );
        }
        self.log(&format!(
            "Found expected penalties {expected_penalty_msg}: {all_penalties:?}"
        ));
    }

    pub fn expect_no_penalties(&mut self) {
        let penalties = self.filter_received_network_events(|ev| match ev {
            NetworkMessage::ReportPeer { peer_id, msg, .. } => Some((*peer_id, *msg)),
            _ => None,
        });
        if !penalties.is_empty() {
            panic!("Expected no penalties but found {penalties:?}");
        }
    }

    #[track_caller]
    pub fn expect_penalty(&mut self, peer_id: PeerId, expect_penalty_msg: &'static str) {
        let penalty_msg = self
            .pop_received_network_event(|ev| match ev {
                NetworkMessage::ReportPeer {
                    peer_id: p_id, msg, ..
                } if p_id == &peer_id => Some(msg.to_owned()),
                _ => None,
            })
            .unwrap_or_else(|_| {
                panic!(
                    "Expected '{expect_penalty_msg}' penalty for peer {peer_id}: {:#?}",
                    self.network_rx_queue
                )
            });
        assert_eq!(
            penalty_msg, expect_penalty_msg,
            "Unexpected penalty msg for {peer_id}"
        );
        self.log(&format!("Found expected penalty {penalty_msg}"));
    }

    pub fn expect_single_penalty(&mut self, peer_id: PeerId, expect_penalty_msg: &'static str) {
        self.expect_penalty(peer_id, expect_penalty_msg);
        self.expect_no_penalty_for(peer_id);
    }

    pub fn block_with_parent_and_blobs(
        &mut self,
        parent_root: Hash256,
        num_blobs: NumBlobs,
    ) -> (SignedBeaconBlock<E>, Vec<BlobSidecar<E>>) {
        let (mut block, mut blobs) = self.rand_block_and_blobs(num_blobs);
        *block.message_mut().parent_root_mut() = parent_root;
        blobs.iter_mut().for_each(|blob| {
            blob.signed_block_header = block.signed_block_header();
        });
        (block, blobs)
    }

    pub fn rand_blockchain(&mut self, depth: usize) -> Vec<Arc<SignedBeaconBlock<E>>> {
        let mut blocks = Vec::<Arc<SignedBeaconBlock<E>>>::with_capacity(depth);
        for slot in 0..depth {
            let parent = blocks
                .last()
                .map(|b| b.canonical_root())
                .unwrap_or_else(Hash256::random);
            let mut block = self.rand_block();
            *block.message_mut().parent_root_mut() = parent;
            *block.message_mut().slot_mut() = slot.into();
            blocks.push(block.into());
        }
        self.log(&format!(
            "Blockchain dump {:#?}",
            blocks
                .iter()
                .map(|b| format!(
                    "block {} {} parent {}",
                    b.slot(),
                    b.canonical_root(),
                    b.parent_root()
                ))
                .collect::<Vec<_>>()
        ));
        blocks
    }

    fn assert_sampling_request_ongoing(&self, block_root: Hash256, indices: &[ColumnIndex]) {
        for index in indices {
            let status = self
                .sync_manager
                .get_sampling_request_status(block_root, index)
                .unwrap_or_else(|| panic!("No request state for {index}"));
            if !matches!(status, crate::sync::peer_sampling::Status::Sampling { .. }) {
                panic!("expected {block_root} {index} request to be on going: {status:?}");
            }
        }
    }

    fn assert_sampling_request_nopeers(&self, block_root: Hash256, indices: &[ColumnIndex]) {
        for index in indices {
            let status = self
                .sync_manager
                .get_sampling_request_status(block_root, index)
                .unwrap_or_else(|| panic!("No request state for {index}"));
            if !matches!(status, crate::sync::peer_sampling::Status::NoPeers) {
                panic!("expected {block_root} {index} request to be no peers: {status:?}");
            }
        }
    }

    fn log_sampling_requests(&self, block_root: Hash256, indices: &[ColumnIndex]) {
        let statuses = indices
            .iter()
            .map(|index| {
                let status = self
                    .sync_manager
                    .get_sampling_request_status(block_root, index)
                    .unwrap_or_else(|| panic!("No request state for {index}"));
                (index, status)
            })
            .collect::<Vec<_>>();
        self.log(&format!(
            "Sampling request status for {block_root}: {statuses:?}"
        ));
    }

    async fn single_lookup_from_attestation_setup(&mut self) -> (Hash256, PeerId) {
        let (head_root, head_slot) = self.create_unimported_parent_chain(1).await;
        let peer_id = self.new_connected_peer();
        // Trigger the request
        self.trigger_unknown_block_from_attestation(head_root, peer_id);
        self.expect_block_lookup_request(head_root);
        (head_root, peer_id)
    }

    async fn parent_lookup_from_unknown_block_parent_setup(&mut self) -> (Hash256, PeerId) {
        let (head_root, head_slot) = self.create_unimported_parent_chain(2).await;
        let peer_id = self.new_connected_peer();
        let head_block = self
            .blocks_by_root
            .get(&head_root)
            .expect("block should exist");
        self.trigger_unknown_parent_block(peer_id, head_block.clone());
        (head_root, peer_id)
    }

    fn expect_fully_complete_sync(&mut self, expected_head_root: Hash256) {
        self.progress_until_no_events(NO_FILTER, complete());
        self.assert_head(expected_head_root);
        self.expect_empty_network_fully_synced();
    }

    fn assert_head(&self, expected_head: Hash256) {
        let head = self.harness.chain.head();
        assert_eq!(
            head.head_block_root(),
            expected_head,
            "Not expected head root"
        );
    }

    fn fetch_ancestor_chain(&self, mut block_root: Hash256) -> Vec<Hash256> {
        let mut chain = vec![];
        while let Some(block) = self.blocks_by_root.get(&block_root) {
            chain.push(block_root);
            block_root = block.parent_root();
        }
        chain
    }
}

#[test]
fn stable_rng() {
    let spec = types::MainnetEthSpec::default_spec();
    let mut rng = XorShiftRng::from_seed([42; 16]);
    let (block, _) =
        generate_rand_block_and_blobs::<E>(ForkName::Base, NumBlobs::None, &mut rng, &spec);
    assert_eq!(
        block.canonical_root(),
        Hash256::from_slice(
            &hex::decode("adfd2e9e7a7976e8ccaed6eaf0257ed36a5b476732fee63ff44966602fd099ec")
                .unwrap()
        ),
        "rng produces a consistent value"
    );
}

#[tokio::test]
async fn test_single_block_lookup_happy_path() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.single_lookup_from_attestation_setup().await;
    r.expect_fully_complete_sync(new_head_root);
}

// Tests that if a peer does not respond with a block, we downscore and retry the block only
#[tokio::test]
async fn test_single_block_lookup_empty_response() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.single_lookup_from_attestation_setup().await;
    r.progress_until_no_events(NO_FILTER, complete().return_no_blocks());
    r.expect_penalties("NotEnoughResponsesReturned");
    r.expect_fully_complete_sync(new_head_root);
}

#[tokio::test]
async fn test_single_block_lookup_wrong_response() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.single_lookup_from_attestation_setup().await;
    r.progress_until_no_events(NO_FILTER, complete().return_wrong_blocks());
    r.expect_penalties("UnrequestedBlockRoot");
    r.expect_fully_complete_sync(new_head_root);
}

#[tokio::test]
async fn test_single_block_lookup_failure() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.single_lookup_from_attestation_setup().await;
    r.progress_until_no_events(
        NO_FILTER,
        complete().rpc_error(RPCError::UnsupportedProtocol),
    );
    r.expect_no_penalties();
    r.expect_fully_complete_sync(new_head_root);
}

#[tokio::test]
async fn test_single_block_lookup_peer_disconnected_then_rpc_error() {
    let mut r = TestRig::test_setup();
    let (new_head_root, peer_id) = r.single_lookup_from_attestation_setup().await;
    // The peer disconnect event reaches sync before the rpc error.
    r.peer_disconnected(peer_id);
    // The lookup is not removed as it can still potentially make progress.
    r.assert_active_lookup(new_head_root);
    // The request fails.
    r.progress_until_no_events(NO_FILTER, complete().rpc_error(RPCError::Disconnected));
    r.expect_fully_complete_sync(new_head_root);
}

#[tokio::test]
async fn test_parent_lookup_happy_path() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.parent_lookup_from_unknown_block_parent_setup().await;
    r.expect_fully_complete_sync(new_head_root);
}

#[tokio::test]
async fn test_parent_lookup_wrong_response() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.parent_lookup_from_unknown_block_parent_setup().await;
    r.progress_until_no_events(NO_FILTER, complete().return_wrong_blocks());
    r.expect_penalties("UnrequestedBlockRoot");
    r.expect_fully_complete_sync(new_head_root);
}

#[tokio::test]
async fn test_parent_lookup_rpc_failure() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.parent_lookup_from_unknown_block_parent_setup().await;
    r.progress_until_no_events(
        NO_FILTER,
        complete().rpc_error_response(RpcErrorResponse::ResourceUnavailable),
    );
    r.expect_no_penalties();
    r.expect_fully_complete_sync(new_head_root);
}

// TODO(tree-sync): test blacklist feature
#[tokio::test]
async fn test_parent_lookup_too_many_attempts() {
    let mut r = TestRig::test_setup();
    let (new_head_root, _) = r.parent_lookup_from_unknown_block_parent_setup().await;

    for i in 1..=PARENT_FAIL_TOLERANCE {
        r.progress_until_no_events(
            NO_FILTER,
            complete().rpc_error_response(RpcErrorResponse::ResourceUnavailable),
        );
    }

    r.expect_no_active_lookups_empty_network();
}

#[tokio::test]
async fn test_lookup_peer_disconnected_no_peers_left_while_request() {
    let mut r = TestRig::test_setup();
    let (head_root, peer_id) = r.single_lookup_from_attestation_setup().await;
    r.peer_disconnected(peer_id);
    r.rpc_error_all_active_requests(peer_id);
    // Erroring all rpc requests and disconnecting the peer shouldn't remove the requests
    // from the lookups map as they can still progress.
    r.assert_active_lookup(head_root);
}

#[tokio::test]
async fn test_lookup_disconnection_peer_left() {
    let mut r = TestRig::test_setup();
    let (head_root, peer_1) = r.single_lookup_from_attestation_setup().await;
    let peer_2 = r.new_connected_peer();
    r.trigger_unknown_block_from_attestation(head_root, peer_2);
    // Disconnect the first peer only, which is the one handling the request
    r.peer_disconnected(peer_1);
    r.rpc_error_all_active_requests(peer_1);
    r.assert_active_lookup(head_root);
}

#[tokio::test]
async fn test_lookup_add_peers_to_parent() {
    let mut r = TestRig::test_setup();
    let (head_root, _) = r.create_unimported_parent_chain(4).await;
    let chain = r.fetch_ancestor_chain(head_root);
    let peer_id = r.new_connected_peer();
    r.trigger_unknown_block_from_attestation(head_root, peer_id);
    r.progress_until_no_events(filter().header_requests_only(), complete());

    let new_peers = (0..2).map(|_| r.new_connected_peer()).collect::<Vec<_>>();
    for peer in &new_peers {
        r.trigger_unknown_block_from_attestation(head_root, *peer);
    }
    for block in chain {
        // Parent has the original unknown parent event peer + new peer
        r.assert_lookup_peers(block, &new_peers);
    }
}

#[test]
fn sampling_happy_path() {
    let Some(mut r) = TestRig::test_setup_after_fulu() else {
        return;
    };
    r.new_connected_peers_for_peerdas();
    let (block, data_columns) = r.rand_block_and_data_columns();
    let block_root = block.canonical_root();
    r.trigger_sample_block(block_root, block.slot());
    // Retrieve all outgoing sample requests for random column indexes
    r.progress_until_no_events(NO_FILTER, complete());
    r.expect_clean_finished_sampling();
}

#[test]
fn sampling_with_retries() {
    let Some(mut r) = TestRig::test_setup_after_fulu() else {
        return;
    };
    r.new_connected_peers_for_peerdas();
    // Add another supernode to ensure that the node can retry.
    r.new_connected_supernode_peer();
    let (block, data_columns) = r.rand_block_and_data_columns();
    let block_root = block.canonical_root();
    r.trigger_sample_block(block_root, block.slot());
    r.progress_until_no_events(NO_FILTER, complete().empty_sampling_response_once());
    r.expect_clean_finished_sampling();
}

#[test]
fn sampling_avoid_retrying_same_peer() {
    let Some(mut r) = TestRig::test_setup_after_fulu() else {
        return;
    };
    let peer_1 = r.new_connected_supernode_peer();
    let block_root = Hash256::random();
    r.trigger_sample_block(block_root, Slot::new(0));
    // Retrieve all outgoing sample requests for random column indexes, and return empty responses
    r.progress_until_no_events(
        filter().peer(peer_1),
        complete().rpc_error(RPCError::Disconnected),
    );
    // Should retry the other peer
    let peer_2 = r.new_connected_supernode_peer();
    r.progress_until_no_events(
        filter().peer(peer_2),
        complete().rpc_error(RPCError::Disconnected),
    );
    // Expect no more retries
    r.expect_empty_network();
}

#[test]
fn sampling_batch_requests() {
    let Some(mut r) = TestRig::test_setup_after_fulu() else {
        return;
    };
    let _supernode = r.new_connected_supernode_peer();
    let (block, data_columns) = r.rand_block_and_data_columns();
    let block_root = block.canonical_root();
    r.trigger_sample_block(block_root, block.slot());

    // Retrieve the sample request, which should be batched.
    let (_, column_indexes) = r
        .expect_only_data_columns_by_root_requests(block_root, 1)
        .pop()
        .unwrap();
    assert_eq!(column_indexes.len(), SAMPLING_REQUIRED_SUCCESSES);
    r.assert_sampling_request_ongoing(block_root, &column_indexes);

    r.progress_until_no_events(NO_FILTER, complete());
    r.expect_clean_finished_sampling();
}

#[test]
fn sampling_batch_requests_not_enough_responses_returned() {
    let Some(mut r) = TestRig::test_setup_after_fulu() else {
        return;
    };
    let _supernode = r.new_connected_supernode_peer();
    let (block, data_columns) = r.rand_block_and_data_columns();
    let block_root = block.canonical_root();
    r.trigger_sample_block(block_root, block.slot());

    // Retrieve the sample request, which should be batched.
    let (sync_request_id, column_indexes) = r
        .expect_only_data_columns_by_root_requests(block_root, 1)
        .pop()
        .unwrap();
    assert_eq!(column_indexes.len(), SAMPLING_REQUIRED_SUCCESSES);

    // The request status should be set to Sampling.
    r.assert_sampling_request_ongoing(block_root, &column_indexes);

    // Split the indexes to simulate the case where the supernode doesn't have the requested column.
    let missing_custody_index = *column_indexes.first().unwrap();
    let (column_indexes_supernode_does_not_have, column_indexes_to_complete) =
        column_indexes.split_at(1);

    // Complete the requests but only partially, so a NotEnoughResponsesReturned error occurs.
    r.progress_until_no_events(
        NO_FILTER,
        complete().custody_failure_at_index(missing_custody_index),
    );

    // The request status should be set to NoPeers since the supernode, the only peer, returned not enough responses.
    r.log_sampling_requests(block_root, &column_indexes);
    r.assert_sampling_request_nopeers(block_root, column_indexes_supernode_does_not_have);

    // The sampling request stalls.
    r.expect_empty_network();
    r.expect_no_work_event();
    r.expect_active_sampling(&block_root);
}
