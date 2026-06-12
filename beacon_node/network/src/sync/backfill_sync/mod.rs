//! This module contains the logic for Lighthouse's backfill sync.
//!
//! This kind of sync occurs when a trusted state is provided to the client. The client will perform
//! a [`RangeSync`] to the latest head from the trusted state, such that the client can perform its
//! duties right away. Once completed, a backfill sync occurs, where all old blocks (back to the weak
//! subjectivity point or genesis) are downloaded to keep a consistent history.
//!
//! Backfill walks the parent chain of the current anchor using the `beacon_blocks_by_head` RPC: a
//! single request returns a run of ancestors of the anchor in descending slot order. The pipeline is
//! linear and processes one segment at a time:
//!
//! 1. Fetch ancestors: request `beacon_blocks_by_head(beacon_root = oldest_block_parent)`.
//! 2. Fetch their data (blobs/data columns) by root for blocks within the data-availability window.
//! 3. Process the segment, which imports the blocks and advances the store anchor.
//!
//! The store's [`AnchorInfo`] (`oldest_block_parent` / `oldest_block_slot`) is the cursor: each
//! segment is read from and advanced in the store, so backfill keeps no separate epoch bookkeeping.

use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::{
    AncestorBlocks, CustodyByRootResult, LookupRequestResult, RpcRequestSendError,
    RpcResponseResult, SyncNetworkContext,
};
use beacon_chain::block_verification_types::RangeSyncBlock;
use beacon_chain::data_availability_checker::AvailableBlockData;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::service::api_types::SingleLookupReqId;
use lighthouse_network::types::{BackFillState, NetworkGlobals};
use lighthouse_network::{PeerAction, PeerId};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use types::{DataColumnSidecarList, Epoch, EthSpec, Hash256, SignedBeaconBlock};

/// Number of epochs worth of blocks per custody-backfill batch. Block backfill walks the parent
/// chain via `beacon_blocks_by_head` and no longer uses epoch batches, but custody backfill still
/// references this constant.
pub const BACKFILL_EPOCHS_PER_BATCH: u64 = 1;

/// Return type when attempting to start the backfill sync process.
pub enum SyncStart {
    /// The chain started syncing or is already syncing.
    Syncing {
        /// The number of slots that have been processed so far.
        completed: usize,
        /// The number of slots still to be processed.
        remaining: usize,
    },
    /// The chain didn't start syncing.
    NotSyncing,
}

/// A standard result from calling public functions on [`BackFillSync`].
pub enum ProcessResult {
    /// The call was successful.
    Successful,
    /// The call resulted in completing the backfill sync.
    SyncCompleted,
}

/// The current step of the linear backfill pipeline. Only one segment is in flight at a time.
enum BackFillStep<E: EthSpec> {
    /// Ready to request the next run of ancestors from the current anchor.
    Idle,
    /// A `beacon_blocks_by_head` request is in flight for the current anchor.
    FetchingAncestors { req_id: SingleLookupReqId },
    /// Ancestors are downloaded; custody data columns are being fetched by root for the blocks that
    /// require them before the segment can be processed.
    FetchingData(Box<DataFetch<E>>),
    /// A back-sync segment is being processed by the beacon processor. `peers` are exactly the peers
    /// that served this segment (the block peer plus any custody-column peers), so a faulty result
    /// penalizes only them.
    Processing {
        epoch: Epoch,
        peers: HashSet<PeerId>,
    },
}

/// Tracks the per-block custody column fetch for a single discovered segment. `blocks` are in
/// slot-ascending order; `columns` accumulates the fetched columns keyed by block root; `pending`
/// is the set of block roots whose custody request has not yet completed.
struct DataFetch<E: EthSpec> {
    blocks: Vec<Arc<SignedBeaconBlock<E>>>,
    columns: HashMap<Hash256, DataColumnSidecarList<E>>,
    pending: HashSet<Hash256>,
    /// Synced peers used to satisfy the custody requests for this segment.
    candidate_peers: Arc<RwLock<HashSet<PeerId>>>,
    /// Peers that actually served this segment (block peer + custody-column peers), penalized
    /// together if the segment fails to process.
    responsible_peers: HashSet<PeerId>,
}

pub struct BackFillSync<T: BeaconChainTypes> {
    /// Current step of the linear pipeline.
    step: BackFillStep<T::EthSpec>,

    /// Number of blocks successfully imported by this backfill (for logging/metrics).
    imported_blocks: u64,

    /// Reference to the beacon chain to obtain the anchor cursor and import historical blocks.
    beacon_chain: Arc<BeaconChain<T>>,

    /// Reference to the network globals in order to obtain valid peers to backfill blocks from
    /// (i.e synced peers).
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
}

impl<T: BeaconChainTypes> BackFillSync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    ) -> Self {
        // If backfill has already completed (or we started from a trusted genesis root) then mark it
        // completed, otherwise it begins paused until peers are available.
        let anchor_info = beacon_chain.store.get_anchor_info();
        let state = if anchor_info.block_backfill_complete(beacon_chain.genesis_backfill_slot) {
            BackFillState::Completed
        } else {
            BackFillState::Paused
        };

        let bfs = BackFillSync {
            step: BackFillStep::Idle,
            imported_blocks: 0,
            beacon_chain,
            network_globals,
        };

        bfs.set_state(state);
        bfs
    }

    /// Pauses the backfill sync if it's currently syncing.
    pub fn pause(&mut self) {
        if let BackFillState::Syncing = self.state() {
            debug!(
                imported_blocks = self.imported_blocks,
                "Backfill sync paused"
            );
            self.set_state(BackFillState::Paused);
        }
    }

    /// Starts or resumes syncing.
    ///
    /// If resuming is successful, reports back the current syncing metrics.
    ///
    /// Backfill is infallible: it never enters a terminal failed state. If it cannot make progress
    /// (no peers, bad data) it pauses and is resumed by a later `start` call.
    pub fn start(&mut self, network: &mut SyncNetworkContext<T>) -> SyncStart {
        match self.state() {
            BackFillState::Syncing => {} // already syncing, ignore.
            // `Failed` is never set anymore, but resume from it defensively like `Paused`.
            BackFillState::Paused | BackFillState::Failed => {
                self.set_state(BackFillState::Syncing);
                self.request_ancestors(network);
                // `request_ancestors` may pause again (no eligible peers) or complete (genesis).
                if !matches!(self.state(), BackFillState::Syncing) {
                    return SyncStart::NotSyncing;
                }
            }
            BackFillState::Completed => {
                return SyncStart::NotSyncing;
            }
        }

        let anchor_info = self.beacon_chain.store.get_anchor_info();
        let completed = anchor_info
            .anchor_slot
            .as_usize()
            .saturating_sub(anchor_info.oldest_block_slot.as_usize());
        let remaining = anchor_info
            .oldest_block_slot
            .as_usize()
            .saturating_sub(self.beacon_chain.genesis_backfill_slot.as_usize());
        SyncStart::Syncing {
            completed,
            remaining,
        }
    }

    /// Requests the next run of ancestors from the current anchor via `beacon_blocks_by_head`.
    fn request_ancestors(&mut self, network: &mut SyncNetworkContext<T>) {
        // Only request if syncing and no segment is already in flight.
        if self.state() != BackFillState::Syncing || !matches!(self.step, BackFillStep::Idle) {
            return;
        }

        let anchor_info = self.beacon_chain.store.get_anchor_info();
        if anchor_info.block_backfill_complete(self.beacon_chain.genesis_backfill_slot) {
            self.complete_sync();
            return;
        }

        // backfill can't progress without peers in the required custody subnets post-PeerDAS.
        if !self.good_peers_on_sampling_subnets(
            anchor_info.oldest_block_slot.epoch(slots_per_epoch::<T>()),
            network,
        ) {
            debug!("Waiting for peers on custody column subnets, pausing backfill");
            self.set_state(BackFillState::Paused);
            return;
        }

        let synced_peers = self
            .network_globals
            .peers
            .read()
            .synced_peers_for_epoch(anchor_info.oldest_block_slot.epoch(slots_per_epoch::<T>()))
            .cloned()
            .collect::<HashSet<_>>();

        match network
            .backfill_blocks_by_head_request(anchor_info.oldest_block_parent, &synced_peers)
        {
            Ok((req_id, peer_id)) => {
                self.step = BackFillStep::FetchingAncestors { req_id };
                debug!(
                    anchor_root = ?anchor_info.oldest_block_parent,
                    anchor_slot = %anchor_info.oldest_block_slot,
                    %peer_id,
                    "Requesting backfill ancestors"
                );
            }
            Err(RpcRequestSendError::NoPeer(_)) => {
                // No synced peer advertising `beacon_blocks_by_head`. Pause until a suitable peer
                // joins; `start` will resume.
                info!("Backfill sync paused: no peers advertising beacon_blocks_by_head");
                self.set_state(BackFillState::Paused);
            }
            Err(RpcRequestSendError::InternalError(e)) => {
                warn!(error = ?e, "Could not send backfill ancestors request");
                self.set_state(BackFillState::Paused);
            }
        }
    }

    /// A `beacon_blocks_by_head` response has been received for the current segment. The run is the
    /// anchor block followed by its ancestors in descending slot order.
    pub fn on_blocks_by_head_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        request_id: SingleLookupReqId,
        peer_id: PeerId,
        result: RpcResponseResult<AncestorBlocks<T::EthSpec>>,
    ) -> ProcessResult {
        // Ignore stale responses that don't match the in-flight request.
        match &self.step {
            BackFillStep::FetchingAncestors { req_id, .. } if *req_id == request_id => {}
            _ => {
                debug!(?request_id, %peer_id, "Unexpected backfill ancestors response");
                return ProcessResult::Successful;
            }
        }
        self.step = BackFillStep::Idle;

        let ancestor_blocks = match result {
            Ok((ancestor_blocks, _seen_timestamp)) => ancestor_blocks,
            Err(e) => {
                debug!(?request_id, %peer_id, error = ?e, "Backfill ancestors request failed");
                network.report_peer(
                    peer_id,
                    PeerAction::LowToleranceError,
                    "backfill_ancestors_failed",
                );
                // Retry from a different peer.
                self.request_ancestors(network);
                return ProcessResult::Successful;
            }
        };

        // Collect the run anchor-first (descending), then reverse to slot-ascending order as
        // required by `import_historical_block_batch`.
        let mut blocks = Vec::with_capacity(ancestor_blocks.ancestor_blocks.len() + 1);
        blocks.push(ancestor_blocks.first_block);
        blocks.extend(ancestor_blocks.ancestor_blocks);
        blocks.reverse();

        if blocks.is_empty() {
            self.request_ancestors(network);
            return ProcessResult::Successful;
        }

        // Blocks below the data-availability window (or pre-Deneb) need no sidecars and process
        // immediately. If any block requires data columns, fetch them by root first.
        if blocks.iter().any(Self::block_needs_data) {
            return self.start_data_fetch(network, blocks, peer_id);
        }

        self.couple_and_process(network, blocks, HashMap::new(), HashSet::from([peer_id]))
    }

    /// Returns true if we must fetch data columns by root before the block can be coupled. Gloas
    /// blocks carry their data in the execution payload envelope, which we do not backfill, so they
    /// are imported block-only and need no fetch.
    fn block_needs_data(block: &Arc<SignedBeaconBlock<T::EthSpec>>) -> bool {
        !block.fork_name_unchecked().gloas_enabled() && block.num_expected_blobs() > 0
    }

    /// Begins fetching custody data columns by root for the blocks that require them. Once every
    /// custody request completes, the segment is coupled and processed.
    fn start_data_fetch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
        block_peer: PeerId,
    ) -> ProcessResult {
        let segment_epoch = blocks
            .last()
            .map(|b| b.slot().epoch(slots_per_epoch::<T>()))
            .unwrap_or_else(|| Epoch::new(0));
        let candidate_peers = Arc::new(RwLock::new(
            self.network_globals
                .peers
                .read()
                .synced_peers_for_epoch(segment_epoch)
                .cloned()
                .collect::<HashSet<_>>(),
        ));

        let mut fetch = DataFetch {
            blocks,
            columns: HashMap::new(),
            pending: HashSet::new(),
            candidate_peers,
            responsible_peers: HashSet::from([block_peer]),
        };

        let to_fetch = fetch
            .blocks
            .iter()
            .filter(|b| Self::block_needs_data(b))
            .map(|b| (b.canonical_root(), b.slot()))
            .collect::<Vec<_>>();

        for (block_root, block_slot) in to_fetch {
            match network.backfill_custody_request(
                block_root,
                block_slot,
                fetch.candidate_peers.clone(),
            ) {
                Ok(LookupRequestResult::RequestSent(_)) => {
                    fetch.pending.insert(block_root);
                }
                Ok(LookupRequestResult::NoRequestNeeded(_, columns)) => {
                    // Columns already available (e.g. cached from gossip); no request in flight.
                    fetch.columns.insert(block_root, columns);
                }
                Ok(LookupRequestResult::Pending(reason)) => {
                    debug!(
                        ?block_root,
                        reason, "Backfill custody request pending, pausing"
                    );
                    self.set_state(BackFillState::Paused);
                    return ProcessResult::Successful;
                }
                Err(e) => {
                    debug!(?block_root, error = ?e, "Backfill custody request failed, pausing");
                    self.set_state(BackFillState::Paused);
                    return ProcessResult::Successful;
                }
            }
        }

        self.step = BackFillStep::FetchingData(Box::new(fetch));
        // If every needed block was already satisfied from cache, finish immediately.
        self.try_finish_data_fetch(network)
    }

    /// A custody (data-columns-by-root) request issued by backfill has completed for `block_root`.
    pub fn on_custody_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        block_root: Hash256,
        result: CustodyByRootResult<T::EthSpec>,
    ) -> ProcessResult {
        let BackFillStep::FetchingData(fetch) = &mut self.step else {
            debug!(?block_root, "Unexpected backfill custody response");
            return ProcessResult::Successful;
        };
        if !fetch.pending.remove(&block_root) {
            debug!(?block_root, "Backfill custody response for unknown block");
            return ProcessResult::Successful;
        }

        match result {
            Ok(download) => {
                // Record the custody-column peers so a faulty segment penalizes them too.
                fetch
                    .responsible_peers
                    .extend(download.peer_group.all().copied());
                fetch.columns.insert(block_root, download.value);
                self.try_finish_data_fetch(network)
            }
            Err(e) => {
                debug!(?block_root, error = ?e, "Backfill custody request failed, pausing");
                // Drop the in-flight segment; a restart re-requests it from the store anchor.
                self.step = BackFillStep::Idle;
                self.set_state(BackFillState::Paused);
                ProcessResult::Successful
            }
        }
    }

    /// If all custody fetches for the current segment have completed, couple the blocks with their
    /// data and submit the segment for processing.
    fn try_finish_data_fetch(&mut self, network: &mut SyncNetworkContext<T>) -> ProcessResult {
        match &self.step {
            BackFillStep::FetchingData(fetch) if fetch.pending.is_empty() => {}
            _ => return ProcessResult::Successful,
        }

        let BackFillStep::FetchingData(fetch) =
            std::mem::replace(&mut self.step, BackFillStep::Idle)
        else {
            unreachable!("step checked to be FetchingData above");
        };
        let DataFetch {
            blocks,
            columns,
            responsible_peers,
            ..
        } = *fetch;

        self.couple_and_process(network, blocks, columns, responsible_peers)
    }

    /// Couples a discovered segment with its data and submits it for processing. If coupling fails
    /// (inconsistent data from a peer) the segment is dropped and a fresh request is made.
    fn couple_and_process(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        blocks: Vec<Arc<SignedBeaconBlock<T::EthSpec>>>,
        columns: HashMap<Hash256, DataColumnSidecarList<T::EthSpec>>,
        peers: HashSet<PeerId>,
    ) -> ProcessResult {
        match self.couple_blocks(network, &blocks, &columns) {
            Ok(segment) => self.process_segment(network, segment, peers),
            Err(reason) => {
                warn!(
                    reason,
                    "Backfill segment coupling failed, retrying from a new peer"
                );
                self.step = BackFillStep::Idle;
                self.request_ancestors(network);
                ProcessResult::Successful
            }
        }
    }

    /// Couples each discovered block with its data into a [`RangeSyncBlock`]. Blocks needing data
    /// columns use the fetched `columns`; others are imported as [`AvailableBlockData::NoData`].
    fn couple_blocks(
        &self,
        network: &SyncNetworkContext<T>,
        blocks: &[Arc<SignedBeaconBlock<T::EthSpec>>],
        columns: &HashMap<Hash256, DataColumnSidecarList<T::EthSpec>>,
    ) -> Result<Vec<RangeSyncBlock<T::EthSpec>>, String> {
        let da_checker = &network.chain.data_availability_checker;
        let spec = network.chain.spec.clone();

        let mut segment = Vec::with_capacity(blocks.len());
        for block in blocks {
            let range_block = if block.fork_name_unchecked().gloas_enabled() {
                // Gloas data lives in the execution payload envelope, which we do not backfill.
                RangeSyncBlock::new_gloas(block.clone(), None)
                    .map_err(|e| format!("coupling backfill gloas block: {e}"))?
            } else {
                let block_data = if block.num_expected_blobs() > 0 {
                    let cols = columns
                        .get(&block.canonical_root())
                        .cloned()
                        .unwrap_or_default();
                    AvailableBlockData::new_with_data_columns(cols)
                } else {
                    AvailableBlockData::NoData
                };
                RangeSyncBlock::new(block.clone(), block_data, da_checker, spec.clone())
                    .map_err(|e| format!("coupling backfill block: {e:?}"))?
            };
            segment.push(range_block);
        }
        Ok(segment)
    }

    /// Submits a coupled segment to the beacon processor for back-sync import. `peers` are the peers
    /// that served the segment, penalized together if it fails to process.
    fn process_segment(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        segment: Vec<RangeSyncBlock<T::EthSpec>>,
        peers: HashSet<PeerId>,
    ) -> ProcessResult {
        if segment.is_empty() {
            self.request_ancestors(network);
            return ProcessResult::Successful;
        }

        // The epoch is only used for logging/identification of the back-sync batch.
        let epoch = segment
            .first()
            .map(|b| b.as_block().slot().epoch(slots_per_epoch::<T>()))
            .unwrap_or_else(|| Epoch::new(0));
        self.step = BackFillStep::Processing { epoch, peers };

        if let Err(e) = network
            .beacon_processor()
            .send_chain_segment(ChainSegmentProcessId::BackSyncBatchId(epoch), segment)
        {
            error!(error = %e, "Failed to send backfill segment to processor");
            self.step = BackFillStep::Idle;
            // Re-request so the segment isn't lost.
            self.request_ancestors(network);
        }

        ProcessResult::Successful
    }

    /// The beacon processor has completed processing the in-flight segment.
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        epoch: Epoch,
        result: &BatchProcessResult,
    ) -> ProcessResult {
        match &self.step {
            BackFillStep::Processing {
                epoch: expected, ..
            } if *expected == epoch => {}
            _ => {
                debug!(%epoch, "Backfill was not expecting a segment result");
                return ProcessResult::Successful;
            }
        }
        let BackFillStep::Processing { peers, .. } =
            std::mem::replace(&mut self.step, BackFillStep::Idle)
        else {
            unreachable!("step checked to be Processing above");
        };

        match result {
            BatchProcessResult::Success {
                imported_blocks, ..
            } => {
                self.imported_blocks = self.imported_blocks.saturating_add(*imported_blocks as u64);
                debug!(%epoch, imported_blocks, "Backfill segment imported");

                // The store anchor has advanced as part of the import; check if we are done.
                if self
                    .beacon_chain
                    .store
                    .get_anchor_info()
                    .block_backfill_complete(self.beacon_chain.genesis_backfill_slot)
                {
                    self.complete_sync();
                    return ProcessResult::SyncCompleted;
                }

                // Request the next run of ancestors.
                self.request_ancestors(network);
                ProcessResult::Successful
            }
            BatchProcessResult::FaultyFailure { penalty, .. } => {
                // The segment failed validation (bad signatures/proofs). Penalize exactly the peers
                // that served it and retry from fresh peers; backfill never fails terminally.
                warn!(score_adjustment = %penalty, %epoch, "Backfill segment failed processing, penalizing peers and retrying");
                for peer in peers {
                    network.report_peer(peer, *penalty, "backfill_segment_failed");
                }
                self.request_ancestors(network);
                ProcessResult::Successful
            }
            BatchProcessResult::NonFaultyFailure => {
                debug!(%epoch, "Backfill segment non-faulty failure, retrying");
                self.request_ancestors(network);
                ProcessResult::Successful
            }
        }
    }

    /// Marks the backfill as completed and updates the global sync state.
    fn complete_sync(&mut self) {
        info!(
            imported_blocks = self.imported_blocks,
            "Backfill sync completed"
        );
        self.set_state(BackFillState::Completed);
        self.step = BackFillStep::Idle;
    }

    /// Checks all sampling column subnets for peers. Returns `true` if there is at least one peer in
    /// every sampling column subnet, or if PeerDAS isn't enabled for the epoch.
    fn good_peers_on_sampling_subnets(
        &self,
        epoch: Epoch,
        network: &SyncNetworkContext<T>,
    ) -> bool {
        if network.chain.spec.is_peer_das_enabled_for_epoch(epoch) {
            network
                .network_globals()
                .sampling_subnets()
                .iter()
                .all(|subnet_id| {
                    let min_peer_count = 1;
                    network
                        .network_globals()
                        .peers
                        .read()
                        .has_good_peers_in_custody_subnet(subnet_id, min_peer_count)
                })
        } else {
            true
        }
    }

    pub fn register_metrics(&self) {
        // Metrics for the linear backfill pipeline are reported via the global backfill state.
    }

    /// Updates the global network state indicating the current state of a backfill sync.
    fn set_state(&self, state: BackFillState) {
        *self.network_globals.backfill_state.write() = state;
    }

    fn state(&self) -> BackFillState {
        self.network_globals.backfill_state.read().clone()
    }
}

/// Convenience for `T::EthSpec::slots_per_epoch()`.
fn slots_per_epoch<T: BeaconChainTypes>() -> u64 {
    T::EthSpec::slots_per_epoch()
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_chain::test_utils::BeaconChainHarness;
    use lighthouse_network::NetworkConfig;
    use types::MinimalEthSpec;

    #[test]
    fn start_with_no_peers_does_not_sync() {
        let harness = BeaconChainHarness::builder(MinimalEthSpec)
            .default_spec()
            .deterministic_keypairs(8)
            .fresh_ephemeral_store()
            .build();

        let beacon_chain = harness.chain.clone();
        let network_globals = Arc::new(NetworkGlobals::new_test_globals(
            vec![],
            Arc::new(NetworkConfig::default()),
            beacon_chain.spec.clone(),
        ));

        let mut network = SyncNetworkContext::new_for_testing(
            beacon_chain.clone(),
            network_globals.clone(),
            harness.runtime.task_executor.clone(),
        );

        let mut backfill = BackFillSync::new(beacon_chain, network_globals);
        backfill.set_state(BackFillState::Paused);

        // With no peers advertising `beacon_blocks_by_head`, starting must not sync and must not
        // panic.
        let result = backfill.start(&mut network);
        assert!(matches!(result, SyncStart::NotSyncing));
    }
}
