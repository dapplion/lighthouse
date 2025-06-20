//! This module contains the logic for Lighthouse's backfill sync.
//!
//! This kind of sync occurs when a trusted state is provided to the client. The client
//! will perform a [`RangeSync`] to the latest head from the trusted state, such that the
//! client can perform its duties right away. Once completed, a backfill sync occurs, where all old
//! blocks (from genesis) are downloaded in order to keep a consistent history.
//!
//! If a batch fails, the backfill sync cannot progress. In this scenario, we mark the backfill
//! sync as failed, log an error and attempt to retry once a new peer joins the node.

use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::{
    BatchPeers, RangeRequestId, RpcResponseError, SyncNetworkContext,
};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::service::api_types::Id;
use lighthouse_network::types::{BackFillState, NetworkGlobals};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use types::{Epoch, EthSpec, Hash256};

/// The number of times to retry a batch before it is considered failed.
const MAX_BATCH_DOWNLOAD_ATTEMPTS: u8 = 10;

/// Invalid batches are attempted to be re-downloaded from other peers. If a batch cannot be processed
/// after `MAX_BATCH_PROCESSING_ATTEMPTS` times, it is considered faulty.
const MAX_BATCH_PROCESSING_ATTEMPTS: u8 = 10;

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

/// The ways a backfill sync can fail.
// The info in the enum variants is displayed in logging, clippy thinks it's dead code.
#[derive(Debug)]
pub enum BackFillError {
    /// A batch failed to be downloaded.
    BatchDownloadFailed(#[allow(dead_code)] Id),
    /// A batch could not be processed.
    BatchProcessingFailed(#[allow(dead_code)] Id),
    /// A batch entered an invalid state.
    BatchInvalidState(#[allow(dead_code)] Id, #[allow(dead_code)] String),
    /// The sync algorithm entered an invalid state.
    InvalidSyncState(#[allow(dead_code)] String),
    /// The chain became paused.
    Paused,
}

enum SyncingStatus<E: EthSpec> {
    AwaitingDownload(Hash256),
    Downloading(Hash256, Id),
    AwaitingProcessing(RpcBlock<E>, BatchPeers),
    Processing(RpcBlock<E>, BatchPeers),
}

pub struct BackFillSync<T: BeaconChainTypes> {
    status: SyncingStatus<T::EthSpec>,

    /// When a backfill sync fails, we keep track of whether a new fully synced peer has joined.
    /// This signifies that we are able to attempt to restart a failed chain.
    restart_failed_sync: bool,

    peers: Arc<RwLock<HashSet<PeerId>>>,

    /// Reference to the beacon chain to obtain initial starting points for the backfill sync.
    beacon_chain: Arc<BeaconChain<T>>,

    /// Reference to the network globals in order to obtain valid peers to backfill blocks from
    /// (i.e synced peers).
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
}

impl<T: BeaconChainTypes> BackFillSync<T> {
    #[instrument(parent = None,
        level = "info",
        name = "backfill_sync",
        skip_all
    )]
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    ) -> Self {
        // Determine if backfill is enabled or not.
        // If, for some reason a backfill has already been completed (or we've used a trusted
        // genesis root) then backfill has been completed.
        let anchor_info = beacon_chain.store.get_anchor_info();
        let (state, current_start) =
            if anchor_info.block_backfill_complete(beacon_chain.genesis_backfill_slot) {
                (BackFillState::Completed, Epoch::new(0))
            } else {
                (
                    BackFillState::Paused,
                    anchor_info
                        .oldest_block_slot
                        .epoch(T::EthSpec::slots_per_epoch()),
                )
            };

        let bfs = BackFillSync {
            status: SyncingStatus::AwaitingDownload(anchor_info.oldest_block_parent),
            restart_failed_sync: false,
            peers: <_>::default(),
            beacon_chain,
            network_globals,
        };

        // Update the global network state with the current backfill state.
        bfs.set_state(state);
        bfs
    }

    /// Pauses the backfill sync if it's currently syncing.
    #[instrument(parent = None,
        level = "info",
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    pub fn pause(&mut self) {
        if let BackFillState::Syncing = self.state() {
            debug!("Backfill sync paused");
            self.set_state(BackFillState::Paused);
        }
    }

    /// Starts or resumes syncing.
    ///
    /// If resuming is successful, reports back the current syncing metrics.
    #[must_use = "A failure here indicates the backfill sync has failed and the global sync state should be updated"]
    #[instrument(parent = None,
        level = "info",
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    pub fn start(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<SyncStart, BackFillError> {
        match self.state() {
            BackFillState::Syncing => {} // already syncing ignore.
            BackFillState::Paused => {
                if !self.peers.read().is_empty() {
                    // If there are peers to resume with, begin the resume.
                    debug!("Resuming backfill sync");
                    self.set_state(BackFillState::Syncing);
                    self.continue_syncing_blocks(network);
                } else {
                    return Ok(SyncStart::NotSyncing);
                }
            }
            BackFillState::Failed => {
                // Attempt to recover from a failed sync. All local variables should be reset and
                // cleared already for a fresh start.
                // We only attempt to restart a failed backfill sync if a new synced peer has been
                // added.
                if !self.restart_failed_sync {
                    return Ok(SyncStart::NotSyncing);
                }

                self.set_state(BackFillState::Syncing);

                debug!("Resuming a failed backfill sync");

                // begin requesting blocks from the peer pool, until all peers are exhausted.
                self.continue_syncing_blocks(network);
            }
            BackFillState::Completed => return Ok(SyncStart::NotSyncing),
        }

        Ok(SyncStart::Syncing {
            // TODO(tree-sync): is this actually used? The remaining does not account for the 6
            // months of data expiration
            completed: todo!(),
            remaining: todo!(),
        })
    }

    /// A fully synced peer has joined us.
    /// If we are in a failed state, update a local variable to indicate we are able to restart
    /// the failed sync on the next attempt.
    #[instrument(parent = None,
        level = "info",
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    pub fn fully_synced_peer_joined(&mut self) {
        if matches!(self.state(), BackFillState::Failed) {
            self.restart_failed_sync = true;
        }
    }

    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.peers.write().insert(peer_id);
    }

    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.write().remove(peer_id);

        if self.peers.read().is_empty() {
            info!(
                "reason" = "insufficient_synced_peers",
                "Backfill sync paused"
            );
            self.set_state(BackFillState::Paused);
        }
    }

    pub fn on_block_response(
        &mut self,
        id: Id,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match self.status {
            SyncingStatus::Downloading(block_root, expected_id) => {
                if id != expected_id {
                    panic!("unexpected ID");
                }
                match result {
                    Ok((block, peers)) => {
                        // TODO(tree-sync): check that id matches
                        debug!(%id, "Sync block downloaded");
                        self.status = SyncingStatus::Processing(block, peers);
                    }
                    Err(e) => {
                        // TODO(tree-sync): Handle the error explicitly with a match, check unstable
                        debug!(%id, "Sync block download error");
                        self.status = SyncingStatus::AwaitingDownload(block_root);
                    }
                }
            }
            _ => panic!("Bad state"),
        }

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    pub fn handle_block_process_result(
        &mut self,
        id: Id,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match &mut self.status {
            SyncingStatus::Processing(block, _peers) => match result {
                BatchProcessResult::Success => {
                    debug!(%id, "Sync block process success");
                    self.status = SyncingStatus::AwaitingDownload(block.as_block().parent_root())
                }
                BatchProcessResult::Failure { .. } => {
                    debug!(%id, "Sync block process error");
                    self.status = SyncingStatus::AwaitingDownload(block.block_root())
                    // TODO(tree-sync): add peer to failed peers and downscore
                }
            },
            _ => panic!("Bad state"),
        }

        // Continue batches
        self.continue_syncing_blocks(cx);
    }

    fn continue_syncing_blocks(&mut self, cx: &mut SyncNetworkContext<T>) {
        match &mut self.status {
            SyncingStatus::AwaitingDownload(block_root) => {
                // TODO(tree-sync): pick the right ID
                let requester = RangeRequestId::BackfillSync(cx.next_id());
                let failed_peers = HashSet::new();

                match cx.block_components_by_range_request(
                    *block_root,
                    requester,
                    self.peers.clone(),
                    &failed_peers,
                ) {
                    Ok(req_id) => {
                        self.status = SyncingStatus::Downloading(*block_root, req_id);
                    }
                    Err(e) => {
                        // TODO(tree-sync): Match error explicitly
                        // Log failed chain, mark blocks as not syncing
                        todo!("error sending {e:?}");
                    }
                };
            }
            SyncingStatus::Downloading(..) => {} // wait for event
            SyncingStatus::AwaitingProcessing(block, peers) => {
                let id = cx.next_id();
                let Some(beacon_processor) = cx.beacon_processor_if_enabled() else {
                    todo!("processor disabled");
                };
                // TODO(tree-sync): pick the right ID
                if let Err(e) = beacon_processor.send_chain_segment(
                    ChainSegmentProcessId::BackSyncBatchId(id),
                    vec![block.clone()],
                ) {
                    todo!("error sending {e:?}");
                }
                self.status = SyncingStatus::Processing(block.clone(), peers.clone());
            }
            SyncingStatus::Processing(..) => {} // wait for event
        }
    }

    /// Updates the global network state indicating the current state of a backfill sync.
    #[instrument(parent = None,
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    fn set_state(&self, state: BackFillState) {
        *self.network_globals.backfill_state.write() = state;
    }

    fn state(&self) -> BackFillState {
        self.network_globals.backfill_state.read().clone()
    }
}

/// Error kind for attempting to restart the sync from beacon chain parameters.
enum ResetEpochError {
    /// The chain has already completed.
    SyncCompleted,
}
