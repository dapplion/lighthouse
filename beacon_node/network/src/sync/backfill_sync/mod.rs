//! This module contains the logic for Lighthouse's backfill sync.
//!
//! This kind of sync occurs when a trusted state is provided to the client. The client
//! will perform a [`RangeSync`] to the latest head from the trusted state, such that the
//! client can perform its duties right away. Once completed, a backfill sync occurs, where all old
//! blocks (from genesis) are downloaded in order to keep a consistent history.
//!
//! If a batch fails, the backfill sync cannot progress. In this scenario, we mark the backfill
//! sync as failed, log an error and attempt to retry once a new peer joins the node.

use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::{
    BatchPeers, RangeRequestId, RpcResponseError, SyncNetworkContext,
};
use crate::sync::sync_block::{Error as SyncBlockError, OkToImport, SyncBlock, SyncBlockResult};
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::service::api_types::{ComponentsByRootRequestId, Id};
use lighthouse_network::types::{BackFillState, NetworkGlobals};
use lighthouse_network::PeerId;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use types::{EthSpec, Hash256, Slot};

/// The number of times to retry a batch before it is considered failed.
const MAX_BATCH_DOWNLOAD_ATTEMPTS: u8 = 10;

/// Invalid batches are attempted to be re-downloaded from other peers. If a batch cannot be processed
/// after `MAX_BATCH_PROCESSING_ATTEMPTS` times, it is considered faulty.
const MAX_BATCH_PROCESSING_ATTEMPTS: u8 = 10;

/// Return type when attempting to start the backfill sync process.
pub enum SyncStart {
    /// The chain started syncing or is already syncing.
    Syncing,
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
    status: SyncBlock<T>,

    /// When a backfill sync fails, we keep track of whether a new fully synced peer has joined.
    /// This signifies that we are able to attempt to restart a failed chain.
    restart_failed_sync: bool,

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
        let state = if anchor_info.block_backfill_complete(beacon_chain.genesis_backfill_slot) {
            BackFillState::Completed
        } else {
            BackFillState::Paused
        };

        let bfs = BackFillSync {
            status: SyncBlock::new(
                RangeRequestId::BackfillSync(0),
                anchor_info.oldest_block_parent,
                // TODO(tree-sync): not correct fetch the corrent slot
                anchor_info.oldest_block_slot,
                &[],
            ),
            restart_failed_sync: false,
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
                if self.status.peer_count() == 0 {
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

        Ok(SyncStart::Syncing)
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
        self.status.add_peer(peer_id);
    }

    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        self.status.remove_peer(peer_id);

        if self.status.peer_count() == 0 && self.state() == BackFillState::Syncing {
            info!(
                "reason" = "insufficient_synced_peers",
                "Backfill sync paused"
            );
            self.set_state(BackFillState::Paused);
        }
    }

    pub fn on_block_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        if let Err(e) = self.status.on_download_result(req_id, result, cx) {
            self.handle_outcome(Err(e), cx);
        }
    }

    pub fn on_block_process_result(
        &mut self,
        _id: Id,
        result: BatchProcessResult,
        cx: &mut SyncNetworkContext<T>,
    ) {
        let outcome = self.status.on_process_result(result, cx);
        self.handle_outcome(outcome, cx);
    }

    fn continue_syncing_blocks(&mut self, cx: &mut SyncNetworkContext<T>) {
        // TODO(tree-sync): only ok to import the newest block
        let ok_to_import = true;
        let outcome = self
            .status
            .continue_request(cx, OkToImport::Bool(ok_to_import));
        self.handle_outcome(outcome.map(|_| SyncBlockResult::Wait), cx);
    }

    fn handle_outcome(
        &mut self,
        result: Result<SyncBlockResult, SyncBlockError>,
        cx: &mut SyncNetworkContext<T>,
    ) {
        match result {
            Ok(SyncBlockResult::Done { parent_root, slot }) => {
                if self.is_complete(slot) {
                    info!("Backfill sync completed");
                    self.set_state(BackFillState::Completed);
                } else {
                    let peers = self.status.clone_peers();
                    // TODO(tree-sync): retrieve correct slot from fetching headers first
                    let parent_block_slot = Slot::new(0);
                    self.status = SyncBlock::new(
                        RangeRequestId::BackfillSync(cx.next_id()),
                        parent_root,
                        parent_block_slot,
                        &peers.into_iter().collect::<Vec<_>>(),
                    )
                }
            }
            Ok(SyncBlockResult::Wait) => {
                // Do nothing wait for future event
            }
            Err(e) => match e {
                SyncBlockError::InternalError(_) | SyncBlockError::TooManyErrors(_) => {
                    debug!(error = ?e, "Backfill synced failed");
                    self.set_state(BackFillState::Failed);
                }
            },
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

    fn is_complete(&self, slot: Slot) -> bool {
        let anchor_info = self.beacon_chain.store.get_anchor_info();

        if anchor_info.oldest_block_slot != slot {
            warn!(
                "oldest_block_slot not at expected value {} != {}",
                anchor_info.oldest_block_slot, slot
            );
        }

        // Conditions that we have completed a backfill sync
        anchor_info.block_backfill_complete(self.beacon_chain.genesis_backfill_slot)
    }
}

/// Error kind for attempting to restart the sync from beacon chain parameters.
enum ResetEpochError {
    /// The chain has already completed.
    SyncCompleted,
}
