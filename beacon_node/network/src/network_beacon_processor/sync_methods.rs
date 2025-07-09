use crate::metrics::{self};
use crate::network_beacon_processor::{NetworkBeaconProcessor, FUTURE_SLOT_TOLERANCE};
use crate::sync::manager::SyncMessage;
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
use beacon_chain::data_availability_checker::AvailabilityCheckError;
use beacon_chain::data_column_verification::verify_kzg_for_data_column_list;
use beacon_chain::{
    BeaconChainTypes, BlockError, ChainSegmentResult, HistoricalBlockError, NotifyExecutionLayer,
};
use lighthouse_network::service::api_types::{HeaderLookupId, Id};
use lighthouse_network::PeerAction;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};
use types::{ColumnIndex, DataColumnSidecar, Hash256};

/// Id associated to a batch processing request, either a sync batch or a parent lookup.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainSegmentProcessId {
    /// Processing Id of a range syncing batch.
    ForwardSync(HeaderLookupId),
    /// Processing ID for a backfill syncing batch.
    BackfillSync(Id),
}

/// Returned when a chain segment import fails.
pub struct ChainSegmentFailed {
    /// To be displayed in logs.
    pub message: String,
    /// Used to penalize peers.
    pub peer_action: Option<PeerGroupAction>,
}

/// Tracks which block(s) component caused the block to be invalid. Used to attribute fault in sync.
#[derive(Debug)]
pub struct PeerGroupAction {
    pub block_peer: Option<PeerAction>,
    pub column_peer: HashMap<ColumnIndex, PeerAction>,
}

impl PeerGroupAction {
    fn block_peer(action: PeerAction) -> Self {
        Self {
            block_peer: Some(action),
            column_peer: <_>::default(),
        }
    }

    fn column_peers(columns: &[ColumnIndex], action: PeerAction) -> Self {
        Self {
            block_peer: None,
            column_peer: HashMap::from_iter(columns.iter().map(|index| (*index, action))),
        }
    }

    fn from_availability_check_error(e: &AvailabilityCheckError) -> Option<Self> {
        match e {
            AvailabilityCheckError::InvalidBlobs(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            AvailabilityCheckError::InvalidColumn(errors) => Some(PeerGroupAction::column_peers(
                &errors.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                PeerAction::LowToleranceError,
            )),
            AvailabilityCheckError::KzgCommitmentMismatch { .. } => None, // should never happen after checking inclusion proof
            AvailabilityCheckError::Unexpected(_) => None,                // internal
            AvailabilityCheckError::MissingBlobs => {
                Some(PeerGroupAction::block_peer(PeerAction::HighToleranceError))
            }
            // TOOD(das): PeerAction::High may be too soft of a penalty. Also may be deprecated
            // with https://github.com/sigp/lighthouse/issues/6258
            AvailabilityCheckError::MissingCustodyColumns(columns) => Some(
                PeerGroupAction::column_peers(columns, PeerAction::HighToleranceError),
            ),
            AvailabilityCheckError::BlobIndexInvalid(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            AvailabilityCheckError::DataColumnIndexInvalid(_) => None, // unreachable
            AvailabilityCheckError::StoreError(_) => None,             // unreachable
            AvailabilityCheckError::BlockReplayError(_) => None,       // internal error
            AvailabilityCheckError::RebuildingStateCaches(_) => None,  // internal error
            AvailabilityCheckError::SlotClockError => None,            // internal error
        }
    }
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    /// Validate a list of data columns received from RPC requests
    pub async fn validate_rpc_data_columns(
        self: Arc<NetworkBeaconProcessor<T>>,
        _block_root: Hash256,
        data_columns: Vec<Arc<DataColumnSidecar<T::EthSpec>>>,
        _seen_timestamp: Duration,
    ) -> Result<(), String> {
        verify_kzg_for_data_column_list(data_columns.iter(), &self.chain.kzg)
            .map_err(|err| format!("{err:?}"))
    }

    /// Process a sampling completed event, inserting it into fork-choice
    pub async fn process_sampling_completed(
        self: Arc<NetworkBeaconProcessor<T>>,
        block_root: Hash256,
    ) {
        self.chain.process_sampling_completed(block_root).await;
    }

    /// Attempt to import the chain segment (`blocks`) to the beacon chain, informing the sync
    /// thread if more blocks are needed to process it.
    pub async fn process_chain_segment(
        &self,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) {
        let result = match sync_type {
            // this a request from the range sync
            ChainSegmentProcessId::ForwardSync(id) => {
                let start_slot = downloaded_blocks.first().map(|b| b.slot().as_u64());
                let end_slot = downloaded_blocks.last().map(|b| b.slot().as_u64());
                let sent_blocks = downloaded_blocks.len();

                match self
                    .process_blocks(downloaded_blocks.iter(), notify_execution_layer)
                    .await
                {
                    (imported_blocks, Ok(_)) => {
                        let ignored_blocks = sent_blocks - imported_blocks;
                        metrics::inc_counter_by(
                            &metrics::SYNCING_CHAINS_IGNORED_BLOCKS,
                            ignored_blocks as u64,
                        );
                        debug!(
                            %id,
                            first_block_slot = start_slot,
                            last_block_slot = end_slot,
                            processed_blocks = sent_blocks,
                            service= "sync",
                            "Batch processed");
                        BatchProcessResult::Success
                    }
                    (_imported_blocks, Err(e)) => {
                        debug!(
                            %id,
                            first_block_slot = start_slot,
                            last_block_slot = end_slot,
                            error = %e.message,
                            service = "sync",
                            "Batch processing failed");
                        BatchProcessResult::Failure {
                            peer_action: e.peer_action,
                            error: e.message,
                        }
                    }
                }
            }
            // this a request from the Backfill sync
            ChainSegmentProcessId::BackfillSync(epoch) => {
                let start_slot = downloaded_blocks.first().map(|b| b.slot().as_u64());
                let end_slot = downloaded_blocks.last().map(|b| b.slot().as_u64());
                let sent_blocks = downloaded_blocks.len();
                let n_blobs = downloaded_blocks
                    .iter()
                    .map(|wrapped| wrapped.n_blobs())
                    .sum::<usize>();
                let n_data_columns = downloaded_blocks
                    .iter()
                    .map(|wrapped| wrapped.n_data_columns())
                    .sum::<usize>();

                match self.process_backfill_blocks(downloaded_blocks) {
                    Ok(_imported_blocks) => {
                        debug!(
                            batch_epoch = %epoch,
                            first_block_slot = start_slot,
                            keep_execution_payload = !self.chain.store.get_config().prune_payloads,
                            last_block_slot = end_slot,
                            processed_blocks = sent_blocks,
                            processed_blobs = n_blobs,
                            processed_data_columns = n_data_columns,
                            service= "sync",
                            "Backfill batch processed");
                        BatchProcessResult::Success
                    }
                    Err(e) => {
                        debug!(
                            batch_epoch = %epoch,
                            first_block_slot = start_slot,
                            last_block_slot = end_slot,
                            processed_blobs = n_blobs,
                            error = %e.message,
                            service = "sync",
                            "Backfill batch processing failed"
                        );
                        BatchProcessResult::Failure {
                            peer_action: e.peer_action,
                            error: e.message,
                        }
                    }
                }
            }
        };

        self.send_sync_message(SyncMessage::BatchProcessed { sync_type, result });
    }

    /// Helper function to process blocks batches which only consumes the chain and blocks to process.
    async fn process_blocks<'a>(
        &self,
        downloaded_blocks: impl Iterator<Item = &'a RpcBlock<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> (usize, Result<(), ChainSegmentFailed>) {
        let blocks: Vec<_> = downloaded_blocks.cloned().collect();
        match self
            .chain
            .process_chain_segment(blocks, notify_execution_layer)
            .await
        {
            ChainSegmentResult::Successful { imported_blocks } => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_SUCCESS_TOTAL);
                if !imported_blocks.is_empty() {
                    self.chain.recompute_head_at_current_slot().await;

                    for (block_root, block_slot) in &imported_blocks {
                        if self.chain.should_sample_slot(*block_slot) {
                            self.send_sync_message(SyncMessage::SampleBlock(
                                *block_root,
                                *block_slot,
                            ));
                        }
                    }
                }
                (imported_blocks.len(), Ok(()))
            }
            ChainSegmentResult::Failed {
                imported_blocks,
                error,
            } => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_FAILED_TOTAL);
                let r = self.handle_failed_chain_segment(error);
                if !imported_blocks.is_empty() {
                    self.chain.recompute_head_at_current_slot().await;
                }
                (imported_blocks.len(), r)
            }
        }
    }

    /// Helper function to process backfill block batches which only consumes the chain and blocks to process.
    fn process_backfill_blocks(
        &self,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<usize, ChainSegmentFailed> {
        match self
            .chain
            .verify_and_import_historical_block_batch(downloaded_blocks)
        {
            Ok(imported_blocks) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_SUCCESS_TOTAL,
                );
                Ok(imported_blocks)
            }
            Err(e) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_FAILED_TOTAL,
                );
                let peer_action = match &e {
                    HistoricalBlockError::AvailabilityCheckError(e) => {
                        PeerGroupAction::from_availability_check_error(e)
                    }
                    // The peer is faulty if they send blocks with bad roots or invalid signatures
                    HistoricalBlockError::MismatchedBlockRoot { .. }
                    | HistoricalBlockError::InvalidSignature(_) => {
                        Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
                    }
                    // Blobs are served by the block_peer
                    HistoricalBlockError::InvalidBlobsSignature(_) => {
                        Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
                    }
                    HistoricalBlockError::InvalidDataColumnsSignature(indices) => Some(
                        PeerGroupAction::column_peers(indices, PeerAction::LowToleranceError),
                    ),
                    HistoricalBlockError::ValidatorPubkeyCacheTimeout
                    | HistoricalBlockError::IndexOutOfBounds
                    | HistoricalBlockError::StoreError(_)
                    | HistoricalBlockError::Unexpected(_) => {
                        // This is an internal error, do not penalize the peer.
                        None
                    } // Do not use a fallback match, handle all errors explicitly
                };

                if peer_action.is_some() {
                    // All errors that result in a peer penalty are "expected" external faults the
                    // node runner can't do anything about
                    debug!(?e, "Backfill sync processing error");
                } else {
                    // All others are some type of internal error worth surfacing?
                    warn!(?e, "Unexpected backfill sync processing error");
                }

                Err(ChainSegmentFailed {
                    // Render the full error in debug for full details
                    message: format!("{:?}", e),
                    peer_action,
                })
            }
        }
    }

    /// Helper function to handle a `BlockError` from `process_chain_segment`
    fn handle_failed_chain_segment(&self, error: BlockError) -> Result<(), ChainSegmentFailed> {
        let peer_action = match &error {
            BlockError::ParentUnknown { .. } => {
                // blocks should be sequential and all parents should exist
                // Peers are faulty if they send non-sequential blocks.
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            BlockError::FutureSlot {
                present_slot,
                block_slot,
            } => {
                if *present_slot + FUTURE_SLOT_TOLERANCE >= *block_slot {
                    // The block is too far in the future, drop it.
                    warn!(
                        msg = "block for future slot rejected, check your time",
                        %present_slot,
                        %block_slot,
                        FUTURE_SLOT_TOLERANCE,
                        "Block is ahead of our slot clock"
                    );
                }
                // Peers are faulty if they send blocks from the future.
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            // Block is invalid
            BlockError::StateRootMismatch { .. }
            | BlockError::BlockSlotLimitReached
            | BlockError::IncorrectBlockProposer { .. }
            | BlockError::UnknownValidator { .. }
            | BlockError::BlockIsNotLaterThanParent { .. }
            | BlockError::NonLinearParentRoots
            | BlockError::NonLinearSlots
            | BlockError::PerBlockProcessingError(_)
            | BlockError::InconsistentFork(_)
            | BlockError::InvalidSignature(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            // Currently blobs are served by the block peer
            BlockError::InvalidBlobsSignature(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            BlockError::InvalidDataColumnsSignature(indices) => Some(
                PeerGroupAction::column_peers(indices, PeerAction::LowToleranceError),
            ),
            BlockError::GenesisBlock
            | BlockError::WouldRevertFinalizedSlot { .. }
            | BlockError::DuplicateFullyImported(_)
            | BlockError::DuplicateImportStatusUnknown(..) => {
                // This can happen for many reasons. Head sync's can download multiples and parent
                // lookups can download blocks before range sync
                return Ok(());
            }
            // Not syncing to a chain that conflicts with the canonical or manual finalized checkpoint
            BlockError::NotFinalizedDescendant { .. } | BlockError::WeakSubjectivityConflict => {
                Some(PeerGroupAction::block_peer(PeerAction::Fatal))
            }
            BlockError::AvailabilityCheck(e) => PeerGroupAction::from_availability_check_error(e),
            BlockError::ExecutionPayloadError(e) => {
                if !e.penalize_peer() {
                    // These errors indicate an issue with the EL and not the `ChainSegment`.
                    // Pause the syncing while the EL recovers
                    None
                } else {
                    Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
                }
            }
            // We need to penalise harshly in case this represents an actual attack. In case
            // of a faulty EL it will usually require manual intervention to fix anyway, so
            // it's not too bad if we drop most of our peers.
            BlockError::ParentExecutionPayloadInvalid { parent_root } => {
                warn!(
                    ?parent_root,
                    advice = "check execution node for corruption then restart it and Lighthouse",
                    "Failed to sync chain built on invalid parent"
                );
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            // Penalise peers for sending us banned blocks.
            BlockError::KnownInvalidExecutionPayload(block_root) => {
                warn!(?block_root, "Received block known to be invalid");
                Some(PeerGroupAction::block_peer(PeerAction::Fatal))
            }
            BlockError::Slashable => {
                Some(PeerGroupAction::block_peer(PeerAction::MidToleranceError))
            }
            // Do not penalize peers for internal errors.
            // BlobNotRequired is never constructed on this path
            // TODO(sync): Double check that all `BeaconChainError` variants are actually internal
            // errors in thie code path
            BlockError::BeaconChainError(_)
            | BlockError::InternalError(_)
            | BlockError::BlobNotRequired(_) => None,
            // Do not use a fallback match, handle all errors explicitly
        };

        if peer_action.is_some() {
            debug!(?error, "Range sync processing error");
        } else {
            warn!(?error, "Unexpected range sync processing error");
        }

        Err(ChainSegmentFailed {
            message: format!("{error:?}"),
            peer_action,
        })
    }
}

impl Display for ChainSegmentProcessId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForwardSync(id) => write!(f, "ForwardSync/{id}"),
            Self::BackfillSync(id) => write!(f, "BackfillSync/{id}"),
        }
    }
}
