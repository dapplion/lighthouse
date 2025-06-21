use super::network_context::{RpcRequestSendError, RpcResponseError, SyncNetworkContext};
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::network_context::BatchPeers;
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use lighthouse_network::service::api_types::{Id, RangeRequestId};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;
use types::{EthSpec, Hash256, Slot};

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

pub enum Error {
    InternalError(String),
}

impl<T: BeaconChainTypes> SyncBlock<T> {
    pub fn new(id: RangeRequestId, block_root: Hash256, initial_peers: &[PeerId]) -> Self {
        Self {
            id,
            block_root,
            failed_peers: <_>::default(),
            peers: Arc::new(RwLock::new(HashSet::from_iter(
                initial_peers.iter().copied(),
            ))),
            request: SyncingStatus::AwaitingDownload,
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    pub fn clone_peers(&self) -> HashSet<PeerId> {
        self.peers.read().clone()
    }

    pub fn add_peer(&self, peer: PeerId) -> bool {
        self.peers.write().insert(peer)
    }

    pub fn remove_peer(&self, peer: &PeerId) -> bool {
        self.peers.write().remove(peer)
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
            SyncingStatus::Processing(block, peers) => match result {
                BatchProcessResult::Success => {
                    debug!(id = %self.id, "Sync block process success");
                    Ok(SyncBlockResult::Done {
                        parent_root: block.as_block().parent_root(),
                        slot: block.as_block().slot(),
                    })
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
                    self.peers.clone(),
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
                        self.request = SyncingStatus::Processing(block.clone(), peers.clone());
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
            SyncingStatus::Processing(..) => Ok(SyncBlockResult::Wait),
        }
    }

    pub fn is_processing(&self) -> bool {
        matches!(self.request, SyncingStatus::Processing(..))
    }
}

enum SyncingStatus<E: EthSpec> {
    AwaitingDownload,
    Downloading(Id),
    AwaitingProcessing(RpcBlock<E>, BatchPeers),
    Processing(RpcBlock<E>, BatchPeers),
}
