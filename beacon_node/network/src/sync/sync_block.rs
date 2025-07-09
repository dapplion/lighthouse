use super::network_context::{RpcRequestSendError, RpcResponseError, SyncNetworkContext};
use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::network_context::BatchPeers;
use crate::sync::BatchProcessResult;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::BeaconChainTypes;
use lighthouse_network::service::api_types::{ComponentsByRootRequestId, RangeRequestId};
use lighthouse_network::PeerId;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::debug;
use types::{EthSpec, Hash256, Slot};

const MAX_DOWNLOAD_ATTEMPTS: usize = 5;
const MAX_PROCESS_ATTEMPTS: usize = 5;

// TODO(tree-sync): have the peer set inside here when syncing add dedup logic
// TODO(tree-sync): for backfill sync use the sync state to check the peers have this block or not
pub struct SyncBlock<T: BeaconChainTypes> {
    id: RangeRequestId,
    block_root: Hash256,
    failed_peers: HashSet<PeerId>,
    // TODO(tree-sync): deprecate this shared state for manual addition and removal
    peers: Arc<RwLock<HashSet<PeerId>>>,
    request: SyncingStatus<T::EthSpec>,
    download_errors: usize,
    process_errors: usize,
}

enum SyncingStatus<E: EthSpec> {
    AwaitingDownload,
    Downloading(ComponentsByRootRequestId),
    AwaitingProcessing(RpcBlock<E>, BatchPeers),
    Processing(RpcBlock<E>, BatchPeers),
}

#[must_use]
pub enum SyncBlockResult {
    Done { parent_root: Hash256, slot: Slot },
    Wait,
}

#[derive(Debug)]
pub enum Error {
    InternalError(String),
    TooManyErrors(String),
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
            download_errors: 0,
            process_errors: 0,
        }
    }

    pub fn block_root(&self) -> &Hash256 {
        &self.block_root
    }

    pub fn id(&self) -> RangeRequestId {
        self.id
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    pub fn clone_peers(&self) -> HashSet<PeerId> {
        self.peers.read().clone()
    }

    /// Returns whether the value was newly inserted
    pub fn add_peer(&self, peer: PeerId) -> bool {
        self.peers.write().insert(peer)
    }

    pub fn remove_peer(&self, peer: &PeerId) -> bool {
        self.peers.write().remove(peer)
    }

    #[cfg(test)]
    pub fn is_processing(&self) -> bool {
        matches!(self.request, SyncingStatus::Processing(..))
    }

    pub fn on_download_result(
        &mut self,
        req_id: ComponentsByRootRequestId,
        result: Result<(RpcBlock<T::EthSpec>, BatchPeers), RpcResponseError>,
        cx: &mut SyncNetworkContext<T>,
    ) -> Result<(), Error> {
        match &mut self.request {
            SyncingStatus::Downloading(expected_id) => {
                if req_id != *expected_id {
                    return Err(Error::InternalError(format!(
                        "Unexpected request ID {} != {}",
                        req_id, expected_id,
                    )));
                }
                match result {
                    Ok((block, peers)) => {
                        debug!(id = %self.id, "Sync block downloaded");
                        self.request = SyncingStatus::AwaitingProcessing(block, peers);
                        Ok(())
                    }
                    Err(e) => {
                        debug!(id = %self.id, error = ?e, "Sync block download error");
                        self.request = SyncingStatus::AwaitingDownload;

                        self.download_errors += 1;
                        if self.download_errors > MAX_DOWNLOAD_ATTEMPTS {
                            return Err(Error::TooManyErrors("download errors".to_owned()));
                        }

                        Ok(())
                    }
                }
            }
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
                    debug!(id = %self.id, error, "Sync block process error");

                    if let Some(peer_action) = peer_action {
                        for (peer, penalty) in peers.blame(peer_action) {
                            cx.report_peer(peer, penalty, "faulty_batch");
                            self.failed_peers.insert(peer);
                        }
                    }

                    self.process_errors += 1;
                    if self.process_errors > MAX_PROCESS_ATTEMPTS {
                        return Err(Error::TooManyErrors("process errors".to_owned()));
                    }

                    self.request = SyncingStatus::AwaitingDownload;
                    Ok(SyncBlockResult::Wait)
                }
            },
            _ => Err(Error::InternalError(
                "Lookup not in expected state Processing".to_owned(),
            )),
        }
    }

    /// Make progress on the request. Note that a request can never finish on this call, thus it
    /// does not return `SyncBlockResult`.
    pub fn continue_request(
        &mut self,
        cx: &mut SyncNetworkContext<T>,
        ok_to_import: bool,
    ) -> Result<(), Error> {
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
                        Ok(())
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
            SyncingStatus::Downloading(_) => Ok(()),
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
                    return Ok(());
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
                        Ok(())
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
            SyncingStatus::Processing(..) => Ok(()),
        }
    }
}
