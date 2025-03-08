use super::network_context::{RpcResponseResult, SyncNetworkContext};
use beacon_chain::{get_block_root, BeaconChainTypes};
use lighthouse_network::{
    rpc::BlocksByRangeRequest,
    service::api_types::{BlocksByRangeRequestId, BlocksByRangeRequester, PeerStatusId},
    PeerId, SyncInfo,
};
use slog::{debug, warn};
use std::{collections::HashMap, sync::Arc};
use types::{Epoch, EthSpec, SignedBeaconBlock};

pub(crate) struct PeersRestatus {
    peers: HashMap<PeerStatusId, PeerStatus>,
    log: slog::Logger,
}

// Compute the points to binary search

const EPOCH_MOD: Epoch = Epoch::new(64);
const MAX_ERRORS: usize = 3;
// TODO: make this spec dependant
const MAX_REQUEST_COUNT: u64 = 128;

pub(crate) struct PeersRestatusResult {
    from: Epoch,
    target: Epoch,
}

impl PeersRestatus {
    pub fn new(log: slog::Logger) -> Self {
        Self {
            peers: <_>::default(),
            log,
        }
    }

    pub fn add_peer<T: BeaconChainTypes>(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        local_info: SyncInfo,
        peer_id: PeerId,
        remote_info: SyncInfo,
    ) {
        let min_epoch = local_info.finalized_epoch % EPOCH_MOD;
        let max_epoch = remote_info.head_slot.epoch(T::EthSpec::slots_per_epoch()) % EPOCH_MOD;
        let id = PeerStatusId(network.next_id());

        let mut peer_req = PeerStatus::new(id, peer_id, min_epoch, max_epoch);
        if let Err(e) = peer_req.send_next_request(network) {
            warn!(
                self.log,
                "Sync ignores peer after error sending first detailed status request";
                "peer" => ?peer_id,
                "error" => ?e,
            )
        } else {
            // Only persist the peer if the first request is sent successfully
            self.peers.insert(id, peer_req);
        }
    }

    pub fn on_response<T: BeaconChainTypes>(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        resp: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        id: PeerStatusId,
        req_id: BlocksByRangeRequestId,
    ) -> Option<PeersRestatusResult> {
        let Some(peer_req) = self.peers.get_mut(&id) else {
            debug!(
                self.log,
                "Ignoring response to unknown peer status id";
                "id" => ?id,
            );
            return None;
        };

        let peer_id = peer_req.peer_id;
        match peer_req.on_response(network, resp, req_id) {
            Ok(None) => None,
            Ok(Some(result)) => {
                self.peers.remove(&id);
                Some(result)
            }
            Err(e) => {
                // In case of internal errors, too many network errors, or the peer claiming to have
                // too long block skips: give up and default to just using their Status message.
                self.peers.remove(&id);
                debug!(
                    self.log,
                    "Unable to aquire more precise status for range sync peer";
                    "peer" => ?peer_id,
                    "error" => ?e,
                );
            }
        }
    }
}

struct PeerStatus {
    id: PeerStatusId,
    peer_id: PeerId,
    base_epoch: Epoch,
    current_query: Option<(usize, Query)>,
    left_ptr: usize,
    right_ptr: usize,
}

impl PeerStatus {
    fn new(id: PeerStatusId, peer_id: PeerId, min_epoch: Epoch, max_epoch: Epoch) -> Self {
        let right_ptr = ((max_epoch - min_epoch) / EPOCH_MOD).as_usize();
        Self {
            id,
            peer_id,
            base_epoch: min_epoch,
            current_query: None,
            left_ptr: 0,
            right_ptr,
        }
    }

    fn send_next_request<T: BeaconChainTypes>(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        let mid_ptr = self.left_ptr + (self.right_ptr - self.left_ptr) / 2;
        let query_epoch = self.ptr_to_epoch(mid_ptr);

        let mut query = Query::new(self.id, self.peer_id, query_epoch);
        query.send_request(network)?;

        self.current_query = Some((mid_ptr, query));
        Ok(())
    }

    fn on_response<T: BeaconChainTypes>(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        resp: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        req_id: BlocksByRangeRequestId,
    ) -> Result<Option<PeersRestatusResult>, String> {
        let (mid_ptr, current_query) = self
            .current_query
            .as_mut()
            .ok_or(format!("No active request for req_id {req_id:?}"))?;

        let Some(outcome) = current_query.on_response(network, resp, req_id)? else {
            return Ok(None);
        };

        match outcome {
            QueryOutcome::FoundBlock(block) => {
                let block_root = get_block_root(&block);
                // TODO: Should check disk too? I don't think so, then we should check that we
                // don't query blocks that are less than finalized.
                let block_is_known = network.chain.block_is_known_to_fork_choice(&block_root);

                let mid_ptr = *mid_ptr;
                if let Some(index) = self.apply_binary_search_result(mid_ptr, block_is_known) {
                    if index == 0 {
                        todo!();
                    } else {
                        Ok(Some(PeersRestatusResult {
                            from: self.ptr_to_epoch(index - 1),
                            target: self.ptr_to_epoch(index),
                        }))
                    }
                } else {
                    self.send_next_request(network)?;
                    Ok(None)
                }
            }
            QueryOutcome::NoBlocks => Err("Found no blocks in epoch range".to_owned()),
            // Give up and return default status
            QueryOutcome::TooManyErrors => Err("Too many errors".to_owned()),
        }
    }

    fn ptr_to_epoch(&self, ptr: usize) -> Epoch {
        self.base_epoch + EPOCH_MOD * Epoch::new(ptr as u64)
    }

    fn apply_binary_search_result(
        &mut self,
        mid_ptr: usize,
        block_is_known: bool,
    ) -> Option<usize> {
        if block_is_known {
            // Test to the right of the current query
            self.left_ptr = mid_ptr + 1;
        } else {
            // Test to the left of the current query
            self.right_ptr = mid_ptr;
        }

        if self.left_ptr == self.right_ptr {
            // Found the index of the first epoch that includes a block not known to us
            Some(self.left_ptr)
        } else {
            // Continue searching
            None
        }
    }
}

/// The task of a step query is to return the first block from a peer after this epoch
struct Query {
    id: PeerStatusId,
    peer_id: PeerId,
    start_epoch: Epoch,
    current_count: u64,
    status: QueryStatus,
    errors: usize,
}

enum QueryStatus {
    NotStarted,
    Active(BlocksByRangeRequestId),
}

enum QueryOutcome<E: EthSpec> {
    FoundBlock(Arc<SignedBeaconBlock<E>>),
    NoBlocks,
    TooManyErrors,
}

impl Query {
    fn new(id: PeerStatusId, peer_id: PeerId, start_epoch: Epoch) -> Self {
        Self {
            id,
            peer_id,
            start_epoch,
            current_count: 1,
            status: QueryStatus::NotStarted,
            errors: 0,
        }
    }

    fn send_request<T: BeaconChainTypes>(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<(), String> {
        match self.status {
            QueryStatus::NotStarted => {
                let req_id = network
                    .send_blocks_by_range_request(
                        self.peer_id,
                        BlocksByRangeRequest::new(
                            self.start_epoch
                                .start_slot(T::EthSpec::slots_per_epoch())
                                .as_u64(),
                            self.current_count,
                        ),
                        BlocksByRangeRequester::PeerStatus(self.id),
                    )
                    .map_err(|e| format!("{e:?}"))?;
                self.status = QueryStatus::Active(req_id);
                Ok(())
            }
            QueryStatus::Active(_) => Err("Wrong state, not started".to_owned()),
        }
    }

    fn on_response<T: BeaconChainTypes>(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        resp: RpcResponseResult<Vec<Arc<SignedBeaconBlock<T::EthSpec>>>>,
        req_id: BlocksByRangeRequestId,
    ) -> Result<Option<QueryOutcome<T::EthSpec>>, String> {
        match self.status {
            QueryStatus::NotStarted => Err("Wrong state, not started".to_owned()),
            QueryStatus::Active(expected_req_id) => {
                if expected_req_id != req_id {
                    return Err(format!(
                        "Unexpected request ID {req_id} expected {expected_req_id}"
                    ));
                }

                match resp {
                    Ok((blocks, _)) => {
                        if let Some(first_block) = blocks.first() {
                            return Ok(Some(QueryOutcome::FoundBlock(first_block.clone())));
                        } else {
                            // No blocks in requested range, increase and try again
                            self.current_count = self.current_count * 2;
                            if self.current_count > MAX_REQUEST_COUNT {
                                return Ok(Some(QueryOutcome::NoBlocks));
                            }
                            self.status = QueryStatus::NotStarted;
                            self.send_request(network)?;
                            Ok(None)
                        }
                    }
                    Err(_) => {
                        self.errors += 1;
                        if self.errors > MAX_ERRORS {
                            return Ok(Some(QueryOutcome::TooManyErrors));
                        } else {
                            self.status = QueryStatus::NotStarted;
                            self.send_request(network)?;
                            Ok(None)
                        }
                    }
                }
            }
        }
    }
}
