use beacon_chain::{get_block_root, validator_monitor::timestamp_now};
use fnv::FnvHashMap;
use lighthouse_network::{
    rpc::{methods::BlobsByRootRequest, BlocksByRootRequest},
    PeerId,
};
use std::{collections::hash_map::Entry, hash::Hash, sync::Arc};
use strum::IntoStaticStr;
use types::{
    blob_sidecar::BlobIdentifier, BlobSidecar, ChainSpec, EthSpec, Hash256, SignedBeaconBlock, Slot,
};

pub use data_columns_by_range::{
    ActiveBlobsByRangeRequest, ActiveBlocksByRangeRequest, ActiveDataColumnsByRangeRequest,
};
pub use data_columns_by_root::{
    ActiveDataColumnsByRootRequest, DataColumnsByRootSingleBlockRequest,
};

use super::{RpcEvent, RpcResponseResult};

mod data_columns_by_range;
mod data_columns_by_root;

pub struct ActiveRequests<K: Eq + Hash, R: ActiveRequest> {
    requests: FnvHashMap<K, ActiveRequestOutter<R>>,
}

struct ActiveRequestOutter<R: ActiveRequest> {
    inner: R,
    peer_id: PeerId,
    completed_early: bool,
    expect_max_responses: bool,
}

impl<R: ActiveRequest> ActiveRequestOutter<R> {
    fn add_response(&mut self, item: R::Item) -> Result<Option<Vec<R::Item>>, LookupVerifyError> {
        // Reject items after `add_response()` considers the item set complete
        if self.completed_early {
            return Err(LookupVerifyError::TooManyResponses);
        }

        if self.inner.add_response(item)? {
            self.completed_early = true;
            Ok(Some(self.inner.consume_items()))
        } else {
            Ok(None)
        }
    }

    fn terminate(mut self) -> Result<Option<Vec<R::Item>>, LookupVerifyError> {
        if self.completed_early {
            Ok(None)
        } else if self.expect_max_responses {
            Err(LookupVerifyError::NotEnoughResponsesReturned {
                actual: self.inner.consume_items().len(),
            })
        } else {
            Ok(Some(self.inner.consume_items()))
        }
    }
}

impl<K: Eq + Hash, R: ActiveRequest> ActiveRequests<K, R> {
    pub fn new() -> Self {
        Self {
            requests: <_>::default(),
        }
    }

    pub fn insert(&mut self, id: K, request: R, peer_id: PeerId) {
        self.requests.insert(
            id,
            ActiveRequestOutter {
                inner: request,
                peer_id,
                completed_early: false,
                expect_max_responses: false,
            },
        );
    }

    pub fn on_response(
        &mut self,
        id: K,
        rpc_event: RpcEvent<R::Item>,
    ) -> Option<RpcResponseResult<Vec<R::Item>>> {
        let Entry::Occupied(mut request) = self.requests.entry(id) else {
            metrics::inc_counter_vec(&metrics::SYNC_UNKNOWN_NETWORK_REQUESTS, &[R::name()]);
            return None;
        };

        let resp = match rpc_event {
            RpcEvent::Response(item, seen_timestamp) => {
                let request = &mut request.get_mut();
                match request.add_response(item) {
                    Ok(Some(items)) => Ok((items, seen_timestamp)),
                    Ok(None) => return None,
                    Err(e) => Err((e.into(), false)),
                }
            }
            RpcEvent::StreamTermination => match request.remove().terminate() {
                Ok(Some(items)) => Ok((items, timestamp_now())),
                Ok(None) => return None,
                // (err, false = not resolved) because terminate returns Ok() if resolved
                Err(e) => Err((e.into(), false)),
            },
            RpcEvent::RPCError(e) => Err((e.into(), false)),
        };

        match resp {
            Ok(resp) => Some(Ok(resp)),
            // Track if this request has already returned some value downstream. Ensure that
            // downstream code only receives a single Result per request. If the serving peer does
            // multiple penalizable actions per request, downscore and return None. This allows to
            // catch if a peer is returning more blobs than requested or if the excess blobs are
            // invalid.
            Err((e, resolved)) => {
                if resolved {
                    None
                } else {
                    Some(Err(e))
                }
            }
        }
    }

    pub fn active_requests_of_peer(&self, peer_id: &PeerId) -> Vec<&K> {
        self.requests
            .iter()
            .filter(|(_, request)| &request.peer_id == peer_id)
            .map(|(id, _)| id)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }
}

pub trait ActiveRequest {
    type Item;

    fn add_response(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError>;

    fn consume_items(&mut self) -> Vec<Self::Item>;

    fn name() -> &'static str;
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    NoResponseReturned,
    NotEnoughResponsesReturned { actual: usize },
    TooManyResponses,
    UnrequestedBlockRoot(Hash256),
    UnrequestedIndex(u64),
    UnrequestedSlot(Slot),
    InvalidInclusionProof,
    DuplicateData,
}

pub struct ActiveBlocksByRootRequest<E: EthSpec> {
    request: BlocksByRootSingleRequest,
    resolved: bool,
    item: Option<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> ActiveBlocksByRootRequest<E> {
    pub fn new(request: BlocksByRootSingleRequest) -> Self {
        Self {
            request,
            resolved: false,
            item: None,
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveBlocksByRootRequest<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add_response(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        // Valid data, blocks by root expects a single response
        Ok(true)
    }

    fn consume_items(&mut self) -> Vec<Self::Item> {
        if let Some(item) = self.item.take() {
            vec![item]
        } else {
            vec![]
        }
    }

    fn name() -> &'static str {
        "blocks_by_root"
    }
}

#[derive(Debug, Copy, Clone)]
pub struct BlocksByRootSingleRequest(pub Hash256);

impl BlocksByRootSingleRequest {
    pub fn into_request(self, spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new(vec![self.0], spec)
    }
}

#[derive(Debug, Clone)]
pub struct BlobsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl BlobsByRootSingleBlockRequest {
    pub fn into_request(self, spec: &ChainSpec) -> BlobsByRootRequest {
        BlobsByRootRequest::new(
            self.indices
                .into_iter()
                .map(|index| BlobIdentifier {
                    block_root: self.block_root,
                    index,
                })
                .collect(),
            spec,
        )
    }
}

pub struct ActiveBlobsByRootRequest<E: EthSpec> {
    request: BlobsByRootSingleBlockRequest,
    blobs: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> ActiveBlobsByRootRequest<E> {
    pub fn new(request: BlobsByRootSingleBlockRequest) -> Self {
        Self {
            request,
            blobs: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveBlobsByRootRequest<E> {
    type Item = Arc<BlobSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add_response(&mut self, blob: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = blob.block_root();
        if self.request.block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !blob.verify_blob_sidecar_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if !self.request.indices.contains(&blob.index) {
            return Err(LookupVerifyError::UnrequestedIndex(blob.index));
        }
        if self.blobs.iter().any(|b| b.index == blob.index) {
            return Err(LookupVerifyError::DuplicateData);
        }

        self.blobs.push(blob);

        Ok(self.blobs.len() >= self.request.indices.len())
    }

    fn consume_items(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.blobs)
    }

    fn name() -> &'static str {
        "blobs_by_root"
    }
}
