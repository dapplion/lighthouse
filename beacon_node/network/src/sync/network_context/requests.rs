use beacon_chain::{get_block_root, validator_monitor::timestamp_now};
use fnv::FnvHashMap;
use lighthouse_network::{
    rpc::{methods::BlobsByRootRequest, BlocksByRootRequest},
    PeerId,
};
use std::{collections::hash_map::Entry, hash::Hash, marker::PhantomData, sync::Arc};
use strum::IntoStaticStr;
use types::{
    blob_sidecar::BlobIdentifier, BlobSidecar, ChainSpec, EthSpec, Hash256, SignedBeaconBlock,
};

pub use data_columns_by_range::ActiveDataColumnsByRangeRequest;
pub use data_columns_by_root::{
    ActiveDataColumnsByRootRequest, DataColumnsByRootSingleBlockRequest,
};

use super::{RpcEvent, RpcResponseResult};

mod data_columns_by_range;
mod data_columns_by_root;

pub struct ActiveRequests<K: Eq + Hash, R: ActiveRequest> {
    requests: FnvHashMap<K, R>,
}

impl<K: Eq + Hash, R: ActiveRequest> ActiveRequests<K, R> {
    pub fn new() -> Self {
        Self {
            requests: <_>::default(),
        }
    }

    pub fn insert(&mut self, id: K, request: R) {
        self.requests.insert(id, request);
    }

    pub fn on_response(
        &mut self,
        id: K,
        rpc_event: RpcEvent<R::Item>,
    ) -> Option<RpcResponseResult<Vec<R::Item>>> {
        let Entry::Occupied(mut request) = self.requests.entry(id) else {
            return None;
        };

        let resp = match rpc_event {
            RpcEvent::Response(item, seen_timestamp) => {
                let request = request.get_mut();
                match request.add_response(item) {
                    Ok(Some(items)) => Ok((items, seen_timestamp)),
                    Ok(None) => return None,
                    Err(e) => Err((e.into(), request.resolve())),
                }
            }
            RpcEvent::StreamTermination => match request.remove().terminate() {
                Ok(Some(items)) => Ok((items, timestamp_now())),
                Ok(None) => return None,
                // (err, false = not resolved) because terminate returns Ok() if resolved
                Err(e) => Err((e.into(), false)),
            },
            RpcEvent::RPCError(e) => Err((e.into(), request.remove().resolve())),
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
            .filter(|(_, request)| request.peer() == peer_id)
            .map(|(id, _)| id)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.requests.len()
    }
}

pub trait ActiveRequest {
    type Item;

    fn add_response(
        &mut self,
        item: Self::Item,
    ) -> Result<Option<Vec<Self::Item>>, LookupVerifyError>;

    fn terminate(self) -> Result<Option<Vec<Self::Item>>, LookupVerifyError>;

    fn resolve(&mut self) -> bool;

    fn peer(&self) -> &PeerId;
}

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum LookupVerifyError {
    NoResponseReturned,
    NotEnoughResponsesReturned { expected: usize, actual: usize },
    TooManyResponses,
    UnrequestedBlockRoot(Hash256),
    UnrequestedIndex(u64),
    InvalidInclusionProof,
    DuplicateData,
}

pub struct ActiveBlocksByRootRequest<E: EthSpec> {
    request: BlocksByRootSingleRequest,
    resolved: bool,
    pub(crate) peer_id: PeerId,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> ActiveBlocksByRootRequest<E> {
    pub fn new(request: BlocksByRootSingleRequest, peer_id: PeerId) -> Self {
        Self {
            request,
            resolved: false,
            peer_id,
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveBlocksByRootRequest<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add_response(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> Result<Option<Vec<Self::Item>>, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        // Valid data, blocks by root expects a single response
        self.resolved = true;
        Ok(Some(vec![block]))
    }

    fn terminate(self) -> Result<Option<Vec<Self::Item>>, LookupVerifyError> {
        if self.resolved {
            Ok(None)
        } else {
            Err(LookupVerifyError::NoResponseReturned)
        }
    }

    fn resolve(&mut self) -> bool {
        todo!();
    }

    fn peer(&self) -> &PeerId {
        &self.peer_id
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
    resolved: bool,
    pub(crate) peer_id: PeerId,
}

impl<E: EthSpec> ActiveBlobsByRootRequest<E> {
    pub fn new(request: BlobsByRootSingleBlockRequest, peer_id: PeerId) -> Self {
        Self {
            request,
            blobs: vec![],
            resolved: false,
            peer_id,
        }
    }

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response(
        &mut self,
        blob: Arc<BlobSidecar<E>>,
    ) -> Result<Option<Vec<Arc<BlobSidecar<E>>>>, LookupVerifyError> {
        if self.resolved {
            return Err(LookupVerifyError::TooManyResponses);
        }

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
        if self.blobs.len() >= self.request.indices.len() {
            // All expected chunks received, return result early
            self.resolved = true;
            Ok(Some(std::mem::take(&mut self.blobs)))
        } else {
            Ok(None)
        }
    }

    pub fn terminate(self) -> Result<(), LookupVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            Err(LookupVerifyError::NotEnoughResponsesReturned {
                expected: self.request.indices.len(),
                actual: self.blobs.len(),
            })
        }
    }

    /// Mark request as resolved (= has returned something downstream) while marking this status as
    /// true for future calls.
    pub fn resolve(&mut self) -> bool {
        std::mem::replace(&mut self.resolved, true)
    }
}
