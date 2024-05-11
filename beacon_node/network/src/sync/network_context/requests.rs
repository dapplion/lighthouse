use beacon_chain::get_block_root;
use lighthouse_network::rpc::{
    methods::{BlobsByRootRequest, DataColumnsByRootRequest},
    BlocksByRootRequest,
};
use std::sync::Arc;
use strum::IntoStaticStr;
use types::{
    blob_sidecar::BlobIdentifier, data_column_sidecar::DataColumnIdentifier, BlobSidecar,
    ChainSpec, DataColumnSidecar, EthSpec, Hash256, SignedBeaconBlock,
};

#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum RpcByRootVerifyError {
    /// On a request that expects strictly one item, we receive the stream termination before
    /// that item
    NoResponseReturned,
    /// On a request for a strict number of items, we receive the stream termination before the
    /// expected count of items
    NotEnoughResponsesReturned,
    /// Received more items than expected
    TooManyResponses,
    /// Received an item that corresponds to a different request block root
    UnrequestedBlockRoot(Hash256),
    /// Received a blob / column with an index that is not in the requested set
    UnrequestedBlobIndex(u64),
    /// Blob or column inclusion proof does not match its own header
    InvalidInclusionProof,
    /// Received more than one item for the tuple (block_root, index)
    DuplicateData,
}

pub struct ActiveBlocksByRootRequest {
    request: BlocksByRootSingleRequest,
    resolved: bool,
}

impl ActiveBlocksByRootRequest {
    pub fn new(request: BlocksByRootSingleRequest) -> Self {
        Self {
            request,
            resolved: false,
        }
    }

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response<E: EthSpec>(
        &mut self,
        block: Arc<SignedBeaconBlock<E>>,
    ) -> Result<Arc<SignedBeaconBlock<E>>, RpcByRootVerifyError> {
        if self.resolved {
            return Err(RpcByRootVerifyError::TooManyResponses);
        }

        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(RpcByRootVerifyError::UnrequestedBlockRoot(block_root));
        }

        // Valid data, blocks by root expects a single response
        self.resolved = true;
        Ok(block)
    }

    pub fn terminate(self) -> Result<(), RpcByRootVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            Err(RpcByRootVerifyError::NoResponseReturned)
        }
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
}

impl<E: EthSpec> ActiveBlobsByRootRequest<E> {
    pub fn new(request: BlobsByRootSingleBlockRequest) -> Self {
        Self {
            request,
            blobs: vec![],
            resolved: false,
        }
    }

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response(
        &mut self,
        blob: Arc<BlobSidecar<E>>,
    ) -> Result<Option<Vec<Arc<BlobSidecar<E>>>>, RpcByRootVerifyError> {
        if self.resolved {
            return Err(RpcByRootVerifyError::TooManyResponses);
        }

        let block_root = blob.block_root();
        if self.request.block_root != block_root {
            return Err(RpcByRootVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !blob.verify_blob_sidecar_inclusion_proof().unwrap_or(false) {
            return Err(RpcByRootVerifyError::InvalidInclusionProof);
        }
        if !self.request.indices.contains(&blob.index) {
            return Err(RpcByRootVerifyError::UnrequestedBlobIndex(blob.index));
        }
        if self.blobs.iter().any(|b| b.index == blob.index) {
            return Err(RpcByRootVerifyError::DuplicateData);
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

    /// Handle a stream termination. Expects sender to strictly send the requested number of items
    pub fn terminate(self) -> Result<(), RpcByRootVerifyError> {
        if self.resolved {
            Ok(())
        } else {
            // Expect to receive the stream termination AFTER the expect number of items
            Err(RpcByRootVerifyError::NotEnoughResponsesReturned)
        }
    }
}

#[derive(Debug, Clone)]
pub struct DataColumnsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl DataColumnsByRootSingleBlockRequest {
    pub fn into_request(self, spec: &ChainSpec) -> DataColumnsByRootRequest {
        DataColumnsByRootRequest::new(
            self.indices
                .into_iter()
                .map(|index| DataColumnIdentifier {
                    block_root: self.block_root,
                    index,
                })
                .collect(),
            spec,
        )
    }
}

pub struct ActiveDataColumnsByRootRequest<E: EthSpec, T: Copy> {
    pub requester: T,
    request: DataColumnsByRootSingleBlockRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
    resolved: bool,
}

impl<E: EthSpec, T: Copy> ActiveDataColumnsByRootRequest<E, T> {
    pub fn new(request: DataColumnsByRootSingleBlockRequest, requester: T) -> Self {
        Self {
            requester,
            request,
            items: vec![],
            resolved: false,
        }
    }

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    pub fn add_response(
        &mut self,
        data_column: Arc<DataColumnSidecar<E>>,
    ) -> Result<Option<Vec<Arc<DataColumnSidecar<E>>>>, RpcByRootVerifyError> {
        if self.resolved {
            return Err(RpcByRootVerifyError::TooManyResponses);
        }

        let block_root = data_column.block_root();
        if self.request.block_root != block_root {
            return Err(RpcByRootVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !data_column.verify_inclusion_proof().unwrap_or(false) {
            return Err(RpcByRootVerifyError::InvalidInclusionProof);
        }
        if !self.request.indices.contains(&data_column.index) {
            return Err(RpcByRootVerifyError::UnrequestedBlobIndex(
                data_column.index,
            ));
        }
        if self.items.iter().any(|b| b.index == data_column.index) {
            return Err(RpcByRootVerifyError::DuplicateData);
        }

        self.items.push(data_column);
        if self.items.len() >= self.request.indices.len() {
            // All expected chunks received, return result early
            self.resolved = true;
            Ok(Some(std::mem::take(&mut self.items)))
        } else {
            Ok(None)
        }
    }

    /// Handle stream termination. Allows the sender to return less items than requested.
    pub fn terminate(self) -> Option<Vec<Arc<DataColumnSidecar<E>>>> {
        if self.resolved {
            None
        } else {
            Some(self.items)
        }
    }
}
