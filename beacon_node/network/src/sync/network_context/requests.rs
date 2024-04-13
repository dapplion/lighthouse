use beacon_chain::get_block_root;
use lighthouse_network::rpc::{methods::BlobsByRootRequest, BlocksByRootRequest, RPCError};
use std::sync::Arc;
use types::{
    blob_sidecar::BlobIdentifier, BlobSidecar, ChainSpec, EthSpec, Hash256, SignedBeaconBlock,
};

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
    ) -> Result<Arc<SignedBeaconBlock<E>>, RPCError> {
        if self.resolved {
            return Err(RPCError::InvalidData("too many responses".to_string()));
        }

        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(RPCError::InvalidData(format!(
                "un-requested block root {block_root:?}"
            )));
        }

        // Valid data, blocks by root expects a single response
        self.resolved = true;
        Ok(block)
    }

    pub fn terminate(self) -> Result<(), RPCError> {
        if self.resolved {
            Ok(())
        } else {
            Err(RPCError::InvalidData("no response returned".to_string()))
        }
    }
}

#[derive(Debug)]
pub struct BlocksByRootSingleRequest(pub Hash256);

impl BlocksByRootSingleRequest {
    pub fn into_request(&self, spec: &ChainSpec) -> BlocksByRootRequest {
        BlocksByRootRequest::new(vec![self.0], spec)
    }
}

pub struct BlobsByRootSingleBlockRequest {
    pub block_root: Hash256,
    pub indices: Vec<u64>,
}

impl BlobsByRootSingleBlockRequest {
    pub fn into_request(&self, spec: &ChainSpec) -> BlobsByRootRequest {
        BlobsByRootRequest::new(
            self.indices
                .iter()
                .map(|index| BlobIdentifier {
                    block_root: self.block_root,
                    index: *index,
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
    ) -> Result<Option<Vec<Arc<BlobSidecar<E>>>>, RPCError> {
        if self.resolved {
            return Err(RPCError::InvalidData("too many responses".to_string()));
        }

        let block_root = blob.block_root();
        if self.request.block_root != block_root {
            return Err(RPCError::InvalidData(format!(
                "un-requested block root {block_root:?}"
            )));
        }
        if !blob.verify_blob_sidecar_inclusion_proof().unwrap_or(false) {
            return Err(RPCError::InvalidData("invalid inclusion proof".to_string()));
        }
        if !self.request.indices.contains(&blob.index) {
            return Err(RPCError::InvalidData(format!(
                "un-requested blob index {}",
                blob.index
            )));
        }
        if self.blobs.iter().any(|b| b.index == blob.index) {
            return Err(RPCError::InvalidData("duplicated data".to_string()));
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

    pub fn terminate(self) -> Option<Vec<Arc<BlobSidecar<E>>>> {
        if self.resolved {
            return None;
        } else {
            Some(self.blobs)
        }
    }
}
