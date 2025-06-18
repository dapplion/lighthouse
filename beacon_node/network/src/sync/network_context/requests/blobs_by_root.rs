use lighthouse_network::rpc::methods::BlobsByRootRequest;
use std::collections::HashMap;
use std::sync::Arc;
use types::{blob_sidecar::BlobIdentifier, BlobSidecar, EthSpec, ForkContext, Hash256};

use super::{ActiveRequestItems, LookupVerifyError};

pub struct BlobCountPerBlock(pub HashMap<Hash256, usize>);

pub struct BlobsByRootRequestItems<E: EthSpec> {
    // TODO(tree-sync): we know ahead of time how many blobs each block has, track it
    block_roots: Vec<Hash256>,
    indices: Vec<u64>,
    items: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> BlobsByRootRequestItems<E> {
    pub fn new(request: BlobCountPerBlock) -> Self {
        Self {
            block_roots: todo!(),
            indices: todo!(),
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlobsByRootRequestItems<E> {
    type Item = Arc<BlobSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, blob: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = blob.block_root();
        if !self.block_roots.contains(&block_root) {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !blob.verify_blob_sidecar_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if !self.indices.contains(&blob.index) {
            return Err(LookupVerifyError::UnrequestedIndex(blob.index));
        }
        if self.items.iter().any(|b| b.index == blob.index) {
            return Err(LookupVerifyError::DuplicatedData(blob.slot(), blob.index));
        }

        self.items.push(blob);

        Ok(self.items.len() >= self.block_roots.len() * self.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
