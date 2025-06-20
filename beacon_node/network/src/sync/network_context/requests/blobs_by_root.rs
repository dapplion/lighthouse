use std::sync::Arc;
use types::{BlobSidecar, EthSpec, Hash256};

use super::{ActiveRequestItems, LookupVerifyError};

pub struct BlobsByRootRequestItems<E: EthSpec> {
    block_root: Hash256,
    indices: Vec<u64>,
    items: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> BlobsByRootRequestItems<E> {
    pub fn new(block_root: Hash256, indices: Vec<u64>) -> Self {
        Self {
            block_root,
            indices,
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
        if self.block_root != block_root {
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

        Ok(self.items.len() >= self.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
