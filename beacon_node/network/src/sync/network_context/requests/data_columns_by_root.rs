use std::sync::Arc;
use types::{DataColumnSidecar, EthSpec, Hash256};

use super::{ActiveRequestItems, LookupVerifyError};

pub struct DataColumnsByRootRequestItems<E: EthSpec> {
    block_root: Hash256,
    indices: Vec<u64>,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> DataColumnsByRootRequestItems<E> {
    pub fn new(block_root: Hash256, indices: Vec<u64>) -> Self {
        Self {
            block_root,
            indices,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for DataColumnsByRootRequestItems<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    /// Appends a chunk to this multi-item request. If all expected chunks are received, this
    /// method returns `Some`, resolving the request before the stream terminator.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = data_column.block_root();
        if self.block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        if !data_column.verify_inclusion_proof() {
            return Err(LookupVerifyError::InvalidInclusionProof);
        }
        if !self.indices.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        if self.items.iter().any(|d| d.index == data_column.index) {
            return Err(LookupVerifyError::DuplicatedData(
                data_column.slot(),
                data_column.index,
            ));
        }

        self.items.push(data_column);

        Ok(self.items.len() >= self.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
