use lighthouse_network::rpc::methods::DataColumnsByRootRequest;
use std::sync::Arc;
use types::{
    ChainSpec, ColumnIndex, DataColumnSidecar, DataColumnsByRootIdentifier, EthSpec, ForkName,
    Hash256, RuntimeVariableList,
};

use super::{ActiveRequestItems, LookupVerifyError};

pub struct DataColumnsByRootRequestSameIndices {
    block_roots: Vec<Hash256>,
    indices: Vec<ColumnIndex>,
}

pub struct DataColumnsByRootRequestItems<E: EthSpec> {
    // Assumes each block root has the same indices
    block_roots: Vec<Hash256>,
    indices: Vec<ColumnIndex>,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> DataColumnsByRootRequestItems<E> {
    pub fn new(block_roots: Vec<Hash256>, indices: Vec<ColumnIndex>) -> Self {
        Self {
            block_roots,
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
        if !self.block_roots.contains(&block_root) {
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

        Ok(self.items.len() >= self.block_roots.len() * self.indices.len())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
