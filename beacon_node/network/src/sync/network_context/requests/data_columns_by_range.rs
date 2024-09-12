use super::{ActiveRequest, LookupVerifyError};
use lighthouse_network::rpc::methods::DataColumnsByRangeRequest;
use std::sync::Arc;
use types::{DataColumnSidecar, EthSpec};

/// Accumulates results of a data_columns_by_range request. Only returns items after receiving the
/// stream termination.
pub struct ActiveDataColumnsByRangeRequest<E: EthSpec> {
    request: DataColumnsByRangeRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
}

impl<E: EthSpec> ActiveDataColumnsByRangeRequest<E> {
    pub fn new(request: DataColumnsByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveDataColumnsByRangeRequest<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    fn add_response(&mut self, data_column: Self::Item) -> Result<bool, LookupVerifyError> {
        if !self.request.columns.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        // TODO: check slot is within bounds

        self.items.push(data_column);

        Ok(self.items.len() >= self.request.count as usize * self.request.columns.len())
    }

    fn consume_items(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
