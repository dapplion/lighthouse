use super::{ActiveRequest, LookupVerifyError};
use lighthouse_network::{rpc::methods::DataColumnsByRangeRequest, PeerId};
use std::sync::Arc;
use types::{DataColumnSidecar, EthSpec};

/// Accumulates results of a data_columns_by_range request. Only returns items after receiving the
/// stream termination.
pub struct ActiveDataColumnsByRangeRequest<E: EthSpec> {
    request: DataColumnsByRangeRequest,
    items: Vec<Arc<DataColumnSidecar<E>>>,
    resolved: bool,
    pub(crate) peer_id: PeerId,
}

impl<E: EthSpec> ActiveDataColumnsByRangeRequest<E> {
    pub fn new(request: DataColumnsByRangeRequest, peer_id: PeerId) -> Self {
        Self {
            request,
            items: vec![],
            resolved: false,
            peer_id,
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveDataColumnsByRangeRequest<E> {
    type Item = Arc<DataColumnSidecar<E>>;

    fn add_response(
        &mut self,
        data_column: Arc<DataColumnSidecar<E>>,
    ) -> Result<Option<Vec<Self::Item>>, LookupVerifyError> {
        if !self.request.columns.contains(&data_column.index) {
            return Err(LookupVerifyError::UnrequestedIndex(data_column.index));
        }
        // TODO: check slot is within bounds

        self.items.push(data_column);
        Ok(None)
    }

    fn terminate(mut self) -> Result<Option<Vec<Self::Item>>, LookupVerifyError> {
        if self.resolved {
            Ok(None)
        } else {
            Ok(Some(std::mem::take(&mut self.items)))
        }
    }

    /// Mark request as resolved (= has returned something downstream) while marking this status as
    /// true for future calls.
    fn resolve(&mut self) -> bool {
        std::mem::replace(&mut self.resolved, true)
    }

    fn peer(&self) -> &PeerId {
        &self.peer_id
    }
}
