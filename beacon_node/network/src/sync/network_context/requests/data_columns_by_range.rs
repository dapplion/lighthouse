use super::{ActiveRequest, LookupVerifyError};
use lighthouse_network::rpc::{
    methods::{BlobsByRangeRequest, DataColumnsByRangeRequest},
    BlocksByRangeRequest,
};
use std::sync::Arc;
use types::{BlobSidecar, DataColumnSidecar, EthSpec, SignedBeaconBlock};

/// Accumulates results of a blocks_by_range request. Only returns items after receiving the
/// stream termination.
pub struct ActiveBlocksByRangeRequest<E: EthSpec> {
    request: BlocksByRangeRequest,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> ActiveBlocksByRangeRequest<E> {
    pub fn new(request: BlocksByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveBlocksByRangeRequest<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    fn add_response(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError> {
        if item.slot().as_u64() < *self.request.start_slot()
            || item.slot().as_u64() >= self.request.start_slot() + self.request.count()
        {
            return Err(LookupVerifyError::UnrequestedSlot(item.slot()));
        }

        self.items.push(item);

        Ok(self.items.len() >= *self.request.count() as usize)
    }

    fn consume_items(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }

    fn name() -> &'static str {
        "blocks_by_range"
    }
}

/// Accumulates results of a blobs_by_range request. Only returns items after receiving the
/// stream termination.
pub struct ActiveBlobsByRangeRequest<E: EthSpec> {
    request: BlobsByRangeRequest,
    items: Vec<Arc<BlobSidecar<E>>>,
}

impl<E: EthSpec> ActiveBlobsByRangeRequest<E> {
    pub fn new(request: BlobsByRangeRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequest for ActiveBlobsByRangeRequest<E> {
    type Item = Arc<BlobSidecar<E>>;

    fn add_response(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError> {
        if item.slot() < self.request.start_slot
            || item.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(item.slot()));
        }
        // TODO: Should check if index is within bounds

        self.items.push(item);

        // Skip check if blobs are ready as it's rare that all blocks have max blobs
        Ok(false)
    }

    fn consume_items(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }

    fn name() -> &'static str {
        "blobs_by_range"
    }
}

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

    fn add_response(&mut self, item: Self::Item) -> Result<bool, LookupVerifyError> {
        if item.slot() < self.request.start_slot
            || item.slot() >= self.request.start_slot + self.request.count
        {
            return Err(LookupVerifyError::UnrequestedSlot(item.slot()));
        }
        if !self.request.columns.contains(&item.index) {
            return Err(LookupVerifyError::UnrequestedIndex(item.index));
        }

        self.items.push(item);

        Ok(self.items.len() >= self.request.count as usize * self.request.columns.len())
    }

    fn consume_items(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }

    fn name() -> &'static str {
        "data_columns_by_range"
    }
}
