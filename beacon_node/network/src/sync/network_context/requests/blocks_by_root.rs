use lighthouse_network::rpc::BlocksByRootRequest;
use std::sync::Arc;
use types::{EthSpec, ForkContext, Hash256, SignedBeaconBlock};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Copy, Clone)]
pub struct BlocksByRootSingleRequest(pub Hash256);

impl BlocksByRootSingleRequest {
    pub fn into_request(self, fork_context: &ForkContext) -> Result<BlocksByRootRequest, String> {
        // This should always succeed (single block root), but we return a `Result` for safety.
        BlocksByRootRequest::new(vec![self.0], fork_context)
    }
}

pub struct BlocksByRootRequestItems<E: EthSpec> {
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByRootRequestItems<E> {
    pub fn new() -> Self {
        Self { items: vec![] }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlocksByRootRequestItems<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    /// Collect the single response without hashing it on the async sync task.
    /// Root equality is checked by the per-peer-limited block processing worker before import
    /// or any requests based on the returned body's contents.
    fn add(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        self.items.push(block);
        // Always returns true, blocks by root expects a single response
        Ok(true)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
