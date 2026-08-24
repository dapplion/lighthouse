use beacon_chain::get_block_root;
use lighthouse_network::rpc::BlocksByRootRequest;
use std::collections::HashSet;
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
    request: BlocksByRootSingleRequest,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByRootRequestItems<E> {
    pub fn new(request: BlocksByRootSingleRequest) -> Self {
        Self {
            request,
            items: vec![],
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlocksByRootRequestItems<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = get_block_root(&block);
        if self.request.0 != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        self.items.push(block);
        // Always returns true, blocks by root expects a single response
        Ok(true)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}

/// Request a batch of block roots in one `BlocksByRoot`. Forward sync asks for a whole
/// chain at once; the response must cover exactly the roots asked for.
#[derive(Debug, Clone)]
pub struct BlocksByRootBatchRequest(pub Vec<Hash256>);

impl BlocksByRootBatchRequest {
    pub fn into_request(self, fork_context: &ForkContext) -> Result<BlocksByRootRequest, String> {
        BlocksByRootRequest::new(self.0, fork_context)
    }
}

pub struct BlocksByRootBatchRequestItems<E: EthSpec> {
    /// Roots still outstanding. Doubles as the check that a response was asked for and
    /// that no root arrives twice.
    wanted: HashSet<Hash256>,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByRootBatchRequestItems<E> {
    pub fn new(request: &BlocksByRootBatchRequest) -> Self {
        Self {
            wanted: request.0.iter().copied().collect(),
            items: Vec::with_capacity(request.0.len()),
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlocksByRootBatchRequestItems<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    fn add(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = get_block_root(&block);
        if !self.wanted.remove(&block_root) {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        self.items.push(block);
        // The response must cover exactly the roots requested, so it is complete only
        // once every one has arrived. A short response is an error, not a partial.
        Ok(self.wanted.is_empty())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
