use beacon_chain::get_block_root;
use lighthouse_network::rpc::BlocksByRootRequest;
use std::collections::HashSet;
use std::sync::Arc;
use types::{EthSpec, ForkContext, Hash256, SignedBeaconBlock};

use super::{ActiveRequestItems, LookupVerifyError};

/// One or more block roots to request. Lookup sync asks for a single root; forward sync
/// asks for a whole chain at once. Either way the response must cover exactly the roots
/// requested, so a short response is an error rather than a partial result.
#[derive(Debug, Clone)]
pub struct BlocksByRootSingleRequest(pub Vec<Hash256>);

impl BlocksByRootSingleRequest {
    pub fn new(block_root: Hash256) -> Self {
        Self(vec![block_root])
    }

    pub fn into_request(self, fork_context: &ForkContext) -> Result<BlocksByRootRequest, String> {
        BlocksByRootRequest::new(self.0, fork_context)
    }
}

pub struct BlocksByRootRequestItems<E: EthSpec> {
    /// Roots still outstanding. Doubles as the check that a response was asked for and
    /// that no root arrives twice.
    wanted: HashSet<Hash256>,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByRootRequestItems<E> {
    pub fn new(request: &BlocksByRootSingleRequest) -> Self {
        Self {
            wanted: request.0.iter().copied().collect(),
            items: Vec::with_capacity(request.0.len()),
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for BlocksByRootRequestItems<E> {
    type Item = Arc<SignedBeaconBlock<E>>;

    /// Append a response chunk. The request resolves once every requested root has
    /// arrived; for a single-root request that is the first chunk.
    /// The active request SHOULD be dropped after `add` returns an error.
    fn add(&mut self, block: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = get_block_root(&block);
        if !self.wanted.remove(&block_root) {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        self.items.push(block);
        Ok(self.wanted.is_empty())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
