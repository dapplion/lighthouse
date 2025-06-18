use beacon_chain::get_block_root;
use lighthouse_network::rpc::BlocksByRootRequest;
use std::sync::Arc;
use types::{EthSpec, ForkContext, Hash256, SignedBeaconBlock};

use super::{ActiveRequestItems, LookupVerifyError};

pub struct BlocksByRootRequestItems<E: EthSpec> {
    request: BlocksByRootRequest,
    items: Vec<Arc<SignedBeaconBlock<E>>>,
}

impl<E: EthSpec> BlocksByRootRequestItems<E> {
    pub fn new(request: BlocksByRootRequest) -> Self {
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
        // TODO(tree-sync): Cache this block root calculation
        let block_root = get_block_root(&block);
        if !self
            .request
            .block_roots()
            .iter()
            .any(|root| root == &block_root)
        {
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
