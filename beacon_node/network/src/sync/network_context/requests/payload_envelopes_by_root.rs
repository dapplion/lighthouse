use lighthouse_network::rpc::methods::PayloadEnvelopesByRootRequest;
use std::collections::HashSet;
use std::sync::Arc;
use types::{EthSpec, ForkContext, Hash256, SignedExecutionPayloadEnvelope};

use super::{ActiveRequestItems, LookupVerifyError};

#[derive(Debug, Clone)]
pub struct PayloadRootsRequest(pub Vec<Hash256>);

impl PayloadRootsRequest {
    pub fn new(block_root: Hash256) -> Self {
        Self(vec![block_root])
    }

    pub fn into_request(
        self,
        fork_context: &ForkContext,
    ) -> Result<PayloadEnvelopesByRootRequest, String> {
        PayloadEnvelopesByRootRequest::new(self.0, fork_context)
    }
}

pub struct PayloadEnvelopesByRootRequestItems<E: EthSpec> {
    /// Roots still outstanding. Doubles as the check that a response was asked for and
    /// that no root arrives twice.
    wanted: HashSet<Hash256>,
    items: Vec<Arc<SignedExecutionPayloadEnvelope<E>>>,
}

impl<E: EthSpec> PayloadEnvelopesByRootRequestItems<E> {
    pub fn new(request: &PayloadRootsRequest) -> Self {
        Self {
            wanted: request.0.iter().copied().collect(),
            items: Vec::with_capacity(request.0.len()),
        }
    }
}

impl<E: EthSpec> ActiveRequestItems for PayloadEnvelopesByRootRequestItems<E> {
    type Item = Arc<SignedExecutionPayloadEnvelope<E>>;

    /// Resolves once every requested root has arrived; drop the request on error.
    fn add(&mut self, envelope: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = envelope.message.beacon_block_root;
        if !self.wanted.remove(&block_root) {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }
        self.items.push(envelope);
        Ok(self.wanted.is_empty())
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
