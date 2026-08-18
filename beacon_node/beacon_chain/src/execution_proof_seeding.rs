//! Seeds the network with the EIP-8025 execution proofs this node's proof engine has produced.
//!
//! Proving and signing both happen in the engine, so the beacon node holds no validator key and
//! only relays what it is handed. An engine that only verifies returns nothing here and the node
//! seeds nothing: whether a node seeds is a property of its engine, not of its configuration.
use crate::{BeaconChain, BeaconChainTypes};
use tracing::{debug, warn};
use tree_hash::TreeHash;
use types::execution::SignedExecutionProof;
use types::{Domain, Hash256};

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Collect the signed execution proofs our proof engine holds for an executed payload.
    pub async fn fetch_execution_proofs(
        &self,
        beacon_block_root: Hash256,
    ) -> Vec<SignedExecutionProof> {
        let Some(proof_engine) = &self.proof_engine else {
            return vec![];
        };

        let Some(envelope) = self
            .pending_payload_cache
            .get_executed_payload_envelope(&beacon_block_root)
        else {
            debug!(?beacon_block_root, "No envelope to prove");
            return vec![];
        };

        // Stand-in for the EIP-8025 `new_payload_request_root`. Lighthouse does not merkleize the
        // `NewPayloadRequest` it sends to the EL, and producer and verifier only need to agree on
        // the identifier.
        let new_payload_request_root = envelope.message.payload.tree_hash_root();

        let fork_name = self.spec.fork_name_at_slot::<T::EthSpec>(envelope.slot());
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            self.genesis_validators_root,
        );

        match proof_engine
            .get_execution_proofs(beacon_block_root, new_payload_request_root, domain)
            .await
        {
            Ok(proofs) => proofs,
            Err(e) => {
                warn!(?beacon_block_root, error = ?e, "Could not fetch execution proofs");
                vec![]
            }
        }
    }
}
