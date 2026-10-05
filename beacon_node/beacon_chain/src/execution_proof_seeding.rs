//! Seeds the network with the EIP-8025 execution proofs this node's proof engine has produced.
//!
//! Proving and signing both happen in the engine, so the beacon node holds no validator key and
//! only relays what it is handed. An engine that only verifies returns nothing here and the node
//! seeds nothing: whether a node seeds is a property of its engine, not of its configuration.
use crate::{BeaconChain, BeaconChainTypes};
use tracing::{debug, warn};
use types::execution::SignedExecutionProof;
use types::{Domain, EthSpec, Hash256, Slot};

/// How far back a sweep looks for payloads to seed.
///
/// Ethproofs serves a block's first proof around five minutes after it and the rest of the cohort
/// over the following twenty, so a payload is proven long after it stopped being the head and a
/// sweep that only looked at recent slots would seed nothing. 256 slots is about fifty minutes of
/// mainnet.
const SEEDING_WINDOW: u64 = 256;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Canonical payloads within the seeding window that proofs have not yet validated.
    pub fn unproven_payload_block_roots(&self) -> Vec<Hash256> {
        let head = self.canonical_head.cached_head();
        let head_slot = head.head_slot();
        let finalized_slot = head
            .finalized_checkpoint()
            .epoch
            .start_slot(T::EthSpec::slots_per_epoch());
        let oldest = head_slot
            .as_u64()
            .saturating_sub(SEEDING_WINDOW)
            .max(finalized_slot.as_u64());

        let mut roots: Vec<Hash256> = vec![];
        for slot in (oldest..=head_slot.as_u64()).map(Slot::new) {
            // A skipped slot carries the previous slot's root, so the same payload repeats.
            let Ok(root) = head.snapshot.beacon_state.get_block_root(slot) else {
                continue;
            };
            if roots.last() == Some(root) || self.execution_proofs_satisfied(root) {
                continue;
            }
            roots.push(*root);
        }
        roots
    }

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

        let fork_name = self.spec.fork_name_at_slot::<T::EthSpec>(envelope.slot());
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            self.genesis_validators_root,
        );

        match proof_engine
            .get_execution_proofs(
                beacon_block_root,
                envelope.message.payload.block_hash,
                envelope.message.payload.parent_hash,
                domain,
            )
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
