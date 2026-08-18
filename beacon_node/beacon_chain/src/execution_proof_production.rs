//! Produces EIP-8025 execution proofs for payloads this node has imported.
//!
//! This is the seeder side of the experiment: it lets one node supply proofs to a network of
//! consumers that gate payload import on them. It is not the endgame design. EIP-8025 expects the
//! proof to be signed by a validator or the builder, which means the signature belongs in the
//! validator client; here the beacon node signs with a key handed to it on the command line, which
//! is only acceptable on a devnet.
use crate::{BeaconChain, BeaconChainTypes};
use bls::SecretKey;
use tracing::{debug, warn};
use tree_hash::TreeHash;
use types::execution::{ExecutionProof, ProofData, ProofType, PublicInput, SignedExecutionProof};
use types::{Domain, Hash256, SignedRoot};

/// Signing key and identity used to produce execution proofs.
pub struct ExecutionProofProducer {
    pub secret_key: SecretKey,
    pub validator_index: u64,
    /// Proof types to produce for each payload. Consumers require proofs from several distinct
    /// systems, so a lone seeder has to cover all of them.
    pub proof_types: Vec<ProofType>,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Produce a signed execution proof per configured proof type for an imported payload.
    ///
    /// Returns empty unless this node is configured as a producer. Proof types the engine has no
    /// proof for are skipped rather than failing the batch, since engines may support only some.
    pub async fn produce_execution_proofs(
        &self,
        beacon_block_root: Hash256,
    ) -> Vec<SignedExecutionProof> {
        let (Some(producer), Some(proof_engine)) =
            (&self.execution_proof_producer, &self.proof_engine)
        else {
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
        // `NewPayloadRequest` it sends to the EL, and a mock engine only needs producer and
        // verifier to agree on the identifier.
        let new_payload_request_root = envelope.message.payload.tree_hash_root();

        let slot = envelope.slot();
        let fork_name = self.spec.fork_name_at_slot::<T::EthSpec>(slot);
        let domain = self.spec.compute_domain(
            Domain::ExecutionProof,
            self.spec.fork_version_for_name(fork_name),
            self.genesis_validators_root,
        );

        let mut proofs = vec![];
        for proof_type in &producer.proof_types {
            let proof_data = match proof_engine
                .get_execution_proof(new_payload_request_root, *proof_type)
                .await
            {
                Ok(Some(proof_data)) => proof_data,
                Ok(None) => {
                    debug!(?beacon_block_root, proof_type, "Engine has no proof");
                    continue;
                }
                Err(e) => {
                    warn!(?beacon_block_root, proof_type, error = ?e, "Could not fetch proof");
                    continue;
                }
            };

            let proof_data = match ProofData::new(proof_data) {
                Ok(proof_data) => proof_data,
                Err(e) => {
                    warn!(?beacon_block_root, proof_type, error = ?e, "Proof exceeds MAX_PROOF_SIZE");
                    continue;
                }
            };

            let message = ExecutionProof {
                proof_data,
                proof_type: *proof_type,
                public_input: PublicInput {
                    new_payload_request_root,
                },
                beacon_block_root,
            };
            let signature = producer.secret_key.sign(message.signing_root(domain));

            proofs.push(SignedExecutionProof {
                message,
                validator_index: producer.validator_index,
                signature,
            });
        }

        debug!(?beacon_block_root, %slot, count = proofs.len(), "Produced execution proofs");
        proofs
    }
}
