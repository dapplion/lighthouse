//! Minimal EIP-8025 proof-engine client.
//!
//! Implements only `verify_execution_proof` from the proof-engine API
//! (consensus-specs `_features/eip8025/proof-engine.md`). The proof engine is a trusted,
//! locally-operated service; its verdict is authoritative for proof validity but never for
//! payload validity.

use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use ssz::Decode;
use std::time::Duration;
use types::ExecutionBlockHash;
use types::execution::{ExecutionProof, SignedExecutionProof};

pub const DEFAULT_VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

const PATH_PROOF_VERIFICATIONS: &str = "/v1/execution_proof_verifications";
const PATH_PROOFS: &str = "/v1/execution_proofs";

#[derive(Debug)]
pub enum ProofEngineError {
    HttpClient(String),
    InvalidUrl(String),
    InvalidResponse(String),
}

/// Outcome of `verify_execution_proof`. `Invalid` means the artifact does not verify; it says
/// nothing about the validity of the payload it claims to prove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofVerificationOutcome {
    Valid,
    Invalid,
}

#[derive(Deserialize)]
struct VerifyResponse {
    status: VerifyStatus,
}

#[derive(Deserialize, Clone, Copy)]
enum VerifyStatus {
    #[serde(rename = "VALID")]
    Valid,
    #[serde(rename = "INVALID")]
    Invalid,
}

pub struct ProofEngine {
    client: reqwest::Client,
    url: SensitiveUrl,
}

impl ProofEngine {
    pub fn new(url: SensitiveUrl) -> Result<Self, ProofEngineError> {
        let client = reqwest::Client::builder()
            .timeout(DEFAULT_VERIFY_TIMEOUT)
            .build()
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?;
        Ok(Self { client, url })
    }

    /// Collect the signed proofs this engine has produced for a payload.
    ///
    /// Empty for an engine that only verifies, which is how a node opts out of seeding: the
    /// difference between a seeder and a consumer is a property of the engine, not of the node.
    ///
    /// `domain` is passed in rather than derived here so the engine needs no chain configuration to
    /// sign, the same arrangement a remote signer has with a validator client.
    pub async fn get_execution_proofs(
        &self,
        beacon_block_root: types::Hash256,
        block_hash: ExecutionBlockHash,
        parent_hash: ExecutionBlockHash,
        domain: types::Hash256,
    ) -> Result<Vec<SignedExecutionProof>, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path(PATH_PROOFS);
        let bytes = self
            .client
            .get(url)
            .query(&[
                ("beacon_block_root", format!("{beacon_block_root:?}")),
                ("block_hash", format!("{block_hash:?}")),
                ("parent_hash", format!("{parent_hash:?}")),
                ("domain", format!("{domain:?}")),
            ])
            .send()
            .await
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .error_for_status()
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| ProofEngineError::InvalidResponse(e.to_string()))?;

        Vec::from_ssz_bytes(&bytes).map_err(|e| ProofEngineError::InvalidResponse(format!("{e:?}")))
    }

    /// EIP-8025 `ProofEngine.verify_execution_proof`.
    pub async fn verify_execution_proof(
        &self,
        proof: &ExecutionProof,
    ) -> Result<ProofVerificationOutcome, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path(PATH_PROOF_VERIFICATIONS);
        let response: VerifyResponse = self
            .client
            .post(url)
            .query(&[
                (
                    "block_hash",
                    format!("{:?}", proof.zk_proof.public_inputs.block_hash),
                ),
                (
                    "parent_hash",
                    format!("{:?}", proof.zk_proof.public_inputs.parent_hash),
                ),
                ("proof_type", proof.zk_proof.proof_type.to_string()),
                ("beacon_block_root", format!("{:?}", proof.beacon_root)),
            ])
            .header("content-type", "application/octet-stream")
            .body(proof.zk_proof.proof_data.to_vec())
            .send()
            .await
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .error_for_status()
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .json()
            .await
            .map_err(|e| ProofEngineError::InvalidResponse(e.to_string()))?;

        Ok(match response.status {
            VerifyStatus::Valid => ProofVerificationOutcome::Valid,
            VerifyStatus::Invalid => ProofVerificationOutcome::Invalid,
        })
    }
}
