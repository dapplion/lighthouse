//! Minimal EIP-8025 proof-engine client.
//!
//! Implements only `verify_execution_proof` from the proof-engine API
//! (consensus-specs `_features/eip8025/proof-engine.md`). The proof engine is a trusted,
//! locally-operated service; its verdict is authoritative for proof validity but never for
//! payload validity.

use sensitive_url::SensitiveUrl;
use serde::Deserialize;
use std::time::Duration;
use types::Hash256;
use types::execution::ExecutionProof;

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

    /// Fetch the proof this engine holds for `new_payload_request_root` and `proof_type`.
    ///
    /// Only the proof producer calls this; a consumer never needs it, since proofs reach it over
    /// gossip. Returns `None` when the engine has no proof of that type for that payload.
    pub async fn get_execution_proof(
        &self,
        new_payload_request_root: Hash256,
        proof_type: u8,
    ) -> Result<Option<Vec<u8>>, ProofEngineError> {
        let mut url = self.url.expose_full().clone();
        url.set_path(&format!(
            "{PATH_PROOFS}/{new_payload_request_root:?}/{proof_type}"
        ));
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let bytes = response
            .error_for_status()
            .map_err(|e| ProofEngineError::HttpClient(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| ProofEngineError::InvalidResponse(e.to_string()))?;

        Ok(Some(bytes.to_vec()))
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
                    "new_payload_request_root",
                    format!("{:?}", proof.public_input.new_payload_request_root),
                ),
                ("proof_type", proof.proof_type.to_string()),
                (
                    "beacon_block_root",
                    format!("{:?}", proof.beacon_block_root),
                ),
            ])
            .header("content-type", "application/octet-stream")
            .body(proof.proof_data.to_vec())
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
