//! Client for the Ethproofs public API, which is where the proofs come from.
//!
//! Two unauthenticated routes carry everything this needs:
//!
//! - `GET /api/v0/proofs/download/block/{block_hash}` returns a zip of every proof submitted for
//!   that execution block, one entry per proof named `<team>_<cluster_uuid>_<proof_id>.bin`.
//! - `GET /api/v0/blocks/{number}` returns block metadata, used only by the fixture mode.
//!
//! A payload's `block_hash` on a network that follows mainnet execution *is* the hash Ethproofs
//! indexes, so the live path needs no block numbers and no chain walking: it asks for the hash the
//! beacon node asked about.
//!
//! Measured on 2026-10-05: the first proofs for a block appear about five minutes after it, the
//! cohort fills to seven or eight systems by twenty, and every block carries at least four. Proofs
//! run from 250 KB to 2.1 MB, so they exceed the spec's 300 KiB `MAX_PROOF_SIZE`; ours is 4 MiB,
//! deliberately, or real artifacts would not fit.

use std::collections::HashMap;
use std::io::Read;
use std::sync::LazyLock;
use types::ExecutionBlockHash;
use types::execution::{MAX_PROOF_SIZE, ProofType};

const API_BASE: &str = "https://ethproofs.org/api/v0";

/// Proof type per proving team, fixed so that two seeders agree on which system is which.
///
/// The first four are the teams that prove every block rather than every hundredth, so a
/// requirement of two distinct systems is satisfiable from this set alone, and they stay inside
/// `MAX_EXECUTION_PROOFS_PER_PAYLOAD` if proof types ever become gossip subnets.
static PROOF_TYPES: LazyLock<HashMap<&'static str, ProofType>> = LazyLock::new(|| {
    HashMap::from([
        ("antchain-openlabs", 0),
        ("axiom", 1),
        ("matter-labs", 2),
        ("zisk", 3),
        ("brevis", 4),
        ("cysic", 5),
        ("succinct", 6),
        ("zkm", 7),
    ])
});

/// A proof artifact as Ethproofs served it.
pub struct FetchedProof {
    pub proof_type: ProofType,
    pub team: String,
    pub bytes: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct BlockResponse {
    hash: String,
}

/// Every proof Ethproofs holds for `block_hash`, at most one per proving system.
///
/// An empty result means nobody has proven that block yet, which is the normal answer for a block
/// younger than about five minutes.
pub async fn fetch_by_hash(
    client: &reqwest::Client,
    block_hash: ExecutionBlockHash,
    max_proofs: usize,
) -> Result<Vec<FetchedProof>, String> {
    let archive = client
        .get(format!("{API_BASE}/proofs/download/block/{block_hash:?}"))
        .send()
        .await
        .map_err(|e| format!("cannot reach ethproofs: {e}"))?;

    if archive.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(vec![]);
    }

    let bytes = archive
        .error_for_status()
        .map_err(|e| format!("ethproofs refused {block_hash:?}: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("truncated download for {block_hash:?}: {e}"))?;

    extract(&bytes, max_proofs)
}

/// The proofs of one pinned mainnet block, for a devnet whose payloads Ethproofs has never seen.
pub async fn fetch_by_number(
    client: &reqwest::Client,
    block_number: u64,
    max_proofs: usize,
) -> Result<Vec<FetchedProof>, String> {
    let block: BlockResponse = client
        .get(format!("{API_BASE}/blocks/{block_number}"))
        .send()
        .await
        .map_err(|e| format!("cannot reach ethproofs: {e}"))?
        .error_for_status()
        .map_err(|e| format!("block {block_number} not indexed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("block {block_number} metadata is not json: {e}"))?;

    let bytes = client
        .get(format!("{API_BASE}/proofs/download/block/{}", block.hash))
        .send()
        .await
        .map_err(|e| format!("cannot download proofs for block {block_number}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("no proofs for block {block_number}: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("truncated download for block {block_number}: {e}"))?;

    extract(&bytes, max_proofs)
}

/// Read one proof per proving system out of a download, smallest first.
fn extract(archive: &[u8], max_proofs: usize) -> Result<Vec<FetchedProof>, String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|e| format!("download is not a zip: {e}"))?;

    let mut proofs: Vec<FetchedProof> = vec![];
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| format!("unreadable zip entry {index}: {e}"))?;
        if !entry.name().ends_with(".bin") {
            continue;
        }

        // `<team>_<cluster_uuid>_<proof_id>.bin`, and team slugs contain hyphens, never underscores.
        let Some(team) = entry.name().split('_').next().map(str::to_string) else {
            continue;
        };
        let Some(proof_type) = PROOF_TYPES.get(team.as_str()).copied() else {
            continue;
        };
        if proofs.iter().any(|held| held.proof_type == proof_type) {
            continue;
        }

        let mut bytes = vec![];
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read {}: {e}", entry.name()))?;

        // Larger than the SSZ type can carry, so a consumer could not decode it anyway.
        if bytes.len() > MAX_PROOF_SIZE {
            continue;
        }

        proofs.push(FetchedProof {
            proof_type,
            team,
            bytes,
        });
    }

    proofs.sort_by(|a, b| {
        a.bytes
            .len()
            .cmp(&b.bytes.len())
            .then_with(|| a.proof_type.cmp(&b.proof_type))
    });
    proofs.truncate(max_proofs);

    Ok(proofs)
}
