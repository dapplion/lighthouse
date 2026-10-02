//! Minimal client for the Ethproofs public API, so this engine can serve proof artifacts that
//! real proving clusters produced rather than bytes it made up.
//!
//! Two endpoints, both unauthenticated:
//!
//! - `GET /api/v0/blocks/{number}` returns block metadata, including the canonical hash.
//! - `GET /api/v0/proofs/download/block/{hash}` returns a zip holding every proof submitted for
//!   that block, one entry per proof named `<team>_<cluster_uuid>_<proof_id>.bin`.
//!
//! Proofs are opaque: each team uses its own encoding, zstd frames or gzip or a bare serialization.
//! That is the point. What a devnet wants from them is realistic size and entropy, not something a
//! verifier could check.

use serde::Deserialize;
use std::io::Read;
use types::execution::MAX_PROOF_SIZE;

const API_BASE: &str = "https://ethproofs.org/api/v0";

/// The whole prover cohort only proves every hundredth mainnet block. Off-stride blocks carry a
/// proof or two, which is not enough to give every proof type distinct bytes.
const BLOCK_STRIDE: u64 = 100;

/// A block known to hold proofs from nine teams. Pinned rather than discovered so that two engines
/// started at different times agree on the bytes, and so a devnet does not change under us.
pub const DEFAULT_BLOCK: u64 = 25_778_500;

/// Download quota is ten requests a minute, so give up long before tripping it.
const MAX_BLOCKS_TO_TRY: usize = 3;

pub struct FetchedProof {
    pub proving_system: String,
    pub block_number: u64,
    pub bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct BlockResponse {
    hash: String,
}

/// Fetch `count` proofs, each from a different proving system.
///
/// Walks backwards in stride from `block` if one block does not carry enough of them.
pub async fn fetch(count: usize, block: u64) -> Result<Vec<FetchedProof>, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("cannot build http client: {e}"))?;

    let mut proofs: Vec<FetchedProof> = vec![];
    let mut block_number = block - block % BLOCK_STRIDE;

    for _ in 0..MAX_BLOCKS_TO_TRY {
        if proofs.len() >= count {
            break;
        }

        for proof in fetch_block(&client, block_number).await? {
            if proofs.len() >= count {
                break;
            }
            // One proof per system, so that distinct proof types carry distinct bytes.
            if !proofs
                .iter()
                .any(|held| held.proving_system == proof.proving_system)
            {
                proofs.push(proof);
            }
        }
        block_number -= BLOCK_STRIDE;
    }

    if proofs.len() < count {
        return Err(format!(
            "found {} proofs across {MAX_BLOCKS_TO_TRY} blocks, needed {count}",
            proofs.len()
        ));
    }
    Ok(proofs)
}

/// Every proof submitted for one block, smallest first so a devnet gossips the cheap ones by
/// default and the ordering does not depend on how the archive happens to be laid out.
async fn fetch_block(
    client: &reqwest::Client,
    block_number: u64,
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

    let archive = client
        .get(format!("{API_BASE}/proofs/download/block/{}", block.hash))
        .send()
        .await
        .map_err(|e| format!("cannot download proofs for block {block_number}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("no proofs for block {block_number}: {e}"))?
        .bytes()
        .await
        .map_err(|e| format!("truncated download for block {block_number}: {e}"))?;

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|e| format!("block {block_number} download is not a zip: {e}"))?;

    let mut proofs = vec![];
    for index in 0..zip.len() {
        let mut entry = zip
            .by_index(index)
            .map_err(|e| format!("unreadable zip entry {index}: {e}"))?;
        if !entry.name().ends_with(".bin") {
            continue;
        }
        // `<team>_<cluster_uuid>_<proof_id>.bin`, and team slugs themselves contain hyphens only.
        let Some(proving_system) = entry.name().split('_').next().map(str::to_string) else {
            continue;
        };

        let mut bytes = vec![];
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("cannot read {}: {e}", entry.name()))?;

        // The SSZ type cannot carry more than this, and it is a REJECT on gossip besides.
        if bytes.len() > MAX_PROOF_SIZE {
            continue;
        }

        proofs.push(FetchedProof {
            proving_system,
            block_number,
            bytes,
        });
    }

    proofs.sort_by(|a, b| {
        a.bytes
            .len()
            .cmp(&b.bytes.len())
            .then_with(|| a.proving_system.cmp(&b.proving_system))
    });
    Ok(proofs)
}
