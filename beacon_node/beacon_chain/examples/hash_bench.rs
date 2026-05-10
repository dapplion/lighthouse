//! Microbench: typed `tree_hash_root` vs direct-byte custom hasher for
//! `Transactions` and `Withdrawals` lists from real mainnet blocks.
//!
//! Goal: figure out how much of the custom-blinder cost is actually the SHA-256
//! work (irreducible) vs the typed parse overhead (allocations) — separately
//! for the transactions list and the withdrawals list. If the custom hasher
//! beats the typed path by a wide margin for both, both are worth replacing.
//! If withdrawals are negligible either way, only the transactions hasher is
//! worth the surgery.
//!
//! Run:
//!     cargo run --release --example hash_bench -p beacon_chain -- [iters]

use ssz::Decode;
use std::env;
use std::time::{Duration, Instant};
use tree_hash::{Hash256, TreeHash, merkle_root, mix_in_length};
use types::{EthSpec, MainnetEthSpec, Transactions, Withdrawals};

const SAMPLE_PATH_CAPELLA: &str = "/tmp/sample_block.ssz";
const SAMPLE_PATH_DENEB: &str = "/tmp/sample_block_deneb.ssz";

const SBB_HEADER_LEN: usize = 100;
const BB_HEADER_LEN: usize = 84;
const BODY_OFF_EXEC_PAYLOAD: usize = 380;
const BODY_OFF_BLS_CHANGES: usize = 384;
const PAYLOAD_OFF_TRANSACTIONS: usize = 504;
const PAYLOAD_OFF_WITHDRAWALS: usize = 508;

const WITHDRAWAL_SIZE: usize = 44; // 8 + 8 + 20 + 8 (fixed-size struct)

fn read_u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// Slice out the SSZ-encoded execution payload bytes from a Capella+
/// SignedBeaconBlock. (Layout up to `BODY_OFF_BLS_CHANGES` is shared between
/// Capella and Deneb.)
fn slice_exec_payload(signed: &[u8]) -> &[u8] {
    let body = &signed[SBB_HEADER_LEN + BB_HEADER_LEN..];
    let off_exec = read_u32_le(body, BODY_OFF_EXEC_PAYLOAD) as usize;
    let off_bls = read_u32_le(body, BODY_OFF_BLS_CHANGES) as usize;
    &body[off_exec..off_bls]
}

fn slice_transactions_and_withdrawals(exec: &[u8]) -> (&[u8], &[u8]) {
    let off_txs = read_u32_le(exec, PAYLOAD_OFF_TRANSACTIONS) as usize;
    let off_with = read_u32_le(exec, PAYLOAD_OFF_WITHDRAWALS) as usize;
    let txs = &exec[off_txs..off_with];
    let withs = &exec[off_with..];
    (txs, withs)
}

/// Tree-hash a single ByteList<u8, max_bytes> from raw bytes.
/// Per the SSZ spec: pad the data to 32-byte chunks, merkleize the chunks
/// padded to `max_bytes / 32` leaves, then mix in the byte length.
fn bytelist_root(bytes: &[u8], max_bytes: usize) -> Hash256 {
    let min_leaves = max_bytes.div_ceil(32);
    let root = merkle_root(bytes, min_leaves);
    mix_in_length(&root, bytes.len())
}

/// Custom `Transactions` tree hash. Walks the SSZ List<Transaction, MAX_TX>
/// offset table directly (no typed allocation), hashes each transaction in
/// place, then list-merkleizes the per-tx roots and mixes in the count.
fn transactions_root_custom<E: EthSpec>(bytes: &[u8]) -> Hash256 {
    let max_tx = E::max_transactions_per_payload();
    let max_bytes = E::max_bytes_per_transaction();

    if bytes.is_empty() {
        // Empty list: root = mix_in_length(zero_root_padded_to_max_tx, 0).
        let empty_root = merkle_root(&[], max_tx);
        return mix_in_length(&empty_root, 0);
    }

    // First u32 is the offset of the first element. For a List of variable-
    // size items, there are `n` u32 offsets up front, where `n = first_offset / 4`.
    let first_off = read_u32_le(bytes, 0) as usize;
    let n = first_off / 4;

    // Read the offset table to enumerate each tx's byte slice.
    let mut tx_roots: Vec<u8> = Vec::with_capacity(n * 32);
    for i in 0..n {
        let start = read_u32_le(bytes, i * 4) as usize;
        let end = if i + 1 < n {
            read_u32_le(bytes, (i + 1) * 4) as usize
        } else {
            bytes.len()
        };
        let tx = &bytes[start..end];
        let root = bytelist_root(tx, max_bytes);
        tx_roots.extend_from_slice(root.as_slice());
    }

    let list_root = merkle_root(&tx_roots, max_tx);
    mix_in_length(&list_root, n)
}

/// SSZ tree hash of one fixed-size Withdrawal record:
///   index (u64, 8) | validator_index (u64, 8) | address (20) | amount (u64, 8)
/// Each field becomes a 32-byte leaf (right-padded with zeros for the smaller
/// scalars). Merkleize 4 leaves.
fn withdrawal_root(record: &[u8]) -> Hash256 {
    debug_assert_eq!(record.len(), WITHDRAWAL_SIZE);
    let mut leaves = [0u8; 4 * 32];
    leaves[0..8].copy_from_slice(&record[0..8]); // index
    leaves[32..32 + 8].copy_from_slice(&record[8..16]); // validator_index
    leaves[64..64 + 20].copy_from_slice(&record[16..36]); // address (20 bytes)
    leaves[96..96 + 8].copy_from_slice(&record[36..44]); // amount
    merkle_root(&leaves, 4)
}

/// Custom `Withdrawals` tree hash. Withdrawals is `List<Withdrawal, MAX_W>`
/// where each `Withdrawal` is fixed-size (44 bytes) so the SSZ encoding has
/// no offset table — items are concatenated back-to-back.
fn withdrawals_root_custom<E: EthSpec>(bytes: &[u8]) -> Hash256 {
    let max_w = E::max_withdrawals_per_payload();
    let n = bytes.len() / WITHDRAWAL_SIZE;
    let mut roots: Vec<u8> = Vec::with_capacity(n * 32);
    for i in 0..n {
        let off = i * WITHDRAWAL_SIZE;
        let r = withdrawal_root(&bytes[off..off + WITHDRAWAL_SIZE]);
        roots.extend_from_slice(r.as_slice());
    }
    let list_root = merkle_root(&roots, max_w);
    mix_in_length(&list_root, n)
}

fn ns(d: Duration, n: usize) -> f64 {
    d.as_secs_f64() * 1e9 / n as f64
}

fn run(label: &str, path: &str, iters: usize) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("# skip {label}: {e}");
            return;
        }
    };
    let exec = slice_exec_payload(&bytes);
    let (tx_bytes, w_bytes) = slice_transactions_and_withdrawals(exec);
    println!(
        "\n=== {label} ===  block {} bytes, exec_payload {} bytes, transactions {} bytes, withdrawals {} bytes",
        bytes.len(),
        exec.len(),
        tx_bytes.len(),
        w_bytes.len()
    );

    // Sanity: typed vs custom must agree on both roots.
    let tx_typed_root = Transactions::<MainnetEthSpec>::from_ssz_bytes(tx_bytes)
        .unwrap()
        .tree_hash_root();
    let tx_custom_root = transactions_root_custom::<MainnetEthSpec>(tx_bytes);
    println!(
        "transactions_root match = {}",
        tx_typed_root == tx_custom_root
    );

    let w_typed_root = Withdrawals::<MainnetEthSpec>::from_ssz_bytes(w_bytes)
        .unwrap()
        .tree_hash_root();
    let w_custom_root = withdrawals_root_custom::<MainnetEthSpec>(w_bytes);
    println!(
        "withdrawals_root match  = {}",
        w_typed_root == w_custom_root
    );

    // ---- transactions: typed parse + tree_hash_root ----
    let t = Instant::now();
    for _ in 0..iters {
        let _r = Transactions::<MainnetEthSpec>::from_ssz_bytes(tx_bytes)
            .unwrap()
            .tree_hash_root();
    }
    let dt_tx_typed = t.elapsed();

    // ---- transactions: custom byte-walking hasher ----
    let t = Instant::now();
    for _ in 0..iters {
        let _r = transactions_root_custom::<MainnetEthSpec>(tx_bytes);
    }
    let dt_tx_custom = t.elapsed();

    // ---- withdrawals: typed parse + tree_hash_root ----
    let t = Instant::now();
    for _ in 0..iters {
        let _r = Withdrawals::<MainnetEthSpec>::from_ssz_bytes(w_bytes)
            .unwrap()
            .tree_hash_root();
    }
    let dt_w_typed = t.elapsed();

    // ---- withdrawals: custom byte-walking hasher ----
    let t = Instant::now();
    for _ in 0..iters {
        let _r = withdrawals_root_custom::<MainnetEthSpec>(w_bytes);
    }
    let dt_w_custom = t.elapsed();

    println!("{:<48} {:>12} {:>12}", "method", "ns/iter", "us/iter");
    let row = |label: &str, dt: Duration| {
        println!(
            "{:<48} {:>12.0} {:>12.2}",
            label,
            ns(dt, iters),
            ns(dt, iters) / 1000.0
        );
    };
    row("transactions: typed parse + tree_hash_root", dt_tx_typed);
    row("transactions: custom byte hasher", dt_tx_custom);
    row("withdrawals:  typed parse + tree_hash_root", dt_w_typed);
    row("withdrawals:  custom byte hasher", dt_w_custom);
    println!(
        "tx speedup custom vs typed:           {:.2}x",
        dt_tx_typed.as_secs_f64() / dt_tx_custom.as_secs_f64()
    );
    println!(
        "withdrawals speedup custom vs typed:  {:.2}x",
        dt_w_typed.as_secs_f64() / dt_w_custom.as_secs_f64()
    );
    println!(
        "tx hash share of total custom-blinder cost: dominant if {:.0}us > snappy + walk",
        ns(dt_tx_custom, iters) / 1000.0
    );
}

fn main() {
    let iters: usize = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    println!("# iters: {iters}");
    run("Capella", SAMPLE_PATH_CAPELLA, iters);
    run("Deneb", SAMPLE_PATH_DENEB, iters);
}
