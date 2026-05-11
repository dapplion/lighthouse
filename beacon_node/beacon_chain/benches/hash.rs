//! Typed `tree_hash_root` vs the public direct-byte
//! `transactions_tree_hash_root_from_ssz_bytes` for `Transactions`, plus a
//! handcrafted byte-walking `Withdrawals` hasher to confirm withdrawals
//! aren't worth replacing.
//!
//! Inputs (must exist; produced by `cargo run --release --example
//! extract_block -p beacon_chain -- <era_file> <slot> <out>`):
//!     /tmp/sample_block.ssz       (Capella)
//!     /tmp/sample_block_deneb.ssz (Deneb)
//!
//! Run:
//!     cargo bench -p beacon_chain --bench hash
//!
//! Headline (real mainnet blocks, see commit messages on
//! experiment-era-static-cold-load): transactions custom is ~2× faster than
//! the typed path; withdrawals custom is ~1.05× — not worth the maintenance
//! burden of a hand-rolled hasher.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ssz::Decode;
use tree_hash::{Hash256, TreeHash, merkle_root, mix_in_length};
use types::{
    EthSpec, MainnetEthSpec, Transactions, Withdrawals, transactions_tree_hash_root_from_ssz_bytes,
};

const SBB_HEADER_LEN: usize = 100;
const BB_HEADER_LEN: usize = 84;
const BODY_OFF_EXEC_PAYLOAD: usize = 380;
const BODY_OFF_BLS_CHANGES: usize = 384;
const PAYLOAD_OFF_TRANSACTIONS: usize = 504;
const PAYLOAD_OFF_WITHDRAWALS: usize = 508;
const WITHDRAWAL_SIZE: usize = 44;

fn read_u32_le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn slice_exec_payload(signed: &[u8]) -> &[u8] {
    let body = &signed[SBB_HEADER_LEN + BB_HEADER_LEN..];
    let off_exec = read_u32_le(body, BODY_OFF_EXEC_PAYLOAD) as usize;
    let off_bls = read_u32_le(body, BODY_OFF_BLS_CHANGES) as usize;
    &body[off_exec..off_bls]
}

fn slice_transactions_and_withdrawals(exec: &[u8]) -> (&[u8], &[u8]) {
    let off_txs = read_u32_le(exec, PAYLOAD_OFF_TRANSACTIONS) as usize;
    let off_with = read_u32_le(exec, PAYLOAD_OFF_WITHDRAWALS) as usize;
    (&exec[off_txs..off_with], &exec[off_with..])
}

fn withdrawal_root(record: &[u8]) -> Hash256 {
    debug_assert_eq!(record.len(), WITHDRAWAL_SIZE);
    let mut leaves = [0u8; 4 * 32];
    leaves[0..8].copy_from_slice(&record[0..8]);
    leaves[32..32 + 8].copy_from_slice(&record[8..16]);
    leaves[64..64 + 20].copy_from_slice(&record[16..36]);
    leaves[96..96 + 8].copy_from_slice(&record[36..44]);
    merkle_root(&leaves, 4)
}

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

const SAMPLE_PATHS: &[(&str, &str)] = &[
    ("Capella", "/tmp/sample_block.ssz"),
    ("Deneb", "/tmp/sample_block_deneb.ssz"),
];

fn bench_hash(c: &mut Criterion) {
    for &(label, path) in SAMPLE_PATHS {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("# skip {label}: {e}");
                continue;
            }
        };
        let exec = slice_exec_payload(&bytes).to_vec();
        let (tx_bytes, w_bytes) = slice_transactions_and_withdrawals(&exec);
        let tx_bytes = tx_bytes.to_vec();
        let w_bytes = w_bytes.to_vec();

        // Sanity: custom must match typed for both lists.
        let tx_typed = Transactions::<MainnetEthSpec>::from_ssz_bytes(&tx_bytes)
            .expect("tx parse")
            .tree_hash_root();
        let tx_custom = transactions_tree_hash_root_from_ssz_bytes::<MainnetEthSpec>(&tx_bytes)
            .expect("tx custom");
        assert_eq!(tx_typed, tx_custom, "{label} transactions hash diverged");
        let w_typed = Withdrawals::<MainnetEthSpec>::from_ssz_bytes(&w_bytes)
            .expect("w parse")
            .tree_hash_root();
        let w_custom = withdrawals_root_custom::<MainnetEthSpec>(&w_bytes);
        assert_eq!(w_typed, w_custom, "{label} withdrawals hash diverged");

        let mut group = c.benchmark_group(format!("hash_{label}"));

        group.throughput(Throughput::Bytes(tx_bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("transactions", "typed"),
            &tx_bytes,
            |b, bytes| {
                b.iter(|| {
                    Transactions::<MainnetEthSpec>::from_ssz_bytes(bytes)
                        .expect("parse")
                        .tree_hash_root()
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("transactions", "custom"),
            &tx_bytes,
            |b, bytes| {
                b.iter(|| {
                    transactions_tree_hash_root_from_ssz_bytes::<MainnetEthSpec>(bytes)
                        .expect("custom")
                });
            },
        );

        group.throughput(Throughput::Bytes(w_bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("withdrawals", "typed"),
            &w_bytes,
            |b, bytes| {
                b.iter(|| {
                    Withdrawals::<MainnetEthSpec>::from_ssz_bytes(bytes)
                        .expect("parse")
                        .tree_hash_root()
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("withdrawals", "custom"),
            &w_bytes,
            |b, bytes| {
                b.iter(|| withdrawals_root_custom::<MainnetEthSpec>(bytes));
            },
        );

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = bench_hash
}
criterion_main!(benches);
