//! Microbenchmark for `StaticColdStore::put_batch`.
//!
//! Times one ERA's worth of slot-keyed writes (8192 entries) into each of the
//! three slot-keyed columns the ERA importer hits — `Block`, `BlockRoots`,
//! `StateRoots`. Prints per-column wall time and aggregate.
//!
//! Run with:
//!
//!     cargo run --release --example static_cold_bench -p store -- [N_ERAS]
//!
//! Default `N_ERAS=1` simulates one ERA. Pass a larger N to exercise rolling
//! into the next file_id (each file holds 8192 slots).

use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use store::config::ColdBackendKind;
use store::{ColdStore, DBColumnCold, StaticColdStore, StoreConfig};
use types::{ChainSpec, MainnetEthSpec, Slot};

const SLOTS_PER_ERA: u64 = 8192;

fn make_block_payload(slot: u64) -> Vec<u8> {
    // Simulate a typical ~200-byte blinded SignedBeaconBlock payload pre-Bellatrix.
    // Compressible repetitive bytes are unrealistic; use a slot-keyed pattern.
    let mut v = vec![0u8; 200];
    v[0..8].copy_from_slice(&slot.to_le_bytes());
    for (i, byte) in v.iter_mut().enumerate().skip(8) {
        *byte = (slot.wrapping_mul(31).wrapping_add(i as u64) & 0xff) as u8;
    }
    v
}

fn root_payload(slot: u64) -> Vec<u8> {
    // 32-byte root, like BlockRoots / StateRoots.
    let mut v = vec![0u8; 32];
    v[0..8].copy_from_slice(&slot.to_le_bytes());
    v
}

fn time_put_batch(
    store: &StaticColdStore<MainnetEthSpec>,
    column: DBColumnCold,
    items: Vec<(Slot, Vec<u8>)>,
    label: &str,
) {
    let n = items.len();
    let bytes: usize = items.iter().map(|(_, v)| v.len()).sum();
    let t = Instant::now();
    store.put_batch(column, items).expect("put_batch");
    let dt = t.elapsed();
    let dt_s = dt.as_secs_f64();
    println!(
        "{label:<24} n={n:<6} bytes={bytes:<10} elapsed={dt_s:>8.4}s rate={:.1} entries/s {:.2} MB/s",
        n as f64 / dt_s,
        (bytes as f64 / 1_048_576.0) / dt_s,
    );
}

fn main() {
    let n_eras: u64 = env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let bench_root: PathBuf = env::args().nth(2).map(PathBuf::from).unwrap_or_else(|| {
        Path::new("/mnt/ssd/lh-bench/claude-lh-era-files-static/microbench").into()
    });

    let _ = std::fs::remove_dir_all(&bench_root);
    std::fs::create_dir_all(&bench_root).expect("mkdir bench_root");
    let root = bench_root.clone();
    println!("# bench root: {}", root.display());
    println!("# n_eras: {n_eras}");

    let cfg = StoreConfig {
        cold_backend: ColdBackendKind::Static,
        ..StoreConfig::default()
    };
    let _spec = Arc::new(ChainSpec::mainnet());

    // open() needs `&Path` and `&StoreConfig`; the embedded KV at `<root>/index/`
    // gets created automatically via BeaconNodeBackend.
    let store = StaticColdStore::<MainnetEthSpec>::open(&root, &cfg).expect("open static cold");

    let total_t = Instant::now();
    for era in 1..=n_eras {
        let start = (era - 1) * SLOTS_PER_ERA;
        let end = era * SLOTS_PER_ERA;

        let blocks: Vec<(Slot, Vec<u8>)> = (start..end)
            .map(|s| (Slot::new(s), make_block_payload(s)))
            .collect();
        let block_roots: Vec<(Slot, Vec<u8>)> = (start..end)
            .map(|s| (Slot::new(s), root_payload(s)))
            .collect();
        let state_roots: Vec<(Slot, Vec<u8>)> = (start..end)
            .map(|s| (Slot::new(s), root_payload(s)))
            .collect();

        println!("--- era {era} ---");
        time_put_batch(&store, DBColumnCold::Block, blocks, "Block");
        time_put_batch(&store, DBColumnCold::BlockRoots, block_roots, "BlockRoots");
        time_put_batch(&store, DBColumnCold::StateRoots, state_roots, "StateRoots");
    }
    let total = total_t.elapsed().as_secs_f64();
    println!(
        "TOTAL n_eras={n_eras} elapsed={:.3}s avg_per_era={:.3}s",
        total,
        total / n_eras as f64,
    );

    println!("# data left at: {}", root.display());
}
