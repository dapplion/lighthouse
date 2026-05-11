//! `Column::put_batch` perf for the slot-keyed static cold archive.
//!
//! Times one ERA's worth of writes (8192 entries) into each of the three
//! columns the ERA importer hits — `Block`, `BlockRoots`, `StateRoots`.
//!
//! Run:
//!     cargo bench -p store --bench static_cold

use std::path::PathBuf;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use store::config::ColdBackendKind;
use store::{ColdStore, DBColumnCold, StaticColdStore, StoreConfig};
use types::{ChainSpec, MainnetEthSpec, Slot};

#[allow(dead_code)]
fn _spec_warmup() -> ChainSpec {
    ChainSpec::mainnet()
}

const SLOTS_PER_ERA: u64 = 8192;
type PayloadFn = fn(u64) -> Vec<u8>;
const BENCH_ROOT: &str = "/tmp/static_cold_bench";

fn make_block_payload(slot: u64) -> Vec<u8> {
    let mut v = vec![0u8; 200];
    v[0..8].copy_from_slice(&slot.to_le_bytes());
    for (i, byte) in v.iter_mut().enumerate().skip(8) {
        *byte = (slot.wrapping_mul(31).wrapping_add(i as u64) & 0xff) as u8;
    }
    v
}

fn root_payload(slot: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[0..8].copy_from_slice(&slot.to_le_bytes());
    v
}

fn open_store(root: &PathBuf) -> StaticColdStore<MainnetEthSpec> {
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root).expect("mkdir bench root");
    let cfg = StoreConfig {
        cold_backend: ColdBackendKind::Static,
        ..StoreConfig::default()
    };
    let _spec = Arc::new(ChainSpec::mainnet());
    StaticColdStore::<MainnetEthSpec>::open(root, &cfg).expect("open static cold")
}

fn bench_put_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("static_cold_put_batch_one_era");
    group.throughput(Throughput::Elements(SLOTS_PER_ERA));

    let cases: &[(DBColumnCold, PayloadFn)] = &[
        (DBColumnCold::Block, make_block_payload),
        (DBColumnCold::BlockRoots, root_payload),
        (DBColumnCold::StateRoots, root_payload),
    ];

    for (column, mk) in cases.iter().copied() {
        group.bench_with_input(
            BenchmarkId::new("column", format!("{column:?}")),
            &(column, mk),
            |b, &(col, mk)| {
                b.iter_with_setup(
                    || {
                        let root = PathBuf::from(format!(
                            "{BENCH_ROOT}/{col:?}_{:?}",
                            std::time::Instant::now()
                        ));
                        let store = open_store(&root);
                        let items: Vec<(Slot, Vec<u8>)> =
                            (0..SLOTS_PER_ERA).map(|s| (Slot::new(s), mk(s))).collect();
                        (root, store, items)
                    },
                    |(root, store, items)| {
                        store.put_batch(col, items).expect("put_batch");
                        let _ = std::fs::remove_dir_all(&root);
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_put_batch
}
criterion_main!(benches);
