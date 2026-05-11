//! Full block in -> blinded SSZ out, comparing the typed
//! `clone_as_blinded` + `as_ssz_bytes` path against the direct-byte
//! `era::custom_blinder` path on real mainnet sample blocks.
//!
//! Inputs (must exist; produced by `cargo run --release --example
//! extract_block -p beacon_chain -- <era_file> <slot> <out>`):
//!     /tmp/sample_block.ssz       (Capella)
//!     /tmp/sample_block_deneb.ssz (Deneb)
//!
//! Run:
//!     cargo bench -p beacon_chain --bench blinder

use beacon_chain::era::custom_blinder::{custom_blind_capella, custom_blind_deneb};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ssz::Encode;
use types::{ChainSpec, MainnetEthSpec, SignedBeaconBlock};

type BlindFn = fn(&[u8]) -> Result<Vec<u8>, ssz::DecodeError>;

const SAMPLE_PATHS: &[(&str, &str, BlindFn)] = &[
    (
        "Capella",
        "/tmp/sample_block.ssz",
        custom_blind_capella::<MainnetEthSpec>,
    ),
    (
        "Deneb",
        "/tmp/sample_block_deneb.ssz",
        custom_blind_deneb::<MainnetEthSpec>,
    ),
];

fn bench_blind(c: &mut Criterion) {
    let spec = ChainSpec::mainnet();
    for &(label, path, custom) in SAMPLE_PATHS {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("# skip {label}: {e}");
                continue;
            }
        };

        // Sanity: typed and custom roots must agree byte-exactly.
        let block: SignedBeaconBlock<MainnetEthSpec> =
            SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).expect("parse sample");
        let canonical = block.clone_as_blinded().as_ssz_bytes();
        let custom_out = custom(&bytes).expect("custom blinder");
        assert_eq!(canonical, custom_out, "{label} blinder output diverged");

        let mut group = c.benchmark_group(format!("blinder_{label}"));
        group.throughput(Throughput::Bytes(bytes.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("typed", "parse+blind+encode"),
            &bytes,
            |b, bytes| {
                b.iter(|| {
                    let block: SignedBeaconBlock<MainnetEthSpec> =
                        SignedBeaconBlock::from_ssz_bytes(bytes, &spec).expect("parse");
                    let blinded = block.clone_as_blinded();
                    blinded.as_ssz_bytes()
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("custom", "direct-byte"),
            &bytes,
            |b, bytes| {
                b.iter(|| custom(bytes).expect("custom blinder"));
            },
        );

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_blind
}
criterion_main!(benches);
