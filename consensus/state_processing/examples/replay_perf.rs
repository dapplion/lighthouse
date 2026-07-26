//! Replay perf fixtures (`finalized_state.ssz` + `next_block_*.ssz`) through
//! Lighthouse state processing, mirroring live block import: per-slot
//! processing with known parent state root, per-block bulk signature
//! verification against a prebuilt decompressed pubkey table, then
//! `update_tree_hash_cache` checked against `block.state_root`.
//!
//! With a thresholds file, acts as a perf regression gate: exits 1 if any
//! measured metric exceeds its committed threshold (durations in ms).
//!
//! Usage: replay_perf <fixtures_dir> [thresholds.json]

use std::borrow::Cow;
use std::path::Path;
use std::time::{Duration, Instant};

use bls::PublicKey;
use rayon::prelude::*;
use state_processing::{
    AllCaches, BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, per_block_processing,
    per_block_processing::block_signature_verifier::BlockSignatureVerifier, per_slot_processing,
};
use types::{BeaconState, ChainSpec, MainnetEthSpec, SignedBeaconBlock};

type E = MainnetEthSpec;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("usage: replay_perf <fixtures_dir> [thresholds.json]");
    let thresholds_path = args.next();
    let dir = Path::new(&dir);
    let spec = ChainSpec::mainnet();

    let state_bytes = std::fs::read(dir.join("finalized_state.ssz")).expect("read state");
    eprintln!("state: {} bytes", state_bytes.len());

    let mut block_files: Vec<(u64, std::path::PathBuf)> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().into_string().ok()?;
            let slot = name
                .strip_prefix("next_block_")?
                .strip_suffix(".ssz")?
                .parse()
                .ok()?;
            Some((slot, e.path()))
        })
        .collect();
    block_files.sort();

    let t = Instant::now();
    let blocks: Vec<SignedBeaconBlock<E>> = block_files
        .iter()
        .map(|(_, p)| {
            let bytes = std::fs::read(p).expect("read block");
            SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).expect("decode block")
        })
        .collect();
    eprintln!("decode {} blocks: {:.3?}", blocks.len(), t.elapsed());

    let t = Instant::now();
    let mut state = BeaconState::<E>::from_ssz_bytes(&state_bytes, &spec).expect("decode state");
    let decode_state = t.elapsed();
    eprintln!("decode state (slot {}): {:.3?}", state.slot(), decode_state);

    let t = Instant::now();
    let pubkey_bytes: Vec<_> = state.validators().iter().map(|v| v.pubkey).collect();
    let pubkeys: Vec<PublicKey> = pubkey_bytes
        .par_iter()
        .map(|pk| pk.decompress().expect("decompress pubkey"))
        .collect();
    let decompress = t.elapsed();
    eprintln!(
        "decompress {} pubkeys (rayon): {:.3?}",
        pubkeys.len(),
        decompress
    );

    let pk_index: std::collections::HashMap<_, usize> = pubkey_bytes
        .iter()
        .enumerate()
        .map(|(i, pk)| (*pk, i))
        .collect();

    let t = Instant::now();
    let mut initial_root = state.update_tree_hash_cache().expect("initial tree hash");
    let build_tree = t.elapsed();
    eprintln!(
        "initial tree hash: {:.3?} root {initial_root:?}",
        build_tree
    );

    let t = Instant::now();
    state.build_all_caches(&spec).expect("build caches");
    let build_caches = t.elapsed();
    eprintln!(
        "build caches: {:.3?} (decompose-equivalent total: {:.3?})",
        build_caches,
        decode_state + decompress + build_tree + build_caches
    );

    let mut slot_times = vec![];
    let mut epoch_times = vec![];
    let mut cache_times = vec![];
    let mut sig_times = vec![];
    let mut block_times = vec![];
    let mut hash_times = vec![];
    let mut total_times = vec![];

    let wall = Instant::now();
    for block in &blocks {
        let t_block = Instant::now();

        let mut t = Instant::now();
        let mut is_epoch = false;
        let mut known_root = Some(initial_root);
        while state.slot() < block.slot() {
            let summary = per_slot_processing(&mut state, known_root.take(), &spec)
                .expect("per_slot_processing");
            is_epoch |= summary.is_some();
        }
        if is_epoch {
            epoch_times.push(t.elapsed());
        } else {
            slot_times.push(t.elapsed());
        }

        t = Instant::now();
        state.build_all_caches(&spec).expect("build caches");
        cache_times.push(t.elapsed());

        t = Instant::now();
        let mut ctxt = ConsensusContext::new(block.slot());
        BlockSignatureVerifier::verify_entire_block(
            &state,
            |i| pubkeys.get(i).map(Cow::Borrowed),
            |pk_bytes| {
                pk_index
                    .get(pk_bytes)
                    .and_then(|&i| pubkeys.get(i))
                    .map(Cow::Borrowed)
            },
            block,
            &mut ctxt,
            &spec,
        )
        .expect("signature verification");
        sig_times.push(t.elapsed());

        t = Instant::now();
        per_block_processing(
            &mut state,
            block,
            BlockSignatureStrategy::NoVerification,
            VerifyBlockRoot::True,
            &mut ctxt,
            &spec,
        )
        .expect("per_block_processing");
        block_times.push(t.elapsed());

        t = Instant::now();
        let root = state.update_tree_hash_cache().expect("tree hash");
        hash_times.push(t.elapsed());
        assert_eq!(
            root,
            block.state_root(),
            "state root mismatch at slot {}",
            block.slot()
        );
        initial_root = root;

        total_times.push(t_block.elapsed());
    }
    let wall = wall.elapsed();

    eprintln!(
        "\nreplay {:.3?} over {} blocks ({:.3?}/block), head state root {initial_root:?}\n",
        wall,
        blocks.len(),
        wall / blocks.len() as u32
    );
    print_stats("slot_advance (non-boundary)", &mut slot_times);
    print_stats("slot_advance (epoch boundary)", &mut epoch_times);
    print_stats("build_caches", &mut cache_times);
    print_stats("signature_verify (bulk)", &mut sig_times);
    print_stats("per_block_processing", &mut block_times);
    print_stats("state hash_tree_root", &mut hash_times);
    print_stats("total per block", &mut total_times);

    if let Some(path) = thresholds_path {
        // Vectors are already sorted by `print_stats`.
        gate_on_thresholds(&path, &total_times, &epoch_times, &hash_times);
    }
}

fn print_stats(label: &str, times: &mut [Duration]) {
    times.sort();
    if times.is_empty() {
        eprintln!("{label:<32} (none)");
        return;
    }
    let sum: Duration = times.iter().sum();
    let pct = |p: usize| times[(times.len() - 1) * p / 100];
    eprintln!(
        "{label:<32} n={:<4} avg {:>12.3?}  p50 {:>12.3?}  p90 {:>12.3?}  max {:>12.3?}",
        times.len(),
        sum / times.len() as u32,
        pct(50),
        pct(90),
        times.last().unwrap()
    );
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn pct_ms(sorted_times: &[Duration], p: usize) -> Option<f64> {
    sorted_times
        .get((sorted_times.len().checked_sub(1)?) * p / 100)
        .copied()
        .map(ms)
}

fn avg_ms(times: &[Duration]) -> Option<f64> {
    if times.is_empty() {
        return None;
    }
    let sum: Duration = times.iter().sum();
    Some(ms(sum) / times.len() as f64)
}

fn gate_on_thresholds(
    path: &str,
    total_times: &[Duration],
    epoch_times: &[Duration],
    hash_times: &[Duration],
) {
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read thresholds file"))
            .expect("parse thresholds file");
    let threshold = |key: &str| {
        json.get(key)
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_else(|| panic!("thresholds file missing numeric field `{key}`"))
    };

    let checks = [
        (
            "total per block p50",
            pct_ms(total_times, 50),
            threshold("total_per_block_p50_ms"),
        ),
        (
            "total per block max",
            total_times.last().copied().map(ms),
            threshold("total_per_block_max_ms"),
        ),
        (
            "epoch boundary avg",
            avg_ms(epoch_times),
            threshold("epoch_boundary_avg_ms"),
        ),
        (
            "state hash_tree_root avg",
            avg_ms(hash_times),
            threshold("hash_tree_root_avg_ms"),
        ),
    ];

    let mut breached = false;
    eprintln!(
        "\n{:<28} {:>12} {:>12}  status",
        "metric", "actual", "threshold"
    );
    for (label, actual, limit) in checks {
        let Some(actual) = actual else {
            eprintln!("{label:<28} {:>12} {limit:>10.1}ms  SKIP (no samples)", "-");
            continue;
        };
        let ok = actual <= limit;
        breached |= !ok;
        eprintln!(
            "{label:<28} {actual:>10.1}ms {limit:>10.1}ms  {}",
            if ok { "OK" } else { "FAIL" }
        );
    }
    if breached {
        eprintln!("\nperf regression detected: threshold(s) breached");
        std::process::exit(1);
    }
    eprintln!("\nall perf thresholds passed");
}
