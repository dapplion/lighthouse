/// ERA file consumer + producer tests using minimal preset test vectors.
///
/// Test vectors: 13 ERA files from a Nimbus minimal testnet.
/// - Electra from genesis, Fulu at epoch 100000
/// - SLOTS_PER_HISTORICAL_ROOT = 64 (one ERA = 64 slots = 8 epochs)
/// - 13 ERA files covering 832 slots, 767 blocks, 1024 validators
use beacon_chain::era_file_consumer::EraFileDir;
use fixed_bytes::FixedBytesExtended;
use reth_era::common::file_ops::StreamReader;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use store::{DBColumn, HotColdDB, KeyValueStore, StoreConfig};
use types::{BeaconState, ChainSpec, Config, EthSpec, Hash256, MinimalEthSpec};

fn test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("era_test_vectors")
}

fn load_test_spec() -> ChainSpec {
    let config_str =
        std::fs::read_to_string(test_vectors_dir().join("config.yaml")).expect("read config.yaml");
    let config: Config = serde_yaml::from_str(&config_str).expect("parse config");
    config
        .apply_to_chain_spec::<MinimalEthSpec>(&ChainSpec::minimal())
        .expect("apply config")
}

fn load_genesis_state(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    let bytes = std::fs::read(test_vectors_dir().join("genesis.ssz")).expect("read genesis.ssz");
    BeaconState::from_ssz_bytes(&bytes, spec).expect("decode genesis")
}

type TestStore = HotColdDB<
    MinimalEthSpec,
    store::MemoryStore<MinimalEthSpec>,
    store::MemoryStore<MinimalEthSpec>,
>;

/// Import all ERA files into a fresh ephemeral store.
fn import_all_era_files() -> (TestStore, ChainSpec, u64) {
    let spec = load_test_spec();
    let era_dir_path = test_vectors_dir().join("era");
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&era_dir_path, &spec).expect("open ERA dir");
    let max_era = era_dir.max_era();

    let store = HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone()))
        .expect("create store");

    // Store genesis state
    let mut genesis_state = load_genesis_state(&spec);
    let root = genesis_state.canonical_root().expect("hash genesis");
    let mut ops = vec![];
    store
        .store_cold_state(&root, &genesis_state, &mut ops)
        .expect("build ops");
    store.cold_db.do_atomically(ops).expect("write genesis");

    for era in 1..=max_era {
        era_dir
            .import_era_file(&store, era, &spec, None, None)
            .unwrap_or_else(|e| panic!("import ERA {era}: {e}"));
    }

    (store, spec, max_era)
}

/// Create ephemeral store with genesis state only.
fn empty_store(spec: &ChainSpec) -> TestStore {
    let store =
        HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone())).expect("store");
    let mut genesis = load_genesis_state(spec);
    let root = genesis.canonical_root().expect("hash");
    let mut ops = vec![];
    store
        .store_cold_state(&root, &genesis, &mut ops)
        .expect("ops");
    store.cold_db.do_atomically(ops).expect("write");
    store
}

/// Copy ERA files to temp dir, replacing one with a corrupt version.
fn era_dir_with_corrupt(corrupt_file: &str, target_pattern: &str) -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().expect("tmp");
    let src = test_vectors_dir();
    let dst = tmp.path().join("era");
    std::fs::create_dir_all(&dst).expect("mkdir");

    for entry in std::fs::read_dir(src.join("era")).expect("readdir") {
        let entry = entry.expect("entry");
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains(target_pattern) {
            std::fs::copy(src.join("corrupt").join(corrupt_file), dst.join(&name))
                .expect("copy corrupt");
        } else {
            std::fs::copy(entry.path(), dst.join(&name)).expect("copy");
        }
    }
    tmp
}

// =============================================================================
// CONSUMER TEST — import + verify blocks + verify states
// =============================================================================

#[test]
fn era_consumer_imports_and_verifies() {
    let (store, _spec, max_era) = import_all_era_files();
    let slots_per_era = MinimalEthSpec::slots_per_historical_root() as u64;
    let max_slot = max_era * slots_per_era;

    // Verify all blocks: read from store, re-hash, check root matches index
    let mut seen_roots = HashSet::new();
    let mut verified_blocks = 0;

    for slot in 0..max_slot {
        let key = slot.to_be_bytes().to_vec();
        if let Some(root_bytes) = store
            .cold_db
            .get_bytes(DBColumn::BeaconBlockRoots, &key)
            .expect("read index")
        {
            let expected_root = Hash256::from_slice(&root_bytes);
            if seen_roots.insert(expected_root) {
                let block = store
                    .get_full_block(&expected_root)
                    .expect("query")
                    .unwrap_or_else(|| panic!("block missing for slot {slot}"));
                assert_eq!(
                    block.canonical_root(),
                    expected_root,
                    "block root mismatch at slot {slot}"
                );
                verified_blocks += 1;
            }
        }
    }

    assert!(verified_blocks > 700, "got only {verified_blocks} blocks");

    // Verify genesis state integrity
    let spec = load_test_spec();
    let mut genesis = load_genesis_state(&spec);
    assert_eq!(genesis.validators().len(), 1024);
    assert_ne!(genesis.canonical_root().expect("hash"), Hash256::zero());
}

// =============================================================================
// PRODUCER TEST — byte-identical output
// =============================================================================

#[test]
fn era_producer_output_is_byte_identical() {
    use beacon_chain::era_file_producer;

    let (store, _spec, max_era) = import_all_era_files();
    let output = PathBuf::from("/tmp/era_producer_test_output");
    let _ = std::fs::remove_dir_all(&output);
    std::fs::create_dir_all(&output).expect("mkdir");

    for era in 0..=max_era {
        era_file_producer::create_era_file(&store, era, &output)
            .unwrap_or_else(|e| panic!("produce ERA {era}: {e}"));
    }

    // Compare each produced file with original by sorted filename
    let mut originals: Vec<_> = std::fs::read_dir(test_vectors_dir().join("era"))
        .expect("readdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".era"))
        .collect();
    originals.sort_by_key(|e| e.file_name());

    let mut produced: Vec<_> = std::fs::read_dir(&output)
        .expect("readdir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".era"))
        .collect();
    produced.sort_by_key(|e| e.file_name());

    assert_eq!(originals.len(), produced.len(), "file count mismatch");

    for (orig, prod) in originals.iter().zip(produced.iter()) {
        let orig_bytes = std::fs::read(orig.path()).expect("read original");
        let prod_bytes = std::fs::read(prod.path()).expect("read produced");
        assert_eq!(
            orig_bytes,
            prod_bytes,
            "ERA file mismatch: {:?} vs {:?}",
            orig.file_name(),
            prod.file_name()
        );
    }
}

// =============================================================================
// CORRUPTION TESTS — verify specific error messages
// =============================================================================

/// Helper: init EraFileDir + import up to (exclusive) target ERA, then assert error.
fn assert_import_fails(
    corrupt_file: &str,
    target_pattern: &str,
    target_era: u64,
    expected_err: &str,
) {
    let tmp = era_dir_with_corrupt(corrupt_file, target_pattern);
    let spec = load_test_spec();
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&tmp.path().join("era"), &spec)
        .expect("init should succeed");
    let store = empty_store(&spec);

    for era in 0..target_era {
        era_dir
            .import_era_file(&store, era, &spec, None, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let err = era_dir
        .import_era_file(&store, target_era, &spec, None, None)
        .unwrap_err();
    assert!(
        err.contains(expected_err),
        "expected error containing \"{expected_err}\", got: {err}"
    );
}

#[test]
fn era_rejects_corrupted_block_decompression() {
    assert_import_fails("era1-corrupt-block.era", "-00001-", 1, "decompress");
}

#[test]
fn era_rejects_corrupted_genesis_state() {
    assert_import_fails("era0-corrupt-state.era", "-00000-", 0, "decompress");
}

#[test]
fn era_rejects_corrupted_middle_state() {
    assert_import_fails("era5-corrupt-state.era", "-00005-", 5, "decompress");
}

#[test]
fn era_rejects_corrupted_reference_state() {
    let tmp = era_dir_with_corrupt("era12-corrupt-state.era", "-00012-");
    let spec = load_test_spec();
    match EraFileDir::new::<MinimalEthSpec>(&tmp.path().join("era"), &spec) {
        Ok(_) => panic!("should fail with corrupted reference state"),
        Err(err) => assert!(err.contains("decompress"), "expected decompress: {err}"),
    }
}

#[test]
fn era_rejects_wrong_era_content() {
    // ERA 5 content in ERA 3 slot → state slot mismatch
    assert_import_fails(
        "era3-wrong-content.era",
        "-00003-",
        3,
        "era state slot mismatch",
    );
}

#[test]
fn era_rejects_wrong_era_root() {
    assert_import_fails("era0-wrong-root.era", "-00000-", 0, "era root mismatch");
}

#[test]
fn era_rejects_corrupt_block_summary() {
    // Corrupted block_roots vector → post-Capella summary mismatch
    assert_import_fails(
        "era8-corrupt-block-summary.era",
        "-00008-",
        8,
        "block summary root post-capella mismatch",
    );
}

#[test]
fn era_rejects_wrong_block_root() {
    assert_import_fails(
        "era2-wrong-block-root.era",
        "-00002-",
        2,
        "block root mismatch",
    );
}

// =============================================================================
// TRUSTED STATE ROOT VERIFICATION
// =============================================================================

#[test]
fn era_rejects_wrong_trusted_state_root() {
    let spec = load_test_spec();
    let store = empty_store(&spec);
    let era_dir_path = test_vectors_dir().join("era");
    let era_dir = EraFileDir::new::<MinimalEthSpec>(&era_dir_path, &spec).expect("open");

    // Import ERA 0-2
    for era in 0..=2 {
        era_dir
            .import_era_file(&store, era, &spec, None, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    // Get correct state root for ERA 3
    let era3_file = std::fs::read_dir(&era_dir_path)
        .expect("readdir")
        .filter_map(|e| e.ok())
        .find(|e| e.file_name().to_string_lossy().contains("-00003-"))
        .expect("ERA 3 file");

    let file = std::fs::File::open(era3_file.path()).expect("open");
    let era = reth_era::era::file::EraReader::new(file)
        .read_and_assemble("minimal".to_string())
        .expect("parse");
    let state_bytes = era.group.era_state.decompress().expect("decompress");
    let mut state: BeaconState<MinimalEthSpec> =
        BeaconState::from_ssz_bytes(&state_bytes, &spec).expect("decode");
    let correct_root = state.canonical_root().expect("root");
    let slot = state.slot();

    // Correct root should succeed
    era_dir
        .import_era_file(&store, 3, &spec, Some(correct_root), Some(slot))
        .expect("correct root should pass");

    // Wrong root should fail
    let wrong_root = {
        let mut bytes: [u8; 32] = correct_root.into();
        bytes[0] ^= 0x01;
        Hash256::from(bytes)
    };

    let store2 = empty_store(&spec);
    for era in 0..=2 {
        era_dir
            .import_era_file(&store2, era, &spec, None, None)
            .unwrap_or_else(|e| panic!("ERA {era}: {e}"));
    }

    let err = era_dir
        .import_era_file(&store2, 3, &spec, Some(wrong_root), Some(slot))
        .unwrap_err();
    assert!(
        err.contains("trusted state root mismatch"),
        "expected trusted state root mismatch: {err}"
    );
}
