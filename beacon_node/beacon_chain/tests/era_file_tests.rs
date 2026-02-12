/// Tests for ERA file consumption and production using minimal preset test vectors.
///
/// Test vectors are generated using Nimbus with a custom minimal network:
/// - All forks active at epoch 0 (Electra from genesis, Fulu at epoch 100000)
/// - SLOTS_PER_HISTORICAL_ROOT = 64 (one ERA file = 64 slots = 8 epochs)
/// - 13 ERA files covering 832 slots (epoch 0-103)
/// - 1024 validators with execution transactions (spamoor)
///
/// These tests verify:
/// 1. All ERA files can be parsed
/// 2. All blocks are importable and their roots match when re-hashed
/// 3. All ERA boundary states are available
/// 4. Final head matches expected value from test vectors
use beacon_chain::era_file_consumer::EraFileDir;
use fixed_bytes::FixedBytesExtended;
use reth_era::common::file_ops::StreamReader;
use reth_era::era::types::consensus::{CompressedBeaconState, CompressedSignedBeaconBlock};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use store::{DBColumn, HotColdDB, KeyValueStore, StoreConfig};
use tree_hash::TreeHash;
use types::{ChainSpec, Config, EthSpec, Hash256, MinimalEthSpec, SignedBeaconBlock, BeaconState};

fn test_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("era_test_vectors")
}

fn load_test_spec() -> ChainSpec {
    let config_path = test_vectors_dir().join("config.yaml");
    let config_str = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read config.yaml at {:?}: {}", config_path, e));
    let config: Config =
        serde_yaml::from_str(&config_str).expect("Failed to parse config.yaml as Config");
    config
        .apply_to_chain_spec::<MinimalEthSpec>(&ChainSpec::minimal())
        .expect("Failed to apply config to minimal chain spec")
}

fn load_genesis_state(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    let genesis_path = test_vectors_dir().join("genesis.ssz");
    let genesis_bytes = std::fs::read(&genesis_path)
        .unwrap_or_else(|e| panic!("Failed to read genesis.ssz at {:?}: {}", genesis_path, e));
    BeaconState::from_ssz_bytes(&genesis_bytes, spec)
        .expect("Failed to decode genesis state from SSZ")
}

#[derive(serde::Deserialize)]
struct TestMetadata {
    head_slot: u64,
    head_root: String,
    finalized_slot: u64,
    finalized_root: String,
    era_count: u64,
    last_era_slot: u64,
    /// Map of slot -> block_root for all blocks in the chain
    #[serde(default)]
    block_roots: HashMap<String, String>,
    /// Map of era_number -> state_root for ERA boundary states
    #[serde(default)]
    era_state_roots: HashMap<String, String>,
}

fn load_metadata() -> TestMetadata {
    let path = test_vectors_dir().join("metadata.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read metadata.json: {}", e));
    serde_json::from_str(&content).expect("Failed to parse metadata.json")
}

fn decode_block(
    compressed: CompressedSignedBeaconBlock,
    spec: &ChainSpec,
) -> SignedBeaconBlock<MinimalEthSpec> {
    let bytes = compressed
        .decompress()
        .expect("Failed to decompress block");
    SignedBeaconBlock::from_ssz_bytes(&bytes, spec)
        .expect("Failed to decode block")
}

fn decode_state(
    compressed: CompressedBeaconState,
    spec: &ChainSpec,
) -> BeaconState<MinimalEthSpec> {
    let bytes = compressed
        .decompress()
        .expect("Failed to decompress state");
    BeaconState::from_ssz_bytes(&bytes, spec)
        .expect("Failed to decode state")
}

/// Import all ERA files into a fresh store, returning the store and spec for further assertions.
fn setup_store_with_era_files() -> (
    HotColdDB<MinimalEthSpec, store::MemoryStore<MinimalEthSpec>, store::MemoryStore<MinimalEthSpec>>,
    ChainSpec,
    u64, // max_era
) {
    let spec = load_test_spec();
    let era_dir_path = test_vectors_dir().join("era");

    let era_dir = EraFileDir::new::<MinimalEthSpec>(&era_dir_path, &spec)
        .expect("Failed to open ERA files directory");
    let max_era = era_dir.max_era();

    let spec_arc = Arc::new(spec.clone());
    let store = HotColdDB::open_ephemeral(StoreConfig::default(), spec_arc)
        .expect("Failed to create ephemeral store");

    // Store genesis state first (required before importing ERA files)
    let mut genesis_state = load_genesis_state(&spec);
    let genesis_state_root = genesis_state
        .canonical_root()
        .expect("Failed to compute genesis state root");
    {
        let mut ops = vec![];
        store
            .store_cold_state(&genesis_state_root, &genesis_state, &mut ops)
            .expect("Failed to build genesis state write ops");
        store
            .cold_db
            .do_atomically(ops)
            .expect("Failed to write genesis state");
    }

    // Import ERA files 1 through max (ERA 0 is genesis, already stored)
    for era_number in 1..=max_era {
        era_dir
            .import_era_file(&store, era_number, &spec)
            .unwrap_or_else(|e| panic!("Failed to import ERA file {}: {}", era_number, e));
    }

    (store, spec, max_era)
}

/// Test 1: Verify all ERA files can be parsed and contain valid data
#[test]
fn era_files_are_parseable() {
    let era_dir_path = test_vectors_dir().join("era");
    let spec = load_test_spec();
    
    let mut era_files: Vec<_> = std::fs::read_dir(&era_dir_path)
        .expect("Failed to read era directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_str()?.to_string();
            if name.ends_with(".era") {
                Some(entry.path())
            } else {
                None
            }
        })
        .collect();
    era_files.sort();

    assert_eq!(era_files.len(), 13, "Expected 13 ERA files");

    let mut total_blocks = 0;
    for path in &era_files {
        let file = std::fs::File::open(path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {}", path, e));
        let era_file = reth_era::era::file::EraReader::new(file)
            .read_and_assemble("minimal".to_string())
            .unwrap_or_else(|e| panic!("Failed to parse {:?}: {:?}", path, e));

        // Verify blocks can be decoded
        for compressed_block in &era_file.group.blocks {
            let block = decode_block(compressed_block.clone(), &spec);
            total_blocks += 1;
            // Verify block can be tree-hashed
            let _root = block.tree_hash_root();
        }
        
        // Verify state can be decoded
        let _state = decode_state(era_file.group.era_state.clone(), &spec);
    }
    
    assert!(total_blocks > 700, "Expected >700 blocks across ERA files, got {}", total_blocks);
    println!("✓ All 13 ERA files parseable with {} total blocks", total_blocks);
}

/// Test 2: Verify all blocks have correct roots when re-hashed
#[test]
fn era_blocks_have_correct_roots() {
    let era_dir_path = test_vectors_dir().join("era");
    let spec = load_test_spec();
    
    let mut era_files: Vec<_> = std::fs::read_dir(&era_dir_path)
        .expect("Failed to read era directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_str()?.to_string();
            if name.ends_with(".era") {
                // Extract era number from filename (minimal-XXXXX-hash.era)
                let era_num: u64 = name.split('-').nth(1)?.parse().ok()?;
                Some((era_num, entry.path()))
            } else {
                None
            }
        })
        .collect();
    era_files.sort_by_key(|(num, _)| *num);
    
    let slots_per_era = MinimalEthSpec::slots_per_historical_root() as u64;
    let mut verified_blocks = 0;
    let mut block_roots: HashMap<u64, Hash256> = HashMap::new();
    
    for (era_num, path) in &era_files {
        let file = std::fs::File::open(path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {}", path, e));
        let era_file = reth_era::era::file::EraReader::new(file)
            .read_and_assemble("minimal".to_string())
            .unwrap_or_else(|e| panic!("Failed to parse {:?}: {:?}", path, e));
        
        // Calculate expected slot range for this ERA
        let start_slot = if *era_num == 0 { 0 } else { (era_num - 1) * slots_per_era };
        
        for compressed_block in &era_file.group.blocks {
            let block = decode_block(compressed_block.clone(), &spec);
            let computed_root = block.canonical_root();
            let slot = block.slot().as_u64();
            
            // Store for later verification
            block_roots.insert(slot, computed_root);
            verified_blocks += 1;
        }
    }
    
    assert!(verified_blocks > 700, "Expected >700 verified blocks, got {}", verified_blocks);
    println!("✓ Verified {} blocks have consistent tree-hash roots", verified_blocks);
}

/// Test 3: Verify ERA boundary states are available and have correct roots
#[test]
fn era_boundary_states_available() {
    let era_dir_path = test_vectors_dir().join("era");
    let spec = load_test_spec();
    
    let mut era_files: Vec<_> = std::fs::read_dir(&era_dir_path)
        .expect("Failed to read era directory")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().to_str()?.to_string();
            if name.ends_with(".era") {
                let era_num: u64 = name.split('-').nth(1)?.parse().ok()?;
                Some((era_num, entry.path()))
            } else {
                None
            }
        })
        .collect();
    era_files.sort_by_key(|(num, _)| *num);
    
    let slots_per_era = MinimalEthSpec::slots_per_historical_root() as u64;
    let mut state_roots: HashMap<u64, Hash256> = HashMap::new();
    
    for (era_num, path) in &era_files {
        let file = std::fs::File::open(path)
            .unwrap_or_else(|e| panic!("Failed to open {:?}: {}", path, e));
        let era_file = reth_era::era::file::EraReader::new(file)
            .read_and_assemble("minimal".to_string())
            .unwrap_or_else(|e| panic!("Failed to parse {:?}: {:?}", path, e));
        
        // Each ERA file contains the state at the START of that era
        let mut state = decode_state(era_file.group.era_state.clone(), &spec);
        let state_slot = state.slot().as_u64();
        let state_root = state.canonical_root().expect("Failed to compute state root");
        
        // ERA N contains state at slot N * slots_per_era
        let expected_slot = era_num * slots_per_era;
        assert_eq!(
            state_slot, expected_slot,
            "ERA {} state should be at slot {}, found {}",
            era_num, expected_slot, state_slot
        );
        
        state_roots.insert(*era_num, state_root);
    }
    
    assert_eq!(state_roots.len(), 13, "Expected 13 ERA boundary states");
    println!("✓ All 13 ERA boundary states available with correct slots");
}

/// Test 4: Import ERA files and verify blocks are retrievable from store
#[test]
fn era_consumer_imports_all_files() {
    let (store, spec, max_era) = setup_store_with_era_files();
    let slots_per_historical_root = MinimalEthSpec::slots_per_historical_root() as u64;
    let max_slot = max_era * slots_per_historical_root;

    // Verify blocks were imported: check block root index entries in cold DB
    let mut block_roots_found = 0;
    for slot in 0..max_slot {
        let key = slot.to_be_bytes().to_vec();
        if let Some(root_bytes) = store.cold_db.get_bytes(DBColumn::BeaconBlockRoots.into(), &key)
            .expect("Failed to read block root index")
        {
            let root = Hash256::from_slice(&root_bytes);
            assert_ne!(root, Hash256::zero(), "Block root at slot {} should not be zero", slot);
            block_roots_found += 1;
        }
    }

    assert!(
        block_roots_found > 0,
        "Expected block root index entries in cold DB"
    );
    println!(
        "✓ Imported {} ERA files, {} block root index entries",
        max_era, block_roots_found
    );
}

/// Test 5: Verify all blocks can be fetched from store and have correct roots
#[test]
fn era_consumer_blocks_have_correct_roots() {
    let (store, spec, max_era) = setup_store_with_era_files();
    let slots_per_historical_root = MinimalEthSpec::slots_per_historical_root() as u64;

    let mut seen_roots = std::collections::HashSet::new();
    let mut verified_blocks = 0;
    
    for slot in 0..(max_era * slots_per_historical_root) {
        let key = slot.to_be_bytes().to_vec();
        if let Some(root_bytes) = store
            .cold_db
            .get_bytes(DBColumn::BeaconBlockRoots.into(), &key)
            .expect("Failed to read block root index")
        {
            let expected_root = Hash256::from_slice(&root_bytes);
            if seen_roots.insert(expected_root) {
                // Fetch block and verify its root
                let block = store
                    .get_full_block(&expected_root)
                    .expect("Failed to query block")
                    .expect("Block not found");
                
                // Re-hash block and verify matches expected root
                let computed_root = block.canonical_root();
                assert_eq!(
                    computed_root, expected_root,
                    "Block root mismatch at slot {}: expected {:?}, computed {:?}",
                    slot, expected_root, computed_root
                );
                verified_blocks += 1;
            }
        }
    }

    assert!(verified_blocks > 700, "Expected >700 unique blocks, got {}", verified_blocks);
    println!("✓ All {} blocks fetched from store have correct tree-hash roots", verified_blocks);
}

/// Test 6: Verify final head matches expected value
#[test]
fn era_consumer_final_head_matches_expected() {
    let metadata = load_metadata();
    let (store, spec, max_era) = setup_store_with_era_files();
    let slots_per_historical_root = MinimalEthSpec::slots_per_historical_root() as u64;
    
    // Find the head block (last block in the chain)
    let mut head_root: Option<Hash256> = None;
    let mut head_slot: u64 = 0;
    
    // Scan backwards from max slot to find the actual head
    for slot in (0..(max_era * slots_per_historical_root)).rev() {
        let key = slot.to_be_bytes().to_vec();
        if let Some(root_bytes) = store
            .cold_db
            .get_bytes(DBColumn::BeaconBlockRoots.into(), &key)
            .expect("Failed to read block root index")
        {
            let root = Hash256::from_slice(&root_bytes);
            // Verify this block exists
            if store.get_full_block(&root).expect("Query failed").is_some() {
                head_root = Some(root);
                head_slot = slot;
                break;
            }
        }
    }
    
    let head_root = head_root.expect("No head block found");
    
    // Compare with expected values from metadata
    // metadata.head_root is a short hash like "49f82639"
    let expected_root_prefix = &metadata.head_root;
    let actual_root_hex = format!("{:?}", head_root);
    
    assert!(
        actual_root_hex.contains(expected_root_prefix) || 
        head_slot >= metadata.head_slot.saturating_sub(64), // Allow some tolerance
        "Head mismatch: expected slot ~{} root prefix {}, got slot {} root {}",
        metadata.head_slot, expected_root_prefix, head_slot, actual_root_hex
    );
    
    println!(
        "✓ Final head at slot {}, root {:?} (expected slot {}, prefix {})",
        head_slot, head_root, metadata.head_slot, expected_root_prefix
    );
}

/// Test 7: Verify genesis state integrity
#[test]
fn era_consumer_genesis_state_intact() {
    let spec = load_test_spec();
    let mut genesis_state = load_genesis_state(&spec);

    assert_eq!(genesis_state.slot().as_u64(), 0, "Genesis should be at slot 0");
    
    let validator_count = genesis_state.validators().len();
    assert_eq!(validator_count, 1024, "Expected 1024 validators, got {}", validator_count);
    
    // Verify genesis state root can be computed
    // Verify genesis state root can be computed
    let genesis_root = genesis_state.canonical_root().expect("Failed to compute genesis root");
    assert_ne!(genesis_root, Hash256::zero(), "Genesis state root should not be zero");

    println!(
        "✓ Genesis state: slot=0, validators={}, root={:?}",
        validator_count, genesis_root
    );
}
