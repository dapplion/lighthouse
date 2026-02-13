/// Generate corrupt ERA files for testing.
/// Run: cargo test -p beacon_chain --test beacon_chain_tests gen_corrupt -- --nocapture --ignored
use reth_era::common::file_ops::{StreamReader, StreamWriter};
use reth_era::era::file::{EraFile, EraReader, EraWriter};
use reth_era::era::types::consensus::{CompressedBeaconState, CompressedSignedBeaconBlock};
use ssz::Encode;
use std::path::PathBuf;
use types::{BeaconState, ChainSpec, Config, Graffiti, MinimalEthSpec, SignedBeaconBlock};

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

fn find_era_file(pattern: &str) -> PathBuf {
    let era_dir = test_vectors_dir().join("era");
    for entry in std::fs::read_dir(&era_dir).expect("readdir") {
        let entry = entry.expect("entry");
        if entry.file_name().to_string_lossy().contains(pattern) {
            return entry.path();
        }
    }
    panic!("ERA file matching {pattern} not found");
}

fn read_era(path: &std::path::Path) -> EraFile {
    let file = std::fs::File::open(path).expect("open");
    EraReader::new(file)
        .read_and_assemble("minimal".to_string())
        .expect("parse")
}

fn write_era(era_file: &EraFile, output: &std::path::Path) {
    let file = std::fs::File::create(output).expect("create");
    let mut writer = EraWriter::new(file);
    writer.write_file(era_file).expect("write");
}

#[test]
#[ignore] // Run manually: cargo test ... gen_corrupt -- --ignored --nocapture
fn gen_corrupt() {
    let spec = load_test_spec();
    let out = test_vectors_dir().join("corrupt");
    std::fs::create_dir_all(&out).expect("mkdir");

    // --- era0-wrong-root.era: modified genesis_validators_root ---
    {
        let mut era = read_era(&find_era_file("-00000-"));
        let bytes = era.group.era_state.decompress().expect("decompress");
        let mut state: BeaconState<MinimalEthSpec> =
            BeaconState::from_ssz_bytes(&bytes, &spec).expect("decode");
        state.genesis_validators_root_mut().as_mut_slice()[0] ^= 0x01;
        era.group.era_state =
            CompressedBeaconState::from_ssz(&state.as_ssz_bytes()).expect("compress");
        write_era(&era, &out.join("era0-wrong-root.era"));
        println!("✓ era0-wrong-root.era");
    }

    // --- era8-corrupt-block-summary.era: modified block_roots vector ---
    {
        let mut era = read_era(&find_era_file("-00008-"));
        let bytes = era.group.era_state.decompress().expect("decompress");
        let mut state: BeaconState<MinimalEthSpec> =
            BeaconState::from_ssz_bytes(&bytes, &spec).expect("decode");
        if let Some(r) = state.block_roots_mut().get_mut(0) {
            r.as_mut_slice()[0] ^= 0x01;
        }
        era.group.era_state =
            CompressedBeaconState::from_ssz(&state.as_ssz_bytes()).expect("compress");
        write_era(&era, &out.join("era8-corrupt-block-summary.era"));
        println!("✓ era8-corrupt-block-summary.era");
    }

    // --- era2-wrong-block-root.era: modified block graffiti ---
    {
        let mut era = read_era(&find_era_file("-00002-"));
        if let Some(block_compressed) = era.group.blocks.first_mut() {
            let bytes = block_compressed.decompress().expect("decompress");
            let mut block: SignedBeaconBlock<MinimalEthSpec> =
                SignedBeaconBlock::from_ssz_bytes(&bytes, &spec).expect("decode");
            *block.message_mut().body_mut().graffiti_mut() =
                Graffiti::from(*b"CORRUPTED_BLOCK_DATA!!!!!!!!!!!!");
            *block_compressed =
                CompressedSignedBeaconBlock::from_ssz(&block.as_ssz_bytes()).expect("compress");
        }
        write_era(&era, &out.join("era2-wrong-block-root.era"));
        println!("✓ era2-wrong-block-root.era");
    }

    // --- era3-wrong-state-root.era: modified balance ---
    {
        let mut era = read_era(&find_era_file("-00003-"));
        let bytes = era.group.era_state.decompress().expect("decompress");
        let mut state: BeaconState<MinimalEthSpec> =
            BeaconState::from_ssz_bytes(&bytes, &spec).expect("decode");
        if let Some(bal) = state.balances_mut().get_mut(0) {
            *bal = bal.wrapping_add(1);
        }
        era.group.era_state =
            CompressedBeaconState::from_ssz(&state.as_ssz_bytes()).expect("compress");
        write_era(&era, &out.join("era3-wrong-state-root.era"));
        println!("✓ era3-wrong-state-root.era");
    }

    println!("\nDone: {:?}", out);
}
