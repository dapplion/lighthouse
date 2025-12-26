use reth_era::common::file_ops::StreamReader;
use reth_era::era::file::EraReader;
use reth_era::era::types::consensus::{CompressedBeaconState, CompressedSignedBeaconBlock};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use store::{DBColumn, HotColdDB, ItemStore, KeyValueStoreOp};
use tracing::{info, warn};
use types::{BeaconState, ChainSpec, EthSpec, SignedBeaconBlock, Slot};

pub(crate) fn import_era_files<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: &HotColdDB<E, Hot, Cold>,
    era_files_dir: &Path,
    spec: &ChainSpec,
) -> Result<u64, String> {
    let mut era_files = list_era_files(era_files_dir)?;
    era_files.sort_by_key(|(era_number, _)| *era_number);

    let network_name = spec
        .config_name
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let mut max_era = None;
    for (era_number, path) in era_files {
        info!(era_number, ?path, "Importing era file");
        import_era_file(store, &path, era_number, &network_name, spec)
            .map_err(|error| format!("era file {era_number} {path:?} import failed: {error}"))?;
        max_era = Some(era_number);
    }

    max_era.ok_or_else(|| "era files directory is empty".to_string())
}

fn import_era_file<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: &HotColdDB<E, Hot, Cold>,
    path: &Path,
    era_number: u64,
    network_name: &str,
    spec: &ChainSpec,
) -> Result<(), String> {
    let file = File::open(path).map_err(|error| format!("failed to open era file: {error}"))?;
    let era_file = EraReader::new(file)
        .read_and_assemble(network_name.to_string())
        .map_err(|error| format!("failed to parse era file: {error:?}"))?;

    for compressed_block in era_file.group.blocks {
        let block = decode_block::<E>(compressed_block, spec)?;
        let block_root = block.canonical_root();
        store
            .put_block(&block_root, block)
            .map_err(|error| format!("failed to store block: {error:?}"))?;
    }

    let mut state = decode_state::<E>(era_file.group.era_state, spec)?;
    let state_root = state
        .canonical_root()
        .map_err(|error| format!("failed to hash state: {error:?}"))?;
    // Use put_cold_state as the split is not updated and we need the state into the cold store.
    store
        .put_cold_state(&state_root, &state)
        .map_err(|error| format!("failed to store state: {error:?}"))?;
    write_block_root_index_for_era(store, &state, era_number)?;

    Ok(())
}

fn decode_block<E: EthSpec>(
    compressed: CompressedSignedBeaconBlock,
    spec: &ChainSpec,
) -> Result<SignedBeaconBlock<E>, String> {
    let bytes = compressed
        .decompress()
        .map_err(|error| format!("failed to decompress block: {error:?}"))?;
    SignedBeaconBlock::from_ssz_bytes(&bytes, spec)
        .map_err(|error| format!("failed to decode block: {error:?}"))
}

fn decode_state<E: EthSpec>(
    compressed: CompressedBeaconState,
    spec: &ChainSpec,
) -> Result<BeaconState<E>, String> {
    let bytes = compressed
        .decompress()
        .map_err(|error| format!("failed to decompress state: {error:?}"))?;
    BeaconState::from_ssz_bytes(&bytes, spec)
        .map_err(|error| format!("failed to decode state: {error:?}"))
}

fn write_block_root_index_for_era<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>>(
    store: &HotColdDB<E, Hot, Cold>,
    state: &BeaconState<E>,
    era_number: u64,
) -> Result<(), String> {
    let end_slot = state.slot();
    let slots_per_historical_root = E::slots_per_historical_root() as u64;
    let expected_end_slot = Slot::new(era_number * slots_per_historical_root);
    if end_slot != expected_end_slot {
        return Err(format!(
            "era state slot mismatch: expected {expected_end_slot}, got {end_slot}"
        ));
    }

    let start_slot = end_slot.saturating_sub(slots_per_historical_root);

    let ops = (start_slot.as_u64()..end_slot.as_u64())
        .map(|slot_u64| {
            let slot = Slot::new(slot_u64);
            let block_root = state
                .get_block_root(slot)
                .map_err(|error| format!("failed to read block root {slot}: {error:?}"))?;
            Ok(KeyValueStoreOp::PutKeyValue(
                DBColumn::BeaconBlockRoots,
                slot_u64.to_be_bytes().to_vec(),
                block_root.as_slice().to_vec(),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;

    store
        .cold_db
        .do_atomically(ops)
        .map_err(|error| format!("failed to store block root index: {error:?}"))?;

    Ok(())
}

fn list_era_files(dir: &Path) -> Result<Vec<(u64, PathBuf)>, String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("failed to read era dir: {error}"))?;
    let mut era_files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to read era entry: {error}"))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if !file_name.ends_with(".era") {
            continue;
        }

        let Some((prefix, _hash_part)) = file_name.rsplit_once('-') else {
            continue;
        };
        let Some((_network_name, era_part)) = prefix.rsplit_once('-') else {
            continue;
        };
        let Some(era_number) = era_part.parse().ok() else {
            continue;
        };

        era_files.push((era_number, path));
    }

    if era_files.is_empty() {
        warn!(?dir, "Era files directory is empty");
    }

    Ok(era_files)
}
