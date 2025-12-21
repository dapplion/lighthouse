use crate::network_beacon_processor::ChainSegmentProcessId;
use crate::sync::backfill_sync::{ProcessResult, SyncStart};
use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::block_verification_types::RpcBlock;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::NetworkGlobals;
use lighthouse_network::types::BackFillState;
use reth_era::common::file_ops::StreamReader;
use reth_era::era::file::EraReader;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info};
use typenum::Unsigned;
use types::{EthSpec, SignedBeaconBlock, Slot};

#[derive(Debug)]
#[allow(dead_code)]
pub enum BackFillEraError {
    InternalError(String),
    BadEraFile(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackFillEraState {
    NotStarted,
    Syncing { era_number: u64 },
    Completed,
    Disabled,
}

pub struct BackFillSyncEra<T: BeaconChainTypes> {
    state: BackFillEraState,
    initial_era: Option<u64>,
    era_files_dir: PathBuf,
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
}

impl<T: BeaconChainTypes> BackFillSyncEra<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        era_files_dir: PathBuf,
    ) -> Self {
        Self {
            state: BackFillEraState::NotStarted,
            initial_era: None,
            era_files_dir,
            beacon_chain,
            network_globals,
        }
    }

    pub fn pause(&mut self) {
        if matches!(self.state, BackFillEraState::Syncing { .. }) {
            self.state = BackFillEraState::NotStarted;
            self.network_globals
                .set_backfill_state(BackFillState::Paused);
        }
    }

    pub fn start(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<SyncStart, BackFillEraError> {
        if self.state == BackFillEraState::Disabled {
            return Ok(SyncStart::NotSyncing);
        }

        let anchor_info = self.beacon_chain.store.get_anchor_info();
        if anchor_info.block_backfill_complete(self.beacon_chain.genesis_backfill_slot) {
            self.state = BackFillEraState::Completed;
            self.network_globals
                .set_backfill_state(BackFillState::Completed);
            return Ok(SyncStart::NotSyncing);
        }

        if self.state == BackFillEraState::NotStarted {
            let start_slot = anchor_info.oldest_block_slot;
            let start_era = era_number_for_slot::<T::EthSpec>(start_slot);
            self.initial_era = Some(start_era);
            if let Err(e) = self.send_next_file(network, start_era) {
                self.disable("failed to read era file");
                return Err(e);
            } else {
                self.network_globals
                    .set_backfill_state(BackFillState::Syncing);
            }
        }

        Ok(self.syncing_progress())
    }

    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        era_number: u64,
        result: &BatchProcessResult,
    ) -> Result<ProcessResult, BackFillEraError> {
        let current_era = match self.state {
            BackFillEraState::Syncing { era_number } => era_number,
            _ => return Ok(ProcessResult::Successful),
        };

        if current_era != era_number {
            debug!(
                current_era,
                era_number, "Ignoring backfill processing result for unknown era number"
            );
            return Ok(ProcessResult::Successful);
        }

        match result {
            BatchProcessResult::Success { .. } => {
                if era_start_slot::<T::EthSpec>(current_era)
                    <= self.beacon_chain.genesis_backfill_slot
                {
                    self.state = BackFillEraState::Completed;
                    self.network_globals
                        .set_backfill_state(BackFillState::Completed);
                    info!("Era backfill sync completed");
                    Ok(ProcessResult::SyncCompleted)
                } else {
                    let next_era = current_era.saturating_sub(1);
                    if let Err(e) = self.send_next_file(network, next_era) {
                        self.disable("failed to read era file");
                        return Err(e);
                    }
                    Ok(ProcessResult::Successful)
                }
            }
            BatchProcessResult::FaultyFailure { .. } | BatchProcessResult::NonFaultyFailure => {
                self.disable("batch processing failed");
                Err(BackFillEraError::BadEraFile(format!(
                    "ERA backfill batch {era_number} failed processing"
                )))
            }
        }
    }

    fn send_next_file(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        era_number: u64,
    ) -> Result<(), BackFillEraError> {
        let blocks =
            read_batch::<T::EthSpec>(&self.era_files_dir, era_number, &self.beacon_chain.spec)?;

        if let Err(e) = network.beacon_processor().send_chain_segment(
            ChainSegmentProcessId::BackSyncEraBatchId(era_number),
            blocks,
        ) {
            self.state = BackFillEraState::NotStarted;
            return Err(BackFillEraError::InternalError(format!(
                "failed to send era backfill batch: {e}"
            )));
        } else {
            self.state = BackFillEraState::Syncing { era_number };
        }

        Ok(())
    }

    fn syncing_progress(&self) -> SyncStart {
        let current_era = match self.state {
            BackFillEraState::Syncing { era_number } => era_number,
            _ => return SyncStart::NotSyncing,
        };
        let Some(initial_era) = self.initial_era else {
            return SyncStart::NotSyncing;
        };

        let slots_per_era = slots_per_era::<T::EthSpec>();
        let completed =
            (initial_era.saturating_sub(current_era)).saturating_mul(slots_per_era) as usize;
        let remaining = era_start_slot::<T::EthSpec>(current_era)
            .saturating_sub(self.beacon_chain.genesis_backfill_slot)
            .as_usize();

        SyncStart::Syncing {
            completed,
            remaining,
        }
    }

    fn disable(&mut self, reason: &str) {
        error!(
            reason,
            "Era backfill disabled, falling back to network backfill"
        );
        self.state = BackFillEraState::Disabled;
        self.network_globals
            .set_backfill_state(BackFillState::Paused);
    }
}

fn read_batch<E: EthSpec>(
    era_files_dir: &Path,
    era_number: u64,
    spec: &types::ChainSpec,
) -> Result<Vec<RpcBlock<E>>, BackFillEraError> {
    let path = find_era_file(era_files_dir, era_number)
        .map_err(|e| BackFillEraError::BadEraFile(format!("Bad era file name: {e:?}")))?
        .ok_or_else(|| {
            BackFillEraError::BadEraFile(format!("No era file for number {era_number}"))
        })?;
    let file = File::open(&path)
        .map_err(|e| BackFillEraError::BadEraFile(format!("Unable to read era file: {e:?}")))?;
    let reader = EraReader::new(file);
    let mut blocks = Vec::new();

    for block in reader.iter() {
        let compressed = block
            .map_err(|e| BackFillEraError::BadEraFile(format!("Error reading era block: {e:?}")))?;
        let ssz_bytes = compressed.decompress().map_err(|e| {
            BackFillEraError::BadEraFile(format!("failed to decompress block: {e:?}"))
        })?;
        let block = SignedBeaconBlock::<E>::from_ssz_bytes(&ssz_bytes, spec)
            .map_err(|e| BackFillEraError::BadEraFile(format!("failed to decode block: {e:?}")))?;
        blocks.push(RpcBlock::new_without_blobs(None, Arc::new(block)));
    }

    Ok(blocks)
}

fn parse_era_number(path: &Path) -> Result<Option<u64>, String> {
    let Some(stem) = path.file_stem().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let mut parts = stem.split('-');
    let _config = parts.next();
    let Some(era_str) = parts.next() else {
        return Ok(None);
    };
    let era_number = era_str
        .parse::<u64>()
        .map_err(|_| format!("invalid era number in file: {}", path.display()))?;
    Ok(Some(era_number))
}

fn find_era_file(dir: &Path, era_number: u64) -> Result<Option<PathBuf>, String> {
    let mut found: Option<PathBuf> = None;
    for entry in fs::read_dir(dir).map_err(|e| format!("Error reading dir: {e:?}"))? {
        let entry = entry.map_err(|e| format!("Error reading dir entry: {e:?}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("era") {
            continue;
        }
        let parsed = match parse_era_number(&path)? {
            Some(parsed) => parsed,
            None => continue,
        };
        if parsed == era_number {
            if found.is_some() {
                return Err(format!("multiple era files found for era {era_number}"));
            }
            found = Some(path);
        }
    }

    Ok(found)
}

fn era_number_for_slot<E: EthSpec>(slot: Slot) -> u64 {
    slot.as_u64()
        .saturating_div(E::SlotsPerHistoricalRoot::to_u64())
}

fn era_start_slot<E: EthSpec>(era_number: u64) -> Slot {
    Slot::new(era_number.saturating_mul(E::SlotsPerHistoricalRoot::to_u64()))
}

fn slots_per_era<E: EthSpec>() -> u64 {
    E::SlotsPerHistoricalRoot::to_u64()
}
