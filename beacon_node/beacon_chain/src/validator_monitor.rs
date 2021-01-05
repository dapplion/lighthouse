use eth2::lighthouse::MonitoredValidatorReport;
use slog::{info, Logger};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::Path;
use std::str::{from_utf8, FromStr, Utf8Error};
use std::time::{SystemTime, UNIX_EPOCH};
use types::{
    BeaconBlockHeader, BeaconState, Epoch, EthSpec, IndexedAttestation, PublicKeyBytes,
    SignedAggregateAndProof,
};

/// The number of historical epochs stored in the `ValidatorManager`.
///
/// This is set to 32 epochs (12.8 hours). This should give someone actively monitoring the system
/// enough time to troubleshoot any failures.
pub const DEFAULT_MAX_LEN: usize = 32;

#[derive(Debug)]
pub enum Error {
    InvalidPubkey(String),
    FileError(io::Error),
    InvalidUtf8(Utf8Error),
    ValidatorNotMonitored(PublicKeyBytes),
    NoDataForEpoch(Epoch),
}

pub struct ValidatorEvent<T: EthSpec> {
    pub timestamp: u64,
    pub pubkeys: Vec<PublicKeyBytes>,
    pub location: EventLocation,
    pub data: EventData<T>,
}

#[derive(Copy, Clone, Debug)]
pub enum EventLocation {
    BeaconChain,
    Gossip,
    API,
    Block,
}

pub enum EventData<T: EthSpec> {
    Attestation(IndexedAttestation<T>),
    Block(BeaconBlockHeader),
    Aggregate(SignedAggregateAndProof<T>),
}

struct MonitoredValidator {
    pub id: String,
    pub pubkey: PublicKeyBytes,
    pub index: Option<u64>,
}

impl MonitoredValidator {
    fn new(pubkey: PublicKeyBytes, index: Option<u64>) -> Self {
        Self {
            id: pubkey.to_string(),
            pubkey,
            index,
        }
    }
}

pub struct ValidatorMonitor<T: EthSpec> {
    validators: HashMap<PublicKeyBytes, MonitoredValidator>,
    indices: HashMap<u64, PublicKeyBytes>,
    events: HashMap<Epoch, Vec<ValidatorEvent<T>>>,
    pub max_epochs: usize,
    log: Logger,
}

fn set_max(current: &mut u64, other: u64) {
    *current = std::cmp::max(*current, other);
}

impl<T: EthSpec> ValidatorMonitor<T> {
    pub fn new(max_epochs: usize, log: Logger) -> Self {
        Self {
            validators: <_>::default(),
            indices: <_>::default(),
            events: <_>::default(),
            max_epochs,
            log,
        }
    }

    pub fn generate_validator_report(
        &self,
        epoch: Epoch,
        pubkey: PublicKeyBytes,
    ) -> Result<MonitoredValidatorReport, Error> {
        let validator = self
            .validators
            .get(&pubkey)
            .ok_or_else(|| Error::ValidatorNotMonitored(pubkey))?;

        let mut report = MonitoredValidatorReport {
            epoch,
            pubkey,
            validator_index: validator.index,
            gossip_attestation_seen_timestamp: 0,
            api_attestation_seen_timestamp: 0,
            attestation_seen_in_block_timestamp: 0,
            block_seen_timestamp: 0,
            aggregate_seen_timestamp: 0,
        };

        self.events
            .get(&epoch)
            .ok_or_else(|| Error::NoDataForEpoch(epoch))?
            .iter()
            .filter(|event| event.pubkeys.contains(&pubkey))
            .for_each(|event| {
                let t = event.timestamp;

                match event.data {
                    EventData::Attestation(_) => match event.location {
                        EventLocation::BeaconChain => {}
                        EventLocation::Gossip => {
                            set_max(&mut report.gossip_attestation_seen_timestamp, t)
                        }
                        EventLocation::API => {
                            set_max(&mut report.api_attestation_seen_timestamp, t)
                        }
                        EventLocation::Block => {
                            set_max(&mut report.attestation_seen_in_block_timestamp, t)
                        }
                    },
                    EventData::Block(_) => set_max(&mut report.block_seen_timestamp, t),
                    EventData::Aggregate(_) => set_max(&mut report.aggregate_seen_timestamp, t),
                }
            });

        Ok(report)
    }

    pub fn add_validators_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), Error> {
        let mut bytes = vec![];
        OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(Error::FileError)?;

        self.add_validators_from_comma_separated_str(from_utf8(&bytes).map_err(Error::InvalidUtf8)?)
    }

    pub fn add_validators_from_comma_separated_str(
        &mut self,
        validator_pubkeys: &str,
    ) -> Result<(), Error> {
        validator_pubkeys
            .split(",")
            .map(PublicKeyBytes::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::InvalidPubkey)
            .map(|pubkeys| self.add_validator_pubkeys(pubkeys))
    }

    pub fn add_validator_pubkeys(&mut self, pubkeys: Vec<PublicKeyBytes>) {
        for pubkey in pubkeys {
            let index_opt = self
                .indices
                .iter()
                .find(|(_, candidate)| **candidate == pubkey)
                .map(|(index, _)| *index);

            self.validators
                .entry(pubkey)
                .or_insert_with(|| MonitoredValidator::new(pubkey, index_opt));
        }
    }

    pub fn update_validator_indices(&mut self, state: &BeaconState<T>) {
        state
            .validators
            .iter()
            .enumerate()
            .skip(self.indices.len())
            .for_each(|(i, validator)| {
                let i = i as u64;
                if let Some(validator) = self.validators.get_mut(&validator.pubkey) {
                    validator.index = Some(i);
                }
                self.indices.insert(i, validator.pubkey);
            })
    }

    pub fn register_api_attestation(&mut self, indexed_attestation: &IndexedAttestation<T>) {
        self.register_attestation(EventLocation::API, indexed_attestation)
    }

    pub fn register_gossip_attestation(&mut self, indexed_attestation: &IndexedAttestation<T>) {
        self.register_attestation(EventLocation::Gossip, indexed_attestation)
    }

    pub fn register_attestation_in_block(&mut self, indexed_attestation: &IndexedAttestation<T>) {
        self.register_attestation(EventLocation::Block, indexed_attestation)
    }

    pub fn register_attestation(
        &mut self,
        location: EventLocation,
        indexed_attestation: &IndexedAttestation<T>,
    ) {
        let pubkeys = indexed_attestation
            .attesting_indices
            .iter()
            .filter_map(|i| {
                let pubkey = *self.indices.get(i)?;

                if self.validators.contains_key(&pubkey) {
                    info!(
                        self.log,
                        "Monitored validator attestation";
                        "index" => %indexed_attestation.data.index,
                        "slot" => %indexed_attestation.data.slot,
                        "index" => %indexed_attestation.data.slot,
                        "head" => %indexed_attestation.data.beacon_block_root,
                        "src" => ?location,
                        "validator" => %i,
                    );
                    Some(pubkey)
                } else {
                    None
                }
            })
            .collect();

        self.events
            .entry(indexed_attestation.data.slot.epoch(T::slots_per_epoch()))
            .or_insert_with(|| vec![])
            .push(ValidatorEvent {
                pubkeys,
                timestamp: timestamp_now(),
                location,
                data: EventData::Attestation(indexed_attestation.clone()),
            });

        // Prune after each insert.
        self.prune()
    }

    pub fn prune(&mut self) {
        while self.events.len() > self.max_epochs {
            if let Some(i) = self.events.iter().map(|(epoch, _)| *epoch).min() {
                self.events.remove(&i);
            }
        }
    }
}

fn timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
