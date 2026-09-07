use std::sync::Arc;

use ssz_types::FixedVector;

use crate::{
    attestation::{AttestationDuty, BeaconCommittee, CommitteeIndex},
    core::{ChainSpec, Epoch, EthSpec, RelativeEpoch, Slot},
    state::{BeaconState, BeaconStateError, CommitteeCache},
};

/// The committee shufflings for the epochs surrounding a state's current epoch.
///
/// Callers that need committees must obtain this explicitly rather than reading it from a
/// `BeaconState`, so that shufflings can be shared between states which agree on the shuffling
/// decision root.
///
/// `previous` and `current` are always known. `next` is unknown only in the window opened by
/// `advance`, where the new next epoch is `state.current_epoch() + 2` and its randao seed is not
/// yet available from the state.
#[derive(Debug, Clone, PartialEq)]
pub struct Shufflings {
    state_epoch: Epoch,
    slots_per_epoch: u64,
    previous: Arc<CommitteeCache>,
    current: Arc<CommitteeCache>,
    next: Option<Arc<CommitteeCache>>,
}

impl Shufflings {
    /// Build every shuffling `state` can service.
    pub fn for_state<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let state_epoch = state.current_epoch();
        Ok(Self {
            state_epoch,
            slots_per_epoch: E::slots_per_epoch(),
            previous: state.initialize_committee_cache(
                RelativeEpoch::Previous.into_epoch(state_epoch),
                spec,
            )?,
            current: state
                .initialize_committee_cache(RelativeEpoch::Current.into_epoch(state_epoch), spec)?,
            next: Some(
                state.initialize_committee_cache(
                    RelativeEpoch::Next.into_epoch(state_epoch),
                    spec,
                )?,
            ),
        })
    }

    pub fn state_epoch(&self) -> Epoch {
        self.state_epoch
    }

    /// Rotate into the next epoch, leaving the new next shuffling unknown until it is `set`.
    pub fn advance(&mut self) {
        self.state_epoch = self.state_epoch.saturating_add(1u64);
        self.previous = std::mem::replace(
            &mut self.current,
            self.next
                .take()
                .unwrap_or_else(|| Arc::new(CommitteeCache::default())),
        );
    }

    pub fn set(&mut self, relative_epoch: RelativeEpoch, cache: Arc<CommitteeCache>) {
        match relative_epoch {
            RelativeEpoch::Previous => self.previous = cache,
            RelativeEpoch::Current => self.current = cache,
            RelativeEpoch::Next => self.next = Some(cache),
        }
    }

    pub fn committee_cache(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<&Arc<CommitteeCache>, BeaconStateError> {
        let cache = match relative_epoch {
            RelativeEpoch::Previous => Some(&self.previous),
            RelativeEpoch::Current => Some(&self.current),
            RelativeEpoch::Next => self.next.as_ref(),
        }
        .ok_or(BeaconStateError::CommitteeCacheUninitialized(Some(
            relative_epoch,
        )))?;

        if cache.is_initialized_at(relative_epoch.into_epoch(self.state_epoch)) {
            Ok(cache)
        } else {
            Err(BeaconStateError::CommitteeCacheUninitialized(Some(
                relative_epoch,
            )))
        }
    }

    pub fn committee_cache_at_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<&Arc<CommitteeCache>, BeaconStateError> {
        self.committee_cache(RelativeEpoch::from_epoch(self.state_epoch, epoch)?)
    }

    pub fn committee_cache_at_slot(
        &self,
        slot: Slot,
    ) -> Result<&Arc<CommitteeCache>, BeaconStateError> {
        self.committee_cache_at_epoch(slot.epoch(self.slots_per_epoch))
    }

    pub fn is_initialized(&self, relative_epoch: RelativeEpoch) -> bool {
        self.committee_cache(relative_epoch).is_ok()
    }

    /// Get the Beacon committee at the given slot and index.
    pub fn get_beacon_committee(
        &self,
        slot: Slot,
        index: CommitteeIndex,
    ) -> Result<BeaconCommittee<'_>, BeaconStateError> {
        self.committee_cache_at_slot(slot)?
            .get_beacon_committee(slot, index)
            .ok_or(BeaconStateError::NoCommittee { slot, index })
    }

    /// Get all of the Beacon committees at a given slot.
    pub fn get_beacon_committees_at_slot(
        &self,
        slot: Slot,
    ) -> Result<Vec<BeaconCommittee<'_>>, BeaconStateError> {
        self.committee_cache_at_slot(slot)?
            .get_beacon_committees_at_slot(slot)
    }

    /// Get all of the Beacon committees at a given relative epoch.
    pub fn get_beacon_committees_at_epoch(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<Vec<BeaconCommittee<'_>>, BeaconStateError> {
        self.committee_cache(relative_epoch)?
            .get_all_beacon_committees()
    }

    /// Get the inclusion list committee for the given `slot`. [New in Heze:EIP7805]
    pub fn get_inclusion_list_committee<E: EthSpec>(
        &self,
        slot: Slot,
    ) -> Result<FixedVector<u64, E::InclusionListCommitteeSize>, BeaconStateError> {
        let committee = self
            .committee_cache_at_slot(slot)?
            .get_inclusion_list_committee_at_slot(slot, E::inclusion_list_committee_size())?;
        Ok(FixedVector::new(
            committee.into_iter().map(|index| index as u64).collect(),
        )?)
    }

    pub fn get_committee_count_at_slot(&self, slot: Slot) -> Result<u64, BeaconStateError> {
        Ok(self.committee_cache_at_slot(slot)?.committees_per_slot())
    }

    pub fn get_epoch_committee_count(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<u64, BeaconStateError> {
        Ok(self
            .committee_cache(relative_epoch)?
            .epoch_committee_count()? as u64)
    }

    /// Return the cached active validator indices at some epoch. The indices are shuffled.
    pub fn get_cached_active_validator_indices(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<&[usize], BeaconStateError> {
        Ok(self
            .committee_cache(relative_epoch)?
            .active_validator_indices())
    }

    pub fn get_shuffling(
        &self,
        relative_epoch: RelativeEpoch,
    ) -> Result<&[usize], BeaconStateError> {
        Ok(self.committee_cache(relative_epoch)?.shuffling())
    }

    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
        relative_epoch: RelativeEpoch,
    ) -> Result<Option<AttestationDuty>, BeaconStateError> {
        Ok(self
            .committee_cache(relative_epoch)?
            .get_attestation_duties(validator_index)?)
    }
}
