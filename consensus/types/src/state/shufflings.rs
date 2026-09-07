use std::sync::Arc;

use safe_arith::SafeArith;
use ssz_types::FixedVector;

use crate::{
    attestation::{AttestationDuty, BeaconCommittee, CommitteeIndex},
    core::{ChainSpec, Epoch, EthSpec, RelativeEpoch, Slot},
    state::{BeaconState, BeaconStateError, CommitteeCache},
};

/// The committee shufflings for the previous, current and next epochs relative to `state_epoch`.
///
/// Callers that need committees must obtain this explicitly rather than reading it from a
/// `BeaconState`, so that shufflings can be shared between states which agree on the shuffling
/// decision root.
///
/// Every constructor and mutator checks that each cache is initialized at the epoch it is being
/// installed for, so a `Shufflings` can never hold an uninitialized or misplaced cache and reads
/// need not be fallible.
#[derive(Debug, Clone, PartialEq)]
pub struct Shufflings {
    state_epoch: Epoch,
    slots_per_epoch: u64,
    previous: Arc<CommitteeCache>,
    current: Arc<CommitteeCache>,
    next: Arc<CommitteeCache>,
}

impl Shufflings {
    /// Build every shuffling `state` can service.
    pub fn for_state<E: EthSpec>(
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<Self, BeaconStateError> {
        let state_epoch = state.current_epoch();
        Self::new(
            state_epoch,
            E::slots_per_epoch(),
            state.initialize_committee_cache(
                RelativeEpoch::Previous.into_epoch(state_epoch),
                spec,
            )?,
            state
                .initialize_committee_cache(RelativeEpoch::Current.into_epoch(state_epoch), spec)?,
            state.initialize_committee_cache(RelativeEpoch::Next.into_epoch(state_epoch), spec)?,
        )
    }

    pub fn new(
        state_epoch: Epoch,
        slots_per_epoch: u64,
        previous: Arc<CommitteeCache>,
        current: Arc<CommitteeCache>,
        next: Arc<CommitteeCache>,
    ) -> Result<Self, BeaconStateError> {
        check_initialized(&previous, RelativeEpoch::Previous, state_epoch)?;
        check_initialized(&current, RelativeEpoch::Current, state_epoch)?;
        check_initialized(&next, RelativeEpoch::Next, state_epoch)?;
        Ok(Self {
            state_epoch,
            slots_per_epoch,
            previous,
            current,
            next,
        })
    }

    pub fn state_epoch(&self) -> Epoch {
        self.state_epoch
    }

    /// Check that these shufflings describe `state`, which every caller passing both must do.
    pub fn check_matches<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
    ) -> Result<(), BeaconStateError> {
        if self.state_epoch == state.current_epoch() {
            Ok(())
        } else {
            Err(BeaconStateError::ShufflingsEpochMismatch {
                shufflings: self.state_epoch,
                state: state.current_epoch(),
            })
        }
    }

    /// Rotate into the next epoch. `next` is the shuffling for `state_epoch + 2`, which the caller
    /// must supply because its randao seed is only reachable through the state.
    pub fn advance(&mut self, next: Arc<CommitteeCache>) -> Result<(), BeaconStateError> {
        let state_epoch = self.state_epoch.safe_add(1u64)?;
        check_initialized(&next, RelativeEpoch::Next, state_epoch)?;
        self.state_epoch = state_epoch;
        self.previous =
            std::mem::replace(&mut self.current, std::mem::replace(&mut self.next, next));
        Ok(())
    }

    pub fn set(
        &mut self,
        relative_epoch: RelativeEpoch,
        cache: Arc<CommitteeCache>,
    ) -> Result<(), BeaconStateError> {
        check_initialized(&cache, relative_epoch, self.state_epoch)?;
        match relative_epoch {
            RelativeEpoch::Previous => self.previous = cache,
            RelativeEpoch::Current => self.current = cache,
            RelativeEpoch::Next => self.next = cache,
        }
        Ok(())
    }

    /// Infallible: the constructor and mutators guarantee each slot is initialized.
    pub fn committee_cache(&self, relative_epoch: RelativeEpoch) -> &Arc<CommitteeCache> {
        match relative_epoch {
            RelativeEpoch::Previous => &self.previous,
            RelativeEpoch::Current => &self.current,
            RelativeEpoch::Next => &self.next,
        }
    }

    /// Errors with `EpochOutOfBounds` if `epoch` is outside the covered window.
    pub fn committee_cache_at_epoch(
        &self,
        epoch: Epoch,
    ) -> Result<&Arc<CommitteeCache>, BeaconStateError> {
        Ok(self.committee_cache(RelativeEpoch::from_epoch(self.state_epoch, epoch)?))
    }

    pub fn committee_cache_at_slot(
        &self,
        slot: Slot,
    ) -> Result<&Arc<CommitteeCache>, BeaconStateError> {
        self.committee_cache_at_epoch(slot.epoch(self.slots_per_epoch))
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
        self.committee_cache(relative_epoch)
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
            .committee_cache(relative_epoch)
            .epoch_committee_count()? as u64)
    }

    /// Return the cached active validator indices at some epoch. The indices are shuffled.
    pub fn get_cached_active_validator_indices(&self, relative_epoch: RelativeEpoch) -> &[usize] {
        self.committee_cache(relative_epoch)
            .active_validator_indices()
    }

    pub fn get_shuffling(&self, relative_epoch: RelativeEpoch) -> &[usize] {
        self.committee_cache(relative_epoch).shuffling()
    }

    pub fn get_attestation_duties(
        &self,
        validator_index: usize,
        relative_epoch: RelativeEpoch,
    ) -> Result<Option<AttestationDuty>, BeaconStateError> {
        Ok(self
            .committee_cache(relative_epoch)
            .get_attestation_duties(validator_index)?)
    }
}

fn check_initialized(
    cache: &CommitteeCache,
    relative_epoch: RelativeEpoch,
    state_epoch: Epoch,
) -> Result<(), BeaconStateError> {
    if cache.is_initialized_at(relative_epoch.into_epoch(state_epoch)) {
        Ok(())
    } else {
        Err(BeaconStateError::CommitteeCacheUninitialized(Some(
            relative_epoch,
        )))
    }
}
