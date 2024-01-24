//! Provides the `ParticipationCache`, a custom Lighthouse cache which attempts to reduce CPU and
//! memory usage by:
//!
//! - Caching a map of `validator_index -> participation_flags` for all active validators in the
//!   previous and current epochs.
//! - Caching the total balances of:
//!   - All active validators.
//!   - All active validators matching each of the three "timely" flags.
//! - Caching the "eligible" validators.
//!
//! Additionally, this cache is returned from the `altair::process_epoch` function and can be used
//! to get useful summaries about the validator participation in an epoch.

use crate::common::altair::{get_base_reward, BaseRewardPerIncrement};
use safe_arith::ArithError;
use types::{
    consts::altair::NUM_FLAG_INDICES, Balance, BeaconState, BeaconStateError, ChainSpec, Epoch,
    EthSpec, ParticipationFlags, RelativeEpoch, Validator,
};

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    InvalidFlagIndex(usize),
    NoUnslashedParticipatingIndices,
    MissingValidator(usize),
    BeaconState(BeaconStateError),
    Arith(ArithError),
    InvalidValidatorIndex(usize),
    InconsistentTotalActiveBalance { cached: u64, computed: u64 },
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Self::BeaconState(e)
    }
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Self::Arith(e)
    }
}

/// Caches the participation values for one epoch (either the previous or current).
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct SingleEpochParticipationCache {
    /// Stores the sum of the balances for all validators in `self.unslashed_participating_indices`
    /// for all flags in `NUM_FLAG_INDICES`.
    ///
    /// A flag balance is only incremented if a validator is in that flag set.
    pub(crate) total_flag_balances: [Balance; NUM_FLAG_INDICES],
    /// Stores the sum of all balances of all validators in `self.unslashed_participating_indices`
    /// (regardless of which flags are set).
    total_active_balance: Balance,
}

impl SingleEpochParticipationCache {
    fn new(spec: &ChainSpec) -> Self {
        let zero_balance = Balance::zero(spec.effective_balance_increment);

        Self {
            total_flag_balances: [zero_balance; NUM_FLAG_INDICES],
            total_active_balance: zero_balance,
        }
    }

    /// Returns the total balance of attesters who have `flag_index` set.
    fn total_flag_balance(&self, flag_index: usize) -> Result<u64, Error> {
        self.total_flag_balances
            .get(flag_index)
            .map(Balance::get)
            .ok_or(Error::InvalidFlagIndex(flag_index))
    }

    /// Process an **active** validator, reading from the `epoch_participation` with respect to the
    /// `relative_epoch`.
    ///
    /// ## Errors
    ///
    /// - An error will be returned if the `val_index` validator is inactive at the given
    ///     `relative_epoch`.
    fn process_active_validator(
        &mut self,
        val_index: usize,
        validator: &Validator,
        epoch_participation: &ParticipationFlags,
        current_epoch: Epoch,
        relative_epoch: RelativeEpoch,
    ) -> Result<(), BeaconStateError> {
        // Sanity check to ensure the validator is active.
        let epoch = relative_epoch.into_epoch(current_epoch);
        if !validator.is_active_at(epoch) {
            return Err(BeaconStateError::ValidatorIsInactive { val_index });
        }

        // All active validators increase the total active balance.
        self.total_active_balance
            .safe_add_assign(validator.effective_balance())?;

        // Only unslashed validators may proceed.
        if validator.slashed() {
            return Ok(());
        }

        // Iterate through all the flags and increment the total flag balances for whichever flags
        // are set for `val_index`.
        for (flag, balance) in self.total_flag_balances.iter_mut().enumerate() {
            if epoch_participation.has_flag(flag)? {
                balance.safe_add_assign(validator.effective_balance())?;
            }
        }

        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ValidatorInfo {
    pub effective_balance: u64,
    pub base_reward: u64,
    pub is_eligible: bool,
    pub is_slashed: bool,
    pub is_active_current_epoch: bool,
    pub is_active_previous_epoch: bool,
    pub previous_epoch_participation: ParticipationFlags,
}

impl ValidatorInfo {
    #[inline]
    pub fn is_unslashed_participating_index(&self, flag_index: usize) -> Result<bool, Error> {
        Ok(self.is_active_previous_epoch
            && !self.is_slashed
            && self
                .previous_epoch_participation
                .has_flag(flag_index)
                .map_err(|_| Error::InvalidFlagIndex(flag_index))?)
    }
}

/// Single `HashMap` for validator info relevant to `process_epoch`.
#[derive(Debug, PartialEq, Clone)]
struct ValidatorInfoCache {
    info: Vec<Option<ValidatorInfo>>,
}

impl ValidatorInfoCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            info: vec![None; capacity],
        }
    }
}

/// Maintains a cache to be used during `altair::process_epoch`.
#[derive(PartialEq, Debug, Clone)]
pub struct ParticipationCache {
    current_epoch: Epoch,
    /// Caches information about active validators pertaining to `self.current_epoch`.
    pub(crate) current_epoch_participation: SingleEpochParticipationCache,
    previous_epoch: Epoch,
    /// Caches information about active validators pertaining to `self.previous_epoch`.
    pub(crate) previous_epoch_participation: SingleEpochParticipationCache,
    /// Caches validator information relevant to `process_epoch`.
    validators: ValidatorInfoCache,
    /// Caches the result of the `get_eligible_validator_indices` function.
    eligible_indices: Vec<usize>,
}

impl ParticipationCache {
    /// Instantiate `Self`, returning a fully initialized cache.
    ///
    /// ## Errors
    ///
    /// - The provided `state` **must** be an Altair state. An error will be returned otherwise.
    pub fn new<T: EthSpec>(state: &BeaconState<T>, spec: &ChainSpec) -> Result<Self, Error> {
        let current_epoch = state.current_epoch();
        let previous_epoch = state.previous_epoch();

        // Both the current/previous epoch participations are set to a capacity that is slightly
        // larger than required. The difference will be due slashed-but-active validators.
        let mut current_epoch_participation = SingleEpochParticipationCache::new(spec);
        let mut previous_epoch_participation = SingleEpochParticipationCache::new(spec);

        let mut validators = ValidatorInfoCache::new(state.validators().len());

        let current_epoch_total_active_balance = state.get_total_active_balance()?;
        let base_reward_per_increment =
            BaseRewardPerIncrement::new(current_epoch_total_active_balance, spec)?;

        // Contains the set of validators which are either:
        //
        // - Active in the previous epoch.
        // - Slashed, but not yet withdrawable.
        //
        // Using the full length of `state.validators` is almost always overkill, but it ensures no
        // reallocations.
        let mut eligible_indices = Vec::with_capacity(state.validators().len());

        // Iterate through all validators, updating:
        //
        // 1. Validator participation for current and previous epochs.
        // 2. The "eligible indices".
        //
        // Care is taken to ensure that the ordering of `eligible_indices` is the same as the
        // `get_eligible_validator_indices` function in the spec.
        let iter = state
            .validators()
            .iter()
            .zip(state.current_epoch_participation()?)
            .zip(state.previous_epoch_participation()?)
            .enumerate();
        for (val_index, ((val, curr_epoch_flags), prev_epoch_flags)) in iter {
            let is_active_current_epoch = val.is_active_at(current_epoch);
            let is_active_previous_epoch = val.is_active_at(previous_epoch);
            let is_eligible = state.is_eligible_validator(previous_epoch, val)?;

            if is_active_current_epoch {
                current_epoch_participation.process_active_validator(
                    val_index,
                    val,
                    curr_epoch_flags,
                    current_epoch,
                    RelativeEpoch::Current,
                )?;
            }

            if is_active_previous_epoch {
                assert!(is_eligible);

                previous_epoch_participation.process_active_validator(
                    val_index,
                    val,
                    prev_epoch_flags,
                    current_epoch,
                    RelativeEpoch::Previous,
                )?;
            }

            // Note: a validator might still be "eligible" whilst returning `false` to
            // `Validator::is_active_at`. It's also possible for a validator to be active
            // in the current epoch without being eligible (if it was just activated).
            if is_eligible {
                eligible_indices.push(val_index);
            }

            let mut validator_info = ValidatorInfo {
                effective_balance: val.effective_balance(),
                base_reward: 0, // not read
                is_eligible,
                is_slashed: val.slashed(),
                is_active_current_epoch,
                is_active_previous_epoch,
                previous_epoch_participation: *prev_epoch_flags,
            };

            #[allow(clippy::indexing_slicing)]
            if is_eligible || is_active_current_epoch {
                let effective_balance = val.effective_balance();
                let base_reward =
                    get_base_reward(effective_balance, base_reward_per_increment, spec)?;
                validator_info.base_reward = base_reward;
                validators.info[val_index] = Some(validator_info);
            }
        }

        // Sanity check total active balance.
        if current_epoch_participation.total_active_balance.get()
            != current_epoch_total_active_balance
        {
            return Err(Error::InconsistentTotalActiveBalance {
                cached: current_epoch_total_active_balance,
                computed: current_epoch_participation.total_active_balance.get(),
            });
        }

        Ok(Self {
            current_epoch,
            current_epoch_participation,
            previous_epoch,
            previous_epoch_participation,
            validators,
            eligible_indices,
        })
    }

    /// Equivalent to the specification `get_eligible_validator_indices` function.
    pub fn eligible_validator_indices(&self) -> &[usize] {
        &self.eligible_indices
    }

    /*
     * Balances
     */

    pub fn current_epoch_total_active_balance(&self) -> u64 {
        self.current_epoch_participation.total_active_balance.get()
    }

    pub fn previous_epoch_flag_attesting_balance(&self, flag_index: usize) -> Result<u64, Error> {
        self.previous_epoch_participation
            .total_flag_balance(flag_index)
    }

    /*
     * Active/Unslashed
     */

    pub fn get_validator(&self, val_index: usize) -> Result<&ValidatorInfo, Error> {
        self.validators
            .info
            .get(val_index)
            .ok_or(Error::MissingValidator(val_index))?
            .as_ref()
            .ok_or(Error::MissingValidator(val_index))
    }
}
