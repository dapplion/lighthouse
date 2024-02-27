use crate::{Slot, Validator};
use arbitrary::Arbitrary;
use rpds::HashTrieSetSync as HashTrieSet;

/// Persistent (cheap to clone) cache of all slashed validator indices.
#[derive(Debug, Clone, PartialEq, Arbitrary)]
pub struct SlashingsCache {
    latest_block_slot: Slot,
    #[arbitrary(default)]
    slashed_validators: HashTrieSet<usize>,
}

impl SlashingsCache {
    /// Initialize a new cache for the given list of validators.
    pub fn new<'a, V, I>(latest_block_slot: Slot, validators: V) -> Self
    where
        V: IntoIterator<Item = &'a Validator, IntoIter = I>,
        I: ExactSizeIterator + Iterator<Item = &'a Validator>,
    {
        let slashed_validators = validators
            .into_iter()
            .enumerate()
            .filter_map(|(i, validator)| validator.slashed().then_some(i))
            .collect();
        Self {
            latest_block_slot,
            slashed_validators,
        }
    }

    pub fn record_validator_slashing(&mut self, block_slot: Slot, validator_index: usize) {
        self.slashed_validators.insert_mut(validator_index);
    }

    pub fn is_slashed(&self, validator_index: usize) -> bool {
        self.slashed_validators.contains(&validator_index)
    }

    pub fn update_latest_block_slot(&mut self, latest_block_slot: Slot) {
        self.latest_block_slot = latest_block_slot;
    }
}
