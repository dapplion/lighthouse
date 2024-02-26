use crate::*;
use rpds::HashTrieMapSync;
use std::cmp::Ordering;

type ValidatorIndex = usize;

#[derive(Debug, PartialEq, Clone, Default)]
pub struct PubkeyCache {
    /// Maintain the number of keys added to the map. It is not sufficient to just use the
    /// HashTrieMap len, as it does not increase when duplicate keys are added. Duplicate keys are
    /// used during testing.
    len: usize,
    map: HashTrieMapSync<PublicKeyBytes, ValidatorIndex>,
}

impl PubkeyCache {
    /// Returns the number of validator indices added to the map so far.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> ValidatorIndex {
        self.len
    }

    /// Inserts a validator index into the map.
    ///
    /// The added index must equal the number of validators already added to the map. This ensures
    /// that an index is never skipped.
    pub fn insert(&mut self, pubkey: PublicKeyBytes, index: ValidatorIndex) -> bool {
        match index.cmp(&self.len) {
            Ordering::Greater => false,
            Ordering::Equal => {
                self.map.insert_mut(pubkey, index);
                self.len = self
                    .len
                    .checked_add(1)
                    .expect("map length cannot exceed usize");
                true
            }
            // Ignore inserts for already known keys
            Ordering::Less => true,
        }
    }

    /// Looks up a validator index's by their public key.
    pub fn get(&self, pubkey: &PublicKeyBytes) -> Option<ValidatorIndex> {
        self.map.get(pubkey).copied()
    }
}

impl arbitrary::Arbitrary<'_> for PubkeyCache {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::default())
    }
}
