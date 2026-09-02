//! A map keyed by a block root, for the rule's per-validator loops.
//!
//! `no_std` has no `HashMap`, and a `BTreeMap` pays a 32-byte comparison at
//! every level of the tree. The vote aggregation does one lookup per validator
//! -- the hottest loop in the rule -- so that cost lands on the whole validator
//! set. Roots are hash outputs, so their leading eight bytes are already
//! uniformly distributed and serve as the hash directly; upstream Lighthouse
//! does the same thing with an identity hasher over a root prefix.

extern crate alloc;

use alloc::vec::Vec;

use crate::primitives::{Epoch, Root};

/// A key that can supply its own hash from bytes that are already random.
pub(crate) trait RootKey: Copy + PartialEq {
    fn prefix(&self) -> u64;
}

impl RootKey for Root {
    fn prefix(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self[..8]);
        u64::from_le_bytes(bytes)
    }
}

impl RootKey for (Root, Epoch) {
    fn prefix(&self) -> u64 {
        // Mix the epoch in so two votes for one root in different epochs do not
        // collide on every probe.
        self.0
            .prefix()
            .rotate_left(17)
            .wrapping_add(self.1.as_u64().wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }
}

/// Open addressing with linear probing. Sized to a power of two so the modulo is
/// a mask, and grown well before it is full so probe runs stay short.
pub(crate) struct RootMap<K: RootKey> {
    slots: Vec<Option<(K, u64)>>,
    len: usize,
}

impl<K: RootKey> RootMap<K> {
    pub(crate) fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }

    fn index_of(slots: &[Option<(K, u64)>], key: &K) -> usize {
        let mask = slots.len() - 1;
        let mut i = (key.prefix() as usize) & mask;
        loop {
            match &slots[i] {
                None => return i,
                Some((k, _)) if k == key => return i,
                _ => i = (i + 1) & mask,
            }
        }
    }

    fn grow(&mut self) {
        let new_len = if self.slots.is_empty() {
            64
        } else {
            self.slots.len() * 2
        };
        let mut new_slots: Vec<Option<(K, u64)>> = Vec::new();
        new_slots.resize_with(new_len, || None);
        for entry in self.slots.iter().flatten() {
            let i = Self::index_of(&new_slots, &entry.0);
            new_slots[i] = Some(*entry);
        }
        self.slots = new_slots;
    }

    /// Add `value` to the entry for `key`, inserting it if absent.
    pub(crate) fn add(&mut self, key: K, value: u64) -> Result<(), crate::ArithError> {
        // Keep the load factor under 0.7; beyond that linear probing degrades.
        if self.slots.is_empty() || (self.len + 1) * 10 >= self.slots.len() * 7 {
            self.grow();
        }
        let i = Self::index_of(&self.slots, &key);
        match &mut self.slots[i] {
            Some((_, v)) => {
                *v = v.checked_add(value).ok_or(crate::ArithError)?;
            }
            slot @ None => {
                *slot = Some((key, value));
                self.len = self.len.saturating_add(1);
            }
        }
        Ok(())
    }

    pub(crate) fn get(&self, key: &K) -> Option<u64> {
        if self.slots.is_empty() {
            return None;
        }
        self.slots[Self::index_of(&self.slots, key)]
            .as_ref()
            .map(|(_, v)| *v)
    }

    /// Insert, replacing any existing value.
    pub(crate) fn insert(&mut self, key: K, value: u64) {
        if self.slots.is_empty() || (self.len + 1) * 10 >= self.slots.len() * 7 {
            self.grow();
        }
        let i = Self::index_of(&self.slots, &key);
        if self.slots[i].is_none() {
            self.len = self.len.saturating_add(1);
        }
        self.slots[i] = Some((key, value));
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (K, u64)> + '_ {
        self.slots.iter().flatten().copied()
    }
}
