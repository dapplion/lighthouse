use crate::EthSpec;
use milhouse::mem::MemorySize;
use serde::{Deserialize, Serialize};
use ssz_types::FixedVector;
use std::ops::Deref;
use typenum::Unsigned;

#[derive(Clone, Debug, PartialEq)]
pub struct PTC<E: EthSpec>(pub FixedVector<usize, E::PTCSize>);

impl<'a, E: EthSpec> IntoIterator for &'a PTC<E> {
    type Item = &'a usize;
    type IntoIter = std::slice::Iter<'a, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<E: EthSpec> IntoIterator for PTC<E> {
    type Item = usize;
    type IntoIter = std::vec::IntoIter<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Newtype wrapper around `FixedVector<u64, N>` that implements `MemorySize`,
/// required for use as a leaf type in milhouse `Vector`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
#[serde(bound = "")]
pub struct PtcWindowEntry<N: Unsigned + Clone>(pub FixedVector<u64, N>);

impl<N: Unsigned + Clone> Deref for PtcWindowEntry<N> {
    type Target = FixedVector<u64, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<N: Unsigned + Clone> PtcWindowEntry<N> {
    pub fn from_elem(elem: u64) -> Self {
        PtcWindowEntry(FixedVector::from_elem(elem))
    }

    pub fn new(vec: Vec<u64>) -> Result<Self, ssz_types::Error> {
        Ok(PtcWindowEntry(FixedVector::new(vec)?))
    }
}

impl<N: Unsigned + Clone> MemorySize for PtcWindowEntry<N> {
    fn self_pointer(&self) -> usize {
        self as *const _ as usize
    }

    fn subtrees(&self) -> Vec<&dyn MemorySize> {
        vec![]
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn intrinsic_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.0.len() * std::mem::size_of::<u64>()
    }
}

// Delegate SSZ Encode to the inner FixedVector.
impl<N: Unsigned + Clone> ssz::Encode for PtcWindowEntry<N> {
    fn is_ssz_fixed_len() -> bool {
        <FixedVector<u64, N> as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <FixedVector<u64, N> as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }
}

// Delegate SSZ Decode to the inner FixedVector.
impl<N: Unsigned + Clone> ssz::Decode for PtcWindowEntry<N> {
    fn is_ssz_fixed_len() -> bool {
        <FixedVector<u64, N> as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <FixedVector<u64, N> as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        FixedVector::from_ssz_bytes(bytes).map(PtcWindowEntry)
    }
}

// Delegate TreeHash to the inner FixedVector.
impl<N: Unsigned + Clone> tree_hash::TreeHash for PtcWindowEntry<N> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        <FixedVector<u64, N> as tree_hash::TreeHash>::tree_hash_type()
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        <FixedVector<u64, N> as tree_hash::TreeHash>::tree_hash_packing_factor()
    }

    fn tree_hash_root(&self) -> tree_hash::Hash256 {
        self.0.tree_hash_root()
    }
}
