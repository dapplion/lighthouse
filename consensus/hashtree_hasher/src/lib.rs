//! SSZ merkleization backed by [`hashtree`], the SHA256 library Prysm uses for hash tree roots.
//!
//! `hashtree` exposes a single batched primitive: given `count` blocks of 64 bytes it writes
//! `count` digests of 32 bytes. It runs several SHA256 lanes at once (2 with SHA-NI, 8 with AVX2,
//! 16 with AVX512), so it only beats a plain SHA256 when there are many independent blocks to
//! hash at the same time. `tree_hash::MerkleHasher` folds the tree up as leaves arrive and hashes
//! exactly one 64 byte block at a time, so it cannot use the extra lanes at all. This crate
//! reorganises the same computation level by level, which makes every level one batched call.
//!
//! The target is the SSZ lists that are *not* backed by `milhouse`, i.e. `ssz_types::VariableList`
//! and `ssz_types::FixedVector`. Those have no tree hash cache, so their root is recomputed from
//! scratch every time. `Transactions` is the expensive one: it is a list of byte lists, and each
//! byte list is padded out to `MaxBytesPerTransaction`, so a small transaction pays 25 levels of
//! zero padding on top of its own data. [`merkleize_forest`] hashes those padding levels for all
//! transactions in one call each.
//!
//! # Where the speed actually comes from
//!
//! Adopting this crate wholesale is 7.2x on a 256 transaction list, but that number is four
//! separate changes stacked together, and they are very lopsided. `benches/hashing.rs` prices each
//! one by adding a single change per arm. Measured on a 13th gen Core i5 against
//! `Transactions<MainnetEthSpec>` with 256 mainnet-like transactions:
//!
//! | change | step | running total |
//! | --- | --- | --- |
//! | bulk packing in `ssz_types::tree_hash::hash_vec` | 2.95x | 2.95x |
//! | 40 byte `HalfNode` in `tree_hash::MerkleHasher` | 1.45x | 4.27x |
//! | level-order merkleization (this crate) | 1.10x | 4.72x |
//! | `hashtree` instead of `ethereum_hashing` | 1.54x | 7.27x |
//!
//! The first two are small diffs to upstream crates and account for 4.27x of the 7.27x. Neither
//! needs a new dependency, and neither needs this crate.
//!
//! **Bulk packing** is the big one and it is not about merkleization at all. `hash_vec` walks a
//! basic-element list one element at a time, building a `PackedEncoding` smallvec per element, so
//! a `VariableList<u8, N>` is packed one byte at a time: a 4 KiB transaction costs 4096 of those
//! to produce 146 hashes. Batching only the `write` calls behind a 32 byte accumulator recovers
//! just 1.09x, so the cost is the per-element packing, not the calls. Getting the rest needs a
//! bulk packing path for basic types, which for `u8` is `extend_from_slice` of the whole list.
//!
//! **The 40 byte `HalfNode`** is the change [`SlimMerkleHasher`] implements, and it is independent
//! of the shape of the data: it still pays 1.37x on a list of 1 byte transactions, where bulk
//! packing is worth nothing because each element is already a single write.
//!
//! **`hashtree`** contributes 1.54x, which tracks its 1.59x raw block throughput over
//! `ethereum_hashing` almost exactly. Use [`EthereumHashing`] to run this crate's merkleization on
//! the SHA256 Lighthouse already links and see what the library alone is worth.
//!
//! [`hashtree`]: https://github.com/prysmaticlabs/hashtree

mod list;
mod merkleize;
mod streaming;

pub use list::{
    byte_list_tree_hash_root, byte_list_tree_hash_root_with, byte_lists_tree_hash_root,
    byte_lists_tree_hash_root_with, depth_for_leaves, variable_list_tree_hash_root,
    variable_list_tree_hash_root_with, vec_tree_hash_root, vec_tree_hash_root_with,
};
pub use merkleize::{
    Error, merkleize_chunks, merkleize_chunks_with, merkleize_forest, merkleize_forest_with,
    mix_in_lengths, mix_in_lengths_with,
};
pub use streaming::{SlimMerkleHasher, byte_list_root_streaming, byte_lists_root_streaming};

use std::sync::Once;

/// Length of a SHA256 digest, and of an SSZ chunk.
pub const HASH_LEN: usize = 32;

/// Length of the pair of chunks that hash to one parent node.
pub const CHUNK_PAIR_LEN: usize = 2 * HASH_LEN;

static INIT: Once = Once::new();

/// Point `hashtree` at the fastest SHA256 implementation for this CPU.
///
/// Calling this is optional: `hashtree` detects the CPU on its first hash. We do it behind a
/// `Once` anyway because that first-hash detection is not thread safe.
pub fn init() {
    INIT.call_once(|| {
        hashtree_rs::init();
    });
}

/// Check that the buffers are big enough for `count` blocks, and report how many to hash.
fn check_pair_buffers(output: &[u8], input: &[u8], count: usize) -> Result<(), Error> {
    let required_input = count
        .checked_mul(CHUNK_PAIR_LEN)
        .ok_or(Error::CountOverflow { count })?;
    let required_output = count
        .checked_mul(HASH_LEN)
        .ok_or(Error::CountOverflow { count })?;

    if input.len() < required_input {
        return Err(Error::InputTooShort {
            required: required_input,
            actual: input.len(),
        });
    }
    if output.len() < required_output {
        return Err(Error::OutputTooShort {
            required: required_output,
            actual: output.len(),
        });
    }

    Ok(())
}

/// The primitive a merkleizer folds each level of the tree with.
///
/// Two implementations, so the cost of reorganising the merkleization can be told apart from the
/// cost of the hash itself. The level-order rewrite in this crate and the switch to `hashtree` are
/// independent changes, and they do not contribute equally.
pub trait PairHasher {
    /// Hash `count` blocks of 64 bytes from `input` into `count` digests of 32 bytes in `output`.
    ///
    /// `output` and `input` must not overlap.
    fn hash_pairs(output: &mut [u8], input: &[u8], count: usize) -> Result<(), Error>;
}

/// `hashtree`'s batched SHA256, several blocks per call across SIMD lanes.
pub struct Hashtree;

impl PairHasher for Hashtree {
    fn hash_pairs(output: &mut [u8], input: &[u8], count: usize) -> Result<(), Error> {
        check_pair_buffers(output, input, count)?;

        // `hashtree` dereferences both pointers even when `count == 0` on some implementations,
        // and an empty `Vec` has a dangling pointer, so skip the call entirely.
        if count == 0 {
            return Ok(());
        }

        init();
        hashtree_rs::hash(output, input, count);

        Ok(())
    }
}

/// The SHA256 Lighthouse hashes with today, one 64 byte block per call.
///
/// Pairs with the same level-order merkleization as [`Hashtree`], so benchmarking the two against
/// each other isolates what the `hashtree` library itself is worth.
pub struct EthereumHashing;

impl PairHasher for EthereumHashing {
    fn hash_pairs(output: &mut [u8], input: &[u8], count: usize) -> Result<(), Error> {
        check_pair_buffers(output, input, count)?;

        for i in 0..count {
            let digest =
                ethereum_hashing::hash_fixed(&input[i * CHUNK_PAIR_LEN..][..CHUNK_PAIR_LEN]);
            output[i * HASH_LEN..][..HASH_LEN].copy_from_slice(&digest);
        }

        Ok(())
    }
}

/// Hash `count` blocks of 64 bytes from `input` into `count` digests of 32 bytes in `output`.
///
/// This is the whole of the `hashtree` API. `output` and `input` must not overlap.
pub fn hash_pairs(output: &mut [u8], input: &[u8], count: usize) -> Result<(), Error> {
    Hashtree::hash_pairs(output, input, count)
}
