use crate::{CHUNK_PAIR_LEN, HASH_LEN, Hashtree, PairHasher};
use ethereum_hashing::{ZERO_HASHES, ZERO_HASHES_MAX_INDEX};
use tree_hash::Hash256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A chunk buffer was not a whole number of 32 byte chunks.
    NotChunkAligned { len: usize },
    /// A tree of `depth` levels cannot hold `leaves` leaves.
    TooManyLeaves { leaves: usize, depth: usize },
    /// `depth` is beyond the cached zero hashes, so the tree is deeper than SSZ allows.
    DepthTooLarge { depth: usize },
    /// The chunk buffer does not match the sum of the per-tree leaf counts.
    LeafCountMismatch { expected: usize, actual: usize },
    /// The number of blocks to hash overflowed `usize`.
    CountOverflow { count: usize },
    /// The buffer handed to `hashtree` was too short for the requested block count.
    InputTooShort { required: usize, actual: usize },
    /// The buffer handed to `hashtree` was too short for the requested digest count.
    OutputTooShort { required: usize, actual: usize },
}

/// The root of a subtree of `depth` levels whose leaves are all zero.
fn zero_hash(depth: usize) -> Result<&'static [u8; HASH_LEN], Error> {
    ZERO_HASHES.get(depth).ok_or(Error::DepthTooLarge { depth })
}

/// Returns an error unless `leaves` fits in a tree of `depth` levels.
fn check_capacity(leaves: usize, depth: usize) -> Result<(), Error> {
    if depth > ZERO_HASHES_MAX_INDEX {
        return Err(Error::DepthTooLarge { depth });
    }
    if leaves > 1usize << depth {
        return Err(Error::TooManyLeaves { leaves, depth });
    }
    Ok(())
}

/// Merkleize `chunks` into the root of a tree with `1 << depth` leaves.
///
/// Leaves that `chunks` does not provide are assumed to be zero. This computes the same root as
/// `tree_hash::merkle_root(chunks, 1 << depth)`, but hashes each level of the tree in one batched
/// `hashtree` call instead of one 64 byte block at a time.
///
/// A single tree only has a wide level near the leaves, so the win here is limited to lists that
/// are actually long. Use [`merkleize_forest`] when there are many trees to hash.
pub fn merkleize_chunks(chunks: &[u8], depth: usize) -> Result<Hash256, Error> {
    merkleize_chunks_with::<Hashtree>(chunks, depth)
}

/// [`merkleize_chunks`] over an explicit hash primitive.
pub fn merkleize_chunks_with<H: PairHasher>(chunks: &[u8], depth: usize) -> Result<Hash256, Error> {
    if !chunks.len().is_multiple_of(HASH_LEN) {
        return Err(Error::NotChunkAligned { len: chunks.len() });
    }
    let leaves = chunks.len() / HASH_LEN;
    check_capacity(leaves, depth)?;

    if leaves == 0 {
        return Ok(Hash256::from(*zero_hash(depth)?));
    }
    if depth == 0 {
        return Ok(Hash256::from_slice(&chunks[..HASH_LEN]));
    }

    // `cur` holds the current level, padded to an even number of chunks so that every chunk has a
    // sibling. `next` is scratch for the level above.
    let mut cur = Vec::with_capacity(chunks.len() + HASH_LEN);
    cur.extend_from_slice(chunks);
    let mut next = Vec::with_capacity(chunks.len().div_ceil(2));
    let mut count = leaves;

    for level in 0..depth {
        if !count.is_multiple_of(2) {
            cur.extend_from_slice(zero_hash(level)?);
            count += 1;
        }

        let pairs = count / 2;
        next.clear();
        next.resize(pairs * HASH_LEN, 0);
        H::hash_pairs(&mut next, &cur, pairs)?;

        std::mem::swap(&mut cur, &mut next);
        count = pairs;
    }

    Ok(Hash256::from_slice(&cur[..HASH_LEN]))
}

/// Merkleize many trees at once, hashing each level of every tree in a single batched call.
///
/// `chunks` is the concatenated leaves of every tree in order, and `leaf_counts[i]` is how many of
/// those 32 byte leaves belong to tree `i`. Every tree is merkleized to `depth` levels, so the
/// returned roots line up with `leaf_counts`. Trees with no leaves get the zero root for `depth`.
///
/// This is the shape that pays for a list of byte lists such as `Transactions`. Each element is
/// merkleized in a tree deep enough for `MaxBytesPerTransaction`, so a 500 byte transaction has 16
/// chunks of real data under 21 levels of zero padding, and it is the padding that dominates.
/// Hashing all the elements in lockstep turns each of those levels into one wide call.
pub fn merkleize_forest(
    chunks: &[u8],
    leaf_counts: &[usize],
    depth: usize,
) -> Result<Vec<Hash256>, Error> {
    merkleize_forest_with::<Hashtree>(chunks, leaf_counts, depth)
}

/// [`merkleize_forest`] over an explicit hash primitive.
pub fn merkleize_forest_with<H: PairHasher>(
    chunks: &[u8],
    leaf_counts: &[usize],
    depth: usize,
) -> Result<Vec<Hash256>, Error> {
    if !chunks.len().is_multiple_of(HASH_LEN) {
        return Err(Error::NotChunkAligned { len: chunks.len() });
    }

    let mut expected_chunks = 0usize;
    for &count in leaf_counts {
        check_capacity(count, depth)?;
        expected_chunks = expected_chunks
            .checked_add(count)
            .ok_or(Error::CountOverflow { count })?;
    }
    let expected_bytes = expected_chunks
        .checked_mul(HASH_LEN)
        .ok_or(Error::CountOverflow {
            count: expected_chunks,
        })?;
    if expected_bytes != chunks.len() {
        return Err(Error::LeafCountMismatch {
            expected: expected_bytes,
            actual: chunks.len(),
        });
    }

    let mut roots = vec![Hash256::from(*zero_hash(depth)?); leaf_counts.len()];

    // Empty trees have a known root and no leaves in `chunks`, so drop them from the working set
    // rather than folding zeros up through every level.
    let live: Vec<usize> = leaf_counts
        .iter()
        .enumerate()
        .filter(|&(_, &count)| count > 0)
        .map(|(i, _)| i)
        .collect();
    if live.is_empty() {
        return Ok(roots);
    }
    let mut counts: Vec<usize> = live.iter().map(|&i| leaf_counts[i]).collect();

    // `padded` is every live tree's current level concatenated, each padded to an even number of
    // chunks. `prev` and `out` alternate as the unpadded output of the last and next level.
    let mut padded = Vec::with_capacity(chunks.len() + live.len() * HASH_LEN);
    let mut prev: Vec<u8> = Vec::new();
    let mut out: Vec<u8> = Vec::new();

    for level in 0..depth {
        let zero = zero_hash(level)?;
        {
            let cur: &[u8] = if level == 0 { chunks } else { &prev };
            padded.clear();
            let mut offset = 0;
            for &count in &counts {
                padded.extend_from_slice(&cur[offset..offset + count * HASH_LEN]);
                if !count.is_multiple_of(2) {
                    padded.extend_from_slice(zero);
                }
                offset += count * HASH_LEN;
            }
        }

        let pairs = padded.len() / CHUNK_PAIR_LEN;
        out.clear();
        out.resize(pairs * HASH_LEN, 0);
        H::hash_pairs(&mut out, &padded, pairs)?;

        for count in counts.iter_mut() {
            *count = count.div_ceil(2);
        }
        std::mem::swap(&mut prev, &mut out);
    }

    // `check_capacity` guarantees every tree is down to a single node by now.
    let final_level: &[u8] = if depth == 0 { chunks } else { &prev };
    for (slot, &index) in live.iter().enumerate() {
        let start = slot * HASH_LEN;
        roots[index] = Hash256::from_slice(&final_level[start..start + HASH_LEN]);
    }

    Ok(roots)
}

/// Mix each root with its list length in place, batching the hashes into one call.
///
/// This is `tree_hash::mix_in_length` applied to every element of a list of lists at once. There
/// is one such hash per element and they are all independent, so they may as well share the SIMD
/// lanes.
pub fn mix_in_lengths(roots: &mut [Hash256], lengths: &[usize]) -> Result<(), Error> {
    mix_in_lengths_with::<Hashtree>(roots, lengths)
}

/// [`mix_in_lengths`] over an explicit hash primitive.
pub fn mix_in_lengths_with<H: PairHasher>(
    roots: &mut [Hash256],
    lengths: &[usize],
) -> Result<(), Error> {
    if roots.len() != lengths.len() {
        return Err(Error::LeafCountMismatch {
            expected: roots.len(),
            actual: lengths.len(),
        });
    }
    if roots.is_empty() {
        return Ok(());
    }

    let mut input = Vec::with_capacity(roots.len() * CHUNK_PAIR_LEN);
    for (root, length) in roots.iter().zip(lengths) {
        input.extend_from_slice(root.as_slice());
        let mut length_chunk = [0u8; HASH_LEN];
        length_chunk[..size_of::<usize>()].copy_from_slice(&length.to_le_bytes());
        input.extend_from_slice(&length_chunk);
    }

    let mut output = vec![0u8; roots.len() * HASH_LEN];
    H::hash_pairs(&mut output, &input, roots.len())?;

    for (i, root) in roots.iter_mut().enumerate() {
        *root = Hash256::from_slice(&output[i * HASH_LEN..(i + 1) * HASH_LEN]);
    }

    Ok(())
}
