use crate::merkleize::{Error, merkleize_chunks_with, merkleize_forest_with, mix_in_lengths_with};
use crate::{HASH_LEN, Hashtree, PairHasher};
use tree_hash::{Hash256, TreeHash, TreeHashType, mix_in_length};

/// The number of tree levels needed to hold `leaves` leaves.
///
/// Matches the depth `tree_hash::MerkleHasher::with_leaves` would pick, counting levels *above*
/// the leaves rather than layers.
pub fn depth_for_leaves(leaves: usize) -> usize {
    leaves.next_power_of_two().trailing_zeros() as usize
}

/// Pad `chunks` up to the next 32 byte boundary with zeros.
fn pad_to_chunk(chunks: &mut Vec<u8>) {
    let remainder = chunks.len() % HASH_LEN;
    if remainder != 0 {
        chunks.resize(chunks.len() + HASH_LEN - remainder, 0);
    }
}

/// The `hashtree` equivalent of `ssz_types::tree_hash::vec_tree_hash_root`.
///
/// `max_leaves` is the list's or vector's declared maximum length, exactly as `ssz_types` passes
/// it. Note that the tree depth comes from that maximum and not from `vec.len()`, so a short list
/// of a long-capacity type still pays for the full depth.
///
/// Elements that are not basic types are rooted one at a time through their own `TreeHash` impl,
/// so this batches only the list's own tree. For a list of byte lists, prefer
/// [`byte_lists_tree_hash_root`], which batches the elements too.
pub fn vec_tree_hash_root<T: TreeHash>(vec: &[T], max_leaves: usize) -> Result<Hash256, Error> {
    vec_tree_hash_root_with::<T, Hashtree>(vec, max_leaves)
}

/// [`vec_tree_hash_root`] over an explicit hash primitive.
pub fn vec_tree_hash_root_with<T: TreeHash, H: PairHasher>(
    vec: &[T],
    max_leaves: usize,
) -> Result<Hash256, Error> {
    let leaves = match T::tree_hash_type() {
        TreeHashType::Basic => max_leaves.div_ceil(T::tree_hash_packing_factor()),
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => max_leaves,
    };

    let mut chunks = Vec::with_capacity(vec.len() * HASH_LEN);
    match T::tree_hash_type() {
        TreeHashType::Basic => {
            for item in vec {
                chunks.extend_from_slice(&item.tree_hash_packed_encoding());
            }
            pad_to_chunk(&mut chunks);
        }
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            for item in vec {
                chunks.extend_from_slice(item.tree_hash_root().as_slice());
            }
        }
    }

    merkleize_chunks_with::<H>(&chunks, depth_for_leaves(leaves))
}

/// The `hashtree` equivalent of `<VariableList<T, N> as TreeHash>::tree_hash_root`.
pub fn variable_list_tree_hash_root<T: TreeHash>(
    vec: &[T],
    max_leaves: usize,
) -> Result<Hash256, Error> {
    variable_list_tree_hash_root_with::<T, Hashtree>(vec, max_leaves)
}

/// [`variable_list_tree_hash_root`] over an explicit hash primitive.
pub fn variable_list_tree_hash_root_with<T: TreeHash, H: PairHasher>(
    vec: &[T],
    max_leaves: usize,
) -> Result<Hash256, Error> {
    let root = vec_tree_hash_root_with::<T, H>(vec, max_leaves)?;
    Ok(mix_in_length(&root, vec.len()))
}

/// The root of a single byte list, e.g. one `Transaction`.
///
/// `max_bytes` is the list's declared maximum length in bytes.
pub fn byte_list_tree_hash_root(bytes: &[u8], max_bytes: usize) -> Result<Hash256, Error> {
    byte_list_tree_hash_root_with::<Hashtree>(bytes, max_bytes)
}

/// [`byte_list_tree_hash_root`] over an explicit hash primitive.
pub fn byte_list_tree_hash_root_with<H: PairHasher>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Hash256, Error> {
    let depth = depth_for_leaves(max_bytes.div_ceil(HASH_LEN));

    let mut chunks = Vec::with_capacity(bytes.len().next_multiple_of(HASH_LEN));
    chunks.extend_from_slice(bytes);
    pad_to_chunk(&mut chunks);

    let root = merkleize_chunks_with::<H>(&chunks, depth)?;
    Ok(mix_in_length(&root, bytes.len()))
}

/// The root of a list of byte lists, e.g. `Transactions`.
///
/// `max_bytes_per_list` and `max_lists` are the inner and outer declared maximum lengths, so for
/// `Transactions<E>` they are `E::MaxBytesPerTransaction` and `E::MaxTransactionsPerPayload`.
///
/// Every element is merkleized in lockstep by [`merkleize_forest`], which is what makes this
/// worth doing: the tree over a transaction is 25 levels deep no matter how small the transaction
/// is, and hashing one level of every transaction at once fills the SIMD lanes that a per-element
/// hasher leaves idle.
pub fn byte_lists_tree_hash_root(
    lists: &[&[u8]],
    max_bytes_per_list: usize,
    max_lists: usize,
) -> Result<Hash256, Error> {
    byte_lists_tree_hash_root_with::<Hashtree>(lists, max_bytes_per_list, max_lists)
}

/// [`byte_lists_tree_hash_root`] over an explicit hash primitive.
pub fn byte_lists_tree_hash_root_with<H: PairHasher>(
    lists: &[&[u8]],
    max_bytes_per_list: usize,
    max_lists: usize,
) -> Result<Hash256, Error> {
    let inner_depth = depth_for_leaves(max_bytes_per_list.div_ceil(HASH_LEN));

    let total_chunks: usize = lists.iter().map(|list| list.len().div_ceil(HASH_LEN)).sum();
    let mut chunks = Vec::with_capacity(total_chunks * HASH_LEN);
    let mut leaf_counts = Vec::with_capacity(lists.len());
    for list in lists {
        chunks.extend_from_slice(list);
        pad_to_chunk(&mut chunks);
        leaf_counts.push(list.len().div_ceil(HASH_LEN));
    }

    let mut roots = merkleize_forest_with::<H>(&chunks, &leaf_counts, inner_depth)?;

    let lengths: Vec<usize> = lists.iter().map(|list| list.len()).collect();
    mix_in_lengths_with::<H>(&mut roots, &lengths)?;

    let mut root_chunks = Vec::with_capacity(roots.len() * HASH_LEN);
    for root in &roots {
        root_chunks.extend_from_slice(root.as_slice());
    }

    let root = merkleize_chunks_with::<H>(&root_chunks, depth_for_leaves(max_lists))?;
    Ok(mix_in_length(&root, lists.len()))
}
