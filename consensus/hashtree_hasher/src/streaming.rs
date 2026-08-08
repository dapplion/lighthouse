//! `tree_hash::MerkleHasher` with one thing changed, to find the smallest diff that is worth it.
//!
//! The level-order merkleizer in [`crate::merkleize`] is a rewrite: it buffers the whole level and
//! needs all the leaves up front. This module instead keeps `MerkleHasher`'s streaming algorithm
//! exactly as it is — same half-node stack, same zero-hash fill, same public shape — and changes
//! only what a pending node stores.
//!
//! `tree_hash` parks a live SHA256 context in every half-finished node, so `HalfNode` is 232 bytes
//! (`tree_hash`'s own `context_size` test asserts that number). Since a node's left child is
//! always a finished 32 byte digest, the context buys nothing: the node can hold the 32 bytes and
//! hash once, when the right child arrives. That takes `HalfNode` to 40 bytes and is about a
//! twenty line diff to `merkle_hasher.rs`, with no API change and no new dependency.
//!
//! Whether that is enough is an empirical question, which is why this exists. See the
//! `slim_stream` arm of `benches/hashing.rs`.

use crate::merkleize::Error;
use crate::{CHUNK_PAIR_LEN, HASH_LEN, PairHasher, list::depth_for_leaves};
use ethereum_hashing::{ZERO_HASHES, ZERO_HASHES_MAX_INDEX};
use smallvec::{SmallVec, smallvec};
use std::marker::PhantomData;
use tree_hash::{Hash256, mix_in_length};

/// A node whose left child is known and whose right child has not arrived yet.
///
/// The whole point: 40 bytes here, against 232 in `tree_hash`.
struct HalfNode {
    left: [u8; HASH_LEN],
    /// Tree id of the node, where the root is 1 and ids grow down and to the right.
    id: usize,
}

/// Returns the parent of node `i`.
fn get_parent(i: usize) -> usize {
    i / 2
}

/// Depth of node `i`, where the root (`i == 1`) is at depth 0. A logic error for `i == 0`.
fn get_depth(i: usize) -> usize {
    (usize::BITS as usize)
        .saturating_sub(i.leading_zeros() as usize)
        .saturating_sub(1)
}

/// `tree_hash::MerkleHasher`'s algorithm with a 40 byte `HalfNode` instead of a 232 byte one.
///
/// Generic over the hash primitive so the bookkeeping change can be measured on its own: pair it
/// with [`crate::EthereumHashing`] and the hash function is identical to `tree_hash`'s, leaving
/// the node representation as the only difference.
pub struct SlimMerkleHasher<H> {
    /// Nodes that are waiting on a right child.
    half_nodes: SmallVec<[HalfNode; 8]>,
    /// Number of layers in the tree. A single-leaf tree has a depth of 1.
    depth: usize,
    /// The next leaf we expect to process.
    next_leaf: usize,
    /// Bytes waiting to fill out a leaf.
    buffer: SmallVec<[u8; HASH_LEN]>,
    /// Set once the root is known.
    root: Option<Hash256>,
    _phantom: PhantomData<H>,
}

impl<H: PairHasher> SlimMerkleHasher<H> {
    /// A hasher for a tree with `num_leaves` leaves, rounded up to the next power of two.
    pub fn with_leaves(num_leaves: usize) -> Result<Self, Error> {
        Self::with_depth(depth_for_leaves(num_leaves) + 1)
    }

    /// A hasher for a tree of `depth` layers, holding `1 << (depth - 1)` leaves.
    fn with_depth(depth: usize) -> Result<Self, Error> {
        if depth == 0 || depth > ZERO_HASHES_MAX_INDEX {
            return Err(Error::DepthTooLarge { depth });
        }

        Ok(Self {
            half_nodes: SmallVec::with_capacity(depth - 1),
            depth,
            next_leaf: 1 << (depth - 1),
            buffer: SmallVec::with_capacity(HASH_LEN),
            root: None,
            _phantom: PhantomData,
        })
    }

    /// Hash a pair of chunks into their parent.
    fn hash_pair(left: &[u8; HASH_LEN], right: &[u8]) -> Result<[u8; HASH_LEN], Error> {
        let mut block = [0u8; CHUNK_PAIR_LEN];
        block[..HASH_LEN].copy_from_slice(left);
        block[HASH_LEN..].copy_from_slice(right);

        let mut parent = [0u8; HASH_LEN];
        H::hash_pairs(&mut parent, &block, 1)?;

        Ok(parent)
    }

    /// The padding node for the subtree hanging below node `id`.
    fn zero_hash(&self, id: usize) -> Result<&'static [u8; HASH_LEN], Error> {
        let height = self
            .depth
            .checked_sub(get_depth(id).saturating_add(1))
            .ok_or(Error::DepthTooLarge { depth: self.depth })?;

        ZERO_HASHES
            .get(height)
            .ok_or(Error::DepthTooLarge { depth: height })
    }

    /// Write some bytes to the hasher, splitting them into leaves as they fill up.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut ptr = 0;
        while ptr <= bytes.len() {
            let slice = &bytes[ptr..std::cmp::min(bytes.len(), ptr + HASH_LEN)];

            if self.buffer.is_empty() && slice.len() == HASH_LEN {
                self.process_leaf(slice)?;
                ptr += HASH_LEN;
            } else if self.buffer.len() + slice.len() < HASH_LEN {
                self.buffer.extend_from_slice(slice);
                ptr += HASH_LEN;
            } else {
                let buffered = self.buffer.len();
                let required = HASH_LEN - buffered;

                let mut leaf = [0; HASH_LEN];
                leaf[..buffered].copy_from_slice(&self.buffer);
                leaf[buffered..].copy_from_slice(&slice[0..required]);

                self.process_leaf(&leaf)?;
                self.buffer = smallvec![];

                ptr += required;
            }
        }

        Ok(())
    }

    /// Fold the next leaf into the tree.
    fn process_leaf(&mut self, leaf: &[u8]) -> Result<(), Error> {
        if self.next_leaf >= 1 << self.depth {
            return Err(Error::TooManyLeaves {
                leaves: self.next_leaf,
                depth: self.depth,
            });
        } else if self.next_leaf == 1 {
            // A tree of one layer has the first leaf as its root.
            self.root = Some(Hash256::from_slice(leaf));
        } else if self.next_leaf.is_multiple_of(2) {
            self.process_left_node(self.next_leaf, leaf);
        } else {
            self.process_right_node(self.next_leaf, leaf)?;
        }

        self.next_leaf += 1;

        Ok(())
    }

    /// The root, completing the tree with zero hashes if not every leaf was supplied.
    pub fn finish(mut self) -> Result<Hash256, Error> {
        if !self.buffer.is_empty() {
            let mut leaf = [0; HASH_LEN];
            leaf[..self.buffer.len()].copy_from_slice(&self.buffer);
            self.process_leaf(&leaf)?;
        }

        loop {
            if let Some(root) = self.root {
                break Ok(root);
            } else if let Some(node) = self.half_nodes.last() {
                let right_child = node.id * 2 + 1;
                let zero = *self.zero_hash(right_child)?;
                self.process_right_node(right_child, &zero)?;
            } else if self.next_leaf == 1 {
                // Depth of one and nothing supplied.
                break Ok(Hash256::ZERO);
            } else {
                // No half nodes and a tree of two or more layers means nothing was supplied at
                // all. Seed the leftmost leaf and every later step takes the branch above.
                let zero = *self.zero_hash(self.next_leaf)?;
                self.process_left_node(self.next_leaf, &zero);
            }
        }
    }

    /// Park a node that will be some parent's left child.
    fn process_left_node(&mut self, id: usize, preimage: &[u8]) {
        let mut left = [0u8; HASH_LEN];
        left.copy_from_slice(preimage);

        self.half_nodes.push(HalfNode {
            left,
            id: get_parent(id),
        });
    }

    /// Complete a node as some parent's right child, then collapse as far up the tree as possible.
    fn process_right_node(&mut self, id: usize, preimage: &[u8]) -> Result<(), Error> {
        let mut parent = get_parent(id);
        let mut digest = [0u8; HASH_LEN];
        digest.copy_from_slice(preimage);

        loop {
            match self.half_nodes.last() {
                Some(node) if node.id == parent => {
                    let node = self.half_nodes.pop().ok_or(Error::TooManyLeaves {
                        leaves: 0,
                        depth: 0,
                    })?;
                    digest = Self::hash_pair(&node.left, &digest)?;

                    if parent == 1 {
                        self.root = Some(Hash256::from_slice(&digest));
                        break Ok(());
                    }
                    parent = get_parent(parent);
                }
                _ => {
                    self.half_nodes.push(HalfNode {
                        left: digest,
                        id: parent,
                    });
                    break Ok(());
                }
            }
        }
    }
}

/// A single byte list's root, e.g. one `Transaction`, via [`SlimMerkleHasher`].
pub fn byte_list_root_streaming<H: PairHasher>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Hash256, Error> {
    let mut hasher = SlimMerkleHasher::<H>::with_leaves(max_bytes.div_ceil(HASH_LEN))?;
    hasher.write(bytes)?;
    let root = hasher.finish()?;

    Ok(mix_in_length(&root, bytes.len()))
}

/// A list of byte lists' root, e.g. `Transactions`, via [`SlimMerkleHasher`].
///
/// Mirrors what `ssz_types` does today: root each element on its own, then root the list of roots.
pub fn byte_lists_root_streaming<H: PairHasher>(
    lists: &[&[u8]],
    max_bytes_per_list: usize,
    max_lists: usize,
) -> Result<Hash256, Error> {
    let mut hasher = SlimMerkleHasher::<H>::with_leaves(max_lists)?;
    for list in lists {
        let root = byte_list_root_streaming::<H>(list, max_bytes_per_list)?;
        hasher.write(root.as_slice())?;
    }
    let root = hasher.finish()?;

    Ok(mix_in_length(&root, lists.len()))
}
