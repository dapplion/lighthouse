//! Every root computed by this crate must equal the one `tree_hash`/`ssz_types` compute today.

use hashtree_hasher::{
    Error, EthereumHashing, Hashtree, SlimMerkleHasher, byte_list_root_streaming,
    byte_list_tree_hash_root, byte_lists_root_streaming, byte_lists_tree_hash_root,
    depth_for_leaves, merkleize_chunks, merkleize_forest, mix_in_lengths,
    variable_list_tree_hash_root, vec_tree_hash_root,
};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use ssz_types::{FixedVector, VariableList, typenum};
use tree_hash::{Hash256, TreeHash};
use types::{EthSpec, MainnetEthSpec, Transaction, Transactions};

type E = MainnetEthSpec;

fn rng() -> XorShiftRng {
    XorShiftRng::from_seed([42; 16])
}

fn random_bytes(rng: &mut XorShiftRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.random()).collect()
}

#[test]
fn merkleize_chunks_matches_tree_hash() {
    let mut rng = rng();

    for chunks in 0..40usize {
        let bytes = random_bytes(&mut rng, chunks * 32);

        for depth in depth_for_leaves(chunks.max(1))..=12 {
            let expected = tree_hash::merkle_root(&bytes, 1 << depth);
            let actual = merkleize_chunks(&bytes, depth).unwrap();
            assert_eq!(actual, expected, "chunks {chunks}, depth {depth}");
        }
    }
}

#[test]
fn merkleize_chunks_matches_tree_hash_at_ssz_depths() {
    let mut rng = rng();

    // The depth a `Transaction` is hashed at on mainnet.
    let depth = depth_for_leaves(E::max_bytes_per_transaction().div_ceil(32));
    assert_eq!(depth, 25);

    for chunks in [0, 1, 2, 3, 17, 64, 100] {
        let bytes = random_bytes(&mut rng, chunks * 32);
        assert_eq!(
            merkleize_chunks(&bytes, depth).unwrap(),
            tree_hash::merkle_root(&bytes, 1 << depth),
            "chunks {chunks}"
        );
    }
}

#[test]
fn merkleize_forest_matches_per_tree_merkleize() {
    let mut rng = rng();

    for depth in [0, 1, 2, 5, 25] {
        let max_chunks = 1usize << depth.min(6);
        let counts: Vec<usize> = (0..17).map(|_| rng.random_range(0..=max_chunks)).collect();

        let mut chunks = Vec::new();
        for &count in &counts {
            chunks.extend_from_slice(&random_bytes(&mut rng, count * 32));
        }

        let roots = merkleize_forest(&chunks, &counts, depth).unwrap();

        let mut offset = 0;
        for (i, &count) in counts.iter().enumerate() {
            let tree = &chunks[offset..offset + count * 32];
            assert_eq!(
                roots[i],
                merkleize_chunks(tree, depth).unwrap(),
                "depth {depth}, tree {i} with {count} chunks"
            );
            offset += count * 32;
        }
    }
}

#[test]
fn merkleize_forest_handles_empty_input() {
    assert_eq!(
        merkleize_forest(&[], &[], 5).unwrap(),
        Vec::<Hash256>::new()
    );
    assert_eq!(
        merkleize_forest(&[], &[0, 0, 0], 5).unwrap(),
        vec![merkleize_chunks(&[], 5).unwrap(); 3]
    );
}

#[test]
fn mix_in_lengths_matches_tree_hash() {
    let mut rng = rng();

    let mut roots: Vec<Hash256> = (0..9)
        .map(|_| Hash256::from_slice(&random_bytes(&mut rng, 32)))
        .collect();
    let lengths: Vec<usize> = (0..9).map(|_| rng.random_range(0..100_000)).collect();

    let expected: Vec<Hash256> = roots
        .iter()
        .zip(&lengths)
        .map(|(root, &length)| tree_hash::mix_in_length(root, length))
        .collect();

    mix_in_lengths(&mut roots, &lengths).unwrap();

    assert_eq!(roots, expected);
}

#[test]
fn vec_tree_hash_root_matches_ssz_types() {
    let mut rng = rng();

    // Basic elements, packed several to a chunk.
    for len in [0, 1, 3, 4, 5, 31, 32, 33, 100] {
        let values: Vec<u64> = (0..len).map(|_| rng.random()).collect();

        let list = VariableList::<u64, typenum::U1024>::new(values.clone()).unwrap();
        assert_eq!(
            variable_list_tree_hash_root(&values, 1024).unwrap(),
            list.tree_hash_root(),
            "VariableList<u64, U1024> of len {len}"
        );
    }

    // A fixed vector has no length mix-in.
    let values: Vec<u64> = (0..64).map(|_| rng.random()).collect();
    let vector = FixedVector::<u64, typenum::U64>::new(values.clone()).unwrap();
    assert_eq!(
        vec_tree_hash_root(&values, 64).unwrap(),
        vector.tree_hash_root()
    );

    // Composite elements, one chunk each.
    for len in [0, 1, 2, 7, 40] {
        let values: Vec<Hash256> = (0..len)
            .map(|_| Hash256::from_slice(&random_bytes(&mut rng, 32)))
            .collect();

        let list = VariableList::<Hash256, typenum::U128>::new(values.clone()).unwrap();
        assert_eq!(
            variable_list_tree_hash_root(&values, 128).unwrap(),
            list.tree_hash_root(),
            "VariableList<Hash256, U128> of len {len}"
        );
    }
}

#[test]
fn byte_list_tree_hash_root_matches_transaction() {
    let mut rng = rng();
    let max_bytes = E::max_bytes_per_transaction();

    for len in [0, 1, 31, 32, 33, 500, 4096, 100_000] {
        let bytes = random_bytes(&mut rng, len);

        let transaction =
            Transaction::<<E as EthSpec>::MaxBytesPerTransaction>::new(bytes.clone()).unwrap();

        assert_eq!(
            byte_list_tree_hash_root(&bytes, max_bytes).unwrap(),
            transaction.tree_hash_root(),
            "transaction of {len} bytes"
        );
    }
}

#[test]
fn byte_lists_tree_hash_root_matches_transactions() {
    let mut rng = rng();
    let max_bytes = E::max_bytes_per_transaction();
    let max_lists = E::max_transactions_per_payload();

    for count in [0, 1, 2, 3, 8, 33] {
        let payloads: Vec<Vec<u8>> = (0..count)
            .map(|i| random_bytes(&mut rng, if i % 5 == 0 { 0 } else { 1 + i * 137 }))
            .collect();

        let transactions = Transactions::<E>::new(
            payloads
                .iter()
                .map(|bytes| Transaction::new(bytes.clone()).unwrap())
                .collect(),
        )
        .unwrap();

        let slices: Vec<&[u8]> = payloads.iter().map(|bytes| bytes.as_slice()).collect();

        assert_eq!(
            byte_lists_tree_hash_root(&slices, max_bytes, max_lists).unwrap(),
            transactions.tree_hash_root(),
            "{count} transactions"
        );
    }
}

#[test]
fn slim_merkle_hasher_matches_tree_hash() {
    let mut rng = rng();

    for chunks in 0..40usize {
        let bytes = random_bytes(&mut rng, chunks * 32);

        for depth in depth_for_leaves(chunks.max(1))..=12 {
            let expected = tree_hash::merkle_root(&bytes, 1 << depth);

            let mut hasher = SlimMerkleHasher::<EthereumHashing>::with_leaves(1 << depth).unwrap();
            hasher.write(&bytes).unwrap();
            assert_eq!(
                hasher.finish().unwrap(),
                expected,
                "chunks {chunks}, depth {depth}"
            );
        }
    }
}

#[test]
fn slim_merkle_hasher_handles_partial_leaves() {
    let mut rng = rng();

    // Writes that do not land on a chunk boundary exercise the internal buffer.
    for len in [0, 1, 31, 33, 65, 500] {
        let bytes = random_bytes(&mut rng, len);
        let expected = tree_hash::merkle_root(&bytes, 1 << 6);

        for write_size in [1, 3, 32, 64] {
            let mut hasher = SlimMerkleHasher::<EthereumHashing>::with_leaves(1 << 6).unwrap();
            for piece in bytes.chunks(write_size) {
                hasher.write(piece).unwrap();
            }
            assert_eq!(
                hasher.finish().unwrap(),
                expected,
                "{len} bytes written {write_size} at a time"
            );
        }
    }
}

#[test]
fn streaming_helpers_match_transactions() {
    let mut rng = rng();
    let max_bytes = E::max_bytes_per_transaction();
    let max_lists = E::max_transactions_per_payload();

    for count in [0, 1, 2, 3, 8, 33] {
        let payloads: Vec<Vec<u8>> = (0..count)
            .map(|i| random_bytes(&mut rng, if i % 5 == 0 { 0 } else { 1 + i * 137 }))
            .collect();

        let transactions = Transactions::<E>::new(
            payloads
                .iter()
                .map(|bytes| Transaction::new(bytes.clone()).unwrap())
                .collect(),
        )
        .unwrap();

        let slices: Vec<&[u8]> = payloads.iter().map(|bytes| bytes.as_slice()).collect();
        let expected = transactions.tree_hash_root();

        assert_eq!(
            byte_lists_root_streaming::<EthereumHashing>(&slices, max_bytes, max_lists).unwrap(),
            expected,
            "{count} transactions"
        );
        assert_eq!(
            byte_lists_root_streaming::<Hashtree>(&slices, max_bytes, max_lists).unwrap(),
            expected,
            "{count} transactions"
        );

        for bytes in &payloads {
            assert_eq!(
                byte_list_root_streaming::<EthereumHashing>(bytes, max_bytes).unwrap(),
                byte_list_tree_hash_root(bytes, max_bytes).unwrap()
            );
        }
    }
}

#[test]
fn rejects_oversized_and_misaligned_input() {
    assert_eq!(
        merkleize_chunks(&[0; 33], 4),
        Err(Error::NotChunkAligned { len: 33 })
    );
    assert_eq!(
        merkleize_chunks(&[0; 32 * 5], 2),
        Err(Error::TooManyLeaves {
            leaves: 5,
            depth: 2
        })
    );
    assert_eq!(
        merkleize_chunks(&[0; 32], 64),
        Err(Error::DepthTooLarge { depth: 64 })
    );
    assert_eq!(
        merkleize_forest(&[0; 32], &[2], 4),
        Err(Error::LeafCountMismatch {
            expected: 64,
            actual: 32
        })
    );
}
