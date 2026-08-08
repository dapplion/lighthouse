//! What tree hashing a beacon block costs, and how much of it `hashtree` takes back.
//!
//! Four groups, from the primitive up to a whole block:
//!
//! * `sha256` — the raw batched primitive against `ethereum_hashing`, one 64 byte block at a time.
//!   This is the ceiling for everything below.
//! * `transaction` — the root of a single `Transaction`, which is dominated by the 25 levels of
//!   zero padding up to `MaxBytesPerTransaction` rather than by the transaction itself.
//! * `transactions` — the root of the whole `Transactions` list, where the padding of every
//!   element can be hashed in lockstep.
//! * `beacon_block` — `BeaconBlockFulu::tree_hash_root`, with the transactions list swapped for
//!   the batched path and every other field left on the standard one.
//!
//! The transaction groups have several arms, each adding one change to the one before it, so that
//! each gap prices exactly one thing. Everything below `hashtree` uses `ethereum_hashing`, so the
//! hash function only changes on the last step.
//!
//! * `tree_hash` — what Lighthouse does today, via `ssz_types`.
//! * `chunked_write` — `hash_vec`'s per-element loop kept intact, but buffering a 32 byte chunk
//!   before writing. Prices the `write` calls alone, without a bulk packing path.
//! * `bulk_write` — the unmodified `tree_hash::MerkleHasher`, but handed the whole byte slice in
//!   one `write` instead of one byte at a time. Prices `ssz_types::tree_hash::hash_vec`'s
//!   per-element loop over basic types, packing included.
//! * `slim_stream` — the same streaming algorithm with a 40 byte `HalfNode` instead of a 232 byte
//!   one. Prices parking a live SHA256 context in every pending node.
//! * `level_order` — the level-order rewrite in this crate. Prices abandoning the streaming shape.
//! * `hashtree` — the same rewrite on `hashtree`. Prices the library.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ethereum_hashing::hash_fixed;
use hashtree_hasher::{
    EthereumHashing, Hashtree, PairHasher, byte_list_root_streaming, byte_list_tree_hash_root_with,
    byte_lists_root_streaming, byte_lists_tree_hash_root_with, depth_for_leaves, hash_pairs,
    merkleize_chunks_with,
};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use smallvec::SmallVec;
use ssz_types::VariableList;
use std::hint::black_box;
use std::time::Duration;
use tree_hash::{Hash256, MerkleHasher, TreeHash, mix_in_length};
use types::{
    Address, BeaconBlockBodyFulu, BeaconBlockFulu, ChainSpec, EmptyBlock, EthSpec,
    ExecutionPayloadFulu, FullPayload, MainnetEthSpec, Transaction, Transactions, Withdrawal,
};

type E = MainnetEthSpec;

/// Transaction counts spanning an empty block up to a full mainnet one.
const TRANSACTION_COUNTS: [usize; 4] = [1, 16, 64, 256];

/// Single transaction sizes: a bare transfer, a swap, a contract deployment, a rollup batch.
const TRANSACTION_SIZES: [usize; 4] = [128, 512, 4096, 65_536];

/// Block counts for the raw SHA256 comparison.
const BLOCK_COUNTS: [usize; 5] = [1, 8, 64, 1024, 16_384];

fn rng() -> XorShiftRng {
    XorShiftRng::from_seed([7; 16])
}

fn random_bytes(rng: &mut XorShiftRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.random()).collect()
}

/// Transaction payloads with a size distribution close to a mainnet block: mostly transfers and
/// token calls, with a long tail of calldata-heavy rollup batches.
fn mainnet_like_transactions(rng: &mut XorShiftRng, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let len = match i % 20 {
                0..=9 => rng.random_range(110..250),
                10..=16 => rng.random_range(250..1_500),
                17 | 18 => rng.random_range(1_500..8_000),
                _ => rng.random_range(8_000..60_000),
            };
            random_bytes(rng, len)
        })
        .collect()
}

fn transactions_list(payloads: &[Vec<u8>]) -> Transactions<E> {
    Transactions::<E>::new(
        payloads
            .iter()
            .map(|bytes| Transaction::new(bytes.clone()).unwrap())
            .collect(),
    )
    .unwrap()
}

fn as_slices(payloads: &[Vec<u8>]) -> Vec<&[u8]> {
    payloads.iter().map(|bytes| bytes.as_slice()).collect()
}

/// A byte list's root via the *unmodified* `tree_hash::MerkleHasher`, writing the whole slice in
/// one call.
///
/// `ssz_types::tree_hash::hash_vec` does not do this. For a basic element type it loops over the
/// elements, so a `VariableList<u8, N>` is fed to the hasher one byte at a time, building a
/// `PackedEncoding` smallvec per byte. A 4 KiB transaction takes 4096 `write` calls to produce 146
/// hashes. This arm changes only that, so the gap to `tree_hash` is what bulk-writing is worth on
/// its own, with the hasher and the hash function both untouched.
fn byte_list_root_bulk_write(bytes: &[u8], max_bytes: usize) -> Hash256 {
    let mut hasher = MerkleHasher::with_leaves(max_bytes.div_ceil(32));
    hasher.write(bytes).unwrap();

    mix_in_length(&hasher.finish().unwrap(), bytes.len())
}

/// A byte list's root keeping `hash_vec`'s per-element loop, but buffering a chunk before writing.
///
/// This is the smallest possible version of the `bulk_write` change: it still builds a
/// `PackedEncoding` per element, so it needs no new trait method and no specialisation for byte
/// lists — just a 32 byte accumulator around the existing loop. The gap between this and
/// `bulk_write` is the part of the cost that only a bulk packing path can remove.
fn byte_list_root_chunked_write(bytes: &[u8], max_bytes: usize) -> Hash256 {
    let mut hasher = MerkleHasher::with_leaves(max_bytes.div_ceil(32));

    let mut chunk = SmallVec::<[u8; 32]>::new();
    for byte in bytes {
        chunk.extend_from_slice(&byte.tree_hash_packed_encoding());
        if chunk.len() >= 32 {
            hasher.write(&chunk).unwrap();
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        hasher.write(&chunk).unwrap();
    }

    mix_in_length(&hasher.finish().unwrap(), bytes.len())
}

/// A list of byte lists' root with the chunk-buffered inner loop.
fn byte_lists_root_chunked_write(lists: &[&[u8]], max_bytes: usize, max_lists: usize) -> Hash256 {
    let mut hasher = MerkleHasher::with_leaves(max_lists);
    for list in lists {
        hasher
            .write(byte_list_root_chunked_write(list, max_bytes).as_slice())
            .unwrap();
    }

    mix_in_length(&hasher.finish().unwrap(), lists.len())
}

/// A list of byte lists' root via the unmodified `MerkleHasher`, bulk-writing each element.
///
/// Only the inner lists change. `hash_vec` already writes composite elements a whole 32 byte root
/// at a time, so the outer list is untouched either way.
fn byte_lists_root_bulk_write(lists: &[&[u8]], max_bytes: usize, max_lists: usize) -> Hash256 {
    let mut hasher = MerkleHasher::with_leaves(max_lists);
    for list in lists {
        hasher
            .write(byte_list_root_bulk_write(list, max_bytes).as_slice())
            .unwrap();
    }

    mix_in_length(&hasher.finish().unwrap(), lists.len())
}

/// Merkleize a container's field roots, padding out to the next power of two as SSZ requires.
fn merkleize_field_roots<H: PairHasher>(roots: &[Hash256]) -> Hash256 {
    let mut chunks = Vec::with_capacity(roots.len() * 32);
    for root in roots {
        chunks.extend_from_slice(root.as_slice());
    }
    merkleize_chunks_with::<H>(&chunks, depth_for_leaves(roots.len())).unwrap()
}

/// The root of a Fulu execution payload with the transactions list on the batched path.
///
/// The field list must stay in SSZ order; the `assert_eq!` in `bench_beacon_block` is what keeps
/// it honest.
fn payload_root_batched<H: PairHasher>(payload: &ExecutionPayloadFulu<E>) -> Hash256 {
    let transactions = as_slices_of_list(&payload.transactions);
    let transactions_root = byte_lists_tree_hash_root_with::<H>(
        &transactions,
        E::max_bytes_per_transaction(),
        E::max_transactions_per_payload(),
    )
    .unwrap();

    merkleize_field_roots::<H>(&[
        payload.parent_hash.tree_hash_root(),
        payload.fee_recipient.tree_hash_root(),
        payload.state_root.tree_hash_root(),
        payload.receipts_root.tree_hash_root(),
        payload.logs_bloom.tree_hash_root(),
        payload.prev_randao.tree_hash_root(),
        payload.block_number.tree_hash_root(),
        payload.gas_limit.tree_hash_root(),
        payload.gas_used.tree_hash_root(),
        payload.timestamp.tree_hash_root(),
        payload.extra_data.tree_hash_root(),
        payload.base_fee_per_gas.tree_hash_root(),
        payload.block_hash.tree_hash_root(),
        transactions_root,
        payload.withdrawals.tree_hash_root(),
        payload.blob_gas_used.tree_hash_root(),
        payload.excess_blob_gas.tree_hash_root(),
    ])
}

fn as_slices_of_list(transactions: &Transactions<E>) -> Vec<&[u8]> {
    transactions
        .iter()
        .map(|transaction| transaction.as_ref())
        .collect()
}

fn body_root_batched<H: PairHasher>(body: &BeaconBlockBodyFulu<E, FullPayload<E>>) -> Hash256 {
    merkleize_field_roots::<H>(&[
        body.randao_reveal.tree_hash_root(),
        body.eth1_data.tree_hash_root(),
        body.graffiti.tree_hash_root(),
        body.proposer_slashings.tree_hash_root(),
        body.attester_slashings.tree_hash_root(),
        body.attestations.tree_hash_root(),
        body.deposits.tree_hash_root(),
        body.voluntary_exits.tree_hash_root(),
        body.sync_aggregate.tree_hash_root(),
        payload_root_batched::<H>(&body.execution_payload.execution_payload),
        body.bls_to_execution_changes.tree_hash_root(),
        body.blob_kzg_commitments.tree_hash_root(),
        body.execution_requests.tree_hash_root(),
    ])
}

fn block_root_batched<H: PairHasher>(block: &BeaconBlockFulu<E, FullPayload<E>>) -> Hash256 {
    merkleize_field_roots::<H>(&[
        block.slot.tree_hash_root(),
        block.proposer_index.tree_hash_root(),
        block.parent_root.tree_hash_root(),
        block.state_root.tree_hash_root(),
        body_root_batched::<H>(&block.body),
    ])
}

/// A Fulu block carrying `payloads` as its transactions, plus a full set of withdrawals.
///
/// Everything else is left empty, so the `beacon_block` group measures the transactions list
/// against a floor of near-free fields rather than against a fully populated body.
fn block_with_transactions(spec: &ChainSpec, payloads: &[Vec<u8>]) -> BeaconBlockFulu<E> {
    let mut block = BeaconBlockFulu::<E, FullPayload<E>>::empty(spec);
    let payload = &mut block.body.execution_payload.execution_payload;

    payload.transactions = transactions_list(payloads);
    payload.withdrawals = VariableList::new(
        (0..E::max_withdrawals_per_payload())
            .map(|i| Withdrawal {
                index: i as u64,
                validator_index: i as u64,
                address: Address::repeat_byte(i as u8),
                amount: 32_000_000_000,
            })
            .collect(),
    )
    .unwrap();

    block
}

fn bench_sha256(c: &mut Criterion) {
    let mut rng = rng();
    let mut group = c.benchmark_group("sha256");

    for count in BLOCK_COUNTS {
        let input = random_bytes(&mut rng, count * 64);
        let mut output = vec![0u8; count * 32];

        group.throughput(Throughput::Bytes((count * 64) as u64));

        group.bench_with_input(BenchmarkId::new("hashtree", count), &count, |b, &count| {
            b.iter(|| {
                hash_pairs(&mut output, &input, count).unwrap();
                black_box(&output);
            })
        });

        let mut output = vec![0u8; count * 32];
        group.bench_with_input(
            BenchmarkId::new("ethereum_hashing", count),
            &count,
            |b, &count| {
                b.iter(|| {
                    for i in 0..count {
                        let digest = hash_fixed(&input[i * 64..(i + 1) * 64]);
                        output[i * 32..(i + 1) * 32].copy_from_slice(&digest);
                    }
                    black_box(&output);
                })
            },
        );
    }

    group.finish();
}

fn bench_transaction(c: &mut Criterion) {
    let mut rng = rng();
    let max_bytes = E::max_bytes_per_transaction();
    let mut group = c.benchmark_group("transaction");

    for size in TRANSACTION_SIZES {
        let bytes = random_bytes(&mut rng, size);
        let transaction =
            Transaction::<<E as EthSpec>::MaxBytesPerTransaction>::new(bytes.clone()).unwrap();

        assert_eq!(
            byte_list_tree_hash_root_with::<Hashtree>(&bytes, max_bytes).unwrap(),
            transaction.tree_hash_root()
        );
        assert_eq!(
            byte_list_tree_hash_root_with::<EthereumHashing>(&bytes, max_bytes).unwrap(),
            transaction.tree_hash_root()
        );

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("tree_hash", size),
            &transaction,
            |b, tx| b.iter(|| black_box(tx.tree_hash_root())),
        );

        group.bench_with_input(
            BenchmarkId::new("chunked_write", size),
            &bytes,
            |b, bytes| b.iter(|| black_box(byte_list_root_chunked_write(bytes, max_bytes))),
        );

        group.bench_with_input(BenchmarkId::new("bulk_write", size), &bytes, |b, bytes| {
            b.iter(|| black_box(byte_list_root_bulk_write(bytes, max_bytes)))
        });

        group.bench_with_input(BenchmarkId::new("slim_stream", size), &bytes, |b, bytes| {
            b.iter(|| {
                black_box(byte_list_root_streaming::<EthereumHashing>(bytes, max_bytes).unwrap())
            })
        });

        group.bench_with_input(BenchmarkId::new("level_order", size), &bytes, |b, bytes| {
            b.iter(|| {
                black_box(
                    byte_list_tree_hash_root_with::<EthereumHashing>(bytes, max_bytes).unwrap(),
                )
            })
        });

        group.bench_with_input(BenchmarkId::new("hashtree", size), &bytes, |b, bytes| {
            b.iter(|| {
                black_box(byte_list_tree_hash_root_with::<Hashtree>(bytes, max_bytes).unwrap())
            })
        });
    }

    group.finish();
}

fn bench_transactions(c: &mut Criterion) {
    let mut rng = rng();
    let max_bytes = E::max_bytes_per_transaction();
    let max_transactions = E::max_transactions_per_payload();
    let mut group = c.benchmark_group("transactions");
    group.sample_size(30);

    for count in TRANSACTION_COUNTS {
        let payloads = mainnet_like_transactions(&mut rng, count);
        let total_bytes: usize = payloads.iter().map(|bytes| bytes.len()).sum();
        let transactions = transactions_list(&payloads);
        let slices = as_slices(&payloads);

        assert_eq!(
            byte_lists_tree_hash_root_with::<Hashtree>(&slices, max_bytes, max_transactions)
                .unwrap(),
            transactions.tree_hash_root()
        );
        assert_eq!(
            byte_lists_tree_hash_root_with::<EthereumHashing>(&slices, max_bytes, max_transactions)
                .unwrap(),
            transactions.tree_hash_root()
        );

        group.throughput(Throughput::Bytes(total_bytes as u64));

        group.bench_with_input(
            BenchmarkId::new("tree_hash", count),
            &transactions,
            |b, transactions| b.iter(|| black_box(transactions.tree_hash_root())),
        );

        group.bench_with_input(
            BenchmarkId::new("chunked_write", count),
            &slices,
            |b, slices| {
                b.iter(|| {
                    black_box(byte_lists_root_chunked_write(
                        slices,
                        max_bytes,
                        max_transactions,
                    ))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("bulk_write", count),
            &slices,
            |b, slices| {
                b.iter(|| {
                    black_box(byte_lists_root_bulk_write(
                        slices,
                        max_bytes,
                        max_transactions,
                    ))
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("slim_stream", count),
            &slices,
            |b, slices| {
                b.iter(|| {
                    black_box(
                        byte_lists_root_streaming::<EthereumHashing>(
                            slices,
                            max_bytes,
                            max_transactions,
                        )
                        .unwrap(),
                    )
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("level_order", count),
            &slices,
            |b, slices| {
                b.iter(|| {
                    black_box(
                        byte_lists_tree_hash_root_with::<EthereumHashing>(
                            slices,
                            max_bytes,
                            max_transactions,
                        )
                        .unwrap(),
                    )
                })
            },
        );

        group.bench_with_input(BenchmarkId::new("hashtree", count), &slices, |b, slices| {
            b.iter(|| {
                black_box(
                    byte_lists_tree_hash_root_with::<Hashtree>(slices, max_bytes, max_transactions)
                        .unwrap(),
                )
            })
        });
    }

    group.finish();
}

/// One million transactions of one byte each: the worst shape the type allows.
///
/// `MaxTransactionsPerPayload` is 2^20, so this is close to a full list. Every element is a single
/// chunk of real data sitting under 25 levels of zero padding, which means ~96% of the hashing is
/// padding and no element is long enough to amortise anything. It is the maximum cost per byte of
/// payload, and the shape where merkleizing the elements in lockstep should pay the most.
///
/// This is not a realistic block — 1M transactions of 1 byte will not pass execution — but the
/// tree hash is computed before anything validates the payload, so it bounds what an attacker can
/// make a node spend on hashing alone.
fn bench_transactions_1m(c: &mut Criterion) {
    let count = 1_000_000;
    let max_bytes = E::max_bytes_per_transaction();
    let max_transactions = E::max_transactions_per_payload();

    let payloads: Vec<Vec<u8>> = (0..count).map(|i| vec![(i % 251) as u8]).collect();
    let slices = as_slices(&payloads);
    let transactions = transactions_list(&payloads);

    // One reference root, then check every path against it. Each of these is seconds of work.
    let expected = transactions.tree_hash_root();
    assert_eq!(
        byte_lists_tree_hash_root_with::<Hashtree>(&slices, max_bytes, max_transactions).unwrap(),
        expected
    );
    assert_eq!(
        byte_lists_tree_hash_root_with::<EthereumHashing>(&slices, max_bytes, max_transactions)
            .unwrap(),
        expected
    );
    assert_eq!(
        byte_lists_root_streaming::<EthereumHashing>(&slices, max_bytes, max_transactions).unwrap(),
        expected
    );
    assert_eq!(
        byte_lists_root_bulk_write(&slices, max_bytes, max_transactions),
        expected
    );

    let mut group = c.benchmark_group("transactions_1m");
    // The `tree_hash` arm is seconds per iteration, so take the fewest samples criterion allows.
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(10));
    group.throughput(Throughput::Bytes(count as u64));

    group.bench_function("tree_hash", |b| {
        b.iter(|| black_box(transactions.tree_hash_root()))
    });

    group.bench_function("bulk_write", |b| {
        b.iter(|| {
            black_box(byte_lists_root_bulk_write(
                &slices,
                max_bytes,
                max_transactions,
            ))
        })
    });

    group.bench_function("slim_stream", |b| {
        b.iter(|| {
            black_box(
                byte_lists_root_streaming::<EthereumHashing>(&slices, max_bytes, max_transactions)
                    .unwrap(),
            )
        })
    });

    group.bench_function("level_order", |b| {
        b.iter(|| {
            black_box(
                byte_lists_tree_hash_root_with::<EthereumHashing>(
                    &slices,
                    max_bytes,
                    max_transactions,
                )
                .unwrap(),
            )
        })
    });

    group.bench_function("hashtree", |b| {
        b.iter(|| {
            black_box(
                byte_lists_tree_hash_root_with::<Hashtree>(&slices, max_bytes, max_transactions)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

fn bench_beacon_block(c: &mut Criterion) {
    let mut rng = rng();
    let spec = E::default_spec();
    let mut group = c.benchmark_group("beacon_block");
    group.sample_size(30);

    for count in TRANSACTION_COUNTS {
        let payloads = mainnet_like_transactions(&mut rng, count);
        let block = block_with_transactions(&spec, &payloads);

        assert_eq!(
            block_root_batched::<Hashtree>(&block),
            block.tree_hash_root(),
            "batched block root diverged at {count} transactions; the field lists in this bench \
             are probably out of date with `ExecutionPayloadFulu`/`BeaconBlockBodyFulu`"
        );
        assert_eq!(
            block_root_batched::<EthereumHashing>(&block),
            block.tree_hash_root()
        );

        group.bench_with_input(BenchmarkId::new("tree_hash", count), &block, |b, block| {
            b.iter(|| black_box(block.tree_hash_root()))
        });

        group.bench_with_input(
            BenchmarkId::new("level_order", count),
            &block,
            |b, block| b.iter(|| black_box(block_root_batched::<EthereumHashing>(block))),
        );

        group.bench_with_input(BenchmarkId::new("hashtree", count), &block, |b, block| {
            b.iter(|| black_box(block_root_batched::<Hashtree>(block)))
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sha256,
    bench_transaction,
    bench_transactions,
    bench_transactions_1m,
    bench_beacon_block
);
criterion_main!(benches);
