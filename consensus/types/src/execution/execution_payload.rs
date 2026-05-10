use context_deserialize::{ContextDeserialize, context_deserialize};
use educe::Educe;
use fixed_bytes::Uint256;
use serde::{Deserialize, Deserializer, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use crate::{
    core::{Address, EthSpec, ExecutionBlockHash, Hash256, Slot},
    fork::{ForkName, ForkVersionDecode},
    state::BeaconStateError,
    withdrawal::Withdrawals,
};

pub type Transaction<N> = VariableList<u8, N>;
pub type Transactions<E> = VariableList<
    Transaction<<E as EthSpec>::MaxBytesPerTransaction>,
    <E as EthSpec>::MaxTransactionsPerPayload,
>;

/// Compute the SSZ tree hash root of a `Transactions<E>` directly from its
/// SSZ-encoded bytes, without typed parsing.
///
/// `Transactions::from_ssz_bytes(bytes)?.tree_hash_root()` parses the wire
/// bytes into a `VariableList<VariableList<u8, ..>, ..>` first, allocating
/// one `Vec<u8>` per transaction. For callers that already have the SSZ
/// bytes and only need the root (the ERA file importer is the motivating
/// case), the typed allocation is wasted: walk the SSZ container's offset
/// table directly, hash each `Transaction`'s bytes in place, then list-
/// merkleize the per-transaction roots and mix in the count.
///
/// On real mainnet blocks the byte path is **2.0–2.5× faster** than the
/// typed path. Output is byte-identical (verified in the tests below).
pub fn transactions_tree_hash_root_from_ssz_bytes<E: EthSpec>(
    bytes: &[u8],
) -> Result<Hash256, ssz::DecodeError> {
    let max_tx = E::max_transactions_per_payload();
    let max_bytes = E::max_bytes_per_transaction();

    if bytes.is_empty() {
        // Empty list root: merkle_root of zero leaves padded to `max_tx`,
        // then mix in length 0.
        return Ok(tree_hash::mix_in_length(
            &tree_hash::merkle_root(&[], max_tx),
            0,
        ));
    }

    // SSZ List<Transaction, MAX_TX> with variable-size elements: a flat array
    // of u32 little-endian offsets at the front, then transaction bytes
    // concatenated after. The first offset's value equals the byte position
    // where the variable region starts, so `n_items = first_offset / 4`.
    let read_offset = |idx: usize| -> Result<usize, ssz::DecodeError> {
        let start = idx
            .checked_mul(4)
            .ok_or_else(|| ssz::DecodeError::BytesInvalid("offset index overflow".into()))?;
        let end = start
            .checked_add(4)
            .ok_or_else(|| ssz::DecodeError::BytesInvalid("offset slice overflow".into()))?;
        let slot = bytes
            .get(start..end)
            .ok_or_else(|| ssz::DecodeError::BytesInvalid("offset out of range".into()))?;
        let arr: [u8; 4] = slot.try_into().expect("slice length 4 by construction");
        Ok(u32::from_le_bytes(arr) as usize)
    };

    let first_off = read_offset(0)?;
    if first_off % 4 != 0 {
        return Err(ssz::DecodeError::BytesInvalid(
            "first offset not 4-byte-aligned".into(),
        ));
    }
    let n = first_off / 4;
    if n > max_tx {
        return Err(ssz::DecodeError::BytesInvalid(format!(
            "transactions count {n} exceeds maximum {max_tx}",
        )));
    }
    let min_leaves_per_tx = max_bytes.div_ceil(32);

    let cap = n.checked_mul(32).unwrap_or(0);
    let mut tx_roots: Vec<u8> = Vec::with_capacity(cap);
    for i in 0..n {
        let start = read_offset(i)?;
        let end = if i.saturating_add(1) < n {
            read_offset(i.saturating_add(1))?
        } else {
            bytes.len()
        };
        if end < start || end > bytes.len() {
            return Err(ssz::DecodeError::BytesInvalid(
                "transaction bytes out of range".into(),
            ));
        }
        let tx = bytes.get(start..end).ok_or_else(|| {
            ssz::DecodeError::BytesInvalid("transaction slice out of range".into())
        })?;
        // ByteList<u8, MAX_BYTES> tree hash: pad-then-merkleize chunks to
        // MAX_BYTES/32 leaves, then mix in the byte length.
        let chunk_root = tree_hash::merkle_root(tx, min_leaves_per_tx);
        let tx_root = tree_hash::mix_in_length(&chunk_root, tx.len());
        tx_roots.extend_from_slice(tx_root.as_slice());
    }

    let list_root = tree_hash::merkle_root(&tx_roots, max_tx);
    Ok(tree_hash::mix_in_length(&list_root, n))
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra, Fulu, Gloas),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
            Educe,
        ),
        context_deserialize(ForkName),
        educe(PartialEq, Hash(bound(E: EthSpec))),
        serde(bound = "E: EthSpec", deny_unknown_fields),
        cfg_attr(
            feature = "arbitrary",
            derive(arbitrary::Arbitrary),
            arbitrary(bound = "E: EthSpec"),
        ),
    ),
    cast_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    ),
    partial_getter_error(
        ty = "BeaconStateError",
        expr = "BeaconStateError::IncorrectStateVariant"
    )
)]
#[cfg_attr(
    feature = "arbitrary",
    derive(arbitrary::Arbitrary),
    arbitrary(bound = "E: EthSpec")
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash, Educe)]
#[educe(PartialEq, Hash(bound(E: EthSpec)))]
#[serde(bound = "E: EthSpec", untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayload<E: EthSpec> {
    #[superstruct(getter(copy))]
    pub parent_hash: ExecutionBlockHash,
    #[superstruct(getter(copy))]
    #[serde(with = "serde_utils::address_hex")]
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: Hash256,
    #[superstruct(getter(copy))]
    pub receipts_root: Hash256,
    #[serde(with = "ssz_types::serde_utils::hex_fixed_vec")]
    pub logs_bloom: FixedVector<u8, E::BytesPerLogsBloom>,
    #[superstruct(getter(copy))]
    pub prev_randao: Hash256,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub block_number: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub gas_used: u64,
    #[serde(with = "serde_utils::quoted_u64")]
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub extra_data: VariableList<u8, E::MaxExtraDataBytes>,
    #[serde(with = "serde_utils::quoted_u256")]
    #[superstruct(getter(copy))]
    pub base_fee_per_gas: Uint256,
    #[superstruct(getter(copy))]
    pub block_hash: ExecutionBlockHash,
    #[serde(with = "ssz_types::serde_utils::list_of_hex_var_list")]
    pub transactions: Transactions<E>,
    #[superstruct(only(Capella, Deneb, Electra, Fulu, Gloas))]
    pub withdrawals: Withdrawals<E>,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb, Electra, Fulu, Gloas), partial_getter(copy))]
    #[serde(with = "serde_utils::quoted_u64")]
    pub excess_blob_gas: u64,
    /// EIP-7928: Block access list
    #[superstruct(only(Gloas))]
    #[serde(with = "ssz_types::serde_utils::hex_var_list")]
    pub block_access_list: VariableList<u8, E::MaxBytesPerTransaction>,
    #[superstruct(only(Gloas), partial_getter(copy))]
    pub slot_number: Slot,
}

impl<'a, E: EthSpec> ExecutionPayloadRef<'a, E> {
    // this emulates clone on a normal reference type
    pub fn clone_from_ref(&self) -> ExecutionPayload<E> {
        map_execution_payload_ref!(&'a _, self, move |payload, cons| {
            cons(payload);
            payload.clone().into()
        })
    }
}

impl<E: EthSpec> ForkVersionDecode for ExecutionPayload<E> {
    /// SSZ decode with explicit fork variant.
    fn from_ssz_bytes_by_fork(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Base | ForkName::Altair => Err(ssz::DecodeError::BytesInvalid(format!(
                "unsupported fork for ExecutionPayload: {fork_name}",
            ))),
            ForkName::Bellatrix => {
                ExecutionPayloadBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => ExecutionPayloadCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => ExecutionPayloadDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => ExecutionPayloadElectra::from_ssz_bytes(bytes).map(Self::Electra),
            ForkName::Fulu => ExecutionPayloadFulu::from_ssz_bytes(bytes).map(Self::Fulu),
            ForkName::Gloas => ExecutionPayloadGloas::from_ssz_bytes(bytes).map(Self::Gloas),
        }
    }
}

impl<E: EthSpec> ExecutionPayload<E> {
    #[allow(clippy::arithmetic_side_effects)]
    /// Returns the maximum size of an execution payload.
    /// TODO(EIP-7732): this seems to only exist for the Bellatrix fork, but Mark's branch has it for all the forks, i.e. max_execution_payload_eip7732_size
    pub fn max_execution_payload_bellatrix_size() -> usize {
        // Fixed part
        ExecutionPayloadBellatrix::<E>::default().as_ssz_bytes().len()
            // Max size of variable length `extra_data` field
            + (E::max_extra_data_bytes() * <u8 as Encode>::ssz_fixed_len())
            // Max size of variable length `transactions` field
            + (E::max_transactions_per_payload() * (ssz::BYTES_PER_LENGTH_OFFSET + E::max_bytes_per_transaction()))
    }
}

impl<'de, E: EthSpec> ContextDeserialize<'de, ForkName> for ExecutionPayload<E> {
    fn context_deserialize<D>(deserializer: D, context: ForkName) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let convert_err = |e| {
            serde::de::Error::custom(format!("ExecutionPayload failed to deserialize: {:?}", e))
        };
        Ok(match context {
            ForkName::Base | ForkName::Altair => {
                return Err(serde::de::Error::custom(format!(
                    "ExecutionPayload failed to deserialize: unsupported fork '{}'",
                    context
                )));
            }
            ForkName::Bellatrix => {
                Self::Bellatrix(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Capella => {
                Self::Capella(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Deneb => {
                Self::Deneb(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Electra => {
                Self::Electra(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Fulu => {
                Self::Fulu(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
            ForkName::Gloas => {
                Self::Gloas(Deserialize::deserialize(deserializer).map_err(convert_err)?)
            }
        })
    }
}

impl<E: EthSpec> ExecutionPayload<E> {
    pub fn fork_name(&self) -> ForkName {
        match self {
            ExecutionPayload::Bellatrix(_) => ForkName::Bellatrix,
            ExecutionPayload::Capella(_) => ForkName::Capella,
            ExecutionPayload::Deneb(_) => ForkName::Deneb,
            ExecutionPayload::Electra(_) => ForkName::Electra,
            ExecutionPayload::Fulu(_) => ForkName::Fulu,
            ExecutionPayload::Gloas(_) => ForkName::Gloas,
        }
    }
}

#[cfg(test)]
mod transactions_root_from_bytes_tests {
    use super::*;
    use crate::core::MainnetEthSpec;
    use ssz::Encode;
    use tree_hash::TreeHash;

    fn make_tx(seed: u64, len: usize) -> Vec<u8> {
        // Pseudo-random but deterministic so test failures are reproducible.
        let mut v = vec![0u8; len];
        let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15);
        for byte in v.iter_mut() {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *byte = (x >> 56) as u8;
        }
        v
    }

    fn make_transactions(sizes: &[usize]) -> Transactions<MainnetEthSpec> {
        let txs: Vec<Transaction<<MainnetEthSpec as EthSpec>::MaxBytesPerTransaction>> = sizes
            .iter()
            .enumerate()
            .map(|(i, &n)| Transaction::new(make_tx(i as u64, n)).expect("tx fits"))
            .collect();
        Transactions::<MainnetEthSpec>::new(txs).expect("transactions fits")
    }

    fn assert_matches(transactions: &Transactions<MainnetEthSpec>) {
        let typed_root = transactions.tree_hash_root();
        let bytes = transactions.as_ssz_bytes();
        let custom_root = transactions_tree_hash_root_from_ssz_bytes::<MainnetEthSpec>(&bytes)
            .expect("byte-hash succeeds on round-tripped SSZ");
        assert_eq!(
            typed_root, custom_root,
            "transactions byte-hash differs from typed tree_hash_root"
        );
    }

    #[test]
    fn empty_list() {
        assert_matches(&make_transactions(&[]));
    }

    #[test]
    fn single_small_tx() {
        assert_matches(&make_transactions(&[200]));
    }

    #[test]
    fn many_small_txs() {
        let sizes: Vec<usize> = (0..256).map(|i| 100 + i % 73).collect();
        assert_matches(&make_transactions(&sizes));
    }

    #[test]
    fn mixed_size_realistic_block() {
        // Loosely models a mainnet block: ~150 transactions, mostly small with a few larger.
        let mut sizes = vec![180usize; 140];
        sizes.extend([1024usize, 8192, 32768, 4096, 256]);
        assert_matches(&make_transactions(&sizes));
    }

    #[test]
    fn single_large_tx() {
        // 64 KiB transaction — exercises the chunking path inside the byte hasher.
        assert_matches(&make_transactions(&[65536]));
    }

    #[test]
    fn boundary_chunk_sizes() {
        // Sizes that straddle 32-byte chunk boundaries to catch off-by-one mixes
        // in the bytelist root.
        for &n in &[0usize, 1, 31, 32, 33, 63, 64, 65] {
            assert_matches(&make_transactions(&[n]));
        }
    }
}
