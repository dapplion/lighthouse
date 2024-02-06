use crate::{
    ChainSpec, Domain, EthSpec, Fork, Gwei, Hash256, PublicKey, SecretKey, Signature, SignedRoot,
    Slot,
};
use ethereum_hashing::hash;
use safe_arith::{ArithError, SafeArith};
use ssz::Encode;
use std::cmp;
use std::convert::TryInto;

#[derive(arbitrary::Arbitrary, PartialEq, Debug, Clone)]
pub struct SelectionProof(Signature);

impl SelectionProof {
    pub fn new<T: EthSpec>(
        slot: Slot,
        secret_key: &SecretKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> Self {
        let domain = spec.get_domain(
            slot.epoch(T::slots_per_epoch()),
            Domain::SelectionProof,
            fork,
            genesis_validators_root,
        );
        let message = slot.signing_root(domain);

        Self(secret_key.sign(message))
    }

    /// Returns the "modulo" used for determining if a `SelectionProof` elects an aggregator.
    pub fn modulo_base(committee_len: usize, spec: &ChainSpec) -> Result<u64, ArithError> {
        Ok(cmp::max(
            1,
            (committee_len as u64).safe_div(spec.target_aggregators_per_committee)?,
        ))
    }

    /// validator_effective_balance = state.validators[index].effective_balance
    /// committee_total_effective_balance = get_total_balance(state, set(committee))
    pub fn modulo_maxeb(
        validator_effective_balance: Gwei,
        committee_total_effective_balance: Gwei,
        spec: &ChainSpec,
    ) -> Result<u64, ArithError> {
        let min_balance_increments =
            validator_effective_balance.safe_div(spec.min_activation_balance)?;
        let committee_balance_increments =
            committee_total_effective_balance.safe_div(spec.min_activation_balance)?;
        let denominator = committee_balance_increments.safe_mul(min_balance_increments)?;
        let numerator = denominator.safe_sub(
            committee_balance_increments
                .safe_sub(spec.target_aggregators_per_committee)?
                .safe_mul(min_balance_increments)?,
        )?;
        Ok(denominator.safe_div(numerator)?.into())
    }

    pub fn is_aggregator_from_modulo(&self, modulo: u64) -> Result<bool, ArithError> {
        let signature_hash = hash(&self.0.as_ssz_bytes());
        let signature_hash_int = u64::from_le_bytes(
            signature_hash
                .get(0..8)
                .expect("hash is 32 bytes")
                .try_into()
                .expect("first 8 bytes of signature should always convert to fixed array"),
        );

        signature_hash_int.safe_rem(modulo).map(|rem| rem == 0)
    }

    pub fn verify<T: EthSpec>(
        &self,
        slot: Slot,
        pubkey: &PublicKey,
        fork: &Fork,
        genesis_validators_root: Hash256,
        spec: &ChainSpec,
    ) -> bool {
        let domain = spec.get_domain(
            slot.epoch(T::slots_per_epoch()),
            Domain::SelectionProof,
            fork,
            genesis_validators_root,
        );
        let message = slot.signing_root(domain);

        self.0.verify(pubkey, message)
    }
}

impl Into<Signature> for SelectionProof {
    fn into(self) -> Signature {
        self.0
    }
}

impl From<Signature> for SelectionProof {
    fn from(sig: Signature) -> Self {
        Self(sig)
    }
}
