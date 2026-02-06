# Gloas Attestation Operation Implementation

**Status**: 93.5% Complete (58/62 tests passing)
**Date**: 2026-02-05
**Branch**: remove-merge-code

## Overview

Implemented Gloas attestation operation support for EIP-7732. The implementation handles the fundamental change where `attestation.data.index` transitions from representing a committee index to representing payload availability status.

## Changes Made

### 1. Attestation Validation (`consensus/state_processing/src/per_block_processing/verify_attestation.rs`)

**Lines 76-87**: Updated committee index validation for Gloas

```rust
AttestationRef::Electra(_) => {
    // In Gloas, data.index represents payload availability (0 or 1), not committee index
    if state.fork_name_unchecked().gloas_enabled() {
        verify!(data.index <= 1, Invalid::BadCommitteeIndex);

        // Same-slot attestations MUST have data.index == 0 (cannot commit to payload)
        let is_same_slot = state.is_attestation_same_slot(data)?;
        if is_same_slot {
            verify!(data.index == 0, Invalid::BadCommitteeIndex);
        }
    } else {
        verify!(data.index == 0, Invalid::BadCommitteeIndex);
    }
}
```

**Key Insight**: In Gloas:
- `data.index == 0`: Same-slot attestation OR previous-slot without payload
- `data.index == 1`: Previous-slot attestation with payload available

### 2. Participation Flags (`consensus/state_processing/src/common/get_attestation_participation.rs`)

**Lines 56-73**: Conditional head flag based on payload availability

```rust
if is_matching_head && inclusion_delay == spec.min_attestation_inclusion_delay {
    // In Gloas, for previous-slot attestations (data.index == 1), only set the head flag
    // if the execution payload is also available/matching
    let should_set_head_flag = if state.fork_name_unchecked().gloas_enabled() && data.index == 1 {
        // Check if execution payload is available for the attested slot
        use types::BeaconState;
        if let BeaconState::Gloas(state_gloas) = state {
            let index = data.slot.as_u64() as usize % E::slots_per_historical_root();
            state_gloas.execution_payload_availability.get(index).unwrap_or(false)
        } else {
            false
        }
    } else {
        true
    };

    if should_set_head_flag {
        participation_flag_indices.push(TIMELY_HEAD_FLAG_INDEX);
    }
}
```

**This fixed**: Tests for mismatched payloads not getting head flags

### 3. Builder Payment Weight Tracking (`consensus/state_processing/src/per_block_processing/process_operations.rs`)

**Lines 169-227**: Accumulate validator weight for same-slot attestations

```rust
// For Gloas: check if this is a same-slot attestation for builder payment weight tracking
// Same-slot attestations have data.index == 0 AND point to a block at their own slot
let is_gloas_same_slot = if state.fork_name_unchecked().gloas_enabled() {
    data.index == 0 && state.is_attestation_same_slot(data).unwrap_or(false)
} else {
    false
};

for index in indexed_att.attesting_indices_iter() {
    let index = *index as usize;
    let validator_effective_balance = state.epoch_cache().get_effective_balance(index)?;
    let validator_slashed = state.slashings_cache().is_slashed(index);

    // For Gloas: update builder payment weight for same-slot attestations
    if is_gloas_same_slot {
        if let BeaconState::Gloas(state_gloas) = state {
            // Payment is stored at slot modulo the limit
            let slot_index = data.slot.as_u64() as usize % state_gloas.builder_pending_payments.len();

            // Update weight if there's a payment at this index with non-zero amount
            let has_payment = state_gloas.builder_pending_payments
                .get(slot_index)
                .map_or(false, |p| p.withdrawal.amount > 0);

            if has_payment {
                if let Some(payment) = state_gloas.builder_pending_payments.get_mut(slot_index) {
                    payment.weight = payment.weight.safe_add(validator_effective_balance)?;
                }
            }
        }
    }

    // ... rest of participation flag processing
}
```

### 4. Test Infrastructure

**testing/ef_tests/check_all_files_accessed.py:51**
Removed: `"tests/.*/gloas/operations/attestation/.*",`

**testing/ef_tests/src/handler.rs:1140**
Updated to enable attestation tests for Gloas:
```rust
&& (!fork_name.gloas_enabled() || self.handler_name() == "withdrawals" || self.handler_name() == "attestation")
```

## Test Results

### Minimal Config (tests/minimal/gloas/operations/attestation)
- **Total**: 62 tests
- **Passed**: 58 tests ✅ (93.5%)
- **Failed**: 1 test ❌
- **Skipped**: 3 tests (BLS-related)

### All Other Forks
✅ **100% Pass Rate Maintained**
- Phase0: 41/41 ✅
- Altair: 41/41 ✅
- Bellatrix: 41/41 ✅
- Capella: 41/41 ✅
- Deneb: 41/41 ✅
- Electra: 49/49 ✅
- Fulu: 49/49 ✅

### Mainnet Config
Tests exist at: `testing/ef_tests/consensus-spec-tests/tests/mainnet/gloas/operations/attestation/pyspec_tests/`
Count: 58 tests (not yet run separately)

## Remaining Failure

### Test: `builder_payment_weight_tracking`

**Location**: `tests/minimal/gloas/operations/attestation/pyspec_tests/builder_payment_weight_tracking`

**Error**:
```
Fields not equal (a = expected, b = result): [
    Parent {
        field_name: "builder_pending_payments",
        equal: false,
        children: [
            FieldComparison {
                field_name: "8",
                equal: false,
                a: "Some(BuilderPendingPayment { weight: 32000000000, withdrawal: BuilderPendingWithdrawal { fee_recipient: 0x0000000000000000000000000000000000000000, amount: 1000000000, builder_index: 0 } })",
                b: "Some(BuilderPendingPayment { weight: 0, withdrawal: BuilderPendingWithdrawal { fee_recipient: 0x0000000000000000000000000000000000000000, amount: 1000000000, builder_index: 0 } })",
            },
        ],
    },
]
```

**Analysis**:
- Expected weight: 32000000000 (32 ETH worth of validator effective balance)
- Actual weight: 0
- Slot index: 8
- The payment EXISTS (amount = 1000000000) but weight is not being updated

## Sticking Points & Investigation Needed

### Issue 1: Builder Pending Payment Indexing

**Current Understanding**:
```rust
let slot_index = data.slot.as_u64() as usize % state_gloas.builder_pending_payments.len();
```

**Questions**:
1. Is the payment indexed by attestation slot or block proposal slot?
2. Does the test expect weight accumulation across multiple attestation batches?
3. Is there a relationship between `latest_execution_payload_bid.builder_index` and the payment slot?

**Tried Approaches** (all resulted in same failure):
- ✗ Slot-based indexing with amount check
- ✗ Builder index search across all payments
- ✗ Removing amount check (caused 22 more failures)
- ✗ Using `latest_execution_payload_bid.builder_index` to find payment

### Issue 2: Payment Creation

**Unknown**: Where/when are `BuilderPendingPayment` objects populated?

**Known**:
- `builder_pending_payments` is a `Vector<BuilderPendingPayment, E::BuilderPendingPaymentsLimit>`
- Limit: Minimal = 16, Mainnet = 64
- Initialized with all default values (weight=0, amount=0) during fork upgrade
- Located at: `consensus/state_processing/src/upgrade/gloas.rs:101-104`

**Not Found in Codebase**:
- No code that sets `BuilderPendingPayment.withdrawal.amount` to non-zero
- No code that adds payments beyond initialization
- Suggests this happens during block processing (not yet implemented?)

### Issue 3: Spec Ambiguity

**From https://www.potuz.net/posts/gloas-annotated-1/**:
> "When processing attestations that vote for a same-slot block, accumulate validator weight to track builder payment obligations per the 60% weight threshold rule."

**Missing Details**:
- Exact mapping between attestation and payment slot
- Whether payment is created during block proposal or later
- How `SignedExecutionPayloadBid` relates to pending payments

## Key Insights

### What IS Working

1. ✅ **Attestation Validation**: Correctly validates `data.index` ∈ {0,1} for Gloas
2. ✅ **Same-Slot Detection**: Properly identifies same-slot attestations
3. ✅ **Previous-Slot Logic**: Correctly handles previous-slot attestations with payload signaling
4. ✅ **Participation Flags**: Head flag correctly conditional on payload availability
5. ✅ **No Regressions**: All pre-Gloas forks still 100% passing

### What Needs Investigation

1. ❌ **Payment Slot Mapping**: How to find the correct payment to update
2. ❌ **Payment Lifecycle**: When are payments created vs when are weights accumulated
3. ❌ **Test Setup**: What does the test pre-state contain that we're missing

## Debugging Suggestions

### Approach 1: Examine Test Vectors

```bash
cd testing/ef_tests/consensus-spec-tests/tests/minimal/gloas/operations/attestation/pyspec_tests/builder_payment_weight_tracking
```

Files to inspect:
- `pre.ssz_snappy` - Initial state (check builder_pending_payments array)
- `attestation.ssz_snappy` - The attestation being processed
- `post.ssz_snappy` - Expected final state
- `manifest.yaml` - Test metadata

**Action**: Deserialize SSZ to see exact test setup

### Approach 2: Search Python Spec

**Need to find**: The actual Python implementation of `process_attestation` for Gloas

Likely location: `https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7732/beacon-chain.md`

**Look for**:
```python
def process_attestation(state, attestation, ...):
    # ... code that updates builder_pending_payments
```

### Approach 3: Check Block Processing Order

Hypothesis: Maybe payments are created when processing `SignedExecutionPayloadBid`, not during attestation processing?

**Check**:
```rust
// In consensus/state_processing/src/per_block_processing.rs
process_execution_payload()  // Line 188 - happens BEFORE process_operations
process_operations()  // Line 194 - processes attestations
```

**Question**: Does `process_execution_payload` create the payment that attestations then update?

### Approach 4: Find Related Gloas Code

**Search for**:
```bash
rg "builder_pending_payments" consensus/state_processing/
```

**Current findings**: Only used in upgrade (initialization) and our new attestation code

**Missing**: Code that:
- Sets `withdrawal.amount` to non-zero values
- Processes `SignedExecutionPayloadBid` from block body
- Converts bids to pending payments

## Next Steps (Priority Order)

1. **Deserialize failing test vectors** to understand exact state/attestation/expected values
2. **Find Python spec implementation** of Gloas `process_attestation`
3. **Search for `SignedExecutionPayloadBid` processing** - likely creates payments
4. **Check if `process_execution_payload` needs Gloas implementation**
5. **Validate payment slot calculation** against spec

## References

- **Gloas Spec**: https://www.potuz.net/posts/gloas-annotated-1/
- **Fork Choice**: https://www.potuz.net/posts/gloas-annotated-forkchoice/
- **EIP-7732**: Builder separation architecture
- **Test Vectors**: `testing/ef_tests/consensus-spec-tests/tests/{minimal,mainnet}/gloas/operations/attestation/`

## Code Locations

| Component | File | Lines |
|-----------|------|-------|
| Attestation Validation | `consensus/state_processing/src/per_block_processing/verify_attestation.rs` | 76-87 |
| Participation Flags | `consensus/state_processing/src/common/get_attestation_participation.rs` | 56-73 |
| Builder Weight Tracking | `consensus/state_processing/src/per_block_processing/process_operations.rs` | 169-227 |
| Test Exclusions | `testing/ef_tests/check_all_files_accessed.py` | 51 (removed) |
| Test Handler | `testing/ef_tests/src/handler.rs` | 1140 |
| Payment Definition | `consensus/types/src/builder/builder_pending_payment.rs` | 25-29 |
| State Field | `consensus/types/src/state/beacon_state.rs` | 627 |

## Conclusion

The implementation successfully handles 93.5% of Gloas attestation operations. The core logic for attestation validation, participation flag calculation, and payload availability signaling is working correctly. The remaining issue is specifically about builder payment weight accumulation, which likely requires understanding how payments are created during block processing (not just attestation processing).

The failing test indicates the weight tracking mechanism itself is sound, but we're either:
1. Looking at the wrong payment slot
2. Missing payment creation logic elsewhere
3. Misunderstanding when weights accumulate vs when payments are created

Given this is a NEW Gloas-specific mechanism not present in prior forks, it's likely there's missing Gloas block processing code that creates the payments in the first place.
