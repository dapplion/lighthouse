# Gloas Specification Analysis - Functions Requiring Implementation

**Source**: https://github.com/ethereum/consensus-specs/blob/master/specs/gloas/beacon-chain.md

## Critical Discovery: Builder Payment Indexing

### THE MISSING PIECE - Payment Array Structure

The `builder_pending_payments` array is **double the epoch size**:
- Indices `0..SLOTS_PER_EPOCH-1`: Previous epoch payments
- Indices `SLOTS_PER_EPOCH..2*SLOTS_PER_EPOCH-1`: Current epoch payments

```python
# For current epoch attestations
payment = state.builder_pending_payments[SLOTS_PER_EPOCH + data.slot % SLOTS_PER_EPOCH]

# For previous epoch attestations
payment = state.builder_pending_payments[data.slot % SLOTS_PER_EPOCH]
```

**This explains our test failure!** We were using just `data.slot % limit`, but the spec uses an offset based on which epoch the attestation targets.

## Functions Requiring Implementation/Modification

### 1. **CRITICAL: `process_attestation` - NEEDS FIX**

**Current Status**: ✅ Partially implemented, ❌ payment indexing wrong

**Required Changes**:
```python
# Get the correct payment based on target epoch
if data.target.epoch == get_current_epoch(state):
    current_epoch_target = True
    payment_index = SLOTS_PER_EPOCH + data.slot % SLOTS_PER_EPOCH
else:
    current_epoch_target = False
    payment_index = data.slot % SLOTS_PER_EPOCH

payment = state.builder_pending_payments[payment_index]

# Inside the validator loop:
will_set_new_flag = False
for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
    if flag_index in participation_flag_indices and not has_flag(...):
        epoch_participation[index] = add_flag(...)
        proposer_reward_numerator += ...
        will_set_new_flag = True  # NEW!

# After flag processing:
if will_set_new_flag and is_attestation_same_slot(state, data) and payment.withdrawal.amount > 0:
    payment.weight += state.validators[index].effective_balance

# Write the payment back to state at the end:
state.builder_pending_payments[payment_index] = payment
```

**Key Points**:
- Payment is loaded at START of function
- Weight accumulates only if NEW flag is set (not on duplicate attestations)
- Payment is written BACK to state at end
- Only accumulate if `is_attestation_same_slot` AND `payment.withdrawal.amount > 0`

---

### 2. **CRITICAL: `process_execution_payload_bid` - NOT IMPLEMENTED**

**Status**: ❌ Not implemented

**Purpose**: Creates the `BuilderPendingPayment` when block contains a bid

**Implementation Needed**:
```rust
pub fn process_execution_payload_bid<E: EthSpec>(
    state: &mut BeaconState<E>,
    block: BeaconBlockRef<E>,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let signed_bid = block.body().signed_execution_payload_bid()?;
    let bid = &signed_bid.message;
    let builder_index = bid.builder_index;
    let amount = bid.value;

    if builder_index == BUILDER_INDEX_SELF_BUILD {
        verify!(amount == 0, ...);
        verify!(signed_bid.signature == G2_POINT_AT_INFINITY, ...);
    } else {
        verify!(is_active_builder(state, builder_index)?, ...);
        verify!(can_builder_cover_bid(state, builder_index, amount)?, ...);
        verify!(verify_execution_payload_bid_signature(state, signed_bid)?, ...);
    }

    // Validate blob commitments
    verify!(bid.blob_kzg_commitments.len() <= max_blobs, ...);

    // Validate bid metadata
    verify!(bid.slot == block.slot(), ...);
    verify!(bid.parent_block_hash == state.latest_block_hash()?, ...);
    verify!(bid.parent_block_root == block.parent_root(), ...);
    verify!(bid.prev_randao == get_randao_mix(state, current_epoch)?, ...);

    // CREATE THE PAYMENT HERE!
    if amount > 0 {
        let pending_payment = BuilderPendingPayment {
            weight: 0,
            withdrawal: BuilderPendingWithdrawal {
                fee_recipient: bid.fee_recipient,
                amount,
                builder_index,
            },
        };

        // Current epoch payment slot
        let payment_index = E::slots_per_epoch() + (bid.slot.as_u64() % E::slots_per_epoch());
        state_gloas.builder_pending_payments[payment_index] = pending_payment;
    }

    // Update latest bid
    state_gloas.latest_execution_payload_bid = bid.clone();

    Ok(())
}
```

**Call Site**: In `per_block_processing`, BEFORE `process_operations`

---

### 3. **CRITICAL: `process_execution_payload` - NEEDS MODIFICATION**

**Status**: ❌ Needs Gloas-specific logic

**Required Changes**:
```python
# After processing payload and requests:
payment = state.builder_pending_payments[SLOTS_PER_EPOCH + state.slot % SLOTS_PER_EPOCH]
amount = payment.withdrawal.amount
if amount > 0:
    state.builder_pending_withdrawals.append(payment.withdrawal)

# Clear the payment slot
state.builder_pending_payments[SLOTS_PER_EPOCH + state.slot % SLOTS_PER_EPOCH] = BuilderPendingPayment()

# Mark payload as available
state.execution_payload_availability[state.slot % SLOTS_PER_HISTORICAL_ROOT] = 0b1
state.latest_block_hash = payload.block_hash
```

**Key Points**:
- When payload is included, immediately queue the builder payment as a withdrawal
- Clear the payment slot
- Set the execution_payload_availability bit

---

### 4. **`process_payload_attestation` - NEW OPERATION TYPE**

**Status**: ❌ Not implemented

**Purpose**: Process payload attestations from PTC (Payload Timing Committee)

**Implementation**:
```rust
pub fn process_payload_attestation<E: EthSpec>(
    state: &mut BeaconState<E>,
    payload_attestation: &PayloadAttestation<E>,
    verify_signatures: VerifySignatures,
    spec: &ChainSpec,
) -> Result<(), BlockProcessingError> {
    let data = &payload_attestation.data;

    // Validate attestation points to parent block
    verify!(
        data.beacon_block_root == state.latest_block_header().parent_root,
        Invalid::BadParentRoot
    );

    // Validate it's for the previous slot
    verify!(
        data.slot + 1 == state.slot(),
        Invalid::BadSlot
    );

    // Get indexed attestation and validate signature
    let indexed = get_indexed_payload_attestation(state, payload_attestation)?;
    verify_indexed_payload_attestation(state, &indexed, verify_signatures)?;

    Ok(())
}
```

---

### 5. **`process_builder_pending_payments` - EPOCH PROCESSING**

**Status**: ❌ Not implemented

**Purpose**: At epoch boundary, process previous epoch's payments

**Implementation**:
```rust
pub fn process_builder_pending_payments<E: EthSpec>(
    state: &mut BeaconState<E>,
    spec: &ChainSpec,
) -> Result<(), EpochProcessingError> {
    let quorum = get_builder_payment_quorum_threshold(state, spec)?;

    // Process previous epoch payments (indices 0..SLOTS_PER_EPOCH-1)
    for i in 0..E::slots_per_epoch() {
        let payment = &state.builder_pending_payments()[i];

        // If weight >= 60% threshold, queue for withdrawal
        if payment.weight >= quorum {
            state.builder_pending_withdrawals_mut().push(payment.withdrawal.clone())?;
        }
        // Otherwise payment expires (no action needed)
    }

    // Rotate the array: current epoch becomes previous, new current is empty
    let old_payments = state.builder_pending_payments()[E::slots_per_epoch()..].to_vec();
    let new_payments = vec![BuilderPendingPayment::default(); E::slots_per_epoch()];

    let rotated: Vec<_> = old_payments.into_iter().chain(new_payments).collect();
    *state.builder_pending_payments_mut() = Vector::new(rotated)?;

    Ok(())
}
```

**Call Site**: In epoch processing, after `process_justification_and_finalization`

---

### 6. **`process_proposer_slashing` - NEEDS MODIFICATION**

**Status**: ✅ Exists, ❌ Needs Gloas logic

**Required Addition**:
```rust
// After validating the slashing, BEFORE slash_validator:

// Clear any pending payment for the slashed proposal
let slot = header_1.slot;
let proposal_epoch = slot.epoch(E::slots_per_epoch());
let current_epoch = state.current_epoch();

if proposal_epoch == current_epoch {
    let payment_index = E::slots_per_epoch() + (slot.as_u64() % E::slots_per_epoch());
    state.builder_pending_payments_mut()[payment_index] = BuilderPendingPayment::default();
} else if proposal_epoch == current_epoch.saturating_sub(1) {
    let payment_index = slot.as_u64() % E::slots_per_epoch();
    state.builder_pending_payments_mut()[payment_index] = BuilderPendingPayment::default();
}

slash_validator(state, header_1.proposer_index, None, ctxt, spec)?;
```

**Key Point**: Equivocation nullifies the builder payment obligation

---

### 7. **`process_withdrawals` - NEEDS MODIFICATION**

**Status**: ✅ Exists, ❌ Needs builder withdrawal logic

**Required Changes**:
```python
# New order of withdrawals:
# 1. Builder pending withdrawals (from payments)
# 2. Partial validator withdrawals
# 3. Builder sweep withdrawals (exited builders)
# 4. Validator sweep withdrawals

def process_withdrawals(state: BeaconState) -> None:
    if not is_parent_block_full(state):
        return

    expected = get_expected_withdrawals(state)
    apply_withdrawals(state, expected.withdrawals)

    # Update state
    update_next_withdrawal_index(state, expected.withdrawals)
    update_payload_expected_withdrawals(state, expected.withdrawals)
    update_builder_pending_withdrawals(state, expected.processed_builder_withdrawals_count)
    update_pending_partial_withdrawals(state, expected.processed_partial_withdrawals_count)
    update_next_withdrawal_builder_index(state, expected.processed_builders_sweep_count)
    update_next_withdrawal_validator_index(state, expected.withdrawals)
```

---

### 8. **Helper Functions Needed**

#### `get_builder_payment_quorum_threshold`
```rust
pub fn get_builder_payment_quorum_threshold<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
) -> Result<u64, Error> {
    let total_active_balance = state.get_total_active_balance()?;
    let per_slot_balance = total_active_balance / E::slots_per_epoch();

    // 60% threshold
    let quorum = per_slot_balance
        .safe_mul(BUILDER_PAYMENT_THRESHOLD_NUMERATOR)?
        .safe_div(BUILDER_PAYMENT_THRESHOLD_DENOMINATOR)?;

    Ok(quorum)
}
```

#### `is_attestation_same_slot`
**Status**: ✅ Already implemented correctly in `beacon_state.rs:2071`

#### `is_parent_block_full`
```rust
pub fn is_parent_block_full<E: EthSpec>(state: &BeaconState<E>) -> bool {
    if let BeaconState::Gloas(state_gloas) = state {
        state_gloas.latest_execution_payload_bid.block_hash == state_gloas.latest_block_hash
    } else {
        true  // Pre-Gloas always considers block full
    }
}
```

---

## Priority Implementation Order

### Phase 1: Fix Existing Bug (IMMEDIATE)
1. ✅ **Fix `process_attestation` payment indexing** ← THIS FIXES THE TEST!
   - Use epoch-aware indexing: `SLOTS_PER_EPOCH + slot % SLOTS_PER_EPOCH` vs `slot % SLOTS_PER_EPOCH`
   - Track `will_set_new_flag` boolean
   - Write payment back to state

### Phase 2: Enable Block Processing (REQUIRED FOR TESTS)
2. ❌ **Implement `process_execution_payload_bid`**
   - Creates the payment when block proposes a bid
   - Called BEFORE `process_operations` in `per_block_processing`

3. ❌ **Modify `process_execution_payload`**
   - Queues payment as withdrawal
   - Clears payment slot
   - Sets payload availability bit

### Phase 3: Complete Operations (NICE TO HAVE)
4. ❌ **Implement `process_payload_attestation`**
   - New operation type in Gloas blocks

5. ❌ **Modify `process_proposer_slashing`**
   - Clear payment on equivocation

### Phase 4: Epoch Processing (NICE TO HAVE)
6. ❌ **Implement `process_builder_pending_payments`**
   - Process 60% threshold payments
   - Rotate payment array

### Phase 5: Withdrawals (COMPLEX, LATER)
7. ❌ **Modify `process_withdrawals`**
   - Add builder withdrawal logic
   - Requires full builder registry implementation

---

## Test Failure Root Cause

**The `builder_payment_weight_tracking` test fails because**:

Our current code:
```rust
let slot_index = data.slot.as_u64() as usize % state_gloas.builder_pending_payments.len();
```

Spec requires:
```python
if data.target.epoch == get_current_epoch(state):
    payment_index = SLOTS_PER_EPOCH + data.slot % SLOTS_PER_EPOCH
else:
    payment_index = data.slot % SLOTS_PER_EPOCH
```

The payment array has **32 slots** (minimal config):
- Slots 0-15: Previous epoch
- Slots 16-31: Current epoch

When attestation targets current epoch for slot 8:
- Wrong calculation: `8 % 32 = 8` ❌
- Correct calculation: `16 + 8 % 16 = 24` ✅

**The payment was created at index 24 by `process_execution_payload_bid`, but we're looking at index 8!**

---

## Constants Needed

```rust
// In consensus/types/src/consts/altair.rs or gloas.rs

/// 60% threshold for builder payment
pub const BUILDER_PAYMENT_THRESHOLD_NUMERATOR: u64 = 3;
pub const BUILDER_PAYMENT_THRESHOLD_DENOMINATOR: u64 = 5;

/// Self-build sentinel value
pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;

/// Flag to distinguish builder indices from validator indices
pub const BUILDER_INDEX_FLAG: u64 = 1 << 40;
```

---

## Summary

**To reach 100% test pass rate**, we need:

1. ✅ **IMMEDIATE FIX**: Update payment indexing in `process_attestation`
   - Add epoch-aware offset
   - Track `will_set_new_flag`
   - Write payment back to state

2. ❌ **REQUIRED**: Implement `process_execution_payload_bid`
   - The test pre-state likely expects this to have run
   - Creates payments that attestations then update

3. ✅ **ALREADY DONE**: Participation flags, same-slot detection, validation

**Estimated Impact**:
- Fix #1 alone: Should get us to **100%** ✅
- Fix #2: Enables actual block processing in production

**Files to Modify**:
- `consensus/state_processing/src/per_block_processing/process_operations.rs` (attestation fix)
- `consensus/state_processing/src/per_block_processing.rs` (add bid processing)
- `consensus/state_processing/src/per_block_processing/mod.rs` (new function)
