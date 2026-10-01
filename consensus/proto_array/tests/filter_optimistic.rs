//! `filter_block_tree` with and without `ChainConfig::filter_optimistic_nodes`.
//!
//! Each test asserts the head both ways, as `(flag off, flag on)`.

use fixed_bytes::FixedBytesExtended;
use proto_array::{Block, ExecutionStatus, JustifiedBalances, PayloadStatus, ProtoArrayForkChoice};
use std::collections::BTreeSet;
use types::{
    AttestationShufflingId, ChainSpec, Checkpoint, Epoch, EthSpec, ExecutionBlockHash, Hash256,
    MainnetEthSpec, Slot,
};

type E = MainnetEthSpec;

fn root(i: u64) -> Hash256 {
    Hash256::from_low_u64_be(i)
}

fn payload(i: u64) -> ExecutionBlockHash {
    ExecutionBlockHash::from_root(root(i))
}

fn spec() -> ChainSpec {
    let mut spec = E::default_spec();
    spec.proposer_score_boost = 50;
    // Pre-Gloas: V17 nodes, one node per block.
    spec.gloas_fork_epoch = None;
    spec
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        epoch: Epoch::new(0),
        root: root(0),
    }
}

fn junk_shuffling_id() -> AttestationShufflingId {
    AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero())
}

/// A fork choice whose anchor is block 0 with a VALID payload.
fn rig() -> ProtoArrayForkChoice {
    ProtoArrayForkChoice::new::<E>(
        Slot::new(0),
        Slot::new(0),
        Hash256::zero(),
        checkpoint(),
        checkpoint(),
        junk_shuffling_id(),
        junk_shuffling_id(),
        ExecutionStatus::Valid(payload(0)),
        None,
        None,
        0,
        &spec(),
    )
    .unwrap()
}

fn add_block(
    fc: &mut ProtoArrayForkChoice,
    slot: u64,
    block: u64,
    parent: u64,
    execution_status: ExecutionStatus,
) {
    fc.process_block::<E>(
        Block {
            slot: Slot::new(slot),
            root: root(block),
            parent_root: Some(root(parent)),
            state_root: Hash256::zero(),
            target_root: Hash256::zero(),
            current_epoch_shuffling_id: junk_shuffling_id(),
            next_epoch_shuffling_id: junk_shuffling_id(),
            justified_checkpoint: checkpoint(),
            finalized_checkpoint: checkpoint(),
            execution_status,
            unrealized_justified_checkpoint: None,
            unrealized_finalized_checkpoint: None,
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
            proposer_index: Some(0),
            payload_received: false,
        },
        Slot::new(slot),
        &spec(),
        std::time::Duration::ZERO,
    )
    .unwrap();
}

fn head(fc: &mut ProtoArrayForkChoice, validators: usize, filter: bool) -> Hash256 {
    let balances = JustifiedBalances::from_effective_balances(vec![1; validators]).unwrap();
    fc.find_head::<E>(
        checkpoint(),
        checkpoint(),
        &balances,
        Hash256::zero(),
        &BTreeSet::new(),
        Slot::new(0),
        filter,
        &spec(),
    )
    .unwrap()
    .root()
}

/// The head with the flag off (spec behaviour) and on.
fn heads(fc: &mut ProtoArrayForkChoice, validators: usize) -> (Hash256, Hash256) {
    (head(fc, validators, false), head(fc, validators, true))
}

fn head_payload_status(
    fc: &mut ProtoArrayForkChoice,
    validators: usize,
    filter: bool,
) -> PayloadStatus {
    let balances = JustifiedBalances::from_effective_balances(vec![1; validators]).unwrap();
    fc.find_head::<E>(
        checkpoint(),
        checkpoint(),
        &balances,
        Hash256::zero(),
        &BTreeSet::new(),
        Slot::new(2),
        filter,
        &gloas_spec(),
    )
    .unwrap()
    .payload_status()
}

fn gloas_spec() -> ChainSpec {
    let mut spec = E::default_spec();
    spec.proposer_score_boost = 50;
    spec.gloas_fork_epoch = Some(Epoch::new(0));
    spec
}

fn status(fc: &ProtoArrayForkChoice, block: u64) -> ExecutionStatus {
    fc.get_block(&root(block)).unwrap().execution_status
}

/// A VALID import promotes its optimistic ancestors, so one validated block heals a whole run and
/// both settings agree again at once.
#[test]
fn importing_a_valid_child_promotes_its_optimistic_ancestors() {
    let mut fc = rig();
    add_block(&mut fc, 1, 1, 0, ExecutionStatus::Optimistic(payload(1)));
    add_block(&mut fc, 2, 2, 1, ExecutionStatus::Optimistic(payload(2)));
    assert_eq!(
        heads(&mut fc, 1),
        (root(2), root(0)),
        "filtering wedges the head at the anchor while both blocks are optimistic"
    );

    // The EL comes back and validates block 3. Executing it required blocks 1 and 2.
    add_block(&mut fc, 3, 3, 2, ExecutionStatus::Valid(payload(3)));

    assert_eq!(status(&fc, 1), ExecutionStatus::Valid(payload(1)));
    assert_eq!(status(&fc, 2), ExecutionStatus::Valid(payload(2)));
    assert_eq!(
        heads(&mut fc, 1),
        (root(3), root(3)),
        "one valid import heals the run and both settings agree"
    );
}

/// The case the heal cannot reach: while the EL is behind nothing imports VALID, so there is
/// nothing to propagate from.
#[test]
fn an_all_optimistic_chain_pins_the_head_at_the_last_valid_block() {
    let mut fc = rig();
    for block in 1..=10 {
        add_block(
            &mut fc,
            block,
            block,
            block - 1,
            ExecutionStatus::Optimistic(payload(block)),
        );
    }

    assert_eq!(
        heads(&mut fc, 1),
        (root(10), root(0)),
        "ten blocks imported; filtering leaves the head on the anchor"
    );
}

/// What filtering costs: block 1 carries every vote, block 2 carries none, and filtering still
/// picks block 2.
#[test]
fn filtering_overrides_lmd_weight_and_follows_the_valid_branch() {
    let mut fc = rig();
    add_block(&mut fc, 1, 1, 0, ExecutionStatus::Optimistic(payload(1)));

    // Every validator attests to the optimistic block.
    for validator in 0..3 {
        fc.process_attestation(validator, root(1), Slot::new(1), true)
            .unwrap();
    }

    // A proposer builds on the valid parent instead.
    add_block(&mut fc, 2, 2, 0, ExecutionStatus::Valid(payload(2)));
    assert_eq!(
        heads(&mut fc, 3),
        (root(1), root(2)),
        "spec follows the votes; filtering takes the unvoted valid sibling"
    );

    // The valid branch extends; neither rule is stuck, they just disagree.
    add_block(&mut fc, 3, 3, 2, ExecutionStatus::Valid(payload(3)));
    assert_eq!(heads(&mut fc, 3), (root(1), root(3)));
}

/// A Gloas block's own `FULL` node is reached by the `Pending` step, which bypasses the filtered
/// block tree. Filtering has to reject an unjudged payload there too, or the head is `FULL` on a
/// payload no EL has seen — the exact thing the flag is for.
#[test]
fn filtering_rejects_the_full_node_of_an_unjudged_gloas_payload() {
    let spec = gloas_spec();
    let mut fc = ProtoArrayForkChoice::new::<E>(
        Slot::new(0),
        Slot::new(0),
        Hash256::zero(),
        checkpoint(),
        checkpoint(),
        junk_shuffling_id(),
        junk_shuffling_id(),
        ExecutionStatus::Valid(payload(0)),
        Some(payload(0)),
        Some(payload(0)),
        0,
        &spec,
    )
    .unwrap();

    // Block 1 builds on the anchor's `EMPTY` side, so it hangs off a node the walk can reach.
    fc.process_block::<E>(
        Block {
            slot: Slot::new(1),
            root: root(1),
            parent_root: Some(root(0)),
            state_root: Hash256::zero(),
            target_root: Hash256::zero(),
            current_epoch_shuffling_id: junk_shuffling_id(),
            next_epoch_shuffling_id: junk_shuffling_id(),
            justified_checkpoint: checkpoint(),
            finalized_checkpoint: checkpoint(),
            execution_status: ExecutionStatus::NotYetRevealed(payload(1)),
            unrealized_justified_checkpoint: None,
            unrealized_finalized_checkpoint: None,
            execution_payload_parent_hash: Some(payload(99)),
            execution_payload_block_hash: Some(payload(1)),
            proposer_index: Some(0),
            payload_received: false,
        },
        Slot::new(1),
        &spec,
        std::time::Duration::ZERO,
    )
    .unwrap();

    // The envelope arrives but the EL is still syncing.
    fc.on_payload_envelope_received(root(1), ExecutionStatus::Optimistic(payload(1)))
        .unwrap();

    // Vote for the payload being present, so the `FULL` node outweighs `EMPTY`.
    for validator in 0..3 {
        fc.process_attestation(validator, root(1), Slot::new(2), true)
            .unwrap();
    }

    assert_eq!(head_payload_status(&mut fc, 3, false), PayloadStatus::Full);
    assert_eq!(head_payload_status(&mut fc, 3, true), PayloadStatus::Empty);
}
