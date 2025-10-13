use proto_array::{ExecutionStatus, ProtoNode};
use types::{AttestationShufflingId, ChainSpec, Checkpoint, Epoch, Hash256, Slot};

/// A block that is to be applied to the fork choice.
///
/// A simplified version of `types::BeaconBlock`.
#[derive(Clone, Debug, PartialEq)]
pub struct Block {
    pub slot: Slot,
    pub root: Hash256,
    pub parent_root: Option<Hash256>,
    pub state_root: Hash256,
    pub target_root: Hash256,
    pub current_epoch_shuffling_id: AttestationShufflingId,
    pub next_epoch_shuffling_id: AttestationShufflingId,
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    /// Indicates if an execution node has marked this block as valid. Also contains the execution
    /// block hash.
    pub execution_status: ExecutionStatus,
    pub unrealized_justified_checkpoint: Option<Checkpoint>,
    pub unrealized_finalized_checkpoint: Option<Checkpoint>,
}

impl Block {
    /// Compute the proposer shuffling decision root of a child block in `child_block_epoch`.
    ///
    /// This function assumes that `child_block_epoch >= self.epoch`. It is the responsibility of
    /// the caller to check this condition, or else incorrect results will be produced.
    pub fn proposer_shuffling_root_for_child_block(
        &self,
        child_block_epoch: Epoch,
        spec: &ChainSpec,
    ) -> Hash256 {
        let block_epoch = self.current_epoch_shuffling_id.shuffling_epoch;

        // For child blocks in the Fulu fork epoch itself, we want to use the old logic. There is no
        // lookahead in the first Fulu epoch. So we check whether Fulu is enabled at
        // `child_block_epoch - 1`, i.e. whether `child_block_epoch > fulu_fork_epoch`.
        if !spec
            .fork_name_at_epoch(child_block_epoch.saturating_sub(1_u64))
            .fulu_enabled()
        {
            // Prior to Fulu the proposer shuffling decision root for the current epoch is the same
            // as the attestation shuffling for the *next* epoch, i.e. it is determined at the start
            // of the current epoch.
            if block_epoch == child_block_epoch {
                self.next_epoch_shuffling_id.shuffling_decision_block
            } else {
                // Otherwise, the child block epoch is greater, so its decision root is its parent
                // root itself (this block's root).
                self.root
            }
        } else {
            // After Fulu the proposer shuffling is determined with lookahead, so if the block
            // lies in the same epoch as its parent, its decision root is the same as the
            // parent's current epoch attester shuffling
            //
            // i.e. the block from the end of epoch N - 2.
            if child_block_epoch == block_epoch {
                self.current_epoch_shuffling_id.shuffling_decision_block
            } else if child_block_epoch == block_epoch + 1 {
                // If the block is the next epoch, then it instead shares its decision root with
                // the parent's *next epoch* attester shuffling.
                self.next_epoch_shuffling_id.shuffling_decision_block
            } else {
                // The child block lies in the future beyond the lookahead, at the point where this
                // block (its parent) will be the decision block.
                self.root
            }
        }
    }

    fn to_proto_node(self, parent_index: Option<usize>) -> ProtoNode {
        ProtoNode {
            slot: self.slot,
            root: self.root,
            target_root: self.target_root,
            current_epoch_shuffling_id: self.current_epoch_shuffling_id,
            next_epoch_shuffling_id: self.next_epoch_shuffling_id,
            state_root: self.state_root,
            parent: parent_index,
            justified_checkpoint: self.justified_checkpoint,
            finalized_checkpoint: self.finalized_checkpoint,
            weight: 0,
            best_child: None,
            best_descendant: None,
            execution_status: self.execution_status,
            unrealized_justified_checkpoint: self.unrealized_justified_checkpoint,
            unrealized_finalized_checkpoint: self.unrealized_finalized_checkpoint,
        };
    }
}
