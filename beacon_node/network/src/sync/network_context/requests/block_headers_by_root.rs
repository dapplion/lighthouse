use super::{ActiveRequestItems, LookupVerifyError};
use std::sync::Arc;
use types::{Hash256, SignedBeaconBlockHeader};

/// Accumulates the response of a `beacon_block_headers_by_root` request. The responder walks the
/// parent chain of `beacon_root` (inclusive) and emits up to `count` headers in descending slot
/// order, so the first chunk MUST be `beacon_root` and the rest are its ancestors.
pub struct BlockHeadersByRootRequestItems {
    beacon_root: Hash256,
    count: usize,
    items: Vec<Arc<SignedBeaconBlockHeader>>,
}

impl BlockHeadersByRootRequestItems {
    pub fn new(beacon_root: Hash256, count: usize) -> Self {
        Self {
            beacon_root,
            count,
            items: vec![],
        }
    }
}

impl ActiveRequestItems for BlockHeadersByRootRequestItems {
    type Item = Arc<SignedBeaconBlockHeader>;

    /// Append a response chunk. The headers must form a parent chain in strictly descending slot
    /// order, with the tip (first chunk) equal to the requested `beacon_root`.
    fn add(&mut self, header: Self::Item) -> Result<bool, LookupVerifyError> {
        let root = header.message.canonical_root();
        if let Some(child) = self.items.last() {
            if child.message.parent_root != root {
                return Err(LookupVerifyError::UnrequestedBlockRoot(root));
            }
            if header.message.slot >= child.message.slot {
                return Err(LookupVerifyError::UnrequestedSlot(header.message.slot));
            }
        } else if self.beacon_root != root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(root));
        }

        self.items.push(header);
        // Fewer than `count` is legal — the walk may hit `min_slot` or the serving range — in
        // which case the request completes on stream termination.
        Ok(self.items.len() >= self.count)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
