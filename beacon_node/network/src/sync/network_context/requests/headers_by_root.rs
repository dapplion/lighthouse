use super::{ActiveRequestItems, LookupVerifyError};
use types::{BeaconBlockHeader, Hash256};

pub struct HeadersByRootRequestItems {
    next_block_root: Hash256,
    max_count: usize,
    items: Vec<BeaconBlockHeader>,
}

impl HeadersByRootRequestItems {
    pub fn new(block_root: Hash256, max_count: usize) -> Self {
        Self {
            next_block_root: block_root,
            max_count,
            items: vec![],
        }
    }
}

impl ActiveRequestItems for HeadersByRootRequestItems {
    type Item = BeaconBlockHeader;

    /// Append a response to the single chunk request. If the chunk is valid, the request is
    /// resolved immediately.
    /// The active request SHOULD be dropped after `add_response` returns an error
    fn add(&mut self, header: Self::Item) -> Result<bool, LookupVerifyError> {
        let block_root = header.canonical_root();
        if self.next_block_root != block_root {
            return Err(LookupVerifyError::UnrequestedBlockRoot(block_root));
        }

        if self.items.len() >= self.max_count {
            return Err(LookupVerifyError::TooManyResponses);
        }

        self.next_block_root = header.parent_root;
        self.items.push(header);

        Ok(false)
    }

    fn consume(&mut self) -> Vec<Self::Item> {
        std::mem::take(&mut self.items)
    }
}
