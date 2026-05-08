//! Slot-keyed durable archive for finalized blinded blocks.
//!
//! `StaticBlockStore` is a black box from `HotColdDB`'s perspective: hand it block bytes,
//! ask it for them back by slot, ask it how far it has durably stored. Era boundaries,
//! file format, manifest layout, sealing, and rename semantics are entirely internal.
//!
//! Contract:
//! - `put(slot, bytes)` is durable on return. The caller is allowed to rely on this for
//!   source-of-truth flips (e.g. writing a reverse-index entry, deleting from hot KV).

use crate::Error;
use std::path::{Path, PathBuf};
use types::Slot;

#[derive(Debug)]
pub struct StaticBlockStore {
    #[allow(dead_code)]
    root_dir: PathBuf,
}

impl StaticBlockStore {
    /// Open the archive rooted at `path`.
    pub fn open(_path: &Path) -> Result<Self, Error> {
        todo!()
    }

    /// Read the block at `slot`, if present.
    pub fn get(&self, _slot: Slot) -> Result<Option<Vec<u8>>, Error> {
        todo!()
    }

    /// Durably store `bytes` at `slot`. Must not return `Ok` until the bytes are recoverable
    /// after a crash.
    pub fn put(&self, _slot: Slot, _bytes: &[u8]) -> Result<(), Error> {
        todo!()
    }
}
