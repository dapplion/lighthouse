//! Slot-keyed archive API for finalized blob sidecars.
//!
//! This is the minimal surface needed to test HotColdDB integration. The file
//! backend is intentionally not implemented yet.

use std::{
    fmt, io,
    path::{Path, PathBuf},
};
use types::Slot;

#[derive(Debug)]
pub struct StaticBlobStore {
    root_dir: PathBuf,
}

#[derive(Debug)]
pub enum StaticBlobStoreError {
    Io(io::Error),
    Unsupported(&'static str),
}

impl fmt::Display for StaticBlobStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "static blob store io error: {e}"),
            Self::Unsupported(message) => {
                write!(f, "static blob store unsupported operation: {message}")
            }
        }
    }
}

impl From<io::Error> for StaticBlobStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl StaticBlobStore {
    /// Open the archive rooted at `path`.
    pub fn open(path: &Path) -> Result<Self, StaticBlobStoreError> {
        Ok(Self {
            root_dir: path.to_path_buf(),
        })
    }

    /// Read SSZ-encoded blob sidecars for `slot`, if present.
    pub fn get(&self, _slot: Slot) -> Result<Option<Vec<u8>>, StaticBlobStoreError> {
        let _ = &self.root_dir;
        Err(StaticBlobStoreError::Unsupported("get"))
    }

    /// Store SSZ-encoded blob sidecars at `slot`.
    pub fn put(&self, _slot: Slot, _bytes: &[u8]) -> Result<(), StaticBlobStoreError> {
        let _ = &self.root_dir;
        Err(StaticBlobStoreError::Unsupported("put"))
    }
}
