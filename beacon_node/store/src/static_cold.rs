//! Lighthouse cold-DB façade over the `static_file_storage` library.
//!
//! `StaticColdStore` registers one `StaticFile` per cold column under
//! `<root>/{blk,bbr,bsr,bss,bsd}/`, plus an embedded KV at `<root>/index/`
//! for root-keyed indices (e.g. `ColdStateSummary`). All file-format,
//! durability, and recovery semantics live in `static_file_storage` —
//! see `common/static_file_storage/src/lib.rs` and
//! `specs/static-cold-backend.md`.

use crate::config::StoreConfig;
use crate::database::interface::BeaconNodeBackend;
use crate::{DBColumnCold, KeyValueStore};
use static_file_storage::{Config as StaticFileConfig, Error as StaticFileError, StaticFile};
use std::{collections::HashMap, fs, marker::PhantomData, path::Path};
use strum::IntoEnumIterator;
use types::{EthSpec, Slot};

/// Per-column on-disk subdir + file-format settings. On first creation the
/// build's values are persisted; the on-disk values win on re-open (with
/// `max_value_bytes` ratcheted upward by the library when the build's default
/// is larger).
#[derive(Debug, Clone, Copy)]
struct ColumnConfig {
    /// On-disk subdirectory name under the store root. Stable across builds.
    subdir: &'static str,
    file: StaticFileConfig,
}

fn column_config(column: DBColumnCold) -> ColumnConfig {
    match column {
        DBColumnCold::Block => ColumnConfig {
            subdir: "blk",
            file: StaticFileConfig {
                record_type: [0x01, 0x00],
                compression: true,
                max_value_bytes: 10 * 1024 * 1024,
            },
        },
        DBColumnCold::BlockRoots => ColumnConfig {
            subdir: "bbr",
            file: StaticFileConfig {
                record_type: [0x02, 0x00],
                compression: false,
                max_value_bytes: 64,
            },
        },
        DBColumnCold::StateRoots => ColumnConfig {
            subdir: "bsr",
            file: StaticFileConfig {
                record_type: [0x03, 0x00],
                compression: false,
                max_value_bytes: 64,
            },
        },
        DBColumnCold::StateSnapshot => ColumnConfig {
            subdir: "bss",
            file: StaticFileConfig {
                record_type: [0x04, 0x00],
                compression: false,
                max_value_bytes: 1024 * 1024 * 1024,
            },
        },
        DBColumnCold::StateDiff => ColumnConfig {
            // HDiff is already compressed internally (zstd'd validator and
            // balance chunks; xdelta3 state diff). No benefit to wrapping it
            // in snappy here.
            subdir: "bsd",
            file: StaticFileConfig {
                record_type: [0x05, 0x00],
                compression: false,
                max_value_bytes: 1024 * 1024 * 1024,
            },
        },
    }
}

pub struct StaticColdStore<E: EthSpec> {
    /// All cold columns the static archive backs, opened eagerly at boot.
    /// Frozen after construction; per-column writer state is locked inside
    /// each `StaticFile`.
    columns: HashMap<DBColumnCold, StaticFile>,
    /// Embedded KV for root-keyed indices (e.g. `ColdStateSummary`). The
    /// slot-keyed file backend is the bulk archive; this side-table lets us
    /// look up `state_root → slot` without scanning the bulk files.
    index_db: BeaconNodeBackend<E>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> StaticColdStore<E> {
    /// Open the archive rooted at `path`. Every cold column is opened eagerly
    /// so subsequent reads/writes are pure hashmap lookups with no I/O on the
    /// hot path. An embedded KV is opened at `<path>/index/` for the
    /// root-keyed indices.
    pub fn open(path: &Path, config: &StoreConfig) -> Result<Self, crate::Error> {
        fs::create_dir_all(path).map_err(StaticFileError::Io)?;
        let mut columns = HashMap::new();
        for column in DBColumnCold::iter() {
            let cfg = column_config(column);
            columns.insert(column, StaticFile::open(path.join(cfg.subdir), cfg.file)?);
        }
        let index_db = BeaconNodeBackend::open(config, &path.join("index"))?;
        Ok(Self {
            columns,
            index_db,
            _phantom: PhantomData,
        })
    }
}

// Slot-keyed columns are served from the static files; root-keyed index
// columns are served from the embedded KV at `<root>/index/`.
impl<E: EthSpec> crate::ColdStore<E> for StaticColdStore<E> {
    fn get(&self, c: DBColumnCold, slot: Slot) -> Result<Option<Vec<u8>>, crate::Error> {
        self.columns[&c].get(slot.as_u64()).map_err(Into::into)
    }

    fn put_batch(&self, c: DBColumnCold, items: Vec<(Slot, Vec<u8>)>) -> Result<(), crate::Error> {
        let items = items.into_iter().map(|(s, v)| (s.as_u64(), v)).collect();
        self.columns[&c].put_batch(items).map_err(Into::into)
    }

    fn contains(&self, c: DBColumnCold, slot: Slot) -> Result<bool, crate::Error> {
        self.columns[&c].contains(slot.as_u64()).map_err(Into::into)
    }

    fn iter_from(&self, c: DBColumnCold, from: Slot) -> crate::SlotIter<'_> {
        // TODO(static): this is O(highest - from) reads, one File::open per slot,
        // and most slots in sparse columns (StateSnapshot/StateDiff) yield None.
        // Acceptable today because iter_from is only used by infrequent paths
        // (forwards iter, invariants). Improve if it becomes a hotspot.
        let column = &self.columns[&c];
        let Some(highest) = column.highest_written_slot() else {
            return Box::new(std::iter::empty());
        };
        let from = from.as_u64();
        if from > highest {
            return Box::new(std::iter::empty());
        }
        Box::new(
            (from..=highest).filter_map(move |slot| match column.get(slot) {
                Ok(Some(value)) => Some(Ok((Slot::new(slot), value))),
                Ok(None) => None,
                Err(e) => Some(Err(e.into())),
            }),
        )
    }

    fn get_index(
        &self,
        c: crate::DBColumnColdIndex,
        root: types::Hash256,
    ) -> Result<Option<Slot>, crate::Error> {
        use ssz::Decode;
        Ok(self
            .index_db
            .get_bytes(c.db_column(), root.as_slice())?
            .map(|bytes| Slot::from_ssz_bytes(&bytes))
            .transpose()?)
    }

    fn put_index_batch(
        &self,
        c: crate::DBColumnColdIndex,
        items: Vec<(types::Hash256, Slot)>,
    ) -> Result<(), crate::Error> {
        use ssz::Encode;
        let col = c.db_column();
        let ops = items
            .into_iter()
            .map(|(root, slot)| {
                crate::KeyValueStoreOp::PutKeyValue(
                    col,
                    root.as_slice().to_vec(),
                    slot.as_ssz_bytes(),
                )
            })
            .collect();
        self.index_db.do_atomically(ops)
    }

    fn iter_index(&self, c: crate::DBColumnColdIndex) -> crate::IndexIter<'_> {
        use ssz::Decode;
        Box::new(
            self.index_db
                .iter_column::<types::Hash256>(c.db_column())
                .map(|res| res.and_then(|(root, value)| Ok((root, Slot::from_ssz_bytes(&value)?)))),
        )
    }

    fn sync(&self) -> Result<(), crate::Error> {
        KeyValueStore::sync(&self.index_db)
    }
}
