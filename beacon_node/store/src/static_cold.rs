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

#[cfg(test)]
mod tests {
    use crate::ColdStore;

    use super::*;
    use tempfile::TempDir;
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

    struct TestFixture {
        #[allow(dead_code)]
        temp_dir: TempDir,
        store: StaticColdStore<E>,
    }

    impl TestFixture {
        fn new() -> Self {
            let temp_dir = TempDir::new().unwrap();
            let store = StaticColdStore::open(temp_dir.path(), &default_config()).unwrap();
            Self { temp_dir, store }
        }
    }

    fn default_config() -> StoreConfig {
        StoreConfig::default()
    }

    fn make_test_data(slot: Slot, size: usize) -> Vec<u8> {
        // Deterministic test data: slot number repeated
        vec![slot.as_u64() as u8; size]
    }

    #[test]
    fn test_get_on_empty_store_returns_none() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        assert_eq!(fixture.store.get(column, Slot::new(0)).unwrap(), None);
        assert_eq!(fixture.store.get(column, Slot::new(99999)).unwrap(), None);
        assert!(!fixture.store.contains(column, Slot::new(0)).unwrap());
    }

    #[test]
    fn test_open() {
        let temp_dir = TempDir::new().unwrap();
        let _store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();

        for column in DBColumnCold::iter() {
            let cfg = column_config(column);

            let col_path = temp_dir.path().join(cfg.subdir);
            assert!(
                col_path.exists(),
                "Column directory should exist: {:?}",
                col_path
            );

            let conf_path = col_path.join(CONFIG_FILE);
            assert!(
                conf_path.exists(),
                "Column config should exist: {:?}",
                conf_path
            );
        }
    }

    #[test]
    fn test_persistence_across_reopen() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();

            for i in 0..32u64 {
                let slot = Slot::new(i);
                store
                    .put(column, slot, &make_test_data(slot, 1024))
                    .unwrap();
            }
        }

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();

            for i in 0..32u64 {
                let slot = Slot::new(i);
                let value = store
                    .get(column, slot)
                    .unwrap()
                    .expect("Slot should persist across reopen");

                assert_eq!(value, make_test_data(slot, 1024));
            }
        }
    }

    #[test]
    fn test_compressed_and_uncompressed_columns_round_trip() {
        let fixture = TestFixture::new();
        let slot = Slot::new(42);
        let payload = vec![0xAB; 8192];

        let compressed_column = DBColumnCold::Block;
        let uncompressed_column = DBColumnCold::StateSnapshot;

        fixture
            .store
            .put(compressed_column, slot, &payload)
            .unwrap();
        fixture
            .store
            .put(uncompressed_column, slot, &payload)
            .unwrap();

        let compressed = fixture.store.get(compressed_column, slot).unwrap().unwrap();
        let uncompressed = fixture
            .store
            .get(uncompressed_column, slot)
            .unwrap()
            .unwrap();

        assert_eq!(compressed, payload);
        assert_eq!(uncompressed, payload);
        assert_eq!(compressed, uncompressed);
    }

    #[test]
    fn test_iter_from_returns_committed_slots_in_order_and_skips_gaps() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::BlockRoots;

        fixture
            .store
            .put(column, Slot::new(0), &make_test_data(Slot::new(0), 32))
            .unwrap();
        fixture
            .store
            .put(column, Slot::new(3), &make_test_data(Slot::new(3), 32))
            .unwrap();
        fixture
            .store
            .put(column, Slot::new(7), &make_test_data(Slot::new(7), 32))
            .unwrap();

        let results: Vec<(Slot, Vec<u8>)> =
            ColdStore::iter_from(&fixture.store, column, Slot::new(0))
                .collect::<Result<_, _>>()
                .unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, Slot::new(0));
        assert_eq!(results[1].0, Slot::new(3));
        assert_eq!(results[2].0, Slot::new(7));
    }

    #[test]
    fn test_iter_from_mid_range_skips_gap() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::BlockRoots;

        fixture
            .store
            .put(column, Slot::new(0), &make_test_data(Slot::new(0), 32))
            .unwrap();
        fixture
            .store
            .put(column, Slot::new(5), &make_test_data(Slot::new(5), 32))
            .unwrap();
        fixture
            .store
            .put(column, Slot::new(7), &make_test_data(Slot::new(7), 32))
            .unwrap();

        let results: Vec<(Slot, Vec<u8>)> =
            ColdStore::iter_from(&fixture.store, column, Slot::new(3))
                .collect::<Result<_, _>>()
                .unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, Slot::new(5));
        assert_eq!(results[1].0, Slot::new(7));
    }

    #[test]
    fn test_iter_from_past_highest_returns_empty() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::BlockRoots;

        fixture
            .store
            .put(column, Slot::new(5), &make_test_data(Slot::new(5), 32))
            .unwrap();

        let results: Vec<_> = ColdStore::iter_from(&fixture.store, column, Slot::new(6))
            .collect::<Result<_, _>>()
            .unwrap();

        assert!(results.is_empty());
    }

    #[test]
    fn test_put_batch_empty_is_noop() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;
        fixture.store.put_batch(column, vec![]).unwrap();
        assert!(fixture.store.get(column, Slot::new(0)).unwrap().is_none());
    }

    #[test]
    fn test_put_get_single() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;
        let slot = Slot::new(100);
        let data = make_test_data(slot, 1024);

        fixture.store.put(column, slot, &data).unwrap();

        let retrieved = fixture
            .store
            .get(column, slot)
            .unwrap()
            .expect("Data should be retrievable");

        assert_eq!(data, retrieved)
    }

    #[test]
    fn test_put_get_multiple() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        let items: Vec<(Slot, Vec<u8>)> = (0..100)
            .map(|i| {
                let slot = Slot::new(i as u64);
                let data = make_test_data(slot, 512 + i * 10);
                (slot, data)
            })
            .collect();

        fixture.store.put_batch(column, items.clone()).unwrap();

        for (slot, expected_data) in items {
            let retrived = fixture
                .store
                .get(column, slot)
                .unwrap()
                .expect("Each slot should be readable");
            assert_eq!(expected_data, retrived, "Mismatch at slot {}", slot);
        }
    }

    #[test]
    fn test_put_get_all_columns() {
        let fixture = TestFixture::new();
        let slot = Slot::new(50);

        let columns = vec![
            (DBColumnCold::Block, 4096),
            (DBColumnCold::BlockRoots, 32),
            (DBColumnCold::StateRoots, 32),
            (DBColumnCold::StateSnapshot, 8192),
            (DBColumnCold::StateDiff, 2048),
        ];

        for (column, size) in columns {
            let data = make_test_data(slot, size);
            fixture.store.put(column, slot, &data).unwrap();

            let retrieved = fixture
                .store
                .get(column, slot)
                .unwrap()
                .expect("Should be readable");
            assert_eq!(data, retrieved, "Mismatch in column {:?}", column);
        }
    }

    #[test]
    fn test_single_put_out_of_order_rejected() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        fixture
            .store
            .put(
                column,
                Slot::new(100),
                &make_test_data(Slot::new(100), 1024),
            )
            .unwrap();

        let result = fixture
            .store
            .put(column, Slot::new(99), &make_test_data(Slot::new(99), 1024));
        assert!(
            result.is_err(),
            "Single put should reject out-of-order slot"
        );
    }

    #[test]
    fn test_put_batch_out_of_order_rejects() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        // Attempt to write in descending order
        let items = vec![
            (Slot::new(100), make_test_data(Slot::new(100), 1024)),
            (Slot::new(99), make_test_data(Slot::new(99), 1024)),
        ];

        let result = fixture.store.put_batch(column, items);
        assert!(result.is_err(), "Should reject out of order");
    }

    #[test]
    fn test_put_batch_crosses_file_boundary() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        // Write slots 8190 and 8191 first (file 0)
        fixture
            .store
            .put(
                column,
                Slot::new(8190),
                &make_test_data(Slot::new(8190), 512),
            )
            .unwrap();
        fixture
            .store
            .put(
                column,
                Slot::new(8191),
                &make_test_data(Slot::new(8191), 512),
            )
            .unwrap();

        // Batch that crosses from file 0 into file 1
        let items = vec![
            (Slot::new(8192), make_test_data(Slot::new(8192), 512)),
            (Slot::new(8193), make_test_data(Slot::new(8193), 512)),
        ];
        fixture.store.put_batch(column, items).unwrap();

        // Verify all four slots are readable
        for slot in [8190u64, 8191, 8192, 8193] {
            let s = Slot::new(slot);
            let data = fixture
                .store
                .get(column, s)
                .unwrap()
                .expect("slot should exist");
            assert_eq!(
                data,
                make_test_data(s, 512),
                "Data mismatch at slot {}",
                slot
            );
        }
    }

    #[test]
    fn test_put_batch_idempotent_first_item_then_new_slots() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        fixture
            .store
            .put(column, Slot::new(0), &make_test_data(Slot::new(0), 1024))
            .unwrap();

        // Batch where first item is a re-put of slot 0 (same bytes),
        // followed by genuinely new slots.
        let items = vec![
            (Slot::new(0), make_test_data(Slot::new(0), 1024)),
            (Slot::new(1), make_test_data(Slot::new(1), 1024)),
            (Slot::new(2), make_test_data(Slot::new(2), 1024)),
        ];
        fixture.store.put_batch(column, items).unwrap();

        assert_eq!(
            fixture.store.get(column, Slot::new(0)).unwrap(),
            Some(make_test_data(Slot::new(0), 1024))
        );
        assert_eq!(
            fixture.store.get(column, Slot::new(1)).unwrap(),
            Some(make_test_data(Slot::new(1), 1024))
        );
        assert_eq!(
            fixture.store.get(column, Slot::new(2)).unwrap(),
            Some(make_test_data(Slot::new(2), 1024))
        );
    }

    #[test]
    fn test_put_batch_rejects_mismatched_first_item_at_highest_slot() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;

        fixture
            .store
            .put(column, Slot::new(0), &make_test_data(Slot::new(0), 1024))
            .unwrap();

        let items = vec![
            (Slot::new(0), make_test_data(Slot::new(0), 999)), // different size
            (Slot::new(1), make_test_data(Slot::new(1), 1024)),
        ];
        let result = fixture.store.put_batch(column, items);
        assert!(
            result.is_err(),
            "Mismatched re-put in batch should be rejected"
        );
    }

    #[test]
    fn test_identical_reput_at_committed_slot_succeeds() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;
        let slot = Slot::new(50);
        let data = make_test_data(slot, 1024);

        fixture.store.put(column, slot, &data).unwrap();

        // Re-write identical data at same slot
        let result = fixture.store.put(column, slot, &data);
        assert!(result.is_ok());

        let retrieved = fixture.store.get(column, slot).unwrap();
        assert_eq!(retrieved, Some(data));
    }

    #[test]
    fn test_mismatched_value_at_committed_slot_rejected() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;
        let slot = Slot::new(50);
        let data1 = make_test_data(slot, 1024);
        let mut data2 = make_test_data(slot, 1024);
        data2[0] = data2[0] + 1;

        fixture.store.put(column, slot, &data1).unwrap();

        // Different write to same slot
        let result = fixture.store.put(column, slot, &data2);

        assert!(
            result.is_err(),
            "Should reject conflicting data at same slot"
        );

        // Verify orginal data is intact
        let retrieved = fixture
            .store
            .get(column, slot)
            .unwrap()
            .expect("Should be retrievable");
        assert_eq!(data1, retrieved);
    }

    #[test]
    fn test_cannot_fill_previously_skipped_slot() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::BlockRoots;

        // Write slot 0 and slot 5, skipping 1-4
        fixture
            .store
            .put(column, Slot::new(0), &make_test_data(Slot::new(0), 32))
            .unwrap();
        fixture
            .store
            .put(column, Slot::new(5), &make_test_data(Slot::new(5), 32))
            .unwrap();

        let result = fixture
            .store
            .put(column, Slot::new(2), &make_test_data(Slot::new(2), 32));
        assert!(
            result.is_err(),
            "Should reject filling a previously-skipped slot"
        );
    }

    #[test]
    fn test_contains() {
        let fixture = TestFixture::new();
        let column = DBColumnCold::Block;
        let slot = Slot::new(42);

        assert!(!fixture.store.contains(column, slot).unwrap());

        fixture
            .store
            .put(column, slot, &make_test_data(slot, 1024))
            .unwrap();

        assert!(fixture.store.contains(column, slot).unwrap());
        assert!(!fixture.store.contains(column, Slot::new(43)).unwrap());
    }

    #[test]
    fn test_reopen_truncates_uncommitted_data_tail() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;
        let cfg = column_config(column);

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            store
                .put(column, Slot::new(0), &make_test_data(Slot::new(0), 1024))
                .unwrap();
        }

        let data_path = temp_dir.path().join(cfg.subdir).join("data_00000");

        let committed_len = std::fs::metadata(&data_path).unwrap().len();

        {
            let mut f = OpenOptions::new().append(true).open(&data_path).unwrap();
            f.write_all(b"UNCOMMITTED_GARBAGE").unwrap();
            f.sync_all().unwrap();
        }

        let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();

        let healed_len = std::fs::metadata(&data_path).unwrap().len();
        assert_eq!(
            healed_len, committed_len,
            "Uncommitted tail should be truncated"
        );

        assert_eq!(
            store.get(column, Slot::new(0)).unwrap(),
            Some(make_test_data(Slot::new(0), 1024))
        );
        assert!(store.get(column, Slot::new(1)).unwrap().is_none());
    }

    #[test]
    fn test_reopen_truncates_incomplete_payload() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;
        let cfg = column_config(column);

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            store
                .put(column, Slot::new(0), &make_test_data(Slot::new(0), 1024))
                .unwrap();
        }

        let data_path = temp_dir.path().join(cfg.subdir).join("data_00000");

        {
            let mut f = OpenOptions::new().append(true).open(&data_path).unwrap();

            let mut header = vec![0u8; 8];
            header[0] = 0x01;
            header[2..6].copy_from_slice(&4096u32.to_le_bytes());
            f.write_all(&header).unwrap();

            f.write_all(&vec![0xAA; 128]).unwrap();
            f.sync_all().unwrap();
        }

        let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();

        assert_eq!(
            store.get(column, Slot::new(0)).unwrap(),
            Some(make_test_data(Slot::new(0), 1024))
        );

        assert!(store.get(column, Slot::new(1)).unwrap().is_none());
    }

    #[test]
    fn test_corrupted_offset_within_committed_range_causes_read_error() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;
        let cfg = column_config(column);

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            store
                .put(column, Slot::new(0), &make_test_data(Slot::new(0), 256))
                .unwrap();
            store
                .put(column, Slot::new(1), &make_test_data(Slot::new(1), 256))
                .unwrap();
        }

        // Corrupt slot 1's offset to point to a garbage position.
        // The conf says highest_written_slot = 1 and current_data_len is
        // the true length, so heal won't zero this - it's within the
        // committed range. This tests that a corrupted offset yields a
        // read error rather than silent corruption.
        {
            let off_path = temp_dir.path().join(cfg.subdir).join("data_00000.off");
            let mut f = OpenOptions::new().write(true).open(&off_path).unwrap();
            f.seek(SeekFrom::Start(8)).unwrap();
            f.write_all(&u64::MAX.to_le_bytes()).unwrap();
            f.sync_all().unwrap();
        }

        let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
        // Slot 0 is untouched and should still be readable.
        assert_eq!(
            store.get(column, Slot::new(0)).unwrap(),
            Some(make_test_data(Slot::new(0), 256))
        );
        // Slot 1's offset now points to u64::MAX, past the data file.
        assert!(store.get(column, Slot::new(1)).is_err());
    }

    #[test]
    fn test_reopen_clears_stale_offsets_beyond_committed_slot() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;
        let cfg = column_config(column);

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            store
                .put(column, Slot::new(0), &make_test_data(Slot::new(0), 256))
                .unwrap();
            store
                .put(column, Slot::new(5), &make_test_data(Slot::new(5), 256))
                .unwrap();
        }

        {
            let off_path = temp_dir.path().join(cfg.subdir).join("data_00000.off");

            let mut f = OpenOptions::new().write(true).open(&off_path).unwrap();
            let pos = 10 * 8;
            f.seek(SeekFrom::Start(pos)).unwrap();
            f.write_all(&9999u64.to_le_bytes()).unwrap();
            f.sync_all().unwrap();
        }

        let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();

        assert!(store.get(column, Slot::new(10)).unwrap().is_none());

        assert_eq!(
            store.get(column, Slot::new(0)).unwrap(),
            Some(make_test_data(Slot::new(0), 256))
        );
        assert_eq!(
            store.get(column, Slot::new(5)).unwrap(),
            Some(make_test_data(Slot::new(5), 256))
        );
    }

    #[test]
    fn test_corrupted_column_conf_causes_open_failure() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;
        let cfg = column_config(column);

        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            store
                .put(column, Slot::new(0), &make_test_data(Slot::new(0), 64))
                .unwrap();
        }

        let conf_path = temp_dir.path().join(cfg.subdir).join(CONFIG_FILE);
        std::fs::write(&conf_path, b"NOT_A_VALID_CONFIG").unwrap();

        let result = StaticColdStore::<E>::open(temp_dir.path(), &default_config());
        assert!(result.is_err(), "Corrupted conf should prevent opening");
    }

    #[test]
    fn test_max_value_bytes_ratchets_up_with_larger_default() {
        let temp_dir = TempDir::new().unwrap();
        let column = DBColumnCold::Block;
        let cfg = column_config(column);
        let conf_path = temp_dir.path().join(cfg.subdir).join(CONFIG_FILE);

        // Open with default config (Block has max_value_bytes = 10MB)
        {
            let store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            store
                .put(column, Slot::new(0), &make_test_data(Slot::new(0), 64))
                .unwrap();
        }

        {
            let mut on_disk = read_config(&conf_path).unwrap();

            // Simulate an older build with a smaller persisted limit.
            on_disk.max_value_bytes = 1024;

            let tmp_path = temp_dir.path().join(cfg.subdir).join(CONFIG_TMP_FILE);

            let downgraded = ColumnConfig {
                subdir: cfg.subdir,
                record_type: on_disk.record_type,
                compression: on_disk.compression,
                max_value_bytes: on_disk.max_value_bytes,
            };

            atomic_write_config(
                &conf_path,
                &tmp_path,
                &temp_dir.path().join(cfg.subdir),
                on_disk.highest_written_slot,
                on_disk.current_data_len,
                &downgraded,
            )
            .unwrap();
        }

        // Reopen with default config - the 10MB default should ratchet up
        // the on-disk 1024 to 10MB.
        {
            let _store = StaticColdStore::<E>::open(temp_dir.path(), &default_config()).unwrap();
            let on_disk = read_config(&conf_path).unwrap();
            assert_eq!(on_disk.max_value_bytes, 10 * 1024 * 1024);
        }
    }
}
