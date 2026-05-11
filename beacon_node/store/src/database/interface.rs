#[cfg(feature = "leveldb")]
use crate::database::leveldb_impl;
#[cfg(feature = "redb")]
use crate::database::redb_impl;
use crate::{
    ColdStore, ColumnIter, ColumnKeyIter, DBColumn, DBColumnCold, DBColumnColdIndex, Error,
    IndexIter, ItemStore, Key, KeyValueStore, SlotIter, StaticColdStore, metrics,
};
use crate::{KeyValueStoreOp, StoreConfig, config::DatabaseBackend};
use ssz::{Decode, Encode};
use std::collections::HashSet;
use std::path::Path;
use types::EthSpec;
use types::{Hash256, Slot};

pub enum BeaconNodeBackend<E: EthSpec> {
    #[cfg(feature = "leveldb")]
    LevelDb(leveldb_impl::LevelDB<E>),
    #[cfg(feature = "redb")]
    Redb(redb_impl::Redb<E>),
}

impl<E: EthSpec> ItemStore<E> for BeaconNodeBackend<E> {}

/// Runtime selector for the cold backend.
///
/// Held by the production `HotColdDB` so the cold strategy can be picked at
/// startup based on `StoreConfig`. `Kv` keeps the existing behaviour
/// (everything in the KV store); `Static` uses the slot-keyed file backend.
///
/// The `Kv` arm inlines the byte-translation (slot/root → bytes) directly here
/// rather than going through an intermediate `impl ColdStore for BeaconNodeBackend`
/// — `BeaconNodeBackend` is only ever a `ColdStore` via this enum, so the
/// indirection isn't earning anything.
pub enum ColdBackend<E: EthSpec> {
    Kv(BeaconNodeBackend<E>),
    Static(StaticColdStore<E>),
}

impl<E: EthSpec> ColdStore<E> for ColdBackend<E> {
    fn get(&self, c: DBColumnCold, slot: Slot) -> Result<Option<Vec<u8>>, Error> {
        match self {
            Self::Kv(db) => db.get_bytes(c.db_column(), &slot.as_u64().to_be_bytes()),
            Self::Static(db) => ColdStore::<E>::get(db, c, slot),
        }
    }
    fn put_batch(&self, c: DBColumnCold, items: Vec<(Slot, Vec<u8>)>) -> Result<(), Error> {
        match self {
            Self::Kv(db) => {
                let col = c.db_column();
                let ops = items
                    .into_iter()
                    .map(|(slot, value)| {
                        crate::KeyValueStoreOp::PutKeyValue(
                            col,
                            slot.as_u64().to_be_bytes().to_vec(),
                            value,
                        )
                    })
                    .collect();
                db.do_atomically(ops)
            }
            Self::Static(db) => ColdStore::<E>::put_batch(db, c, items),
        }
    }
    fn contains(&self, c: DBColumnCold, slot: Slot) -> Result<bool, Error> {
        match self {
            Self::Kv(db) => db.key_exists(c.db_column(), &slot.as_u64().to_be_bytes()),
            Self::Static(db) => ColdStore::<E>::contains(db, c, slot),
        }
    }
    fn iter_from(&self, c: DBColumnCold, from: Slot) -> SlotIter<'_> {
        match self {
            Self::Kv(db) => Box::new(
                db.iter_column_from::<Vec<u8>>(c.db_column(), &from.as_u64().to_be_bytes())
                    .map(|res| {
                        res.and_then(|(key_bytes, value)| {
                            let bytes: [u8; 8] =
                                key_bytes.try_into().map_err(|_| Error::InvalidBytes)?;
                            Ok((Slot::new(u64::from_be_bytes(bytes)), value))
                        })
                    }),
            ),
            Self::Static(db) => ColdStore::<E>::iter_from(db, c, from),
        }
    }
    // `Slot::as_ssz_bytes()` is byte-identical to the legacy
    // `ColdStateSummary { slot }` wrapper so existing dbs round-trip without
    // migration. Pinned by `ssz_compat_with_legacy_summary` in `lib.rs`.
    fn get_index(&self, c: DBColumnColdIndex, root: Hash256) -> Result<Option<Slot>, Error> {
        match self {
            Self::Kv(db) => Ok(db
                .get_bytes(c.db_column(), root.as_slice())?
                .map(|bytes| Slot::from_ssz_bytes(&bytes))
                .transpose()?),
            Self::Static(db) => ColdStore::<E>::get_index(db, c, root),
        }
    }
    fn put_index_batch(
        &self,
        c: DBColumnColdIndex,
        items: Vec<(Hash256, Slot)>,
    ) -> Result<(), Error> {
        match self {
            Self::Kv(db) => {
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
                db.do_atomically(ops)
            }
            Self::Static(db) => ColdStore::<E>::put_index_batch(db, c, items),
        }
    }
    fn iter_index(&self, c: DBColumnColdIndex) -> IndexIter<'_> {
        match self {
            Self::Kv(db) => Box::new(db.iter_column::<Hash256>(c.db_column()).map(|res| {
                res.and_then(|(root, value)| Ok((root, Slot::from_ssz_bytes(&value)?)))
            })),
            Self::Static(db) => ColdStore::<E>::iter_index(db, c),
        }
    }
    fn sync(&self) -> Result<(), Error> {
        match self {
            Self::Kv(db) => KeyValueStore::sync(db),
            Self::Static(db) => ColdStore::<E>::sync(db),
        }
    }
}

impl<E: EthSpec> KeyValueStore<E> for BeaconNodeBackend<E> {
    fn get_bytes(&self, column: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::get_bytes(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::get_bytes(txn, column, key),
        }
    }

    fn put_bytes(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options(),
            ),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options(),
            ),
        }
    }

    fn put_bytes_sync(&self, column: DBColumn, key: &[u8], value: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options_sync(),
            ),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::put_bytes_with_options(
                txn,
                column,
                key,
                value,
                txn.write_options_sync(),
            ),
        }
    }

    fn sync(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::sync(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::sync(txn),
        }
    }

    fn key_exists(&self, column: DBColumn, key: &[u8]) -> Result<bool, Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_exists(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_exists(txn, column, key),
        }
    }

    fn key_delete(&self, column: DBColumn, key: &[u8]) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::key_delete(txn, column, key),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::key_delete(txn, column, key),
        }
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::do_atomically(txn, batch),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::do_atomically(txn, batch),
        }
    }

    fn compact(&self) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact(txn),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
        }
    }

    fn iter_column_keys_from<K: Key>(
        &self,
        _column: DBColumn,
        from: &[u8],
    ) -> ColumnKeyIter<'_, K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_keys_from(txn, _column, from)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => {
                redb_impl::Redb::iter_column_keys_from(txn, _column, from)
            }
        }
    }

    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<'_, K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::iter_column_keys(txn, column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_keys(txn, column),
        }
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<'_, K> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => {
                leveldb_impl::LevelDB::iter_column_from(txn, column, from)
            }
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::iter_column_from(txn, column, from),
        }
    }

    fn compact_column(&self, _column: DBColumn) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::compact_column(txn, _column),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::compact(txn),
        }
    }

    fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::delete_batch(txn, col, ops),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::delete_batch(txn, col, ops),
        }
    }

    fn delete_if(
        &self,
        column: DBColumn,
        f: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        match self {
            #[cfg(feature = "leveldb")]
            BeaconNodeBackend::LevelDb(txn) => leveldb_impl::LevelDB::delete_if(txn, column, f),
            #[cfg(feature = "redb")]
            BeaconNodeBackend::Redb(txn) => redb_impl::Redb::delete_if(txn, column, f),
        }
    }
}

impl<E: EthSpec> BeaconNodeBackend<E> {
    pub fn open(config: &StoreConfig, path: &Path) -> Result<Self, Error> {
        metrics::inc_counter_vec(&metrics::DISK_DB_TYPE, &[&config.backend.to_string()]);
        match config.backend {
            #[cfg(feature = "leveldb")]
            DatabaseBackend::LevelDb => {
                leveldb_impl::LevelDB::open(path).map(BeaconNodeBackend::LevelDb)
            }
            #[cfg(feature = "redb")]
            DatabaseBackend::Redb => redb_impl::Redb::open(path).map(BeaconNodeBackend::Redb),
        }
    }
}

pub struct WriteOptions {
    /// fsync before acknowledging a write operation.
    pub sync: bool,
}

impl WriteOptions {
    pub fn new() -> Self {
        WriteOptions { sync: false }
    }
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self::new()
    }
}
