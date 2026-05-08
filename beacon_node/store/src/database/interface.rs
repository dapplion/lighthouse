#[cfg(feature = "leveldb")]
use crate::database::leveldb_impl;
#[cfg(feature = "redb")]
use crate::database::redb_impl;
use crate::{
    ColdStore, ColumnIter, ColumnKeyIter, DBColumn, DBColumnColdIndex, Error, ItemStore, Key,
    KeyValueStore, SlotIter, metrics,
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

impl<E: EthSpec> ColdStore<E> for BeaconNodeBackend<E> {
    fn get(&self, column: DBColumn, slot: Slot) -> Result<Option<Vec<u8>>, Error> {
        KeyValueStore::get_bytes(self, column, &slot.as_u64().to_be_bytes())
    }

    fn put_batch(&self, column: DBColumn, items: Vec<(Slot, Vec<u8>)>) -> Result<(), Error> {
        let ops = items
            .into_iter()
            .map(|(slot, value)| {
                crate::KeyValueStoreOp::PutKeyValue(
                    column,
                    slot.as_u64().to_be_bytes().to_vec(),
                    value,
                )
            })
            .collect();
        KeyValueStore::do_atomically(self, ops)
    }

    fn contains(&self, column: DBColumn, slot: Slot) -> Result<bool, Error> {
        KeyValueStore::key_exists(self, column, &slot.as_u64().to_be_bytes())
    }

    fn iter_from(&self, column: DBColumn, from: Slot) -> SlotIter<'_> {
        Box::new(
            KeyValueStore::iter_column_from::<Vec<u8>>(self, column, &from.as_u64().to_be_bytes())
                .map(|res| {
                    res.and_then(|(key_bytes, value)| {
                        let bytes: [u8; 8] =
                            key_bytes.try_into().map_err(|_| Error::InvalidBytes)?;
                        Ok((Slot::new(u64::from_be_bytes(bytes)), value))
                    })
                }),
        )
    }

    fn get_index(&self, column: DBColumnColdIndex, root: Hash256) -> Result<Option<Slot>, Error> {
        Ok(
            KeyValueStore::get_bytes(self, column.db_column(), root.as_slice())?
                .map(|bytes| Slot::from_ssz_bytes(&bytes))
                .transpose()?,
        )
    }

    fn put_index_batch(
        &self,
        column: DBColumnColdIndex,
        items: Vec<(Hash256, Slot)>,
    ) -> Result<(), Error> {
        let col = column.db_column();
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
        KeyValueStore::do_atomically(self, ops)
    }

    fn sync(&self) -> Result<(), Error> {
        KeyValueStore::sync(self)
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
