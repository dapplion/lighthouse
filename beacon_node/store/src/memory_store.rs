use crate::{
    ColdStore, ColumnIter, ColumnKeyIter, DBColumn, DBColumnColdIndex, Error, ItemStore, Key,
    KeyValueStore, KeyValueStoreOp, SlotIter, get_key_for_col, hot_cold_store::BytesKey,
};
use parking_lot::RwLock;
use ssz::{Decode, Encode};
use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;
use types::Hash256;
use types::*;

type DBMap = BTreeMap<BytesKey, Vec<u8>>;

/// A thread-safe `BTreeMap` wrapper.
pub struct MemoryStore<E: EthSpec> {
    db: RwLock<DBMap>,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> MemoryStore<E> {
    /// Create a new, empty database.
    pub fn open() -> Self {
        Self {
            db: RwLock::new(BTreeMap::new()),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec> KeyValueStore<E> for MemoryStore<E> {
    /// Get the value of some key from the database. Returns `None` if the key does not exist.
    fn get_bytes(&self, col: DBColumn, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        Ok(self.db.read().get(&column_key).cloned())
    }

    /// Puts a key in the database.
    fn put_bytes(&self, col: DBColumn, key: &[u8], val: &[u8]) -> Result<(), Error> {
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        self.db.write().insert(column_key, val.to_vec());
        Ok(())
    }

    fn put_bytes_sync(&self, col: DBColumn, key: &[u8], val: &[u8]) -> Result<(), Error> {
        self.put_bytes(col, key, val)
    }

    fn sync(&self) -> Result<(), Error> {
        // no-op
        Ok(())
    }

    /// Return true if some key exists in some column.
    fn key_exists(&self, col: DBColumn, key: &[u8]) -> Result<bool, Error> {
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        Ok(self.db.read().contains_key(&column_key))
    }

    /// Delete some key from the database.
    fn key_delete(&self, col: DBColumn, key: &[u8]) -> Result<(), Error> {
        let column_key = BytesKey::from_vec(get_key_for_col(col, key));
        self.db.write().remove(&column_key);
        Ok(())
    }

    fn do_atomically(&self, batch: Vec<KeyValueStoreOp>) -> Result<(), Error> {
        for op in batch {
            match op {
                KeyValueStoreOp::PutKeyValue(col, key, value) => {
                    let column_key = get_key_for_col(col, &key);
                    self.db
                        .write()
                        .insert(BytesKey::from_vec(column_key), value);
                }

                KeyValueStoreOp::DeleteKey(col, key) => {
                    let column_key = get_key_for_col(col, &key);
                    self.db.write().remove(&BytesKey::from_vec(column_key));
                }
            }
        }
        Ok(())
    }

    fn iter_column_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnIter<'_, K> {
        // We use this awkward pattern because we can't lock the `self.db` field *and* maintain a
        // reference to the lock guard across calls to `.next()`. This would be require a
        // struct with a field (the iterator) which references another field (the lock guard).
        let start_key = BytesKey::from_vec(get_key_for_col(column, from));
        let keys = self
            .db
            .read()
            .range(start_key..)
            .take_while(|(k, _)| k.remove_column_variable(column).is_some())
            .filter_map(|(k, _)| k.remove_column_variable(column).map(|k| k.to_vec()))
            .collect::<Vec<_>>();
        Box::new(keys.into_iter().filter_map(move |key| {
            KeyValueStore::get_bytes(self, column, &key)
                .transpose()
                .map(|res| {
                    let k = K::from_bytes(&key)?;
                    let v = res?;
                    Ok((k, v))
                })
        }))
    }

    fn iter_column_keys<K: Key>(&self, column: DBColumn) -> ColumnKeyIter<'_, K> {
        Box::new(self.iter_column(column).map(|res| res.map(|(k, _)| k)))
    }

    fn compact_column(&self, _column: DBColumn) -> Result<(), Error> {
        Ok(())
    }

    fn iter_column_keys_from<K: Key>(&self, column: DBColumn, from: &[u8]) -> ColumnKeyIter<'_, K> {
        // We use this awkward pattern because we can't lock the `self.db` field *and* maintain a
        // reference to the lock guard across calls to `.next()`. This would be require a
        // struct with a field (the iterator) which references another field (the lock guard).
        let start_key = BytesKey::from_vec(get_key_for_col(column, from));
        let keys = self
            .db
            .read()
            .range(start_key..)
            .take_while(|(k, _)| k.remove_column_variable(column).is_some())
            .filter_map(|(k, _)| k.remove_column_variable(column).map(|k| k.to_vec()))
            .collect::<Vec<_>>();
        Box::new(keys.into_iter().map(move |key| K::from_bytes(&key)))
    }

    fn delete_batch(&self, col: DBColumn, ops: HashSet<&[u8]>) -> Result<(), Error> {
        for op in ops {
            let column_key = get_key_for_col(col, op);
            self.db.write().remove(&BytesKey::from_vec(column_key));
        }
        Ok(())
    }

    fn delete_if(
        &self,
        column: DBColumn,
        mut f: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.db.write().retain(|key, value| {
            if key.remove_column_variable(column).is_some() {
                !f(value).unwrap_or(false)
            } else {
                true
            }
        });
        Ok(())
    }
}

impl<E: EthSpec> ItemStore<E> for MemoryStore<E> {}

impl<E: EthSpec> ColdStore<E> for MemoryStore<E> {
    fn get(&self, column: DBColumn, slot: Slot) -> Result<Option<Vec<u8>>, Error> {
        KeyValueStore::get_bytes(self, column, &slot.as_u64().to_be_bytes())
    }

    fn put_batch(&self, column: DBColumn, items: Vec<(Slot, Vec<u8>)>) -> Result<(), Error> {
        let ops = items
            .into_iter()
            .map(|(slot, value)| {
                KeyValueStoreOp::PutKeyValue(column, slot.as_u64().to_be_bytes().to_vec(), value)
            })
            .collect();
        KeyValueStore::do_atomically(self, ops)
    }

    fn exists(&self, column: DBColumn, slot: Slot) -> Result<bool, Error> {
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
                KeyValueStoreOp::PutKeyValue(col, root.as_slice().to_vec(), slot.as_ssz_bytes())
            })
            .collect();
        KeyValueStore::do_atomically(self, ops)
    }

    fn sync(&self) -> Result<(), Error> {
        KeyValueStore::sync(self)
    }
}
