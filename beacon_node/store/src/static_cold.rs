//! Slot-keyed durable archive for finalized cold-DB columns.
//!
//! `StaticColdStore` is a black box: `(column, slot, bytes)` in, same back.
//! See `specs/static-cold-backend.md` for the abstraction-level contract.
//!
//! # Layout
//!
//! ```text
//! <cold-root>/
//!   {blk,bbr,bsr,bss,bsd}/      # one subdir per DBColumnCold
//!     data_{file_id:05}         # file_id = slot / 8192
//!     data_{file_id:05}.off     # 8192 × u64 LE offsets, 0 = no record
//!     column.conf               # 36-byte commit marker, atomic-renamed
//!   index/                      # embedded KV for DBColumnColdIndex
//! ```
//!
//! # File format
//!
//! Data file: e2store version record (`65 32 00 00 00 00 00 00`), then records
//! appended as `type[2] | length[4 LE] | reserved[2]=0 | payload` (snappy-
//! framed if `column.compression`). Per-column tags in `column_config`.
//!
//! `column.conf`: `b"LHSTBLK2" | highest_slot u64 LE (u64::MAX = empty) |
//! current_data_len u64 LE | record_type[2] | compression u8 | reserved | max_value_bytes u64 LE`.
//! Atomic update: write `.tmp`, fsync, rename, fsync dir.
//!
//! # Put contract
//!
//! Durable on return. Slots arrive ascending **or** are identical-value
//! re-puts of an already-committed slot (so `migrate_database` retries after
//! a mid-loop crash are safe). Previously-skipped slots (offset 0) cannot
//! be filled — that would break the append-only data file.
//!
//! # Recovery on open
//!
//! Data file truncated to `current_data_len`; `.off` entries beyond
//! `highest_slot` cleared. The `column.conf` rename is the commit point.
//!
//! # TODO(static): tests
//!
//! - happy path `open` / `get` / `put` per `DBColumnCold`
//! - out-of-order put rejection
//! - identical-value re-put at any committed slot succeeds; mismatched
//!   value or skipped-slot fill rejected
//! - crash windows around data, `.off`, and `column.conf` (heal on open)
//! - `max_value_bytes` ratchet-up persists on next open
//! - `COLD_BACKEND_KEY` mismatch refuses to start

use crate::config::StoreConfig;
use crate::database::interface::BeaconNodeBackend;
use crate::{DBColumnCold, KeyValueStore};
use parking_lot::Mutex;
use snap::{read::FrameDecoder, write::FrameEncoder};
use std::{
    collections::HashMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};
use strum::IntoEnumIterator;
use types::{EthSpec, Slot};

const SLOTS_PER_FILE: u64 = 8192;
const OFFSET_SIZE: u64 = 8;
const OFFSET_FILE_LEN: u64 = SLOTS_PER_FILE * OFFSET_SIZE;
const CONFIG_FILE: &str = "column.conf";
const CONFIG_TMP_FILE: &str = "column.conf.tmp";
const DATA_FILE_PREFIX: &str = "data_";
const CONFIG_MAGIC: &[u8; 8] = b"LHSTBLK2";
const CONFIG_LEN: usize = 36;
/// Empty-store sentinel for `highest_written_slot` in the per-column config.
const EMPTY_SLOT: u64 = u64::MAX;
/// e2store version record, written once at the start of each data file.
const VERSION_RECORD: [u8; 8] = [0x65, 0x32, 0, 0, 0, 0, 0, 0];

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_SNAPPY: u8 = 1;

/// Per-column configuration. On first creation of a column the values come
/// from `column_config`; thereafter they are persisted in the column file-set
/// `static_blocks.conf` and the on-disk values win over current-build defaults.
#[derive(Debug, Clone, Copy)]
struct ColumnConfig {
    /// On-disk subdirectory name under the store root. Stable across builds.
    subdir: &'static str,
    /// e2store record type tag for this column.
    record_type: [u8; 2],
    /// Whether values are snappy-framed before write.
    compression: bool,
    /// Upper bound on a single decoded record's size in bytes.
    max_value_bytes: u64,
}

/// Per-column file format defaults.
fn column_config(column: DBColumnCold) -> ColumnConfig {
    match column {
        DBColumnCold::Block => ColumnConfig {
            subdir: "blk",
            record_type: [0x01, 0x00],
            compression: true,
            max_value_bytes: 10 * 1024 * 1024,
        },
        DBColumnCold::BlockRoots => ColumnConfig {
            subdir: "bbr",
            record_type: [0x02, 0x00],
            compression: false,
            max_value_bytes: 64,
        },
        DBColumnCold::StateRoots => ColumnConfig {
            subdir: "bsr",
            record_type: [0x03, 0x00],
            compression: false,
            max_value_bytes: 64,
        },
        DBColumnCold::StateSnapshot => ColumnConfig {
            subdir: "bss",
            record_type: [0x04, 0x00],
            compression: false,
            max_value_bytes: 1024 * 1024 * 1024,
        },
        DBColumnCold::StateDiff => ColumnConfig {
            // HDiff is already compressed internally (zstd'd validator and
            // balance chunks; xdelta3 state diff). No benefit to wrapping it
            // in snappy here.
            subdir: "bsd",
            record_type: [0x05, 0x00],
            compression: false,
            max_value_bytes: 1024 * 1024 * 1024,
        },
    }
}

pub struct StaticColdStore<E: EthSpec> {
    /// All cold columns the static archive backs, opened eagerly at boot.
    /// Frozen after construction; per-column writer state is locked inside
    /// each `Column`.
    columns: HashMap<DBColumnCold, Column>,
    /// Embedded KV for root-keyed indices (e.g. `ColdStateSummary`). The
    /// slot-keyed file backend is the bulk archive; this side-table lets us
    /// look up `state_root → slot` without scanning the bulk files.
    index_db: BeaconNodeBackend<E>,
    _phantom: PhantomData<E>,
}

type StoreResult<T> = std::result::Result<T, StaticColdStoreError>;

#[derive(Debug)]
pub enum StaticColdStoreError {
    Io(io::Error),
    Compression(io::Error),
    Invalid(String),
    Unsupported(&'static str),
}

impl fmt::Display for StaticColdStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "static cold store io error: {e}"),
            Self::Compression(e) => write!(f, "static cold store compression error: {e}"),
            Self::Invalid(message) => write!(f, "static cold store invalid data: {message}"),
            Self::Unsupported(op) => write!(f, "static cold store does not support {op}"),
        }
    }
}

impl From<io::Error> for StaticColdStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl<E: EthSpec> StaticColdStore<E> {
    /// Open the archive rooted at `path`. Every cold column is opened eagerly
    /// so subsequent reads/writes are pure hashmap lookups with no I/O on the
    /// hot path. An embedded KV is opened at `<path>/index/` for the
    /// root-keyed indices.
    pub fn open(path: &Path, config: &StoreConfig) -> Result<Self, crate::Error> {
        fs::create_dir_all(path).map_err(StaticColdStoreError::Io)?;
        let mut columns = HashMap::new();
        for column in DBColumnCold::iter() {
            let cfg = column_config(column);
            columns.insert(column, Column::open(path.join(cfg.subdir), cfg)?);
        }
        let index_db = BeaconNodeBackend::open(config, &path.join("index"))?;
        Ok(Self {
            columns,
            index_db,
            _phantom: PhantomData,
        })
    }

    /// Read the value at `(column, slot)`, if present.
    pub fn get(&self, column: DBColumnCold, slot: Slot) -> StoreResult<Option<Vec<u8>>> {
        self.columns[&column].get(slot)
    }

    /// Durably store `bytes` at `(column, slot)`. Slots within a column must
    /// arrive strictly ascending. A re-put of an identical value at the
    /// current highest slot is treated as a no-op so callers that pre-write
    /// a slot at startup (e.g. genesis block_root) don't trip the
    /// out-of-order check on the first migration.
    pub fn put(&self, column: DBColumnCold, slot: Slot, bytes: &[u8]) -> StoreResult<()> {
        self.columns[&column].put(slot, bytes)
    }

    /// Return `true` if a value exists at `(column, slot)`. Cheaper than `get`
    /// because only the `.off` sidecar is consulted; the data file is not read.
    pub fn contains(&self, column: DBColumnCold, slot: Slot) -> StoreResult<bool> {
        self.columns[&column].contains(slot)
    }
}

/// Single-column slot-keyed file set. Owns one subdirectory of data + `.off` +
/// config files.
#[derive(Debug)]
struct Column {
    root_dir: PathBuf,
    config: ColumnConfig,
    highest_written_slot: Mutex<Option<Slot>>,
}

struct ColumnConfigOnDisk {
    highest_written_slot: Option<Slot>,
    current_data_len: u64,
    record_type: [u8; 2],
    compression: bool,
    max_value_bytes: u64,
}

impl Column {
    fn open(root_dir: PathBuf, defaults: ColumnConfig) -> StoreResult<Self> {
        fs::create_dir_all(&root_dir)?;

        // First-open: persist current-build defaults. Re-open: persisted
        // settings win over `defaults`, which preserves on-disk readability
        // even if the build's defaults change later.
        let config_path = root_dir.join(CONFIG_FILE);
        let tmp_path = root_dir.join(CONFIG_TMP_FILE);
        if !config_path.exists() {
            atomic_write_config(&config_path, &tmp_path, &root_dir, None, 0, &defaults)?;
        }

        let on_disk = read_config(&config_path)?;
        // record_type and compression are sticky — they're load-bearing for
        // reading old records, so on-disk wins over build-time defaults.
        // max_value_bytes is a soft bound used to cap accepted record sizes;
        // ratchet it up if the build's default is larger so a newer build
        // can write bigger records than an older one persisted, then
        // re-persist immediately so future opens see the new bound.
        let max_value_bytes = on_disk.max_value_bytes.max(defaults.max_value_bytes);
        let config = ColumnConfig {
            subdir: defaults.subdir,
            record_type: on_disk.record_type,
            compression: on_disk.compression,
            max_value_bytes,
        };
        if max_value_bytes != on_disk.max_value_bytes {
            atomic_write_config(
                &config_path,
                &tmp_path,
                &root_dir,
                on_disk.highest_written_slot,
                on_disk.current_data_len,
                &config,
            )?;
        }

        let handle = Self {
            root_dir,
            config,
            highest_written_slot: Mutex::new(None),
        };

        if let Some(slot) = on_disk.highest_written_slot {
            handle.heal_current_file(slot, on_disk.current_data_len)?;
        }
        *handle.highest_written_slot.lock() = on_disk.highest_written_slot;

        Ok(handle)
    }

    fn get(&self, slot: Slot) -> StoreResult<Option<Vec<u8>>> {
        let Some(highest_written_slot) = *self.highest_written_slot.lock() else {
            return Ok(None);
        };
        if slot > highest_written_slot {
            return Ok(None);
        }
        self.read_record(slot)
    }

    /// Read a record at `slot` without consulting the writer mutex. Used by
    /// callers that already hold the lock (`put` for the idempotency check)
    /// or have another reason to know the slot is committed.
    fn read_record(&self, slot: Slot) -> StoreResult<Option<Vec<u8>>> {
        let file_id = file_id(slot);
        let offset = self.read_offset(file_id, slot)?;
        if offset == 0 {
            return Ok(None);
        }

        let data_path = self.data_path(file_id);
        let mut data_file = File::open(&data_path)?;
        data_file.seek(SeekFrom::Start(offset))?;

        let mut header = [0; 8];
        data_file.read_exact(&mut header)?;
        if header[0..2] != self.config.record_type || header[6..8] != [0, 0] {
            return Err(StaticColdStoreError::Invalid(
                "invalid static cold record header".into(),
            ));
        }

        let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut payload = vec![0; len];
        data_file.read_exact(&mut payload)?;

        if self.config.compression {
            decompress_record(&payload, self.config.max_value_bytes).map(Some)
        } else {
            if (payload.len() as u64) > self.config.max_value_bytes {
                return Err(StaticColdStoreError::Invalid(
                    "static cold record exceeds size limit".into(),
                ));
            }
            Ok(Some(payload))
        }
    }

    fn contains(&self, slot: Slot) -> StoreResult<bool> {
        let Some(highest_written_slot) = *self.highest_written_slot.lock() else {
            return Ok(false);
        };
        if slot > highest_written_slot {
            return Ok(false);
        }
        Ok(self.read_offset(file_id(slot), slot)? != 0)
    }

    fn put(&self, slot: Slot, bytes: &[u8]) -> StoreResult<()> {
        let mut highest_written_slot = self.highest_written_slot.lock();
        if let Some(highest) = *highest_written_slot
            && slot <= highest
        {
            // Idempotent re-put: any committed slot can be re-put with the
            // identical value. Required so a `migrate_database` retry after a
            // mid-loop crash can re-walk slots that were already committed in
            // the previous attempt without tripping the strict-ascending
            // invariant. A previously-skipped slot (offset zero) cannot be
            // filled in — that would break the append-only data file.
            let existing = self.read_record(slot)?.ok_or_else(|| {
                StaticColdStoreError::Invalid(format!(
                    "static cold re-put at slot {slot} <= highest {highest} \
                     but no record exists; cannot fill a previously-skipped slot"
                ))
            })?;
            if existing == bytes {
                return Ok(());
            }
            return Err(StaticColdStoreError::Invalid(format!(
                "static cold re-put at slot {slot} with mismatched value"
            )));
        }

        let payload = if self.config.compression {
            compress_record(bytes)?
        } else {
            bytes.to_vec()
        };
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| StaticColdStoreError::Invalid("static cold record too large".into()))?;

        let target_file_id = file_id(slot);
        // Discard an uncommitted next-file tail after a crash.
        let reset_file = (*highest_written_slot).map(file_id) != Some(target_file_id);
        let off_pos = offset_position(slot);
        let data_path = self.data_path(target_file_id);
        let off_path = self.offset_path(target_file_id);

        let mut data_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&data_path)?;
        if reset_file {
            data_file.set_len(0)?;
        }

        if data_file.metadata()?.len() == 0 {
            data_file.write_all(&VERSION_RECORD)?;
        }

        let offset = data_file.seek(SeekFrom::End(0))?;
        write_record(
            &mut data_file,
            self.config.record_type,
            payload_len,
            &payload,
        )?;
        let data_len = data_file.seek(SeekFrom::End(0))?;
        // Data and offset files must hit disk before the config commit marker.
        data_file.sync_all()?;

        let mut off_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&off_path)?;
        if reset_file {
            off_file.set_len(0)?;
        }
        if off_file.metadata()?.len() < OFFSET_FILE_LEN {
            off_file.set_len(OFFSET_FILE_LEN)?;
        }
        off_file.seek(SeekFrom::Start(off_pos))?;
        off_file.write_all(&offset.to_le_bytes())?;
        off_file.sync_all()?;

        // Atomic config update is the commit point.
        self.write_config(Some(slot), data_len)?;
        *highest_written_slot = Some(slot);

        Ok(())
    }

    fn heal_current_file(&self, slot: Slot, current_data_len: u64) -> StoreResult<()> {
        let file_id = file_id(slot);
        let data_path = self.data_path(file_id);
        let data_file = OpenOptions::new().read(true).write(true).open(&data_path)?;
        let data_len = data_file.metadata()?.len();
        if data_len < current_data_len {
            return Err(StaticColdStoreError::Invalid(
                "static cold data file shorter than committed length".into(),
            ));
        }
        if data_len != current_data_len {
            data_file.set_len(current_data_len)?;
            data_file.sync_all()?;
        }

        let off_path = self.offset_path(file_id);
        let mut off_file = OpenOptions::new().read(true).write(true).open(&off_path)?;
        let required_len = offset_position(slot) + OFFSET_SIZE;
        let off_len = off_file.metadata()?.len();
        if off_len < required_len {
            return Err(StaticColdStoreError::Invalid(
                "static cold offset file shorter than committed slot".into(),
            ));
        }
        if off_len < OFFSET_FILE_LEN {
            off_file.set_len(OFFSET_FILE_LEN)?;
        }

        let clear_start = required_len;
        if clear_start < OFFSET_FILE_LEN {
            // Remove offsets to entries beyond the committed slot.
            off_file.seek(SeekFrom::Start(clear_start))?;
            let zeroes = vec![0; (OFFSET_FILE_LEN - clear_start) as usize];
            off_file.write_all(&zeroes)?;
            off_file.sync_all()?;
        }

        Ok(())
    }

    fn write_config(
        &self,
        highest_written_slot: Option<Slot>,
        current_data_len: u64,
    ) -> StoreResult<()> {
        atomic_write_config(
            &self.config_path(),
            &self.root_dir.join(CONFIG_TMP_FILE),
            &self.root_dir,
            highest_written_slot,
            current_data_len,
            &self.config,
        )
    }

    fn read_offset(&self, file_id: u64, slot: Slot) -> StoreResult<u64> {
        let off_path = self.offset_path(file_id);
        let mut off_file = File::open(&off_path)?;
        let mut bytes = [0; 8];
        off_file.seek(SeekFrom::Start(offset_position(slot)))?;
        off_file.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn config_path(&self) -> PathBuf {
        self.root_dir.join(CONFIG_FILE)
    }

    fn data_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("{DATA_FILE_PREFIX}{file_id:05}"))
    }

    fn offset_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("{DATA_FILE_PREFIX}{file_id:05}.off"))
    }
}

fn read_config(path: &Path) -> StoreResult<ColumnConfigOnDisk> {
    let bytes = fs::read(path)?;
    if bytes.len() != CONFIG_LEN || &bytes[0..8] != CONFIG_MAGIC {
        return Err(StaticColdStoreError::Invalid(
            "invalid static cold config".into(),
        ));
    }
    let highest = u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked"));
    let current_data_len =
        u64::from_le_bytes(bytes[16..24].try_into().expect("slice length checked"));
    let record_type = [bytes[24], bytes[25]];
    let compression = match bytes[26] {
        COMPRESSION_NONE => false,
        COMPRESSION_SNAPPY => true,
        other => {
            return Err(StaticColdStoreError::Invalid(format!(
                "unknown compression flag {other}"
            )));
        }
    };
    let max_value_bytes =
        u64::from_le_bytes(bytes[28..36].try_into().expect("slice length checked"));
    Ok(ColumnConfigOnDisk {
        highest_written_slot: (highest != EMPTY_SLOT).then(|| Slot::new(highest)),
        current_data_len,
        record_type,
        compression,
        max_value_bytes,
    })
}

fn atomic_write_config(
    config_path: &Path,
    tmp_path: &Path,
    root_dir: &Path,
    highest_written_slot: Option<Slot>,
    current_data_len: u64,
    config: &ColumnConfig,
) -> StoreResult<()> {
    let mut bytes = [0u8; CONFIG_LEN];
    bytes[0..8].copy_from_slice(CONFIG_MAGIC);
    bytes[8..16].copy_from_slice(
        &highest_written_slot
            .map_or(EMPTY_SLOT, |slot| slot.as_u64())
            .to_le_bytes(),
    );
    bytes[16..24].copy_from_slice(&current_data_len.to_le_bytes());
    bytes[24..26].copy_from_slice(&config.record_type);
    bytes[26] = if config.compression {
        COMPRESSION_SNAPPY
    } else {
        COMPRESSION_NONE
    };
    bytes[27] = 0;
    bytes[28..36].copy_from_slice(&config.max_value_bytes.to_le_bytes());

    {
        let mut tmp = File::create(tmp_path)?;
        tmp.write_all(&bytes)?;
        tmp.sync_all()?;
    }

    fs::rename(tmp_path, config_path)?;
    sync_dir(root_dir)
}

fn file_id(slot: Slot) -> u64 {
    slot.as_u64() / SLOTS_PER_FILE
}

fn offset_position(slot: Slot) -> u64 {
    (slot.as_u64() % SLOTS_PER_FILE) * OFFSET_SIZE
}

fn compress_record(bytes: &[u8]) -> StoreResult<Vec<u8>> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder
        .write_all(bytes)
        .map_err(StaticColdStoreError::Compression)?;
    encoder.flush().map_err(StaticColdStoreError::Compression)?;
    Ok(encoder.get_ref().clone())
}

fn write_record(
    file: &mut File,
    record_type: [u8; 2],
    payload_len: u32,
    payload: &[u8],
) -> StoreResult<()> {
    file.write_all(&record_type)?;
    file.write_all(&payload_len.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(payload)?;
    Ok(())
}

fn decompress_record(bytes: &[u8], max_value_bytes: u64) -> StoreResult<Vec<u8>> {
    let decoder = FrameDecoder::new(bytes);
    let mut limited = decoder.take(max_value_bytes + 1);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .map_err(StaticColdStoreError::Compression)?;
    if decompressed.len() as u64 > max_value_bytes {
        return Err(StaticColdStoreError::Invalid(
            "static cold record exceeds decompressed size limit".into(),
        ));
    }
    Ok(decompressed)
}

fn sync_dir(path: &Path) -> StoreResult<()> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}

// Slot-keyed columns are served from the static files; root-keyed index
// columns are served from the embedded KV at `<root>/index/`.
impl<E: EthSpec> crate::ColdStore<E> for StaticColdStore<E> {
    fn get(&self, c: DBColumnCold, slot: Slot) -> Result<Option<Vec<u8>>, crate::Error> {
        StaticColdStore::get(self, c, slot).map_err(Into::into)
    }

    fn put_batch(&self, c: DBColumnCold, items: Vec<(Slot, Vec<u8>)>) -> Result<(), crate::Error> {
        for (slot, value) in items {
            self.put(c, slot, &value)?;
        }
        Ok(())
    }

    fn contains(&self, c: DBColumnCold, slot: Slot) -> Result<bool, crate::Error> {
        StaticColdStore::contains(self, c, slot).map_err(Into::into)
    }

    fn iter_from(&self, c: DBColumnCold, from: Slot) -> crate::SlotIter<'_> {
        // TODO(static): this is O(highest - from) reads, one File::open per slot,
        // and most slots in sparse columns (StateSnapshot/StateDiff) yield None.
        // Acceptable today because iter_from is only used by infrequent paths
        // (forwards iter, invariants). Improve if it becomes a hotspot.
        let column = &self.columns[&c];
        let Some(highest) = *column.highest_written_slot.lock() else {
            return Box::new(std::iter::empty());
        };
        if from > highest {
            return Box::new(std::iter::empty());
        }
        let column_ref = column;
        Box::new(
            (from.as_u64()..=highest.as_u64())
                .map(Slot::new)
                .filter_map(move |slot| match column_ref.read_record(slot) {
                    Ok(Some(value)) => Some(Ok((slot, value))),
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
