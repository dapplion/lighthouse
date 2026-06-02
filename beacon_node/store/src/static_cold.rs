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
const CONFIG_MAGIC_V2: &[u8; 8] = b"LHSTBLK2";
const CONFIG_MAGIC: &[u8; 8] = b"LHSTBLK3";
const CONFIG_LEN_V2: usize = 36;
const CONFIG_LEN: usize = 52;
/// Empty-store sentinel for `highest_written_slot` in the per-column config.
const EMPTY_SLOT: u64 = u64::MAX;
/// Sentinel: no backfill file tracked.
const NO_BACKFILL_FILE: u64 = u64::MAX;
/// e2store version record, written once at the start of each data file.
const VERSION_RECORD: [u8; 8] = [0x65, 0x32, 0, 0, 0, 0, 0, 0];

const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_SNAPPY: u8 = 1;

/// Bit 0 of the flags byte.
const FLAG_ALLOW_BACKFILL: u8 = 0b0000_0001;

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
    allow_backfill: bool,
}

/// Per-column file format defaults.
fn column_config(column: DBColumnCold) -> ColumnConfig {
    match column {
        DBColumnCold::Block => ColumnConfig {
            subdir: "blk",
            record_type: [0x01, 0x00],
            compression: true,
            max_value_bytes: 10 * 1024 * 1024,
            allow_backfill: false,
        },
        DBColumnCold::BlockRoots => ColumnConfig {
            subdir: "bbr",
            record_type: [0x02, 0x00],
            compression: false,
            max_value_bytes: 64,
            allow_backfill: false,
        },
        DBColumnCold::StateRoots => ColumnConfig {
            subdir: "bsr",
            record_type: [0x03, 0x00],
            compression: false,
            max_value_bytes: 64,
            allow_backfill: false,
        },
        DBColumnCold::StateSnapshot => ColumnConfig {
            subdir: "bss",
            record_type: [0x04, 0x00],
            compression: false,
            max_value_bytes: 1024 * 1024 * 1024,
            allow_backfill: false,
        },
        DBColumnCold::StateDiff => ColumnConfig {
            // HDiff is already compressed internally (zstd'd validator and
            // balance chunks; xdelta3 state diff). No benefit to wrapping it
            // in snappy here.
            subdir: "bsd",
            record_type: [0x05, 0x00],
            compression: false,
            max_value_bytes: 1024 * 1024 * 1024,
            allow_backfill: false,
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
            let mut cfg = column_config(column);
            cfg.allow_backfill = config.allow_backfill;
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

#[derive(Debug, Default)]
struct ColumnWriteState {
    highest_written_slot: Option<Slot>,
    /// Committed length of the data file that contains `highest_written_slot`.
    current_data_len: u64,
    /// File-id of the most recently backfilled non-current file (0 = none).
    backfill_file_id: u64,
    /// Committed length of `backfill_file_id` (0 when no backfill file).
    backfill_data_len: u64,
}

/// Single-column slot-keyed file set. Owns one subdirectory of data + `.off` +
/// config files.
#[derive(Debug)]
struct Column {
    root_dir: PathBuf,
    config: ColumnConfig,
    state: Mutex<ColumnWriteState>,
}

struct ColumnConfigOnDisk {
    highest_written_slot: Option<Slot>,
    current_data_len: u64,
    record_type: [u8; 2],
    compression: bool,
    max_value_bytes: u64,
    allow_backfill: bool,
    backfill_file_id: u64,
    backfill_data_len: u64,
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
            atomic_write_config(
                &config_path,
                &tmp_path,
                &root_dir,
                None,
                0,
                &defaults,
                NO_BACKFILL_FILE,
                0,
            )?;
        }

        let on_disk = read_config(&config_path)?;
        // record_type and compression are sticky — they're load-bearing for
        // reading old records, so on-disk wins over build-time defaults.
        // max_value_bytes is a soft bound used to cap accepted record sizes;
        // ratchet it up if the build's default is larger so a newer build
        // can write bigger records than an older one persisted, then
        // re-persist immediately so future opens see the new bound.
        let max_value_bytes = on_disk.max_value_bytes.max(defaults.max_value_bytes);
        // allow_backfill is sticky, once set: a store opened with backfill
        // enabled keeps it even if later opened without the flag.
        let allow_backfill = on_disk.allow_backfill || defaults.allow_backfill;
        let config = ColumnConfig {
            subdir: defaults.subdir,
            record_type: on_disk.record_type,
            compression: on_disk.compression,
            max_value_bytes,
            allow_backfill,
        };

        // Re-persist if anything changed (max_value_bytes ratchet or
        // allow_backfill upgrade from V2 -> V3). The format written is
        // determined solely by config.allow_backfill inside atomic_write_config
        if max_value_bytes != on_disk.max_value_bytes || allow_backfill != on_disk.allow_backfill {
            atomic_write_config(
                &config_path,
                &tmp_path,
                &root_dir,
                on_disk.highest_written_slot,
                on_disk.current_data_len,
                &config,
                on_disk.backfill_file_id,
                on_disk.backfill_data_len,
            )?;
        }

        let handle = Self {
            root_dir,
            config,
            state: Mutex::new(ColumnWriteState::default()),
        };

        if let Some(slot) = on_disk.highest_written_slot {
            handle.heal_on_open(
                slot,
                on_disk.current_data_len,
                on_disk.allow_backfill,
                on_disk.backfill_file_id,
                on_disk.backfill_data_len,
            )?;
        }
        *handle.state.lock() = ColumnWriteState {
            highest_written_slot: on_disk.highest_written_slot,
            current_data_len: on_disk.current_data_len,
            backfill_file_id: on_disk.backfill_file_id,
            backfill_data_len: on_disk.backfill_data_len,
        };

        Ok(handle)
    }

    fn get(&self, slot: Slot) -> StoreResult<Option<Vec<u8>>> {
        let highest = self.state.lock().highest_written_slot;
        let Some(highest) = highest else {
            return Ok(None);
        };
        if slot > highest {
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
        let highest = self.state.lock().highest_written_slot;
        let Some(highest) = highest else {
            return Ok(false);
        };
        if slot > highest {
            return Ok(false);
        }
        Ok(self.read_offset(file_id(slot), slot)? != 0)
    }

    fn put(&self, slot: Slot, bytes: &[u8]) -> StoreResult<()> {
        let mut state = self.state.lock();
        if let Some(highest) = state.highest_written_slot {
            if slot <= highest {
                if self.config.allow_backfill {
                    return self.put_backfill(slot, bytes, &mut state);
                }

                // Non-backfill: only identical re-put allowed
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
        }

        // Sequential write
        let payload = if self.config.compression {
            compress_record(bytes)?
        } else {
            bytes.to_vec()
        };
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| StaticColdStoreError::Invalid("static cold record too large".into()))?;

        let target_file_id = file_id(slot);
        // Discard an uncommitted next-file tail after a crash.
        let reset_file = state.highest_written_slot.map(file_id) != Some(target_file_id);
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

        atomic_write_config(
            &self.config_path(),
            &self.root_dir.join(CONFIG_TMP_FILE),
            &self.root_dir,
            Some(slot),
            data_len,
            &self.config,
            state.backfill_file_id,
            state.backfill_data_len,
        )?;
        state.highest_written_slot = Some(slot);
        state.current_data_len = data_len;

        Ok(())
    }

    /// Write a previously-skipped slot. Called from `put` and `put_batch`
    /// with `state` lock held
    fn put_backfill(
        &self,
        slot: Slot,
        bytes: &[u8],
        state: &mut ColumnWriteState,
    ) -> StoreResult<()> {
        let fid = file_id(slot);
        let offset = self.read_offset(fid, slot)?;

        if offset != 0 {
            // Slot already committed - idempotent check.
            let existing = self.read_record(slot)?.ok_or_else(|| {
                StaticColdStoreError::Invalid(
                    "static cold backfill: offset nonzero but record missing".into(),
                )
            })?;
            if existing == bytes {
                return Ok(());
            }
            return Err(StaticColdStoreError::Invalid(format!(
                "static cold backfill at slot {slot} conflicts with existing record"
            )));
        }

        // offset == 0: fill the gap.
        let payload = if self.config.compression {
            compress_record(bytes)?
        } else {
            bytes.to_vec()
        };
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| StaticColdStoreError::Invalid("static cold record too large".into()))?;

        // Open for append - do NOT truncate; file already has phase-1 data.
        let mut data_file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(self.data_path(fid))?;
        if data_file.metadata()?.len() == 0 {
            data_file.write_all(&VERSION_RECORD)?;
        }
        let data_offset = data_file.seek(SeekFrom::End(0))?;
        write_record(
            &mut data_file,
            self.config.record_type,
            payload_len,
            &payload,
        )?;
        data_file.sync_all()?;
        let new_data_len = data_file.metadata()?.len();

        // Write offset (file must already be full-sized from phase-1 writes).
        let mut off_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.offset_path(fid))?;
        if off_file.metadata()?.len() < OFFSET_FILE_LEN {
            off_file.set_len(OFFSET_FILE_LEN)?;
        }
        off_file.seek(SeekFrom::Start(offset_position(slot)))?;
        off_file.write_all(&data_offset.to_le_bytes())?;
        off_file.sync_all()?;

        if Some(fid) == state.highest_written_slot.map(file_id) {
            state.current_data_len = new_data_len;
        } else {
            state.backfill_file_id = fid;
            state.backfill_data_len = new_data_len;
        }

        atomic_write_config(
            &self.config_path(),
            &self.root_dir.join(CONFIG_TMP_FILE),
            &self.root_dir,
            state.highest_written_slot,
            state.current_data_len,
            &self.config,
            state.backfill_file_id,
            state.backfill_data_len,
        )?;

        Ok(())
    }

    /// Append `items` to the column with one fsync per file (data + offset),
    /// not per slot. Whole batch is durable on return — the same caller-visible
    /// contract as `put` — but with O(1) syncs per underlying file instead of
    /// O(n) per item.
    ///
    /// The implementation walks `items` once, grouping them by `file_id`. For
    /// each group it opens the data file and offset file once, appends every
    /// record's bytes (collecting `(slot, offset)` pairs in memory), writes the
    /// offset table, fsyncs both files, then commits via `write_config`. Idempotent
    /// re-put of `items[0]` at `highest_written_slot` is honored as in `put`.
    fn put_batch(&self, items: Vec<(Slot, Vec<u8>)>) -> StoreResult<()> {
        if items.is_empty() {
            return Ok(());
        }

        // Validate ascending order up front (cheap, catches caller bugs).
        for w in items.windows(2) {
            if w[1].0 <= w[0].0 {
                return Err(StaticColdStoreError::Invalid(
                    "static cold put_batch slots must be strictly ascending".into(),
                ));
            }
        }

        let mut state = self.state.lock();
        let mut iter = items.into_iter().peekable();

        // Idempotent re-put: if the first item is exactly highest_written_slot
        // with matching bytes, drop it from the batch.
        if let (Some(highest), Some((first_slot, _))) = (state.highest_written_slot, iter.peek()) {
            if *first_slot < highest {
                if !self.config.allow_backfill {
                    return Err(StaticColdStoreError::Invalid(
                        "static cold put_batch out of order vs highest_written_slot".into(),
                    ));
                }
                // Backfill batch
                let items: Vec<_> = iter.collect();
                for (slot, _) in &items {
                    if *slot > highest {
                        return Err(StaticColdStoreError::Invalid(
                            "static cold put_batch mixed sequential/backfill".into(),
                        ));
                    }
                }
                return self.put_batch_backfill(items, &mut state);
            }
            if *first_slot == highest {
                let (slot, value) = iter.next().expect("peeked");
                let existing = self.read_record(slot)?.ok_or_else(|| {
                    StaticColdStoreError::Invalid(
                        "static cold missing record at highest slot".into(),
                    )
                })?;
                if existing != value {
                    return Err(StaticColdStoreError::Invalid(
                        "static cold re-put with mismatched value".into(),
                    ));
                }
            }
        }

        // Group remaining items by file_id, write each group with a single
        // fsync per file.
        let mut last_slot: Option<Slot> = None;
        let mut last_data_len: u64 = 0;
        while iter.peek().is_some() {
            let target_file_id = file_id(iter.peek().expect("peeked").0);
            let mut group: Vec<(Slot, Vec<u8>)> = Vec::new();
            while let Some(&(slot, _)) = iter.peek() {
                if file_id(slot) != target_file_id {
                    break;
                }
                group.push(iter.next().expect("peeked"));
            }

            let reset_file = state.highest_written_slot.map(file_id) != Some(target_file_id);
            let data_path = self.data_path(target_file_id);
            let off_path = self.offset_path(target_file_id);

            // Data file: append all records, then fsync once.
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
            // BufWriter coalesces the small-record header writes (8 bytes) and
            // the small payloads into larger syscalls.
            let mut offsets: Vec<(Slot, u64)> = Vec::with_capacity(group.len());
            {
                let mut writer = std::io::BufWriter::with_capacity(1 << 20, &mut data_file);
                let mut cursor = writer.get_ref().metadata()?.len();
                for (slot, value) in &group {
                    let payload: std::borrow::Cow<'_, [u8]> = if self.config.compression {
                        compress_record(value)?.into()
                    } else {
                        value.as_slice().into()
                    };
                    let payload_len = u32::try_from(payload.len()).map_err(|_| {
                        StaticColdStoreError::Invalid("static cold record too large".into())
                    })?;
                    offsets.push((*slot, cursor));
                    // Inline `write_record` to avoid the `&mut File` -> BufWriter mismatch.
                    writer.write_all(&self.config.record_type)?;
                    writer.write_all(&payload_len.to_le_bytes())?;
                    writer.write_all(&0u16.to_le_bytes())?;
                    writer.write_all(&payload)?;
                    cursor += 8 + payload.len() as u64;
                }
                writer.flush()?;
            }
            let data_len = data_file.seek(SeekFrom::End(0))?;
            data_file.sync_all()?;

            // Offset file: open, ensure full size, write all offsets in seek+write
            // pairs (8 bytes each), then fsync once.
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
            for (slot, offset) in &offsets {
                off_file.seek(SeekFrom::Start(offset_position(*slot)))?;
                off_file.write_all(&offset.to_le_bytes())?;
            }
            off_file.sync_all()?;

            // Track final slot/data_len for the single config commit at end of batch.
            if let Some((s, _)) = group.last() {
                last_slot = Some(*s);
                last_data_len = data_len;
            }
            state.highest_written_slot = last_slot;
        }

        if let Some(s) = last_slot {
            state.current_data_len = last_data_len;
            atomic_write_config(
                &self.config_path(),
                &self.root_dir.join(CONFIG_TMP_FILE),
                &self.root_dir,
                Some(s),
                last_data_len,
                &self.config,
                state.backfill_file_id,
                state.backfill_data_len,
            )?;
        }

        Ok(())
    }

    /// Batched backfill: write all skipped slots (offset==0) in one pass per
    /// file, single config commit at end.
    fn put_batch_backfill(
        &self,
        items: Vec<(Slot, Vec<u8>)>,
        state: &mut ColumnWriteState,
    ) -> StoreResult<()> {
        // Validate and separate: skip already-committed identical items,
        // collect items to write.
        let mut to_write: Vec<(Slot, Vec<u8>)> = Vec::with_capacity(items.len());
        for (slot, bytes) in items {
            let offset = self.read_offset(file_id(slot), slot)?;
            if offset != 0 {
                let existing = self.read_record(slot)?.ok_or_else(|| {
                    StaticColdStoreError::Invalid(
                        "static cold backfill: offset nonzero but record missing".into(),
                    )
                })?;
                if existing != bytes {
                    return Err(StaticColdStoreError::Invalid(format!(
                        "static cold backfill at slot {slot} conflicts with existing record"
                    )));
                }
                continue; // idempotent
            }
            to_write.push((slot, bytes));
        }
        if to_write.is_empty() {
            return Ok(());
        }

        // Group by file_id (items are ascending so groups are naturally ascending).
        let mut groups: Vec<(u64, Vec<(Slot, Vec<u8>)>)> = Vec::new();
        for (slot, bytes) in &to_write {
            let file_id = file_id(*slot);
            if groups.last().map_or(true, |(f, _)| *f != file_id) {
                groups.push((file_id, Vec::new()));
            }
            groups
                .last_mut()
                .expect("just pushed")
                .1
                .push((*slot, bytes.clone()));
        }

        let highest_file_id = state.highest_written_slot.map(file_id);

        let non_current_files: std::collections::HashSet<u64> = to_write
            .iter()
            .map(|(slot, _)| file_id(*slot))
            .filter(|file_id| Some(*file_id) != highest_file_id)
            .collect();
        if non_current_files.len() > 1 {
            return Err(StaticColdStoreError::Invalid(
                "static cold backfill batch targets multiple non-current files; split into separate batches".into(),
            ));
        }

        for (file_id, group) in &groups {
            let mut data_file = OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .open(self.data_path(*file_id))?;
            if data_file.metadata()?.len() == 0 {
                data_file.write_all(&VERSION_RECORD)?;
            }

            let mut offsets: Vec<(Slot, u64)> = Vec::with_capacity(group.len());
            {
                let mut w = std::io::BufWriter::with_capacity(1 << 20, &mut data_file);
                let mut cursor = w.get_ref().metadata()?.len();
                for (slot, bytes) in group {
                    let payload = if self.config.compression {
                        compress_record(bytes)?
                    } else {
                        bytes.to_vec()
                    };
                    let payload_len = u32::try_from(payload.len()).map_err(|_| {
                        StaticColdStoreError::Invalid("static cold record too large".into())
                    })?;
                    offsets.push((*slot, cursor));
                    w.write_all(&self.config.record_type)?;
                    w.write_all(&payload_len.to_le_bytes())?;
                    w.write_all(&0u16.to_le_bytes())?;
                    w.write_all(&payload)?;
                    cursor += 8 + payload.len() as u64;
                }
                w.flush()?;
            }
            let new_data_len = data_file.seek(SeekFrom::End(0))?;
            data_file.sync_all()?;

            let mut off_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(self.offset_path(*file_id))?;
            if off_file.metadata()?.len() < OFFSET_FILE_LEN {
                off_file.set_len(OFFSET_FILE_LEN)?;
            }
            for (slot, offset) in &offsets {
                off_file.seek(SeekFrom::Start(offset_position(*slot)))?;
                off_file.write_all(&offset.to_le_bytes())?;
            }
            off_file.sync_all()?;

            if Some(*file_id) == highest_file_id {
                state.current_data_len = new_data_len;
            } else {
                state.backfill_file_id = *file_id;
                state.backfill_data_len = new_data_len;
            }
        }

        // Single atomic config commit.
        atomic_write_config(
            &self.config_path(),
            &self.root_dir.join(CONFIG_TMP_FILE),
            &self.root_dir,
            state.highest_written_slot,
            state.current_data_len,
            &self.config,
            state.backfill_file_id,
            state.backfill_data_len,
        )
    }

    fn heal_on_open(
        &self,
        slot: Slot,
        current_data_len: u64,
        allow_backfill: bool,
        backfill_file_id: u64,
        backfill_data_len: u64,
    ) -> StoreResult<()> {
        let current_file_id = file_id(slot);
        self.heal_file(current_file_id, Some(slot), current_data_len)?;

        if allow_backfill {
            self.scan_and_zero_dangling_offsets(current_file_id, current_data_len)?;

            if backfill_file_id != NO_BACKFILL_FILE && backfill_file_id != current_file_id {
                self.heal_file(backfill_file_id, None, backfill_data_len)?;
                self.scan_and_zero_dangling_offsets(backfill_file_id, backfill_data_len)?;
            }
        }
        Ok(())
    }

    /// Truncate `data_{file_id}` to `committed_len`.  If `highest_slot` is Some,
    /// also clear trailing offset entries beyond that slot.
    fn heal_file(
        &self,
        file_id: u64,
        highest_slot: Option<Slot>,
        committed_len: u64,
    ) -> StoreResult<()> {
        let data_path = self.data_path(file_id);
        if !data_path.exists() {
            return Ok(());
        }

        let data_file = OpenOptions::new().read(true).write(true).open(&data_path)?;
        let data_len = data_file.metadata()?.len();
        if data_len < committed_len {
            return Err(StaticColdStoreError::Invalid(
                "static cold data file shorter than committed length".into(),
            ));
        }
        if data_len != committed_len {
            data_file.set_len(committed_len)?;
            data_file.sync_all()?;
        }

        let Some(slot) = highest_slot else {
            return Ok(());
        };

        let off_path = self.offset_path(file_id);
        if !off_path.exists() {
            return Ok(());
        }

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
            off_file.seek(SeekFrom::Start(clear_start))?;
            off_file.write_all(&vec![0u8; (OFFSET_FILE_LEN - clear_start) as usize])?;
            off_file.sync_all()?;
        }
        Ok(())
    }

    /// Zero any offset entries that point past `committed_data_len`.
    /// O(SLOTS_PER_FILE) = O(8192).  Called only from `heal_on_open`.
    fn scan_and_zero_dangling_offsets(
        &self,
        file_id: u64,
        committed_data_len: u64,
    ) -> StoreResult<()> {
        let off_path = self.offset_path(file_id);
        if !off_path.exists() {
            return Ok(());
        }

        let mut off_file = OpenOptions::new().read(true).write(true).open(&off_path)?;
        let entries = (off_file.metadata()?.len() / OFFSET_SIZE) as usize;
        let mut any = false;
        let mut buf = [0u8; 8];
        for i in 0..entries {
            let pos = (i as u64) * OFFSET_SIZE;
            off_file.seek(SeekFrom::Start(pos))?;
            off_file.read_exact(&mut buf)?;
            let offset = u64::from_le_bytes(buf);
            if offset != 0 && offset >= committed_data_len {
                off_file.seek(SeekFrom::Start(pos))?;
                off_file.write_all(&0u64.to_le_bytes())?;
                any = true;
            }
        }
        if any {
            off_file.sync_all()?;
        }
        Ok(())
    }

    fn read_offset(&self, file_id: u64, slot: Slot) -> StoreResult<u64> {
        let off_path = self.offset_path(file_id);
        let mut off_file = match File::open(&off_path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
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

    let (allow_backfill, backfill_file_id, backfill_data_len) =
        if bytes.len() == CONFIG_LEN && &bytes[0..8] == CONFIG_MAGIC {
            let flags = bytes[27];
            (
                (flags & FLAG_ALLOW_BACKFILL) != 0,
                u64::from_le_bytes(bytes[36..44].try_into().expect("slice length checked")),
                u64::from_le_bytes(bytes[44..52].try_into().expect("slice length checked")),
            )
        } else if bytes.len() == CONFIG_LEN_V2 && &bytes[0..8] == CONFIG_MAGIC_V2 {
            (false, NO_BACKFILL_FILE, 0u64)
        } else {
            return Err(StaticColdStoreError::Invalid(
                "invalid static cold config".into(),
            ));
        };

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
        allow_backfill,
        backfill_file_id,
        backfill_data_len,
    })
}

fn atomic_write_config(
    config_path: &Path,
    tmp_path: &Path,
    root_dir: &Path,
    highest_written_slot: Option<Slot>,
    current_data_len: u64,
    config: &ColumnConfig,
    backfill_file_id: u64,
    backfill_data_len: u64,
) -> StoreResult<()> {
    let bytes: Vec<u8> = if config.allow_backfill {
        let mut b = [0u8; CONFIG_LEN];

        b[0..8].copy_from_slice(CONFIG_MAGIC);
        b[8..16].copy_from_slice(
            &highest_written_slot
                .map_or(EMPTY_SLOT, |slot| slot.as_u64())
                .to_le_bytes(),
        );
        b[16..24].copy_from_slice(&current_data_len.to_le_bytes());
        b[24..26].copy_from_slice(&config.record_type);
        b[26] = if config.compression {
            COMPRESSION_SNAPPY
        } else {
            COMPRESSION_NONE
        };
        b[27] = if config.allow_backfill {
            FLAG_ALLOW_BACKFILL
        } else {
            0
        };
        b[28..36].copy_from_slice(&config.max_value_bytes.to_le_bytes());
        b[36..44].copy_from_slice(&backfill_file_id.to_le_bytes());
        b[44..52].copy_from_slice(&backfill_data_len.to_le_bytes());

        b.to_vec()
    } else {
        let mut b = [0u8; CONFIG_LEN_V2];

        b[0..8].copy_from_slice(CONFIG_MAGIC_V2);
        b[8..16].copy_from_slice(
            &highest_written_slot
                .map_or(EMPTY_SLOT, |slot| slot.as_u64())
                .to_le_bytes(),
        );
        b[16..24].copy_from_slice(&current_data_len.to_le_bytes());
        b[24..26].copy_from_slice(&config.record_type);
        b[26] = if config.compression {
            COMPRESSION_SNAPPY
        } else {
            COMPRESSION_NONE
        };
        b[27] = 0;
        b[28..36].copy_from_slice(&config.max_value_bytes.to_le_bytes());

        b.to_vec()
    };

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
        self.columns[&c].put_batch(items).map_err(Into::into)
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

        let highest = {
            let state = column.state.lock();
            let Some(highest) = state.highest_written_slot else {
                return Box::new(std::iter::empty());
            };
            highest
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

#[cfg(test)]
mod tests {
    use crate::ColdStore;

    use super::*;
    use tempfile::TempDir;
    use types::MainnetEthSpec;

    const SLOT_8192: u64 = 8192;

    fn make_store(temp: &TempDir, allow_backfill: bool) -> StaticColdStore<MainnetEthSpec> {
        let mut config = StoreConfig::default();
        config.allow_backfill = allow_backfill;
        let path = temp.path();
        StaticColdStore::open(path, &config).unwrap()
    }

    fn write_slot(
        store: &StaticColdStore<MainnetEthSpec>,
        col: DBColumnCold,
        slot: u64,
        val: &[u8],
    ) {
        store.put(col, Slot::new(slot), val).unwrap();
    }

    fn get_slot(
        store: &StaticColdStore<MainnetEthSpec>,
        col: DBColumnCold,
        slot: u64,
    ) -> Option<Vec<u8>> {
        store.get(col, Slot::new(slot)).unwrap()
    }

    fn col_dir(temp: &TempDir, col: DBColumnCold) -> std::path::PathBuf {
        temp.path().join(column_config(col).subdir)
    }

    fn data_path(dir: &std::path::Path, file_id: u64) -> std::path::PathBuf {
        dir.join(format!("{DATA_FILE_PREFIX}{file_id:05}"))
    }

    fn offset_path(dir: &std::path::Path, file_id: u64) -> std::path::PathBuf {
        dir.join(format!("{DATA_FILE_PREFIX}{file_id:05}.off"))
    }

    /// Append raw record to data file without updating offset or config
    fn write_raw_record(
        data_path: &std::path::Path,
        record_type: [u8; 2],
        payload: &[u8],
    ) -> std::io::Result<u64> {
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(data_path)?;
        let len = u32::try_from(payload.len()).unwrap();
        let offset = file.seek(std::io::SeekFrom::End(0))?;
        file.write_all(&record_type)?;
        file.write_all(&len.to_le_bytes())?;
        file.write_all(&0u16.to_le_bytes())?;
        file.write_all(payload)?;
        Ok(offset)
    }

    /// Write offset entry directly
    fn write_offset(off_path: &std::path::Path, slot: u64, offset: u64) -> std::io::Result<()> {
        let pos = (slot % SLOT_8192) * 8;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(off_path)?;
        let current_len = file.metadata()?.len();
        if current_len < SLOT_8192 * 8 {
            file.set_len(SLOT_8192 * 8)?;
        }
        file.seek(std::io::SeekFrom::Start(pos))?;
        file.write_all(&offset.to_le_bytes())?;
        Ok(())
    }

    #[test]
    fn test_backfill_skipped_slot_readable() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 10, b"v10");
        write_slot(&store, col, 11, b"v11");
        // skipe 12
        write_slot(&store, col, 13, b"v13");

        write_slot(&store, col, 12, b"v12");

        assert_eq!(get_slot(&store, col, 12), Some(b"v12".to_vec()));
    }

    #[test]
    fn test_backfill_into_current_file() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        // Write slots in file 0 (0-8191)
        write_slot(&store, col, 100, b"v100");
        write_slot(&store, col, 200, b"v200");
        // Backfill slot 50 (same file 0)
        write_slot(&store, col, 50, b"v50");

        assert_eq!(get_slot(&store, col, 50), Some(b"v50".to_vec()));
        assert_eq!(get_slot(&store, col, 200), Some(b"v200".to_vec()));
    }

    #[test]
    fn test_backfill_into_sealed_file() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        // highest in file 1
        write_slot(&store, col, SLOT_8192 + 100, b"v");
        // backfill into file 0 (sealed)
        write_slot(&store, col, 50, b"v50");

        assert_eq!(get_slot(&store, col, 50), Some(b"v50".to_vec()));
        assert_eq!(get_slot(&store, col, SLOT_8192 + 100), Some(b"v".to_vec()));
    }

    #[test]
    fn test_backfill_rejected_when_disabled() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, false); // allow_backfill = false
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 10, b"v10");
        let res = store.put(col, Slot::new(5), b"v5");

        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot fill a previously-skipped slot")
        );
    }

    #[test]
    fn test_backfill_does_not_advance_highest_written_slot() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 100, b"v100");
        write_slot(&store, col, 50, b"v50"); // backfill

        // highest should still be 100
        let val = get_slot(&store, col, 100);
        assert!(val.is_some());
        let val50 = get_slot(&store, col, 50);
        assert!(val50.is_some());
    }

    #[test]
    fn test_backfill_idempotent_reput() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 10, b"v10");
        write_slot(&store, col, 5, b"v5");
        // Re-put same slot with identical value
        let res = store.put(col, Slot::new(5), b"v5");
        assert!(res.is_ok());
        assert_eq!(get_slot(&store, col, 5), Some(b"v5".to_vec()));
    }

    #[test]
    fn test_backfill_rejects_already_populated_slot_with_different_data() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 10, b"v10");
        write_slot(&store, col, 5, b"v5");
        // Re-put different value
        let res = store.put(col, Slot::new(5), b"different");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("conflicts"));
    }

    #[test]
    fn test_backfill_compressed_column_round_trip() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::Block; // compression: true

        write_slot(&store, col, SLOT_8192 + 100, b"v");
        write_slot(&store, col, 50, &[0xAB; 8192]);

        assert_eq!(get_slot(&store, col, 50), Some(vec![0xAB; 8192]));
    }

    #[test]
    fn test_iter_from_includes_backfilled_slots() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 0, b"v0");
        write_slot(&store, col, 10, b"v10");
        write_slot(&store, col, 5, b"v5"); // backfill

        let results: Vec<(Slot, Vec<u8>)> = ColdStore::iter_from(&store, col, Slot::new(0))
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, Slot::new(0));
        assert_eq!(results[1].0, Slot::new(5));
        assert_eq!(results[2].0, Slot::new(10));
    }

    #[test]
    fn test_contains_backfilled_slot() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 10, b"v10");
        assert!(!store.contains(col, Slot::new(5)).unwrap());

        write_slot(&store, col, 5, b"v5"); // backfill
        assert!(store.contains(col, Slot::new(5)).unwrap());
    }

    // Batched backfill

    #[test]
    fn test_backfill_batch_multiple_slots_same_file() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, SLOT_8192 + 100, b"v");
        let items: Vec<(Slot, Vec<u8>)> = (0..5)
            .map(|i| (Slot::new(i), format!("v{i}").into_bytes()))
            .collect();
        store.put_batch(col, items).unwrap();

        for i in 0..5 {
            assert_eq!(
                get_slot(&store, col, i as u64),
                Some(format!("v{i}").into_bytes())
            );
        }
    }

    #[test]
    fn test_backfill_batch_across_file_boundaries() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, SLOT_8192 * 2, b"v");
        // Batch spans files 0 and 1 (both non-current vs highest in file 2)
        let items: Vec<(Slot, _)> = vec![
            (Slot::new(50), b"v50".to_vec()),
            ((SLOT_8192 + 50).into(), b"v".to_vec()),
        ];
        let res = store.put_batch(col, items);

        assert!(res.is_err());
    }

    #[test]
    fn test_backfill_mixed_sequential_and_backfill_batch_rejected() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, 100, b"v100");
        // Batch has backfill slot (50) and sequential slot (200)
        let items: Vec<(Slot, _)> = vec![
            (Slot::new(50), b"v50".to_vec()),
            (Slot::new(200), b"v200".to_vec()),
        ];
        let res = store.put_batch(col, items);

        assert!(res.is_err());
    }

    // Crash recovery

    #[test]
    fn test_heal_truncates_data_and_zeros_dangling_offset_after_crash() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;
        let dir = col_dir(&tmp, col);

        write_slot(&store, col, 10, b"v10");

        // Crash: backfill data + offset written, conf not updated
        let offset = write_raw_record(&data_path(&dir, 0), [0x02, 0x00], b"backfill").unwrap();
        write_offset(&offset_path(&dir, 0), 5, offset).unwrap();

        drop(store);

        let store2 = make_store(&tmp, true);
        assert_eq!(get_slot(&store2, col, 10), Some(b"v10".to_vec()));
        assert_eq!(get_slot(&store2, col, 5), None);
    }

    #[test]
    fn test_heal_preserves_committed_backfill_data() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        write_slot(&store, col, SLOT_8192 + 100, b"v");
        write_slot(&store, col, 50, b"v50");

        drop(store);

        let store2 = make_store(&tmp, true);
        assert_eq!(get_slot(&store2, col, 50), Some(b"v50".to_vec()));
    }

    #[test]
    fn test_sequential_write_after_backfill_correct_data_len() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;

        // Backfill into sealed file
        write_slot(&store, col, SLOT_8192 + 100, b"v");
        write_slot(&store, col, 50, b"v50");
        // Sequential write into current file
        write_slot(&store, col, SLOT_8192 + 200, b"v200");

        drop(store);

        let store2 = make_store(&tmp, true);
        assert_eq!(get_slot(&store2, col, 50), Some(b"v50".to_vec()));
        assert_eq!(
            get_slot(&store2, col, SLOT_8192 + 200),
            Some(b"v200".to_vec())
        );
    }

    /// Test heal truncates uncommitted data in sealed backfill file
    #[test]
    fn test_heal_truncates_uncommitted_backfill_in_sealed_file() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;
        let dir = col_dir(&tmp, col);

        // Commit highest in file 1
        write_slot(&store, col, SLOT_8192 + 100, b"v100");

        // Crash: backfill data + offset written, conf not updated
        let backfill_offset =
            write_raw_record(&data_path(&dir, 0), [0x02, 0x00], b"backfill").unwrap();
        write_offset(&offset_path(&dir, 0), 50, backfill_offset).unwrap();

        drop(store);

        let store2 = make_store(&tmp, true);
        assert_eq!(
            get_slot(&store2, col, SLOT_8192 + 100),
            Some(b"v100".to_vec())
        );
    }

    /// Test multiple sequential uncommitted records get truncated
    #[test]
    fn test_heal_truncates_multiple_uncommitted_backfills() {
        let tmp = TempDir::new().unwrap();
        let store = make_store(&tmp, true);
        let col = DBColumnCold::BlockRoots;
        let dir = col_dir(&tmp, col);

        write_slot(&store, col, 100, b"v100");

        // Write 3 uncommitted backfill records
        for slot in [10, 20, 30] {
            let offset = write_raw_record(
                &data_path(&dir, 0),
                [0x02, 0x00],
                format!("v{slot}").as_bytes(),
            )
            .unwrap();
            write_offset(&offset_path(&dir, 0), slot, offset).unwrap();
        }
        // Partial write of 4th (simulates crash mid-write)
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&data_path(&dir, 0))
                .unwrap();
            file.write_all(&[0x02, 0x00, 8, 0, 0, 0, 0, 0]).unwrap();
        }

        drop(store);

        let store2 = make_store(&tmp, true);
        assert_eq!(get_slot(&store2, col, 100), Some(b"v100".to_vec()));
        // All uncommitted should be truncated
        assert_eq!(get_slot(&store2, col, 10), None);
        assert_eq!(get_slot(&store2, col, 20), None);
        assert_eq!(get_slot(&store2, col, 30), None);
    }

    #[test]
    fn test_v2_conf_upgrades_to_v3_when_backfill_enabled() {
        let tmp = TempDir::new().unwrap();
        let col = DBColumnCold::BlockRoots;
        let dir = col_dir(&tmp, col);
        let conf_path = dir.join(CONFIG_FILE);

        // Open with backfill disabled (writes v2 format)
        {
            let store = make_store(&tmp, false);
            write_slot(&store, col, 10, b"v10");
        }

        // Verify v2 format on disk
        let bytes = std::fs::read(&conf_path).unwrap();
        assert_eq!(&bytes[0..8], b"LHSTBLK2");
        assert_eq!(bytes.len(), CONFIG_LEN_V2);

        // Reopen with backfill enabled - should upgrade to v3
        {
            let store = make_store(&tmp, true);
            write_slot(&store, col, 5, b"v5");
            assert_eq!(get_slot(&store, col, 5), Some(b"v5".to_vec()));
        }

        // Verify v3 format on disk
        let bytes = std::fs::read(&conf_path).unwrap();
        assert_eq!(&bytes[0..8], b"LHSTBLK3");
        assert_eq!(bytes.len(), CONFIG_LEN);
        assert_eq!(bytes[27] & FLAG_ALLOW_BACKFILL, FLAG_ALLOW_BACKFILL);
    }
}
