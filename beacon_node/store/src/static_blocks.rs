//! Slot-keyed durable archive for finalized blinded blocks.
//!
//! `StaticBlockStore` is a black box from `HotColdDB`'s perspective: hand it block bytes,
//! ask it for them back by slot. File mapping, recovery, and rename semantics are internal.
//!
//! Contract:
//! - `put(slot, bytes)` is durable on return. The caller is allowed to rely on this for
//!   source-of-truth flips (e.g. writing a reverse-index entry, deleting from hot KV).
//!
//! See `specs/static-blocks.md` for the on-disk format.

use snap::{read::FrameDecoder, write::FrameEncoder};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use types::Slot;

const SLOTS_PER_FILE: u64 = 8192;
const OFFSET_SIZE: u64 = 8;
const OFFSET_FILE_LEN: u64 = SLOTS_PER_FILE * OFFSET_SIZE;
const CONFIG_FILE: &str = "static_blocks.conf";
const CONFIG_TMP_FILE: &str = "static_blocks.conf.tmp";
const CONFIG_MAGIC: &[u8; 8] = b"LHSTBLK1";
const CONFIG_LEN: usize = 24;
// Empty-store sentinel for `highest_written_slot` in `static_blocks.conf`.
const EMPTY_SLOT: u64 = u64::MAX;
// e2store version record.
const VERSION_RECORD: [u8; 8] = [0x65, 0x32, 0, 0, 0, 0, 0, 0];
// CompressedSignedBeaconBlock e2store record type.
const BLOCK_RECORD_TYPE: [u8; 2] = [0x01, 0x00];
const MAX_DECOMPRESSED_BLOCK_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug)]
pub struct StaticBlockStore {
    root_dir: PathBuf,
    highest_written_slot: Mutex<Option<Slot>>,
}

struct Config {
    highest_written_slot: Option<Slot>,
    current_data_len: u64,
}

type StoreResult<T> = std::result::Result<T, StaticBlockStoreError>;

#[derive(Debug)]
pub enum StaticBlockStoreError {
    Io(io::Error),
    Compression(io::Error),
    Invalid(String),
}

impl fmt::Display for StaticBlockStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "static block store io error: {e}"),
            Self::Compression(e) => write!(f, "static block store compression error: {e}"),
            Self::Invalid(message) => write!(f, "static block store invalid data: {message}"),
        }
    }
}

impl From<io::Error> for StaticBlockStoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl StaticBlockStore {
    /// Open the archive rooted at `path`.
    pub fn open(path: &Path) -> StoreResult<Self> {
        fs::create_dir_all(path)?;

        let store = Self {
            root_dir: path.to_path_buf(),
            highest_written_slot: Mutex::new(None),
        };

        if !store.config_path().exists() {
            store.write_config(None, 0)?;
        }

        let config = store.read_config()?;
        if let Some(slot) = config.highest_written_slot {
            store.heal_current_file(slot, config.current_data_len)?;
        }
        *store.lock_highest()? = config.highest_written_slot;

        Ok(store)
    }

    /// Read the block at `slot`, if present.
    pub fn get(&self, slot: Slot) -> StoreResult<Option<Vec<u8>>> {
        let Some(highest_written_slot) = *self.lock_highest()? else {
            return Ok(None);
        };
        if slot > highest_written_slot {
            return Ok(None);
        }

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
        if header[0..2] != BLOCK_RECORD_TYPE || header[6..8] != [0, 0] {
            return Err(StaticBlockStoreError::Invalid(
                "invalid static block record header".into(),
            ));
        }

        let len = u32::from_le_bytes([header[2], header[3], header[4], header[5]]) as usize;
        let mut compressed = vec![0; len];
        data_file.read_exact(&mut compressed)?;

        decompress_block(&compressed)
    }

    /// Durably store `bytes` at `slot`. Must not return `Ok` until the bytes are recoverable
    /// after a crash.
    pub fn put(&self, slot: Slot, bytes: &[u8]) -> StoreResult<()> {
        let mut highest_written_slot = self.lock_highest()?;
        if highest_written_slot.is_some_and(|highest| slot <= highest) {
            return Err(StaticBlockStoreError::Invalid(
                "static block put out of order".into(),
            ));
        }

        let compressed = compress_block(bytes)?;
        let compressed_len = u32::try_from(compressed.len()).map_err(|_| {
            StaticBlockStoreError::Invalid("compressed static block too large".into())
        })?;

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
        write_block_record(&mut data_file, compressed_len, &compressed)?;
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

    /// Truncate uncommitted data and clear uncommitted offsets after restart.
    fn heal_current_file(&self, slot: Slot, current_data_len: u64) -> StoreResult<()> {
        let file_id = file_id(slot);
        let data_path = self.data_path(file_id);
        let data_file = OpenOptions::new().read(true).write(true).open(&data_path)?;
        let data_len = data_file.metadata()?.len();
        if data_len < current_data_len {
            return Err(StaticBlockStoreError::Invalid(
                "static block data file shorter than committed length".into(),
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
            return Err(StaticBlockStoreError::Invalid(
                "static block offset file shorter than committed slot".into(),
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

    /// Read the global commit marker.
    fn read_config(&self) -> StoreResult<Config> {
        let path = self.config_path();
        let bytes = fs::read(&path)?;
        if bytes.len() != CONFIG_LEN || &bytes[0..8] != CONFIG_MAGIC {
            return Err(StaticBlockStoreError::Invalid(
                "invalid static block config".into(),
            ));
        }

        let highest = u64::from_le_bytes(bytes[8..16].try_into().expect("slice length checked"));
        let current_data_len =
            u64::from_le_bytes(bytes[16..24].try_into().expect("slice length checked"));

        Ok(Config {
            highest_written_slot: (highest != EMPTY_SLOT).then(|| Slot::new(highest)),
            current_data_len,
        })
    }

    /// Atomically write the global commit marker.
    fn write_config(
        &self,
        highest_written_slot: Option<Slot>,
        current_data_len: u64,
    ) -> StoreResult<()> {
        let path = self.config_path();
        let tmp_path = self.root_dir.join(CONFIG_TMP_FILE);
        let mut bytes = [0; CONFIG_LEN];
        bytes[0..8].copy_from_slice(CONFIG_MAGIC);
        bytes[8..16].copy_from_slice(
            &highest_written_slot
                .map_or(EMPTY_SLOT, |slot| slot.as_u64())
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&current_data_len.to_le_bytes());

        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(&bytes)?;
            tmp.sync_all()?;
        }

        fs::rename(&tmp_path, &path)?;
        sync_dir(&self.root_dir)
    }

    /// Read the slot's absolute data-file offset.
    fn read_offset(&self, file_id: u64, slot: Slot) -> StoreResult<u64> {
        let off_path = self.offset_path(file_id);
        let mut off_file = File::open(&off_path)?;
        let mut bytes = [0; 8];
        off_file.seek(SeekFrom::Start(offset_position(slot)))?;
        off_file.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    /// Lock writer state.
    fn lock_highest(&self) -> StoreResult<std::sync::MutexGuard<'_, Option<Slot>>> {
        self.highest_written_slot
            .lock()
            .map_err(|_| StaticBlockStoreError::Invalid("static block mutex poisoned".into()))
    }

    /// Path to the global config file.
    fn config_path(&self) -> PathBuf {
        self.root_dir.join(CONFIG_FILE)
    }

    /// Path to a data file.
    fn data_path(&self, file_id: u64) -> PathBuf {
        self.root_dir.join(format!("static_blocks_{file_id:05}"))
    }

    /// Path to a sidecar offset file.
    fn offset_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("static_blocks_{file_id:05}.off"))
    }
}

/// File id containing `slot`.
fn file_id(slot: Slot) -> u64 {
    slot.as_u64() / SLOTS_PER_FILE
}

/// Byte position of `slot` in its `.off` file.
fn offset_position(slot: Slot) -> u64 {
    (slot.as_u64() % SLOTS_PER_FILE) * OFFSET_SIZE
}

/// Snappy-frame SSZ block bytes.
fn compress_block(bytes: &[u8]) -> StoreResult<Vec<u8>> {
    let mut encoder = FrameEncoder::new(Vec::new());
    encoder
        .write_all(bytes)
        .map_err(StaticBlockStoreError::Compression)?;
    encoder
        .flush()
        .map_err(StaticBlockStoreError::Compression)?;
    Ok(encoder.get_ref().clone())
}

/// Append one compressed block record.
fn write_block_record(file: &mut File, compressed_len: u32, compressed: &[u8]) -> StoreResult<()> {
    file.write_all(&BLOCK_RECORD_TYPE)?;
    file.write_all(&compressed_len.to_le_bytes())?;
    file.write_all(&0u16.to_le_bytes())?;
    file.write_all(compressed)?;
    Ok(())
}

/// Decode one compressed block record payload.
fn decompress_block(bytes: &[u8]) -> StoreResult<Option<Vec<u8>>> {
    let decoder = FrameDecoder::new(bytes);
    let mut limited = decoder.take(MAX_DECOMPRESSED_BLOCK_BYTES + 1);
    let mut decompressed = Vec::new();
    limited
        .read_to_end(&mut decompressed)
        .map_err(StaticBlockStoreError::Compression)?;
    if decompressed.len() as u64 > MAX_DECOMPRESSED_BLOCK_BYTES {
        return Err(StaticBlockStoreError::Invalid(
            "static block exceeds decompressed size limit".into(),
        ));
    }
    Ok(Some(decompressed))
}

/// Fsync directory entries after rename/create.
fn sync_dir(path: &Path) -> StoreResult<()> {
    let dir = File::open(path)?;
    dir.sync_all()?;
    Ok(())
}
