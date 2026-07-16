//! Slot-indexed, append-only static file storage.
//!
//! `StaticFile` owns one directory containing:
//!
//! ```text
//! <root>/
//!   data_{file_id:05}       # `LHSF` header, then raw payloads; file_id = slot / SLOTS_PER_FILE
//!   data_{file_id:05}.idx   # SLOTS_PER_FILE entries `offset u64 | len u32 | crc32 u32`,
//!                           # all-zero = no record; full files gain a seal footer
//!   meta                    # dual-slot commit marker; also carries the column lock
//! ```
//!
//! # Commit marker
//!
//! `meta` holds two fixed slots. A commit writes the inactive slot
//! (`magic | version | seq | highest_slot | data_len | crc`) and fsyncs; open
//! picks the valid slot with the highest seq, so a torn commit self-invalidates
//! and the previous marker wins. No renames, no directory fsyncs on the
//! commit path.
//!
//! # Write contract
//!
//! Writes go through [`Batch`]: strictly ascending slots, streamed to disk on
//! `put`, durable when `commit` returns. Order per file: payloads, fsync,
//! index entries, fsync, seal when moving past a file, then the meta commit.
//! Re-puts of committed slots are verified against the stored crc and skipped;
//! skipped slots can't be filled. An I/O error poisons the handle — writes
//! rejected until reopen, reads stay live. Every read is crc-verified.
//!
//! # Recovery on open
//!
//! Heal to the marker: truncate the top data file to `data_len`, zero index
//! entries beyond `highest_slot`, drop the top file's seal and any files
//! beyond it. An abandoned uncommitted batch triggers the same healing on the
//! next batch.

use parking_lot::{Mutex, MutexGuard};
use std::{
    fmt,
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

/// Slots per data file.
pub const SLOTS_PER_FILE: u64 = 8192;

const ENTRY_LEN: u64 = 16;
const TABLE_LEN: u64 = SLOTS_PER_FILE * ENTRY_LEN;
const META_FILE: &str = "meta";
const META_SLOT_LEN: usize = 64;
const DATA_FILE_PREFIX: &str = "data_";
const IDX_SUFFIX: &str = ".idx";
/// File identity. Format revisions bump `FORMAT_VERSION`, not this.
const MAGIC: &[u8; 4] = b"LHSF";
/// On-disk format version. Bump on any breaking layout change (implies a rebuild).
const FORMAT_VERSION: u32 = 2;
/// Empty-store sentinel for `highest_slot` in the meta slots.
const EMPTY_SLOT: u64 = u64::MAX;
/// Sanity cap per record; bounds the read-side allocation.
const MAX_RECORD_LEN: u64 = 1 << 30;

/// Last durable commit marker.
#[derive(Debug, Clone, Copy)]
struct CommittedState {
    /// Highest committed slot, or `None` when empty.
    highest_slot: Option<u64>,
    /// Committed end of the file containing `highest_slot`.
    data_len: u64,
}

/// One index-table entry: where a record lives and how to verify it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    offset: u64,
    len: u32,
    crc: u32,
}

impl Entry {
    fn serialize(&self) -> [u8; ENTRY_LEN as usize] {
        let mut b = [0u8; ENTRY_LEN as usize];
        b[0..8].copy_from_slice(&self.offset.to_le_bytes());
        b[8..12].copy_from_slice(&self.len.to_le_bytes());
        b[12..16].copy_from_slice(&self.crc.to_le_bytes());
        b
    }

    fn deserialize(b: &[u8; ENTRY_LEN as usize]) -> Option<Self> {
        if b.iter().all(|&x| x == 0) {
            return None;
        }
        Some(Self {
            offset: u64::from_le_bytes(b[0..8].try_into().expect("slice length checked")),
            len: u32::from_le_bytes(b[8..12].try_into().expect("slice length checked")),
            crc: u32::from_le_bytes(b[12..16].try_into().expect("slice length checked")),
        })
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// Writes rejected after an earlier write failure; reopen to heal.
    Poisoned,
    /// Another handle holds the column lock.
    AlreadyOpen(PathBuf),
    /// On-disk state failed validation — repair or rebuild.
    Corrupt(String),
    /// Caller contract violation; state unchanged.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "static file io error: {e}"),
            Self::Poisoned => {
                write!(
                    f,
                    "writes rejected after an earlier write failure; reopen to heal"
                )
            }
            Self::AlreadyOpen(path) => {
                write!(f, "already open by another handle: {}", path.display())
            }
            Self::Corrupt(message) => write!(f, "static file corrupt: {message}"),
            Self::Invalid(message) => write!(f, "static file invalid data: {message}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Slot-keyed file set owning one column directory.
#[derive(Debug)]
pub struct StaticFile {
    root_dir: PathBuf,
    /// Commit marker file; held open for its lock and for commit writes.
    meta: File,
    // Writer holds this across a batch's fsyncs, so readers block. Accepted:
    // simplicity over read concurrency.
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    committed: CommittedState,
    /// Seq of the current marker; the next commit writes seq + 1.
    seq: u64,
    /// Set when a write error leaves on-disk state unverified; further writes
    /// error until reopen. Reads stay safe: `committed` never runs ahead of disk.
    poisoned: bool,
    /// Set when a batch was dropped uncommitted; the next batch heals first.
    dirty: bool,
}

impl StaticFile {
    /// Open or create a `StaticFile` rooted at `root_dir`. The column is
    /// identified by its directory.
    pub fn open(root_dir: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&root_dir)?;
        // Make the column dir's own dirent durable; fsyncs inside it don't.
        if let Some(parent) = root_dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }

        // Lock before touching anything: a second handle would heal
        // destructively under a live writer.
        let meta = f_open(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false),
            &root_dir.join(META_FILE),
        )?;
        match meta.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::AlreadyOpen(root_dir));
            }
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }

        let (seq, committed) = if meta.metadata()?.len() == 0 {
            // A store writes meta before any data file, so data files without
            // one mean external damage — don't wipe them.
            if dir_has_static_files(&root_dir)? {
                return Err(Error::Corrupt(format!(
                    "meta missing but data files exist in {}",
                    root_dir.display()
                )));
            }
            let empty = CommittedState {
                highest_slot: None,
                data_len: 0,
            };
            write_meta(&meta, 1, empty)?;
            sync_dir(&root_dir)?;
            (1, empty)
        } else {
            read_meta(&meta)?
        };

        let handle = Self {
            root_dir,
            meta,
            state: Mutex::new(State {
                committed,
                seq,
                poisoned: false,
                dirty: false,
            }),
        };
        handle.heal_to_marker(committed)?;
        Ok(handle)
    }

    /// Slot of the most recently committed record, if any — the resume point
    /// for interrupted migrations. Slots below it may still be gaps.
    pub fn highest_written_slot(&self) -> Option<u64> {
        self.state.lock().committed.highest_slot
    }

    /// Read the record at `slot`, if present; crc-verified.
    pub fn get(&self, slot: u64) -> Result<Option<Vec<u8>>, Error> {
        if self.highest_written_slot().is_none_or(|h| slot > h) {
            return Ok(None);
        }
        let Some(entry) = self.read_entry(slot)? else {
            return Ok(None);
        };
        if u64::from(entry.len) > MAX_RECORD_LEN {
            return Err(Error::Corrupt(format!(
                "record length {} at slot {slot} exceeds cap",
                entry.len
            )));
        }

        let mut data = File::open(self.data_path(file_id(slot)))?;
        data.seek(SeekFrom::Start(entry.offset))?;
        let mut payload = vec![0; entry.len as usize];
        data.read_exact(&mut payload)?;
        if crc32fast::hash(&payload) != entry.crc {
            return Err(Error::Corrupt(format!("crc mismatch at slot {slot}")));
        }
        Ok(Some(payload))
    }

    /// `true` if a record exists at `slot`. Cheaper than `get` — only the
    /// index is consulted; the payload is not read or verified.
    pub fn contains(&self, slot: u64) -> Result<bool, Error> {
        if self.highest_written_slot().is_none_or(|h| slot > h) {
            return Ok(false);
        }
        Ok(self.read_entry(slot)?.is_some())
    }

    /// Durably store `bytes` at `slot`; a batch of one.
    pub fn put(&self, slot: u64, bytes: &[u8]) -> Result<(), Error> {
        let mut batch = self.batch()?;
        batch.put(slot, bytes)?;
        batch.commit()
    }

    /// Start a write batch. Puts stream to disk; nothing is visible or
    /// durable until [`Batch::commit`].
    pub fn batch(&self) -> Result<Batch<'_>, Error> {
        let mut state = self.state.lock();
        if state.poisoned {
            return Err(Error::Poisoned);
        }
        if state.dirty {
            if let Err(e) = self.heal_to_marker(state.committed) {
                state.poisoned = true;
                return Err(e);
            }
            state.dirty = false;
        }
        Ok(Batch {
            store: self,
            state,
            cur: None,
            last_put: None,
            written: None,
            done: false,
        })
    }

    fn read_entry(&self, slot: u64) -> Result<Option<Entry>, Error> {
        let mut idx = match File::open(self.idx_path(file_id(slot))) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        idx.seek(SeekFrom::Start(entry_position(slot)))?;
        let mut buf = [0u8; ENTRY_LEN as usize];
        idx.read_exact(&mut buf)?;
        Ok(Entry::deserialize(&buf))
    }

    /// Restore files to the marker: truncate the top data file, zero index
    /// entries beyond `highest_slot`, drop the top seal and files beyond.
    fn heal_to_marker(&self, committed: CommittedState) -> Result<(), Error> {
        let Some(highest) = committed.highest_slot else {
            return self.remove_files_beyond(None);
        };
        let top = file_id(highest);

        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.data_path(top))?;
        let data_len = data.metadata()?.len();
        if data_len < committed.data_len {
            return Err(Error::Corrupt(
                "data file shorter than committed length".into(),
            ));
        }
        if data_len != committed.data_len {
            f_set_len(&data, committed.data_len)?;
            sync_file(&data)?;
        }

        let idx = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.idx_path(top))?;
        let idx_len = idx.metadata()?.len();
        if idx_len < TABLE_LEN {
            return Err(Error::Corrupt("index shorter than its table".into()));
        }
        if idx_len > TABLE_LEN {
            // Drop an uncommitted seal.
            f_set_len(&idx, TABLE_LEN)?;
        }
        let zero_from = entry_position(highest) + ENTRY_LEN;
        if zero_from < TABLE_LEN {
            f_write_at(
                &idx,
                zero_from,
                &vec![0u8; (TABLE_LEN - zero_from) as usize],
            )?;
        }
        sync_file(&idx)?;

        self.remove_files_beyond(Some(top))
    }

    /// Remove data/index files newer than `max_file_id`; `None` removes all.
    fn remove_files_beyond(&self, max_file_id: Option<u64>) -> Result<(), Error> {
        let mut removed = false;
        for entry in fs::read_dir(&self.root_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            let Some(file_id) = static_file_id(file_name) else {
                continue;
            };
            if max_file_id.is_none_or(|max| file_id > max) {
                if !entry.file_type()?.is_file() {
                    return Err(Error::Corrupt(format!(
                        "static data path is not a file: {}",
                        entry.path().display()
                    )));
                }
                f_remove(&entry.path())?;
                removed = true;
            }
        }
        if removed {
            sync_dir(&self.root_dir)?;
        }
        Ok(())
    }

    /// Append a seal footer to a full file's index if not already sealed.
    fn seal_file(&self, file_id: u64) -> Result<(), Error> {
        let mut idx = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.idx_path(file_id))?;
        if idx.metadata()?.len() > TABLE_LEN {
            return Ok(());
        }
        let mut table = vec![0u8; TABLE_LEN as usize];
        idx.seek(SeekFrom::Start(0))?;
        idx.read_exact(&mut table)?;

        let mut seal = [0u8; META_SLOT_LEN];
        seal[0..4].copy_from_slice(MAGIC);
        seal[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        seal[8..16].copy_from_slice(&file_id.to_le_bytes());
        seal[16..20].copy_from_slice(&crc32fast::hash(&table).to_le_bytes());
        let crc = crc32fast::hash(&seal[..META_SLOT_LEN - 4]);
        seal[META_SLOT_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

        f_write_at(&idx, TABLE_LEN, &seal)?;
        sync_file(&idx)
    }

    fn data_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("{DATA_FILE_PREFIX}{file_id:05}"))
    }

    fn idx_path(&self, file_id: u64) -> PathBuf {
        self.root_dir
            .join(format!("{DATA_FILE_PREFIX}{file_id:05}{IDX_SUFFIX}"))
    }
}

/// One file being written by a [`Batch`].
struct CurFile {
    file_id: u64,
    data: BufWriter<File>,
    idx: File,
    cursor: u64,
    entries: Vec<(u64, Entry)>,
}

/// Streaming write batch; holds the writer lock. Durable on `commit`;
/// dropping it uncommitted discards the writes (healed lazily).
pub struct Batch<'a> {
    store: &'a StaticFile,
    state: MutexGuard<'a, State>,
    cur: Option<CurFile>,
    last_put: Option<u64>,
    /// Last slot actually written and the data cursor after it.
    written: Option<(u64, u64)>,
    done: bool,
}

impl Batch<'_> {
    /// Stream `bytes` for `slot` to disk. Slots strictly ascending; a re-put
    /// of a committed slot is crc-verified and skipped.
    pub fn put(&mut self, slot: u64, bytes: &[u8]) -> Result<(), Error> {
        if self.state.poisoned {
            return Err(Error::Poisoned);
        }
        if slot == EMPTY_SLOT {
            return Err(Error::Invalid("slot u64::MAX is reserved".into()));
        }
        if self.last_put.is_some_and(|last| slot <= last) {
            return Err(Error::Invalid("slots must be strictly ascending".into()));
        }
        if bytes.len() as u64 > MAX_RECORD_LEN || u32::try_from(bytes.len()).is_err() {
            return Err(Error::Invalid(format!(
                "record at slot {slot} exceeds size limit"
            )));
        }

        // Committed prefix: verify against the stored crc and skip.
        if self.state.committed.highest_slot.is_some_and(|h| slot <= h) {
            let entry = self.store.read_entry(slot)?.ok_or_else(|| {
                Error::Invalid(format!("cannot fill previously-skipped slot {slot}"))
            })?;
            if entry.len as usize != bytes.len() || entry.crc != crc32fast::hash(bytes) {
                return Err(Error::Invalid(format!(
                    "re-put at slot {slot} with mismatched value"
                )));
            }
            self.last_put = Some(slot);
            return Ok(());
        }

        if let Err(e) = self.write_record(slot, bytes) {
            self.state.poisoned = true;
            return Err(e);
        }
        self.last_put = Some(slot);
        Ok(())
    }

    /// Make the batch durable and visible. A batch that wrote nothing is a
    /// no-op.
    pub fn commit(mut self) -> Result<(), Error> {
        let Some((last_slot, data_len)) = self.written else {
            self.done = true;
            return Ok(());
        };
        if let Err(e) = self.finish_current(false) {
            self.state.poisoned = true;
            return Err(e);
        }

        let seq = self.state.seq + 1;
        let committed = CommittedState {
            highest_slot: Some(last_slot),
            data_len,
        };
        if let Err(e) = write_meta(&self.store.meta, seq, committed) {
            self.state.poisoned = true;
            return Err(e);
        }
        self.state.seq = seq;
        self.state.committed = committed;
        self.done = true;
        Ok(())
    }

    fn write_record(&mut self, slot: u64, bytes: &[u8]) -> Result<(), Error> {
        let target = file_id(slot);
        if self.cur.as_ref().is_none_or(|c| c.file_id != target) {
            self.switch_file(target)?;
        }
        let cur = self.cur.as_mut().expect("switched above");

        gate()?;
        cur.data.write_all(bytes)?;
        cur.entries.push((
            slot,
            Entry {
                offset: cur.cursor,
                len: bytes.len() as u32,
                crc: crc32fast::hash(bytes),
            },
        ));
        cur.cursor += bytes.len() as u64;
        self.written = Some((slot, cur.cursor));
        Ok(())
    }

    /// Finish the current file and open `target` for writing.
    fn switch_file(&mut self, target: u64) -> Result<(), Error> {
        if self.cur.is_some() {
            // Moving past the current file: it is full history now, seal it.
            self.finish_current(true)?;
        } else if let Some(top) = self.state.committed.highest_slot.map(file_id)
            && target > top
        {
            // Skipping past the committed top file without touching it.
            self.store.seal_file(top)?;
        }

        let committed = self.state.committed;
        let data = f_open(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false),
            &self.store.data_path(target),
        )?;
        let cursor = if committed.highest_slot.is_some_and(|h| file_id(h) == target) {
            committed.data_len
        } else {
            // New file: plant the header, start just past it.
            if data.metadata()?.len() != 0 {
                f_set_len(&data, 0)?;
            }
            f_write_at(&data, 0, &MAGIC[..])?;
            MAGIC.len() as u64
        };
        let data_len = data.metadata()?.len();
        if data_len < cursor {
            return Err(Error::Corrupt(
                "data file shorter than committed length".into(),
            ));
        }
        if data_len != cursor {
            f_set_len(&data, cursor)?;
        }
        let mut data = data;
        data.seek(SeekFrom::Start(cursor))?;

        let idx = f_open(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false),
            &self.store.idx_path(target),
        )?;
        // Pre-size so absent slots read as zero entries; drop any stale seal.
        if idx.metadata()?.len() != TABLE_LEN {
            f_set_len(&idx, TABLE_LEN)?;
        }

        self.cur = Some(CurFile {
            file_id: target,
            // 1 MiB batches tiny record writes during imports.
            data: BufWriter::with_capacity(1 << 20, data),
            idx,
            cursor,
            entries: Vec::new(),
        });
        Ok(())
    }

    /// Flush and fsync the current file: payloads first, then index entries.
    fn finish_current(&mut self, seal: bool) -> Result<(), Error> {
        let Some(mut cur) = self.cur.take() else {
            return Ok(());
        };
        cur.data.flush()?;
        sync_file(cur.data.get_ref())?;
        for (slot, entry) in &cur.entries {
            f_write_at(&cur.idx, entry_position(*slot), &entry.serialize())?;
        }
        sync_file(&cur.idx)?;
        if seal {
            let id = cur.file_id;
            drop(cur);
            self.store.seal_file(id)?;
        }
        Ok(())
    }
}

impl Drop for Batch<'_> {
    fn drop(&mut self) {
        if self.written.is_some() && !self.done {
            self.state.dirty = true;
        }
    }
}

/// Serialize the marker into one meta slot.
fn serialize_meta_slot(seq: u64, committed: CommittedState) -> [u8; META_SLOT_LEN] {
    let mut b = [0u8; META_SLOT_LEN];
    b[0..4].copy_from_slice(MAGIC);
    b[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    b[8..16].copy_from_slice(&seq.to_le_bytes());
    b[16..24].copy_from_slice(&committed.highest_slot.unwrap_or(EMPTY_SLOT).to_le_bytes());
    b[24..32].copy_from_slice(&committed.data_len.to_le_bytes());
    let crc = crc32fast::hash(&b[..META_SLOT_LEN - 4]);
    b[META_SLOT_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    b
}

/// Parse one meta slot; `None` if it fails validation.
fn parse_meta_slot(b: &[u8]) -> Option<(u64, CommittedState)> {
    if b.len() != META_SLOT_LEN || &b[0..4] != MAGIC {
        return None;
    }
    if u32::from_le_bytes(b[4..8].try_into().expect("slice length checked")) != FORMAT_VERSION {
        return None;
    }
    let crc = u32::from_le_bytes(
        b[META_SLOT_LEN - 4..]
            .try_into()
            .expect("slice length checked"),
    );
    if crc32fast::hash(&b[..META_SLOT_LEN - 4]) != crc {
        return None;
    }
    let seq = u64::from_le_bytes(b[8..16].try_into().expect("slice length checked"));
    let highest = u64::from_le_bytes(b[16..24].try_into().expect("slice length checked"));
    let data_len = u64::from_le_bytes(b[24..32].try_into().expect("slice length checked"));
    Some((
        seq,
        CommittedState {
            highest_slot: (highest != EMPTY_SLOT).then_some(highest),
            data_len,
        },
    ))
}

/// Commit: write the inactive slot and fsync. The fsync is the commit point.
fn write_meta(meta: &File, seq: u64, committed: CommittedState) -> Result<(), Error> {
    let slot_offset = (seq % 2) * META_SLOT_LEN as u64;
    f_write_at(meta, slot_offset, &serialize_meta_slot(seq, committed))?;
    sync_file(meta)
}

/// Pick the valid slot with the highest seq.
fn read_meta(meta: &File) -> Result<(u64, CommittedState), Error> {
    let mut buf = [0u8; META_SLOT_LEN * 2];
    let mut f = meta;
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut buf)?;
    [&buf[..META_SLOT_LEN], &buf[META_SLOT_LEN..]]
        .iter()
        .filter_map(|slot| parse_meta_slot(slot))
        .max_by_key(|(seq, _)| *seq)
        .ok_or_else(|| Error::Corrupt("no valid meta slot".into()))
}

fn file_id(slot: u64) -> u64 {
    slot / SLOTS_PER_FILE
}

fn entry_position(slot: u64) -> u64 {
    (slot % SLOTS_PER_FILE) * ENTRY_LEN
}

fn static_file_id(file_name: &str) -> Option<u64> {
    let suffix = file_name.strip_prefix(DATA_FILE_PREFIX)?;
    let id = suffix.strip_suffix(IDX_SUFFIX).unwrap_or(suffix);
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    id.parse().ok()
}

/// `true` if `root_dir` contains any data or index file.
fn dir_has_static_files(root_dir: &Path) -> Result<bool, Error> {
    for entry in fs::read_dir(root_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if static_file_id(file_name).is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

// ---- gated file ops: every write-path syscall goes through one of these so
// tests can inject a fault at any boundary ----

fn f_open(opts: &OpenOptions, path: &Path) -> Result<File, Error> {
    gate()?;
    Ok(opts.open(path)?)
}

fn f_write_at(file: &File, pos: u64, bytes: &[u8]) -> Result<(), Error> {
    gate()?;
    let mut f = file;
    f.seek(SeekFrom::Start(pos))?;
    f.write_all(bytes)?;
    Ok(())
}

fn f_set_len(file: &File, len: u64) -> Result<(), Error> {
    gate()?;
    Ok(file.set_len(len)?)
}

fn f_remove(path: &Path) -> Result<(), Error> {
    gate()?;
    Ok(fs::remove_file(path)?)
}

#[cfg(not(windows))]
fn sync_dir(path: &Path) -> Result<(), Error> {
    sync_file(&File::open(path)?)
}

/// Windows can't open directories to fsync them; NTFS journals metadata ops.
#[cfg(windows)]
fn sync_dir(_path: &Path) -> Result<(), Error> {
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn sync_file(file: &File) -> Result<(), Error> {
    gate()?;
    file.sync_all()?;
    Ok(())
}

/// macOS sync_all is F_FULLFSYNC, unsupported on some volumes (e.g. SMB);
/// fall back to plain fsync like LevelDB does.
#[cfg(target_os = "macos")]
fn sync_file(file: &File) -> Result<(), Error> {
    gate()?;
    use std::os::fd::AsRawFd;
    match file.sync_all() {
        Err(e) if e.raw_os_error() == Some(libc::ENOTSUP) => {
            if unsafe { libc::fsync(file.as_raw_fd()) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error().into())
            }
        }
        other => Ok(other?),
    }
}

#[inline]
fn gate() -> io::Result<()> {
    #[cfg(test)]
    failpoint::gate()?;
    Ok(())
}

/// Test-only fault injection: arm to fail the Nth gated write op on the
/// arming thread, and every one after it (a failed disk stays failed).
#[cfg(test)]
mod failpoint {
    use parking_lot::Mutex;
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use std::thread::ThreadId;

    static ARMED: Mutex<Option<ThreadId>> = Mutex::new(None);
    static REMAINING: AtomicI64 = AtomicI64::new(0);
    static TRIGGERED: AtomicBool = AtomicBool::new(false);

    pub fn arm(n: i64) {
        *ARMED.lock() = Some(std::thread::current().id());
        REMAINING.store(n, Ordering::SeqCst);
        TRIGGERED.store(false, Ordering::SeqCst);
    }

    pub fn disarm() {
        *ARMED.lock() = None;
    }

    pub fn triggered() -> bool {
        TRIGGERED.load(Ordering::SeqCst)
    }

    pub fn gate() -> io::Result<()> {
        if *ARMED.lock() != Some(std::thread::current().id()) {
            return Ok(());
        }
        if REMAINING.fetch_sub(1, Ordering::SeqCst) <= 0 {
            TRIGGERED.store(true, Ordering::SeqCst);
            return Err(io::Error::other("injected fault"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &tempfile::TempDir) -> StaticFile {
        StaticFile::open(dir.path().to_path_buf()).unwrap()
    }

    #[test]
    fn round_trip_sparse_slots() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        assert_eq!(store.highest_written_slot(), None);

        store.put(100, b"a").unwrap();
        store.put(9000, b"b").unwrap();
        assert_eq!(store.highest_written_slot(), Some(9000));

        assert_eq!(store.get(100).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(101).unwrap(), None);
        assert_eq!(store.get(9000).unwrap(), Some(b"b".to_vec()));
        assert!(!store.contains(101).unwrap());
    }

    #[test]
    fn batch_streams_across_files_and_seals() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);

        let mut batch = store.batch().unwrap();
        batch.put(SLOTS_PER_FILE - 1, b"a").unwrap();
        batch.put(SLOTS_PER_FILE, b"b").unwrap();
        batch.put(3 * SLOTS_PER_FILE, b"c").unwrap();
        batch.commit().unwrap();

        assert_eq!(store.get(SLOTS_PER_FILE - 1).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(SLOTS_PER_FILE).unwrap(), Some(b"b".to_vec()));
        assert_eq!(store.get(3 * SLOTS_PER_FILE).unwrap(), Some(b"c".to_vec()));
        // crossed files sealed, top not, gap file absent
        let idx_len = |id: u64| {
            fs::metadata(dir.path().join(format!("data_{id:05}.idx")))
                .map(|m| m.len())
                .ok()
        };
        assert_eq!(idx_len(0), Some(TABLE_LEN + META_SLOT_LEN as u64));
        assert_eq!(idx_len(1), Some(TABLE_LEN + META_SLOT_LEN as u64));
        assert_eq!(idx_len(2), None);
        assert_eq!(idx_len(3), Some(TABLE_LEN));

        drop(store);
        let store = open(&dir);
        assert_eq!(store.get(SLOTS_PER_FILE).unwrap(), Some(b"b".to_vec()));
    }

    #[test]
    fn reput_of_committed_prefix_is_verified_and_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"a").unwrap();
        store.put(1, b"b").unwrap();

        let mut batch = store.batch().unwrap();
        batch.put(0, b"a").unwrap();
        batch.put(1, b"b").unwrap();
        batch.put(2, b"c").unwrap();
        batch.commit().unwrap();
        assert_eq!(store.get(2).unwrap(), Some(b"c".to_vec()));

        let mut batch = store.batch().unwrap();
        assert!(matches!(batch.put(1, b"wrong"), Err(Error::Invalid(_))));
    }

    #[test]
    fn abandoned_batch_is_invisible_and_healed() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"a").unwrap();

        let mut batch = store.batch().unwrap();
        batch.put(1, b"ghost").unwrap();
        batch.put(SLOTS_PER_FILE, b"ghost2").unwrap();
        drop(batch);

        assert_eq!(store.get(1).unwrap(), None);
        assert_eq!(store.highest_written_slot(), Some(0));

        // next batch heals and works
        store.put(1, b"real").unwrap();
        assert_eq!(store.get(1).unwrap(), Some(b"real".to_vec()));
        assert_eq!(store.get(SLOTS_PER_FILE).unwrap(), None);
    }

    #[test]
    fn torn_commit_falls_back_to_previous_marker() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"a").unwrap(); // seq 2
        store.put(1, b"b").unwrap(); // seq 3
        drop(store);

        // Corrupt the newest slot (seq 3 lives at offset (3 % 2) * 64 = 64).
        let meta_path = dir.path().join("meta");
        let meta = fs::read(&meta_path).unwrap();
        let mut torn = meta.clone();
        torn[64 + 40] ^= 0xff;
        fs::write(&meta_path, &torn).unwrap();

        let store = open(&dir);
        assert_eq!(store.highest_written_slot(), Some(0));
        assert_eq!(store.get(0).unwrap(), Some(b"a".to_vec()));
        assert_eq!(store.get(1).unwrap(), None); // healed away
        drop(store);

        // Both slots corrupt -> refuse to open.
        let mut dead = meta;
        dead[1] ^= 0xff;
        dead[64 + 40] ^= 0xff;
        fs::write(&meta_path, &dead).unwrap();
        assert!(matches!(
            StaticFile::open(dir.path().to_path_buf()),
            Err(Error::Corrupt(_))
        ));
    }

    #[test]
    fn corrupt_payload_detected_by_crc() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"hello world").unwrap();
        drop(store);

        let data_path = dir.path().join("data_00000");
        let mut bytes = fs::read(&data_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&data_path, &bytes).unwrap();

        let store = open(&dir);
        assert!(matches!(store.get(0), Err(Error::Corrupt(_))));
    }

    #[test]
    fn missing_meta_with_data_files_errors() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir).put(0, b"a").unwrap();
        fs::remove_file(dir.path().join("meta")).unwrap();

        assert!(matches!(
            StaticFile::open(dir.path().to_path_buf()),
            Err(Error::Corrupt(_))
        ));
        assert!(dir.path().join("data_00000").exists());
    }

    #[test]
    fn open_removes_uncommitted_future_file() {
        let dir = tempfile::tempdir().unwrap();
        open(&dir).put(0, b"a").unwrap();
        fs::write(dir.path().join("data_00001"), b"stale").unwrap();
        fs::write(dir.path().join("data_00001.idx"), b"stale").unwrap();

        let store = open(&dir);
        assert!(!dir.path().join("data_00001").exists());
        assert!(!dir.path().join("data_00001.idx").exists());
        store.put(SLOTS_PER_FILE, b"b").unwrap();
        assert_eq!(store.get(SLOTS_PER_FILE).unwrap(), Some(b"b".to_vec()));
    }

    #[test]
    fn second_open_rejected_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"a").unwrap();

        assert!(matches!(
            StaticFile::open(dir.path().to_path_buf()),
            Err(Error::AlreadyOpen(_))
        ));

        drop(store);
        assert_eq!(open(&dir).get(0).unwrap(), Some(b"a".to_vec()));
    }

    #[test]
    fn cannot_fill_skipped_slot() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(10, b"a").unwrap();
        assert!(matches!(store.put(5, b"b"), Err(Error::Invalid(_))));
    }

    #[test]
    fn empty_value_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.put(0, b"").unwrap();
        store.put(5, b"x").unwrap();
        assert_eq!(store.get(0).unwrap(), Some(vec![]));
        assert!(store.contains(0).unwrap());
        assert_eq!(store.get(3).unwrap(), None);
    }

    #[test]
    fn max_slot_is_reserved() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        let mut batch = store.batch().unwrap();
        assert!(matches!(batch.put(u64::MAX, b"x"), Err(Error::Invalid(_))));
    }

    /// Enumerate every gated write-path syscall: fail it (and everything
    /// after, like a dead disk), then assert the handle poisons, reopen
    /// heals, committed data survives, and the store is writable again.
    #[test]
    fn write_failure_at_every_io_op_recovers() {
        let mut n = 0;
        loop {
            let dir = tempfile::tempdir().unwrap();
            let hit;
            {
                let store = open(&dir);
                store.put(0, b"base").unwrap();

                failpoint::arm(n);
                let result = (|| -> Result<(), Error> {
                    let mut batch = store.batch()?;
                    batch.put(SLOTS_PER_FILE - 1, b"a")?;
                    batch.put(SLOTS_PER_FILE, b"b")?;
                    batch.put(3 * SLOTS_PER_FILE, b"c")?;
                    batch.commit()
                })();
                hit = failpoint::triggered();
                failpoint::disarm();

                if hit {
                    assert!(result.is_err(), "op {n}: injected fault must surface");
                    assert!(
                        matches!(store.put(90000, b"x"), Err(Error::Poisoned)),
                        "op {n}: handle must be poisoned"
                    );
                } else {
                    result.unwrap();
                }
            }

            let store = StaticFile::open(dir.path().to_path_buf())
                .unwrap_or_else(|e| panic!("op {n}: reopen after fault must heal, got {e}"));
            assert_eq!(
                store.get(0).unwrap(),
                Some(b"base".to_vec()),
                "op {n}: committed data lost"
            );
            let next = store.highest_written_slot().unwrap() + 1;
            store.put(next, b"post").unwrap();

            if !hit {
                break;
            }
            n += 1;
            assert!(n < 500, "runaway failpoint enumeration");
        }
    }
}
