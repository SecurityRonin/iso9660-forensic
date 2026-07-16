//! `impl FileSystem for IsoVfs` — the forensic-vfs adapter (behind the `vfs`
//! feature) so an ISO 9660 volume composes as `Arc<dyn FileSystem>` in the
//! forensic-vfs engine.
//!
//! [`IsoVfs`] wraps an [`IsoReader`] in a `Mutex`, so every read is `&self` over
//! interior mutability and one mounted handle serves N workers (matching the
//! ext4/NTFS adapters). Nodes are addressed by [`FileId::IsoExtent`] — the
//! directory record's data extent LBA — which is the ISO identity primitive
//! (there is no inode table).
//!
//! ## Mapping notes / known limits
//! - **No inode table ⇒ a per-extent record cache.** ISO carries a node's size,
//!   flags, and time *in its parent directory record*, not at the node's own
//!   extent. `read_dir`/`lookup` cache each child record by extent LBA; the
//!   root record is seeded from the PVD at `open`. `meta`/`read_at`/
//!   `extents` consult that cache — the normal root→read_dir→lookup→stat flow
//!   always populates it. An *untraversed file* extent cannot be stat'd (a loud
//!   [`VfsError::Decode`], never a guess); an untraversed *directory* extent is
//!   still resolvable from its `.` self-record.
//! - **Names.** ISO identifiers are UPPERCASE with a `;N` version suffix.
//!   `read_dir` emits the version-stripped name; `lookup` matches
//!   case-insensitively against **both** the raw and the cleaned identifier.
//! - **Times.** An ISO directory record has a single recording date/time; it is
//!   mapped to `born` (matching TSK's `istat`, which shows it as *Created*).
//!   `modified`/`accessed`/`changed` are `None` (honestly absent, not epoch-0).
//!   iso9660-core does not surface the record's GMT-offset byte, so times are a
//!   local wall clock of unknown offset — hence `timestamp_zone` is
//!   [`TimeZonePolicy::LocalUnknown`] and `unix_nanos` is computed from the
//!   wall-clock components without applying an offset.
//! - **Single stream.** ISO has no alternate data streams; a non-`Default`
//!   [`StreamId`] is refused loud.
//! - **Contiguous extents.** ISO files are contiguous; a multi-extent file
//!   (ECMA-119 §9.1.6) yields one [`RunInfo`] per extent. `image_offset` is the
//!   sector's true user-data position (`SectorMode`-aware).
//! - **Deleted/unallocated/symlinks.** ISO 9660 tracks no deletion, so
//!   `deleted`/`unallocated` are empty streams; Rock Ridge `SL` symlinks are
//!   not surfaced, so `read_link` returns an empty target.

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::{Mutex, MutexGuard, PoisonError};

use forensic_vfs::{
    Allocation, ByteRun, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem,
    FsKind, FsMeta, MacbTimes, NodeKind, NodeStream, ResidencyKind, RunAlloc, RunFlags, RunInfo,
    SectorSizes, SmallHex, StreamId, TimeResolution, TimeSource, TimeStamp, TimeZonePolicy,
    VfsError, VfsResult,
};

use crate::dir::DirRecord;
use crate::pvd::IsoDateTime;
use crate::sector::SectorMode;
use crate::{IsoError, IsoReader};

/// One ISO 9660 logical sector.
const ISO_SECTOR: u64 = 2048;

/// Per-node metadata harvested from a directory record and cached by extent LBA.
#[derive(Clone)]
struct RecordMeta {
    is_dir: bool,
    recorded: Option<IsoDateTime>,
    /// `[(lba, size)]` primary ++ extra extents, in directory order.
    extents: Vec<(u32, u32)>,
}

impl RecordMeta {
    fn from_record(rec: &DirRecord) -> Self {
        let mut extents = Vec::with_capacity(1 + rec.extra_extents.len());
        extents.push((rec.lba, rec.size));
        extents.extend_from_slice(&rec.extra_extents);
        Self { is_dir: rec.is_dir(), recorded: rec.recorded.clone(), extents }
    }

    /// Total data length across all extents.
    fn total(&self) -> u64 {
        self.extents.iter().map(|&(_, s)| u64::from(s)).sum()
    }
}

/// Reader plus its per-extent record cache, guarded by one mutex.
struct IsoState<R> {
    reader: IsoReader<R>,
    cache: HashMap<u32, RecordMeta>,
}

/// A mounted ISO 9660 volume exposed through the forensic-vfs `FileSystem`
/// contract. Reads are `&self` over an interior `Mutex`, so one handle serves N
/// workers.
pub struct IsoVfs<R: Read + Seek> {
    state: Mutex<IsoState<R>>,
    root_lba: u32,
    mode: SectorMode,
}

impl<R: Read + Seek + Send> IsoVfs<R> {
    /// Open an ISO 9660 volume over a `Read + Seek` cursor.
    ///
    /// The root directory's own extent (LBA + size) comes from the PVD; its
    /// synthetic record seeds the per-extent cache so `meta(root())` resolves
    /// without a directory read.
    pub fn open(reader: R) -> Result<Self, IsoError> {
        let reader = IsoReader::open(reader)?;
        let mode = reader.sector_mode();
        let root_lba = reader.root_dir_lba();
        let root_size = reader.root_dir_size();
        let mut cache = HashMap::new();
        cache.insert(
            root_lba,
            RecordMeta { is_dir: true, recorded: None, extents: vec![(root_lba, root_size)] },
        );
        Ok(Self { state: Mutex::new(IsoState { reader, cache }), root_lba, mode })
    }

    /// Lock the interior state, recovering from a poisoned mutex rather than
    /// panicking (Paranoid Gatekeeper).
    fn state(&self) -> MutexGuard<'_, IsoState<R>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The extent LBA carried by a [`FileId`]; any other identity domain is a
/// caller error surfaced loud.
fn block_of(id: FileId) -> VfsResult<u32> {
    match id {
        FileId::IsoExtent { block } => Ok(block),
        other => {
            Err(VfsError::Unsupported { layer: "iso9660 file-id", scheme: format!("{other:?}") })
        }
    }
}

/// ISO exposes a single unnamed data stream; a named-stream id is refused loud.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => {
            Err(VfsError::Unsupported { layer: "iso9660 stream", scheme: format!("{other:?}") })
        }
    }
}

/// Translate an iso9660-core error to the VFS error type, keeping I/O distinct
/// from a structural decode failure.
fn map_err(e: IsoError) -> VfsError {
    match e {
        IsoError::Io(source) => VfsError::Io { op: "iso9660 read", source },
        other => VfsError::Decode {
            layer: "iso9660",
            offset: 0,
            detail: other.to_string(),
            bytes: SmallHex::new(&[]),
        },
    }
}

/// Strip a trailing ISO version suffix (`;N`) from a raw file identifier.
fn clean_name(raw: &[u8]) -> Vec<u8> {
    if let Some(pos) = raw.iter().rposition(|&b| b == b';') {
        let ver = raw.get(pos + 1..).unwrap_or(&[]);
        if !ver.is_empty() && ver.iter().all(u8::is_ascii_digit) {
            return raw.get(..pos).unwrap_or(&[]).to_vec();
        }
    }
    raw.to_vec()
}

/// The directory's byte size, read from its `.` self-record at the head of the
/// extent. Also validates that `block` is genuinely a directory extent (the
/// first record is the self-dot pointing back at `block`), so a file extent
/// passed to a directory op fails loud rather than mis-parsing file bytes.
fn dir_size<R: Read + Seek>(reader: &mut IsoReader<R>, block: u32) -> VfsResult<u32> {
    let sector = reader.read_sector_raw(u64::from(block)).map_err(map_err)?;
    match DirRecord::parse(&sector, 0).map_err(map_err)? {
        Some((rec, _)) if rec.name_bytes == [0x00] && rec.lba == block => Ok(rec.size),
        _ => Err(VfsError::Decode {
            layer: "iso9660",
            offset: u64::from(block) * ISO_SECTOR,
            detail: format!("extent {block} is not a directory (no '.' self record)"),
            bytes: SmallHex::new(sector.get(..16).unwrap_or(&[])),
        }),
    }
}

/// Resolve the cached record for `block`, or — for an uncached *directory*
/// extent — synthesize one from its self-record. An uncached *file* extent
/// cannot be resolved (no inode table): a loud error, never a guess.
fn record_for<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    cache: &mut HashMap<u32, RecordMeta>,
    block: u32,
) -> VfsResult<RecordMeta> {
    if let Some(rm) = cache.get(&block) {
        return Ok(rm.clone());
    }
    match dir_size(reader, block) {
        Ok(size) => {
            let rm = RecordMeta {
                is_dir: true,
                recorded: None,
                extents: vec![(block, size)],
            };
            cache.insert(block, rm.clone());
            Ok(rm)
        }
        Err(_) => Err(VfsError::Decode {
            layer: "iso9660",
            offset: u64::from(block) * ISO_SECTOR,
            detail: format!(
                "no directory record cached for extent {block}; enumerate its parent directory first"
            ),
            bytes: SmallHex::new(&[]),
        }),
    }
}

/// Read `[off, off+buf.len())` across a file's (contiguous, possibly multi-)
/// extents, one sector at a time so a large file is never pulled wholesale.
fn read_extents<R: Read + Seek>(
    reader: &mut IsoReader<R>,
    extents: &[(u32, u32)],
    off: u64,
    buf: &mut [u8],
) -> VfsResult<usize> {
    let want = buf.len();
    let mut done = 0usize;
    let mut cursor = off;
    for &(lba, size) in extents {
        let size = u64::from(size);
        if cursor >= size {
            cursor -= size;
            continue;
        }
        let mut pos = cursor;
        cursor = 0;
        while pos < size && done < want {
            let sector_idx = pos / ISO_SECTOR;
            let within = (pos % ISO_SECTOR) as usize;
            let sector = reader.read_sector_raw(u64::from(lba) + sector_idx).map_err(map_err)?;
            let sector_base = sector_idx * ISO_SECTOR;
            let valid = (size - sector_base).min(ISO_SECTOR) as usize;
            let avail = valid - within;
            let n = avail.min(want - done);
            if let (Some(dst), Some(src)) =
                (buf.get_mut(done..done + n), sector.get(within..within + n))
            {
                dst.copy_from_slice(src);
            }
            done += n;
            pos += n as u64;
        }
        if done >= want {
            break;
        }
    }
    Ok(done)
}

/// Days from 1970-01-01 to a proleptic-Gregorian civil date (Howard Hinnant's
/// algorithm), then seconds since the Unix epoch. No external date crate.
fn civil_to_unix(year: i64, month: i64, day: i64, hh: i64, mm: i64, ss: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + hh * 3_600 + mm * 60 + ss
}

/// Map an ISO recording date/time to a VFS timestamp (see the module's Times
/// note: local wall clock, offset not applied).
fn to_timestamp(dt: &IsoDateTime) -> TimeStamp {
    let secs = civil_to_unix(
        i64::from(dt.year),
        i64::from(dt.month),
        i64::from(dt.day),
        i64::from(dt.hour),
        i64::from(dt.minute),
        i64::from(dt.second),
    );
    TimeStamp {
        unix_nanos: i128::from(secs) * 1_000_000_000,
        source: TimeSource::Unspecified,
        resolution: TimeResolution::Seconds,
    }
}

impl<R: Read + Seek + Send> FileSystem for IsoVfs<R> {
    fn kind(&self) -> FsKind {
        FsKind::ISO9660
    }

    fn root(&self) -> FileId {
        FileId::IsoExtent { block: self.root_lba }
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: ISO_SECTOR as u32,
            physical: self.mode.physical_sector_size() as u32,
            cluster_or_block: ISO_SECTOR as u32,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::LocalUnknown
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let block = block_of(ino)?;
        let mut st = self.state();
        let IsoState { reader, cache } = &mut *st;
        let size = dir_size(reader, block)?;
        let records = reader.read_dir(block, size).map_err(map_err)?;
        let mut out: Vec<VfsResult<VfsDirEntry>> = Vec::with_capacity(records.len());
        for rec in &records {
            if rec.is_dot() {
                continue; // cov:unreachable: parse_dir_records already drops '.'/'..'
            }
            cache.insert(rec.lba, RecordMeta::from_record(rec));
            out.push(Ok(VfsDirEntry {
                name: clean_name(&rec.name_bytes),
                id: FileId::IsoExtent { block: rec.lba },
                kind: if rec.is_dir() { NodeKind::Dir } else { NodeKind::File },
            }));
        }
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, ino: FileId, stream: StreamId) -> VfsResult<ExtentStream> {
        let block = block_of(ino)?;
        require_default_stream(stream)?;
        let mode = self.mode;
        let mut st = self.state();
        let IsoState { reader, cache } = &mut *st;
        let rm = record_for(reader, cache, block)?;
        let runs: Vec<VfsResult<RunInfo>> = rm
            .extents
            .iter()
            .map(|&(lba, size)| {
                Ok(RunInfo {
                    run: ByteRun {
                        image_offset: mode.user_data_pos(u64::from(lba)),
                        len: u64::from(size),
                        flags: RunFlags::default(),
                    },
                    alloc: RunAlloc::Allocated,
                })
            })
            .collect();
        Ok(ExtentStream::new(runs.into_iter()))
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let block = block_of(parent)?;
        let mut st = self.state();
        let IsoState { reader, cache } = &mut *st;
        let size = dir_size(reader, block)?;
        let records = reader.read_dir(block, size).map_err(map_err)?;
        for rec in &records {
            if rec.is_dot() {
                continue; // cov:unreachable: parse_dir_records already drops '.'/'..'
            }
            cache.insert(rec.lba, RecordMeta::from_record(rec));
            let cleaned = clean_name(&rec.name_bytes);
            if name.eq_ignore_ascii_case(&rec.name_bytes) || name.eq_ignore_ascii_case(&cleaned) {
                return Ok(Some(FileId::IsoExtent { block: rec.lba }));
            }
        }
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let block = block_of(ino)?;
        let mut st = self.state();
        let IsoState { reader, cache } = &mut *st;
        let rm = record_for(reader, cache, block)?;
        let born = rm.recorded.as_ref().map(to_timestamp);
        Ok(FsMeta {
            ino: u64::from(block),
            kind: if rm.is_dir { NodeKind::Dir } else { NodeKind::File },
            allocated: Allocation::Allocated,
            size: rm.total(),
            nlink: 1,
            uid: None,
            gid: None,
            mode: None,
            times: MacbTimes { modified: None, accessed: None, changed: None, born },
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let block = block_of(ino)?;
        require_default_stream(stream)?;
        let mut st = self.state();
        let IsoState { reader, cache } = &mut *st;
        let rm = record_for(reader, cache, block)?;
        read_extents(reader, &rm.extents, off, buf)
    }

    fn read_link(&self, ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        // Rock Ridge SL symlinks are not surfaced; a node reads as an empty
        // target (matches the ext4/NTFS adapters), not a per-node error.
        let _ = block_of(ino)?;
        Ok(Vec::new())
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        // ISO 9660 tracks no deletion at the filesystem layer.
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_vfs::{Allocation, NodeKind, RunAlloc};
    use hadris_iso::read::PathSeparator;
    use hadris_iso::write::options::{CreationFeatures, FormatOptions};
    use hadris_iso::write::{File as IsoFile, InputFiles, IsoImageWriter};
    use std::io::Cursor;
    use std::sync::Arc;

    /// Mint a plain ISO 9660 image in memory (mirrors `tests/helpers.rs`).
    fn build_iso(label: &str, files: Vec<IsoFile>) -> Cursor<Vec<u8>> {
        let input = InputFiles { path_separator: PathSeparator::ForwardSlash, files };
        let opts = FormatOptions {
            volume_name: label.to_string(),
            system_id: None,
            volume_set_id: None,
            publisher_id: None,
            preparer_id: None,
            application_id: None,
            sector_size: 2048,
            path_separator: PathSeparator::ForwardSlash,
            features: CreationFeatures::default(),
            strict_charset: false,
        };
        let mut buf = Cursor::new(vec![0u8; 8 * 1024 * 1024]);
        IsoImageWriter::format_new(&mut buf, input, opts).expect("hadris-iso write failed");
        Cursor::new(buf.into_inner())
    }

    fn file(name: &str, contents: &[u8]) -> IsoFile {
        IsoFile::File { name: Arc::new(name.to_string()), contents: contents.to_vec() }
    }

    fn dir(name: &str, children: Vec<IsoFile>) -> IsoFile {
        IsoFile::Directory { name: Arc::new(name.to_string()), children }
    }

    fn hello_iso() -> IsoVfs<Cursor<Vec<u8>>> {
        let iso = build_iso("TESTVOL", vec![file("HELLO.TXT", b"Hello, iso9660!")]);
        IsoVfs::open(iso).expect("open ISO")
    }

    fn names(fs: &IsoVfs<Cursor<Vec<u8>>>, dir: FileId) -> Vec<Vec<u8>> {
        fs.read_dir(dir).expect("read_dir").map(|e| e.expect("entry").name).collect()
    }

    #[test]
    fn kind_root_and_zone() {
        let fs = hello_iso();
        assert_eq!(fs.kind(), FsKind::ISO9660);
        assert!(matches!(fs.root(), FileId::IsoExtent { .. }));
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::LocalUnknown);
        let ss = fs.sector_sizes();
        assert_eq!(ss.logical, 2048);
        assert_eq!(ss.cluster_or_block, 2048);
        assert!(ss.physical >= 2048);
        // root() is resolvable via meta without a directory read (seeded cache).
        let rm = fs.meta(fs.root()).expect("root meta");
        assert_eq!(rm.kind, NodeKind::Dir);
    }

    #[test]
    fn lists_root_and_reads_hello() {
        let fs = hello_iso();
        let root = fs.root();
        let listing = names(&fs, root);
        assert!(
            listing.iter().any(|n| n.eq_ignore_ascii_case(b"HELLO.TXT")),
            "root should list HELLO.TXT, got {listing:?}"
        );

        let id = fs.lookup(root, b"hello.txt").expect("lookup").expect("hello.txt present");
        assert!(matches!(id, FileId::IsoExtent { .. }));

        let m = fs.meta(id).expect("meta");
        assert_eq!(m.size, 15);
        assert_eq!(m.kind, NodeKind::File);
        assert_eq!(m.allocated, Allocation::Allocated);
        assert_eq!(m.nlink, 1);
        assert!(m.times.born.is_some(), "recording time maps to born");
        assert!(m.times.modified.is_none());

        let mut buf = [0u8; 64];
        let n = fs.read_at(id, StreamId::Default, 0, &mut buf).expect("read_at");
        assert_eq!(&buf[..n], b"Hello, iso9660!");

        let runs: Vec<_> =
            fs.extents(id, StreamId::Default).expect("extents").map(|r| r.expect("run")).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run.len, 15);
        assert_eq!(runs[0].alloc, RunAlloc::Allocated);
    }

    #[test]
    fn subdirectory_navigation() {
        let iso = build_iso("TESTVOL", vec![dir("SUB", vec![file("INNER.TXT", b"inner")])]);
        let fs = IsoVfs::open(iso).expect("open");
        let sub = fs.lookup(fs.root(), b"SUB").expect("lookup sub").expect("SUB present");
        assert_eq!(fs.meta(sub).expect("meta sub").kind, NodeKind::Dir);
        let inner = fs.lookup(sub, b"inner.txt").expect("lookup inner").expect("INNER.TXT present");
        let mut buf = [0u8; 16];
        let n = fs.read_at(inner, StreamId::Default, 0, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"inner");
    }

    #[test]
    fn read_at_with_offset() {
        let fs = hello_iso();
        let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
        let mut buf = [0u8; 8];
        let n = fs.read_at(id, StreamId::Default, 7, &mut buf).expect("read");
        assert_eq!(&buf[..n], b"iso9660!");
        // reading past EOF yields 0
        assert_eq!(fs.read_at(id, StreamId::Default, 999, &mut buf).unwrap(), 0);
    }

    #[test]
    fn empty_forensic_surfaces() {
        let fs = hello_iso();
        assert_eq!(fs.deleted().unwrap().count(), 0);
        assert_eq!(fs.unallocated().unwrap().count(), 0);
        let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
        assert!(fs.read_link(id, 4096).unwrap().is_empty());
    }

    #[test]
    fn wrong_file_id_and_stream_are_loud() {
        let fs = hello_iso();
        assert!(fs.meta(FileId::Opaque(7)).is_err());
        assert!(fs.read_dir(FileId::Opaque(7)).is_err());
        assert!(fs.lookup(FileId::Opaque(7), b"x").is_err());
        assert!(fs.read_link(FileId::Opaque(7), 8).is_err());
        let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
        assert!(fs.read_at(id, StreamId::Named(1), 0, &mut [0u8; 4]).is_err());
        assert!(fs.extents(id, StreamId::Named(1)).is_err());
    }

    #[test]
    fn read_dir_on_a_file_is_loud() {
        let fs = hello_iso();
        let id = fs.lookup(fs.root(), b"hello.txt").unwrap().unwrap();
        assert!(fs.read_dir(id).is_err());
    }

    #[test]
    fn meta_on_untraversed_file_is_loud() {
        let fs = hello_iso();
        // A file extent never surfaced by read_dir/lookup cannot be stat'd (ISO
        // has no inode table); a directory extent could be probed.
        assert!(fs.meta(FileId::IsoExtent { block: 999_999 }).is_err());
    }

    #[test]
    fn lookup_missing_is_none() {
        let fs = hello_iso();
        assert!(fs.lookup(fs.root(), b"NOPE.TXT").unwrap().is_none());
    }

    #[test]
    fn clean_name_strips_only_a_numeric_version() {
        assert_eq!(clean_name(b"HELLO.TXT;1"), b"HELLO.TXT");
        assert_eq!(clean_name(b"NOVER.TXT"), b"NOVER.TXT");
        // a trailing ';' with no digits, or non-numeric, is left intact
        assert_eq!(clean_name(b"WEIRD;"), b"WEIRD;");
        assert_eq!(clean_name(b"A;B"), b"A;B");
    }

    #[test]
    fn civil_to_unix_epoch_and_known_dates() {
        assert_eq!(civil_to_unix(1970, 1, 1, 0, 0, 0), 0);
        // 2000-01-01 00:00:00 UTC
        assert_eq!(civil_to_unix(2000, 1, 1, 0, 0, 0), 946_684_800);
    }

    #[test]
    fn uncached_directory_extent_is_probed() {
        // A directory extent stat'd on a *fresh* handle (its record not yet
        // cached) is resolvable via its '.' self-record — unlike a file extent.
        let bytes = build_iso("TESTVOL", vec![dir("SUB", vec![file("F.TXT", b"x")])]).into_inner();
        let fs1 = IsoVfs::open(Cursor::new(bytes.clone())).expect("open1");
        let sub = fs1.lookup(fs1.root(), b"SUB").unwrap().unwrap();
        let fs2 = IsoVfs::open(Cursor::new(bytes)).expect("open2");
        let m = fs2.meta(sub).expect("probe uncached dir");
        assert_eq!(m.kind, NodeKind::Dir);
        assert!(m.size > 0);
    }

    #[test]
    fn map_err_separates_io_from_decode() {
        let io = super::map_err(IsoError::Io(std::io::Error::other("boom")));
        assert!(matches!(io, VfsError::Io { .. }));
        let dec = super::map_err(IsoError::NotFound("x".into()));
        assert!(matches!(dec, VfsError::Decode { .. }));
    }
}
