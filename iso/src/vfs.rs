//! `impl FileSystem for IsoVfs` — the forensic-vfs adapter (behind the `vfs`
//! feature). RED skeleton: behaviour is asserted by the tests below and filled
//! in by the GREEN commit.

use std::collections::HashMap;
use std::io::{Read, Seek};
use std::sync::Mutex;

use forensic_vfs::{
    DirStream, ExtentStream, FileId, FileSystem, FsKind, FsMeta, NodeStream, SectorSizes, StreamId,
    TimeZonePolicy, VfsResult,
};

use crate::dir::DirRecord;
use crate::pvd::IsoDateTime;
use crate::sector::SectorMode;
use crate::{IsoError, IsoReader};

/// Per-node metadata harvested from a directory record and cached by extent LBA.
#[derive(Clone)]
struct RecordMeta {
    size: u32,
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
        Self { size: rec.size, is_dir: rec.is_dir(), recorded: rec.recorded.clone(), extents }
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
    pub fn open(reader: R) -> Result<Self, IsoError> {
        let reader = IsoReader::open(reader)?;
        let mode = reader.sector_mode();
        let root_lba = reader.root_dir_lba();
        let root_size = reader.root_dir_size();
        let mut cache = HashMap::new();
        cache.insert(
            root_lba,
            RecordMeta {
                size: root_size,
                is_dir: true,
                recorded: None,
                extents: vec![(root_lba, root_size)],
            },
        );
        Ok(Self { state: Mutex::new(IsoState { reader, cache }), root_lba, mode })
    }
}

impl<R: Read + Seek + Send> FileSystem for IsoVfs<R> {
    fn kind(&self) -> FsKind {
        todo!()
    }
    fn root(&self) -> FileId {
        todo!()
    }
    fn sector_sizes(&self) -> SectorSizes {
        todo!()
    }
    fn timestamp_zone(&self) -> TimeZonePolicy {
        todo!()
    }
    fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
        todo!()
    }
    fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
        todo!()
    }
    fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
        todo!()
    }
    fn meta(&self, _ino: FileId) -> VfsResult<FsMeta> {
        todo!()
    }
    fn read_at(
        &self,
        _ino: FileId,
        _stream: StreamId,
        _off: u64,
        _buf: &mut [u8],
    ) -> VfsResult<usize> {
        todo!()
    }
    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        todo!()
    }
    fn deleted(&self) -> VfsResult<NodeStream> {
        todo!()
    }
    fn unallocated(&self) -> VfsResult<ExtentStream> {
        todo!()
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
        assert_eq!(fs.kind(), FsKind::Iso9660);
        assert!(matches!(fs.root(), FileId::IsoExtent { .. }));
        assert_eq!(fs.timestamp_zone(), TimeZonePolicy::LocalUnknown);
        assert_eq!(fs.sector_sizes().logical, 2048);
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
        assert!(m.times.born.is_some(), "recording time maps to born");

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
        // A file extent that was never surfaced by read_dir/lookup cannot be
        // stat'd (ISO has no inode table); a directory extent could be probed.
        assert!(fs.meta(FileId::IsoExtent { block: 999_999 }).is_err());
    }

    #[test]
    fn lookup_missing_is_none() {
        let fs = hello_iso();
        assert!(fs.lookup(fs.root(), b"NOPE.TXT").unwrap().is_none());
    }
}
