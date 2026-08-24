//! Pure-Rust forensic ISO 9660 reader.
//!
//! Handles multi-session discs, Rock Ridge (RRIP), Joliet (UCS-2 filenames),
//! El Torito boot images, and 2352-byte raw CD sectors.

// Production code is panic-free (`unwrap_used`/`expect_used` denied in Cargo.toml);
// the lib's own `#[cfg(test)]` modules may unwrap freely.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod bw5;
pub mod ccd;
pub mod cdi;
pub mod cdtext;
pub mod cdtoc;
pub mod cue;
pub mod dir;
pub mod el_torito;
pub mod error;
pub mod file_reader;
pub mod mds;
pub mod nrg;
pub mod offset;
mod opener;
pub mod path_table;
pub mod pvd;
pub mod rock_ridge;
pub mod sector;
pub mod session;
pub mod subq;
pub mod toc;
#[cfg(feature = "vfs")]
pub mod vfs;

pub use error::IsoError;
pub use opener::{open, ReadSeek};

/// Maximum bytes that `read_dir` will allocate for a single directory.
///
/// Prevents `DoS` via crafted `root_dir_size` or directory entry size fields.
pub const MAX_DIR_SIZE: u32 = 64 * 1024 * 1024; // 64 MB

/// Maximum directory nesting depth for [`IsoReader::walk`].
///
/// Prevents stack overflow on cyclic or deeply nested directory structures.
pub const MAX_WALK_DEPTH: usize = 256;
pub use file_reader::IsoFileReader;
pub use pvd::IsoDateTime;
pub use sector::SectorMode;

/// A single entry produced by [`IsoReader::walk`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WalkEntry {
    /// Full path from the root, using `/` as separator (e.g. `"DIR/CHILD.TXT"`).
    pub path: String,
    /// Depth from the root (root entries = 0, one directory deep = 1, …).
    pub depth: usize,
    /// The parsed directory record for this entry.
    pub record: DirRecord,
}

pub use dir::{DirRecord, FILE_FLAG_MULTI_EXTENT};

use std::io::{Read, Seek, SeekFrom};

use dir::parse_dir_records;
use el_torito::{boot_catalog_lba, parse_boot_catalog, BootEntry};
use pvd::{
    PrimaryVolumeDescriptor, SupplementaryVolumeDescriptor, BOOT_RECORD_TYPE, PVD_TYPE, SVD_TYPE,
    TERMINATOR_TYPE,
};
use rock_ridge::{continuation, has_sp_entry, sp_skip as extract_sp_skip};
use sector::read_sector_data;

/// Forensic ISO 9660 reader.
///
/// Wraps any `Read + Seek` source and exposes multi-session, Rock Ridge,
/// Joliet, and El Torito metadata alongside raw file data.
pub struct IsoReader<R> {
    inner: R,
    mode: SectorMode,
    pvd: PrimaryVolumeDescriptor,
    svd: Option<SupplementaryVolumeDescriptor>,
    boot_catalog_lba: Option<u32>,
    /// All detected session PVD LBAs (ascending). Candidates after the
    /// mandatory LBA 16 descriptor are structurally validated. Last = active
    /// session.
    pub session_pvd_lbas: Vec<u64>,
    pub has_rock_ridge: bool,
    /// `true` when a UDF NSR02/NSR03 descriptor is present in the Volume
    /// Recognition Sequence (an ISO 9660 / UDF bridge disc).
    has_udf: bool,
    /// SUSP SP `LEN_SKP`: bytes to skip at start of each System Use field (IEEE P1282 §5.3).
    sp_skip: usize,
}

impl<R: Read + Seek> IsoReader<R> {
    /// Open an ISO image, detecting sector mode and parsing the active session.
    pub fn open(mut reader: R) -> Result<Self, IsoError> {
        let mode = SectorMode::detect(&mut reader)?;

        // Scan for all sessions (PVD LBAs). An image with no ISO 9660 PVD is not
        // one this reader can interpret — other filesystems are out of scope.
        let session_pvd_lbas = scan_sessions(&mut reader, mode)?;
        let Some(&active_pvd_lba) = session_pvd_lbas.last() else {
            return Err(IsoError::NotAnIso);
        };

        let (pvd, svd, boot_cat_lba, has_rock_ridge, sp_skip) =
            read_volume_descriptors(&mut reader, mode, active_pvd_lba)?;

        let has_udf = detect_udf(&mut reader, mode)?;

        Ok(Self {
            inner: reader,
            mode,
            pvd,
            svd,
            boot_catalog_lba: boot_cat_lba,
            session_pvd_lbas,
            has_rock_ridge,
            has_udf,
            sp_skip,
        })
    }

    /// Read the raw 2048-byte user-data payload of a single logical sector.
    ///
    /// Handles both ISO (2048-byte) and raw CD-ROM (2352-byte) images
    /// transparently.  Returns an error if `lba` is beyond the image.
    pub fn read_sector_raw(&mut self, lba: u64) -> Result<[u8; 2048], IsoError> {
        let mut buf = [0u8; 2048];
        read_sector_data(&mut self.inner, self.mode, lba, &mut buf)?;
        Ok(buf)
    }

    /// Sector mode of the image (2048-byte ISO or 2352-byte raw CD-ROM).
    /// The parsed Primary Volume Descriptor (the analyzer grades over it).
    #[must_use]
    pub fn pvd(&self) -> &PrimaryVolumeDescriptor {
        &self.pvd
    }

    /// The Supplementary Volume Descriptor (Joliet), if present — exposed for
    /// the `iso9660-forensic` analyzer.
    #[must_use]
    pub fn svd(&self) -> Option<&SupplementaryVolumeDescriptor> {
        self.svd.as_ref()
    }

    /// The boot catalog LBA, if an El Torito boot record is present — exposed
    /// for the `iso9660-forensic` analyzer.
    #[must_use]
    pub fn boot_catalog_lba(&self) -> Option<u32> {
        self.boot_catalog_lba
    }

    pub fn sector_mode(&self) -> SectorMode {
        self.mode
    }

    /// Read and decode the 12-byte Q subchannel for a logical sector.
    ///
    /// Returns `Ok(None)` unless the image is a 2448-byte (subchannel-bearing)
    /// raw format; otherwise extracts the interleaved Q channel from the 96
    /// subcode bytes at offset 2352 of the physical sector (see
    /// [`subq::extract_q`]).
    pub fn read_subchannel_q(&mut self, lba: u64) -> Result<Option<[u8; 12]>, IsoError> {
        match self.mode {
            SectorMode::Raw2448 | SectorMode::Raw2448Mode2 => {}
            _ => return Ok(None),
        }
        let pos = lba * self.mode.physical_sector_size() + 2352;
        self.inner.seek(SeekFrom::Start(pos))?;
        let mut sub = [0u8; 96];
        self.inner.read_exact(&mut sub)?;
        Ok(subq::extract_q(&sub))
    }

    /// Scan every sector's Q subchannel and summarise disc-level identifiers.
    ///
    /// Reads each physical sector in order, extracts the interleaved Q frame,
    /// keeps only CRC-valid frames (blank/garbage subchannel is discarded), and
    /// folds them into a [`subq::QSummary`] (disc catalogue + per-track ISRCs).
    /// Returns an empty summary for images without a 2448-byte subchannel.
    pub fn scan_subchannel_q(&mut self) -> Result<subq::QSummary, IsoError> {
        match self.mode {
            SectorMode::Raw2448 | SectorMode::Raw2448Mode2 => {}
            _ => return Ok(subq::QSummary::default()),
        }
        let phys = self.mode.physical_sector_size();
        let mut frames = Vec::new();
        let mut lba = 0u64;
        let mut sub = [0u8; 96];
        loop {
            self.inner.seek(SeekFrom::Start(lba * phys + 2352))?;
            match self.inner.read_exact(&mut sub) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            if let Some(raw) = subq::extract_q(&sub) {
                if subq::q_crc_valid(&raw) {
                    if let Some(frame) = subq::decode_q(&raw) {
                        frames.push(frame);
                    }
                }
            }
            lba += 1;
        }
        Ok(subq::summarize_q(frames))
    }

    /// Volume label from the Primary Volume Descriptor (trimmed).
    pub fn volume_label(&self) -> &str {
        &self.pvd.volume_label
    }

    // ── PVD metadata getters (ECMA-119 §8.4) ─────────────────────────────────

    pub fn system_id(&self) -> &str {
        &self.pvd.system_id
    }
    pub fn volume_set_id(&self) -> &str {
        &self.pvd.volume_set_id
    }
    pub fn publisher_id(&self) -> &str {
        &self.pvd.publisher_id
    }
    pub fn data_preparer_id(&self) -> &str {
        &self.pvd.data_preparer_id
    }
    pub fn application_id(&self) -> &str {
        &self.pvd.application_id
    }
    pub fn copyright_file_id(&self) -> &str {
        &self.pvd.copyright_file_id
    }
    pub fn abstract_file_id(&self) -> &str {
        &self.pvd.abstract_file_id
    }
    pub fn bibliographic_file_id(&self) -> &str {
        &self.pvd.bibliographic_file_id
    }
    pub fn volume_creation_time(&self) -> Option<&IsoDateTime> {
        self.pvd.volume_creation_time.as_ref()
    }
    pub fn volume_modification_time(&self) -> Option<&IsoDateTime> {
        self.pvd.volume_modification_time.as_ref()
    }
    pub fn volume_expiration_time(&self) -> Option<&IsoDateTime> {
        self.pvd.volume_expiration_time.as_ref()
    }
    pub fn volume_effective_time(&self) -> Option<&IsoDateTime> {
        self.pvd.volume_effective_time.as_ref()
    }
    pub fn volume_space_size(&self) -> u32 {
        self.pvd.volume_space_size
    }
    pub fn logical_block_size(&self) -> u16 {
        self.pvd.logical_block_size
    }
    pub fn path_table_size(&self) -> u32 {
        self.pvd.path_table_size
    }

    /// Read a path table's raw bytes from `lba`, spanning as many sectors as
    /// `path_table_size` requires, truncated to that size. Exposed for the
    /// `iso9660-forensic` path-table audits.
    pub fn read_path_table_bytes(&mut self, lba: u32) -> Result<Vec<u8>, IsoError> {
        let size = self.pvd.path_table_size as usize;
        let sectors = size.div_ceil(2048).max(1);
        let mut data = Vec::with_capacity(sectors * 2048);
        for i in 0..sectors {
            let raw = self.read_sector_raw(u64::from(lba) + i as u64)?;
            data.extend_from_slice(&raw);
        }
        data.truncate(size.min(data.len()));
        Ok(data)
    }
    pub fn l_path_table_lba(&self) -> u32 {
        self.pvd.l_path_table_lba
    }
    pub fn m_path_table_lba(&self) -> u32 {
        self.pvd.m_path_table_lba
    }

    /// LBA of the root directory extent (active session PVD, ECMA-119 §8.4.18).
    pub fn root_dir_lba(&self) -> u32 {
        self.pvd.root_dir_lba
    }
    /// Size in bytes of the root directory extent.
    pub fn root_dir_size(&self) -> u32 {
        self.pvd.root_dir_size
    }

    /// Joliet volume label from the Supplementary VD, if present.
    pub fn joliet_label(&self) -> Option<&str> {
        self.svd.as_ref().filter(|s| s.is_joliet).map(|s| s.volume_label.as_str())
    }

    /// Number of sessions detected (≥ 1 for a valid ISO).
    pub fn session_count(&self) -> usize {
        self.session_pvd_lbas.len()
    }

    /// True if Rock Ridge RRIP extensions are present.
    pub fn has_rock_ridge(&self) -> bool {
        self.has_rock_ridge
    }

    /// `true` when a UDF volume structure (NSR02/NSR03) is present in the Volume
    /// Recognition Sequence — an ISO 9660 / UDF bridge disc.
    #[must_use]
    pub fn has_udf(&self) -> bool {
        self.has_udf
    }

    /// True if a Joliet Supplementary Volume Descriptor is present.
    pub fn has_joliet(&self) -> bool {
        self.svd.as_ref().is_some_and(|s| s.is_joliet)
    }

    /// True if an Enhanced Volume Descriptor is present (ISO 9660:1999, the
    /// "Level 4" volume): a type-2 descriptor with version byte 2 and no Joliet
    /// escape, distinct from a Joliet SVD.
    pub fn has_enhanced_volume_descriptor(&self) -> bool {
        self.svd.as_ref().is_some_and(SupplementaryVolumeDescriptor::is_enhanced)
    }

    /// Read the root directory of the active (last) session.
    pub fn read_root_dir(&mut self) -> Result<Vec<DirRecord>, IsoError> {
        self.read_dir(self.pvd.root_dir_lba, self.pvd.root_dir_size)
    }

    /// Read the root directory of an arbitrary session by index (0 = oldest).
    ///
    /// Returns an error if `idx >= session_count()`.
    pub fn read_session_root_dir(&mut self, idx: usize) -> Result<Vec<DirRecord>, IsoError> {
        let pvd_lba = *self.session_pvd_lbas.get(idx).ok_or_else(|| {
            IsoError::NotFound(format!(
                "session index {idx} out of range ({})",
                self.session_pvd_lbas.len()
            ))
        })?;
        let (pvd, _svd, _boot, _rr, _skip) =
            read_volume_descriptors(&mut self.inner, self.mode, pvd_lba)?;
        self.read_dir(pvd.root_dir_lba, pvd.root_dir_size)
    }

    /// Read a directory given its LBA and size in bytes.
    pub fn read_dir(&mut self, lba: u32, size: u32) -> Result<Vec<DirRecord>, IsoError> {
        if size > MAX_DIR_SIZE {
            return Err(IsoError::ResourceLimit(format!(
                "directory size {size} bytes exceeds limit {MAX_DIR_SIZE}"
            )));
        }
        let mut data = vec![0u8; size as usize];
        let sector_size = 2048;
        let sectors = (size as usize).div_ceil(sector_size);
        for i in 0..sectors {
            let offset = i * sector_size;
            let end = (offset + sector_size).min(size as usize);
            let mut sector_buf = [0u8; 2048];
            read_sector_data(
                &mut self.inner,
                self.mode,
                u64::from(lba) + i as u64,
                &mut sector_buf,
            )?;
            data[offset..end].copy_from_slice(&sector_buf[..end - offset]);
        }
        let mut records = parse_dir_records(&data)?;

        // Apply SUSP SP skip (IEEE P1282 §5.3): trim pre-SUSP padding bytes from
        // the beginning of each directory record's System Use field.  Without this,
        // all SUSP scanners break at `len=0 < 3` when the padding is zero-filled.
        if self.sp_skip > 0 {
            for rec in &mut records {
                let skip = self.sp_skip.min(rec.system_use.len());
                rec.system_use.drain(..skip);
            }
        }

        // Follow Rock Ridge CE (Continuation Area) pointers.
        for rec in &mut records {
            if let Some(ce) = continuation(&rec.system_use) {
                let start = ce.offset as usize;
                let end = start + ce.len as usize;
                if end <= 2048 {
                    let mut ce_buf = [0u8; 2048];
                    read_sector_data(&mut self.inner, self.mode, u64::from(ce.lba), &mut ce_buf)?;
                    rec.system_use.extend_from_slice(&ce_buf[start..end]);
                }
            }
        }

        // Merge multi-extent chains (ECMA-119 §9.1.6).
        // Consecutive same-name records with FILE_FLAG_MULTI_EXTENT form a chain;
        // merge them into the first record's extra_extents and clear the flag.
        let mut merged: Vec<DirRecord> = Vec::with_capacity(records.len());
        let mut iter = records.into_iter().peekable();
        while let Some(mut rec) = iter.next() {
            if rec.flags & FILE_FLAG_MULTI_EXTENT != 0 {
                while let Some(next) = iter.peek() {
                    if next.name_bytes != rec.name_bytes {
                        break;
                    }
                    // `peek()` above returned `Some`, so `next()` cannot be `None`.
                    let Some(next) = iter.next() else { break };
                    rec.extra_extents.push((next.lba, next.size));
                    rec.flags &= !FILE_FLAG_MULTI_EXTENT;
                    if next.flags & FILE_FLAG_MULTI_EXTENT == 0 {
                        break;
                    }
                }
            }
            merged.push(rec);
        }

        Ok(merged)
    }

    /// Open a streaming reader for a file entry without loading it into memory.
    ///
    /// The returned [`IsoFileReader`] implements [`std::io::Read`] and reads
    /// one sector at a time.  For multi-extent files, it chains all extents.
    pub fn open_file(&self, entry: &DirRecord) -> Result<IsoFileReader<R>, IsoError>
    where
        R: Clone,
    {
        if entry.is_dir() {
            return Err(IsoError::NotFound("entry is a directory".into()));
        }
        Ok(IsoFileReader::new(
            self.inner.clone(),
            self.mode,
            entry.lba,
            entry.size,
            entry.extra_extents.clone(),
        ))
    }

    /// Read the full contents of a file entry.
    ///
    /// For multi-extent files, concatenates all extents in directory order.
    pub fn read_file_entry(&mut self, entry: &DirRecord) -> Result<Vec<u8>, IsoError> {
        if entry.is_dir() {
            return Err(IsoError::NotFound("entry is a directory".into()));
        }
        let mut data = Vec::new();
        self.append_extent(entry.lba, entry.size, &mut data)?;
        for &(lba, size) in &entry.extra_extents {
            self.append_extent(lba, size, &mut data)?;
        }
        Ok(data)
    }

    fn append_extent(&mut self, lba: u32, size: u32, out: &mut Vec<u8>) -> Result<(), IsoError> {
        let sector_size = 2048usize;
        let sectors = (size as usize).div_ceil(sector_size);
        for i in 0..sectors {
            let offset = i * sector_size;
            let end = (offset + sector_size).min(size as usize);
            let mut sector_buf = [0u8; 2048];
            read_sector_data(
                &mut self.inner,
                self.mode,
                u64::from(lba) + i as u64,
                &mut sector_buf,
            )?;
            out.extend_from_slice(&sector_buf[..end - offset]);
        }
        Ok(())
    }

    /// Recursively walk the entire directory tree, returning every file and
    /// directory in DFS pre-order.
    ///
    /// Each [`WalkEntry`] contains the full path (root-relative, `/`-separated),
    /// the depth (0 = root level), and the `DirRecord`.
    pub fn walk(&mut self) -> Result<Vec<WalkEntry>, IsoError> {
        let root_lba = self.pvd.root_dir_lba;
        let root_size = self.pvd.root_dir_size;
        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.walk_dir(root_lba, root_size, "", 0, &mut out, &mut visited)?;
        Ok(out)
    }

    /// Walk the Joliet (supplementary) directory tree, depth-first.
    ///
    /// Returns an empty vec when the image has no Joliet SVD. Paths are built
    /// from the raw ISO identifiers (not UCS-2-decoded); this is intended for
    /// structural comparison against the primary tree (shared data extents), so
    /// the `record.lba` values are what matter.
    pub fn walk_joliet(&mut self) -> Result<Vec<WalkEntry>, IsoError> {
        let Some((lba, size)) =
            self.svd.as_ref().filter(|s| s.is_joliet).map(|s| (s.root_dir_lba, s.root_dir_size))
        else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.walk_dir(lba, size, "", 0, &mut out, &mut visited)?;
        Ok(out)
    }

    /// Walk the directory tree of an arbitrary session (0 = oldest), depth-first.
    ///
    /// Reads that session's own PVD for its root directory, then walks it like
    /// [`walk`](Self::walk). `walk_session(session_count() - 1)` is the active
    /// session and equals [`walk`](Self::walk). Used to compare an earlier
    /// session's files against the active tree (superseded / recoverable
    /// content).
    ///
    /// # Errors
    /// Returns [`IsoError::NotFound`] if `idx >= session_count()`.
    pub fn walk_session(&mut self, idx: usize) -> Result<Vec<WalkEntry>, IsoError> {
        let pvd_lba = *self.session_pvd_lbas.get(idx).ok_or_else(|| {
            IsoError::NotFound(format!(
                "session index {idx} out of range ({})",
                self.session_pvd_lbas.len()
            ))
        })?;
        let (pvd, _svd, _boot, _rr, _skip) =
            read_volume_descriptors(&mut self.inner, self.mode, pvd_lba)?;
        let mut out = Vec::new();
        let mut visited = std::collections::HashSet::new();
        self.walk_dir(pvd.root_dir_lba, pvd.root_dir_size, "", 0, &mut out, &mut visited)?;
        Ok(out)
    }

    fn walk_dir(
        &mut self,
        lba: u32,
        size: u32,
        prefix: &str,
        depth: usize,
        out: &mut Vec<WalkEntry>,
        visited: &mut std::collections::HashSet<u32>,
    ) -> Result<(), IsoError> {
        // A directory extent already on this traversal is a cycle (or a shared
        // extent) — list its entries once but do not re-descend, so a crafted or
        // corrupt loop terminates instead of exhausting the depth limit.
        if !visited.insert(lba) {
            return Ok(());
        }
        if depth > MAX_WALK_DEPTH {
            return Err(IsoError::ResourceLimit(format!(
                "directory nesting depth {depth} exceeds limit {MAX_WALK_DEPTH}"
            )));
        }
        for rec in self.read_dir(lba, size)? {
            let name = if let Some(rr) = rock_ridge::alternate_name(&rec.system_use) {
                rr
            } else {
                rec.iso_name()
            };
            let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
            if rec.is_dir() {
                let child_lba = rec.lba;
                let child_size = rec.size;
                out.push(WalkEntry { path: path.clone(), depth, record: rec });
                // A subdirectory whose extent lies past the image (truncation /
                // corruption / dangling reference) is left as a listed entry but
                // not descended into; the unreadable extent is surfaced
                // separately (analyse()'s ISO-OOB-EXTENT). Real I/O errors still
                // propagate.
                match self.walk_dir(child_lba, child_size, &path, depth + 1, out, visited) {
                    Ok(()) => {}
                    Err(IsoError::Io(io)) if io.kind() == std::io::ErrorKind::UnexpectedEof => {}
                    Err(e) => return Err(e),
                }
            } else {
                out.push(WalkEntry { path, depth, record: rec });
            }
        }
        Ok(())
    }

    /// Find a file or directory by path (e.g. `"docs/readme.txt"`).
    ///
    /// Rejects path components that escape the root (`..`).
    pub fn find_entry(&mut self, path: &str) -> Result<DirRecord, IsoError> {
        let parts: Vec<&str> =
            path.trim_matches('/').split('/').filter(|p| !p.is_empty()).collect();

        let mut lba = self.pvd.root_dir_lba;
        let mut size = self.pvd.root_dir_size;

        for (depth, part) in parts.iter().enumerate() {
            if *part == ".." {
                return Err(IsoError::PathTraversal);
            }
            let entries = self.read_dir(lba, size)?;
            let is_last = depth == parts.len() - 1;
            let needle = part.to_ascii_uppercase();
            let found = entries
                .into_iter()
                .find(|e| {
                    let iso = e.iso_name().to_ascii_uppercase();
                    let rr =
                        rock_ridge::alternate_name(&e.system_use).map(|n| n.to_ascii_uppercase());
                    iso == needle || rr.as_deref() == Some(needle.as_str())
                })
                .ok_or_else(|| IsoError::NotFound(part.to_string()))?;

            if is_last {
                return Ok(found);
            }
            if !found.is_dir() {
                return Err(IsoError::NotFound(format!("{part} is not a directory")));
            }
            lba = found.lba;
            size = found.size;
        }
        Err(IsoError::NotFound(path.into()))
    }

    /// Find a file or directory by path, returning `None` if not found.
    ///
    /// Like [`Self::find_entry`] but returns `Ok(None)` instead of `Err(NotFound)`.
    /// Leading `/` is ignored; components are matched case-insensitively against
    /// both the ISO 9660 name and any Rock Ridge NM alternate name.
    pub fn find_path(&mut self, path: &str) -> Result<Option<DirRecord>, IsoError> {
        match self.find_entry(path) {
            Ok(entry) => Ok(Some(entry)),
            Err(IsoError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Parse El Torito boot catalog entries, if an El Torito BRVD is present.
    pub fn boot_entries(&mut self) -> Result<Vec<BootEntry>, IsoError> {
        let cat_lba = match self.boot_catalog_lba {
            Some(l) => l,
            None => return Ok(Vec::new()),
        };
        let mut buf = [0u8; 2048];
        read_sector_data(&mut self.inner, self.mode, u64::from(cat_lba), &mut buf)?;
        Ok(parse_boot_catalog(&buf))
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Scan for all session PVD LBAs by reading every sector starting from 16.
/// The mandatory LBA 16 PVD is retained for compatibility with malformed or
/// truncated-image diagnostics; later candidates must pass root validation.
fn scan_sessions<R: Read + Seek>(reader: &mut R, mode: SectorMode) -> Result<Vec<u64>, IsoError> {
    let mut lbas = Vec::new();
    let mut buf = [0u8; 2048];

    for lba in 16u64..4096 {
        let pos = mode.user_data_pos(lba);
        reader.seek(SeekFrom::Start(pos))?;
        match reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if buf[0] == 0x01
            && &buf[1..6] == b"CD001"
            && buf[6] == 0x01
            && (lba == 16 || is_valid_session_candidate(reader, mode, &buf)?)
        {
            lbas.push(lba);
        }
        if buf[0] == TERMINATOR_TYPE && &buf[1..6] == b"CD001" {
            // Terminator found — but there may be more sessions after a gap.
            // Continue scanning until EOF.
        }
    }
    Ok(lbas)
}

/// Validate the root extent carried by a candidate PVD before treating it as
/// a session boundary. Hybrid images can contain additional `CD001`-looking
/// descriptor chains whose root pointer actually targets file data. The ISO
/// 9660 root directory must begin with a `.` record whose extent points back
/// to the PVD's root extent and is marked as a directory.
fn is_valid_session_candidate<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    pvd_sector: &[u8; 2048],
) -> Result<bool, IsoError> {
    let pvd = match PrimaryVolumeDescriptor::parse(pvd_sector) {
        Ok(pvd) => pvd,
        Err(_) => return Ok(false),
    };
    if pvd.logical_block_size != 2048
        || pvd.root_dir_lba == 0
        || pvd.root_dir_size == 0
        || pvd.root_dir_size > MAX_DIR_SIZE
    {
        return Ok(false);
    }

    let mut root_sector = [0u8; 2048];
    match read_sector_data(reader, mode, u64::from(pvd.root_dir_lba), &mut root_sector) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => return Err(error.into()),
    }

    let Ok(Some((root, _))) = DirRecord::parse(&root_sector, 0) else {
        return Ok(false);
    };
    Ok(root.name_bytes == [0x00]
        && root.is_dir()
        && root.lba == pvd.root_dir_lba
        && root.size == pvd.root_dir_size)
}

/// Detect a UDF filesystem by scanning the Volume Recognition Sequence (sector
/// 16 onward) for an NSR02/NSR03 descriptor. UDF bridge discs carry both the
/// ISO 9660 CD001 descriptors and a UDF NSR descriptor in the same area.
fn detect_udf<R: Read + Seek>(reader: &mut R, mode: SectorMode) -> Result<bool, IsoError> {
    let mut buf = [0u8; 2048];
    for lba in 16u64..32 {
        let pos = mode.user_data_pos(lba);
        reader.seek(SeekFrom::Start(pos))?;
        match reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        if &buf[1..6] == b"NSR02" || &buf[1..6] == b"NSR03" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The volume-descriptor chain extracted from a session:
/// `(pvd, svd, boot_cat_lba, has_rock_ridge, sp_skip)`.
type VolumeDescriptors =
    (PrimaryVolumeDescriptor, Option<SupplementaryVolumeDescriptor>, Option<u32>, bool, usize);

/// Read the VD chain starting at `first_pvd_lba`, extracting PVD, SVD, boot.
fn read_volume_descriptors<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    first_pvd_lba: u64,
) -> Result<VolumeDescriptors, IsoError> {
    let mut buf = [0u8; 2048];
    let mut pvd: Option<PrimaryVolumeDescriptor> = None;
    let mut svd: Option<SupplementaryVolumeDescriptor> = None;
    let mut boot_cat: Option<u32> = None;
    let mut has_rr = false;
    let mut sp_skip = 0usize;

    let mut lba = first_pvd_lba;
    loop {
        read_sector_data(reader, mode, lba, &mut buf)?;
        match buf[0] {
            PVD_TYPE => {
                let p = PrimaryVolumeDescriptor::parse(&buf)?;
                // Check the root dir's System Use for the Rock Ridge SP entry.
                if !has_rr {
                    let (rr, skip) = check_rock_ridge(reader, mode, p.root_dir_lba)?;
                    has_rr = rr;
                    sp_skip = skip;
                }
                pvd = Some(p);
            }
            SVD_TYPE => {
                if let Ok(s) = SupplementaryVolumeDescriptor::parse(&buf) {
                    // Prefer a Joliet SVD (drives UCS-2 listing); otherwise keep
                    // an Enhanced VD (ISO 9660:1999) so it can be reported — but
                    // never let an EVD displace a Joliet SVD already found.
                    let keep = s.is_joliet
                        || (s.is_enhanced() && svd.as_ref().is_none_or(|e| !e.is_joliet));
                    if keep {
                        svd = Some(s);
                    }
                }
            }
            BOOT_RECORD_TYPE => {
                boot_cat = boot_catalog_lba(&buf);
            }
            TERMINATOR_TYPE => break,
            _ => {}
        }
        lba += 1;
    }

    pvd.ok_or_else(|| IsoError::BadDescriptor("no PVD found in VD chain".into()))
        .map(|p| (p, svd, boot_cat, has_rr, sp_skip))
}

/// Check the root directory's first (dot) record for a Rock Ridge SP entry.
///
/// Returns `(has_rock_ridge, sp_skip)` — the skip is the SUSP `LEN_SKP` value
/// from the SP entry (IEEE P1282 §5.3), or 0 if no SP entry is found.
fn check_rock_ridge<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    root_dir_lba: u32,
) -> Result<(bool, usize), IsoError> {
    let mut buf = [0u8; 2048];
    read_sector_data(reader, mode, u64::from(root_dir_lba), &mut buf)?;
    let offset = 0usize;
    if buf[offset] == 0 {
        return Ok((false, 0));
    }
    let len = buf[offset] as usize;
    if len < 34 {
        return Ok((false, 0));
    }
    let name_len = buf[offset + 32] as usize;
    let su_start = 33 + name_len + usize::from(name_len % 2 == 0);
    if su_start >= len {
        return Ok((false, 0));
    }
    let su = &buf[offset + su_start..offset + len];
    let found = has_sp_entry(su);
    let skip = if found { extract_sp_skip(su) } else { 0 };
    Ok((found, skip))
}
