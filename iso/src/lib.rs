//! Pure-Rust forensic ISO 9660 reader.
//!
//! Handles multi-session discs, UDF bridge discs, Rock Ridge (RRIP), Joliet
//! (UCS-2 filenames), El Torito boot images, and 2352-byte raw CD sectors.

pub mod audit;
pub mod ccd;
pub mod cdtext;
pub mod cdtoc;
pub mod cue;
pub mod dir;
pub mod el_torito;
pub mod error;
pub mod file_reader;
pub mod nrg;
pub mod offset;
pub mod path_table;
pub mod pvd;
pub mod rock_ridge;
pub mod sector;
pub mod session;
pub mod subq;
pub mod udf;

pub use error::IsoError;

/// Maximum bytes that `read_dir` will allocate for a single directory.
///
/// Prevents DoS via crafted `root_dir_size` or directory entry size fields.
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

pub use audit::{BothEndianMismatch, GapHit, PreSysHit, SlackHit, SymlinkIssue};

/// Mastering-tool identification based on PVD metadata patterns.
#[derive(Debug, Clone)]
pub struct ToolFingerprint {
    /// Tool name, e.g. `"xorriso"`, `"mkisofs"`, `"unknown"`.
    pub tool: String,
    /// Version string extracted from the data-preparer or application field.
    pub version: Option<String>,
    /// Confidence level: `"HIGH"`, `"MEDIUM"`, or `"LOW"`.
    pub confidence: &'static str,
    /// Human-readable evidence strings.
    pub evidence: Vec<String>,
}

/// Result of comparing the L-path table against the directory tree.
#[derive(Debug, Clone)]
pub struct PathTableAudit {
    pub path_table_lbas: Vec<u32>,
    pub tree_lbas: Vec<u32>,
    /// Directories in the path table but not reachable from the tree.
    pub phantom_lbas: Vec<u32>,
    /// Directories reachable from the tree but absent from the path table.
    pub ghost_lbas: Vec<u32>,
}

/// A directory entry with its modification timestamp for timeline analysis.
#[derive(Debug, Clone)]
pub struct TimelineEntry {
    /// Full path in the ISO.
    pub path: String,
    pub is_dir: bool,
    pub size: u32,
    /// Short (7-byte) Rock Ridge modify timestamp, if present.
    pub modify_ts: Option<[u8; 7]>,
    /// Detected anomaly, e.g. `"epoch-date"`.
    pub anomaly: Option<String>,
}

/// SHA-256 hash of a file in the ISO.
#[derive(Debug, Clone)]
pub struct FileHash {
    pub path: String,
    pub size: u32,
    /// Lowercase hexadecimal SHA-256, 64 characters.
    pub sha256_hex: String,
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
use udf::{detect_udf, parse_udf_state, read_dir_at_lba, read_fe_data, UdfState};
pub use udf::{UdfFileEntry, UdfPartitionKind};

/// Forensic ISO 9660 reader.
///
/// Wraps any `Read + Seek` source and exposes multi-session, Rock Ridge,
/// Joliet, El Torito, and UDF metadata alongside raw file data.
pub struct IsoReader<R> {
    inner: R,
    mode: SectorMode,
    pvd: PrimaryVolumeDescriptor,
    svd: Option<SupplementaryVolumeDescriptor>,
    boot_catalog_lba: Option<u32>,
    /// All LBAs at which a PVD was detected (ascending). Last = active session.
    pub session_pvd_lbas: Vec<u64>,
    pub has_udf: bool,
    pub has_rock_ridge: bool,
    /// SUSP SP LEN_SKP: bytes to skip at start of each System Use field (IEEE P1282 §5.3).
    sp_skip: usize,
    udf_state: Option<UdfState>,
}

impl<R: Read + Seek> IsoReader<R> {
    /// Open an ISO image, detecting sector mode and parsing the active session.
    pub fn open(mut reader: R) -> Result<Self, IsoError> {
        let mode = SectorMode::detect(&mut reader)?;

        // Scan for all sessions (PVD LBAs).  Pure-UDF images (Blu-ray, packet
        // CD) carry no ISO 9660 PVD, so an empty result is not fatal when a UDF
        // recognition sequence is present.
        let session_pvd_lbas = scan_sessions(&mut reader, mode)?;

        let (pvd, svd, boot_cat_lba, has_rock_ridge, sp_skip) =
            if let Some(&active_pvd_lba) = session_pvd_lbas.last() {
                read_volume_descriptors(&mut reader, mode, active_pvd_lba)?
            } else {
                // No ISO 9660 PVD: use empty sentinels (validated as UDF below).
                (PrimaryVolumeDescriptor::default(), None, None, false, 0)
            };

        let has_udf = detect_udf(&mut reader);
        let udf_state = if has_udf { parse_udf_state(&mut reader) } else { None };

        // An image with neither an ISO 9660 PVD nor a UDF structure is not one
        // this reader can interpret.
        if session_pvd_lbas.is_empty() && !has_udf {
            return Err(IsoError::NotAnIso);
        }

        Ok(Self {
            inner: reader,
            mode,
            pvd,
            svd,
            boot_catalog_lba: boot_cat_lba,
            session_pvd_lbas,
            has_udf,
            has_rock_ridge,
            sp_skip,
            udf_state,
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
    pub fn l_path_table_lba(&self) -> u32 {
        self.pvd.l_path_table_lba
    }
    pub fn m_path_table_lba(&self) -> u32 {
        self.pvd.m_path_table_lba
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

    /// True if a Joliet Supplementary Volume Descriptor is present.
    pub fn has_joliet(&self) -> bool {
        self.svd.as_ref().is_some_and(|s| s.is_joliet)
    }

    /// True if a UDF recognition sequence (NSR02/NSR03) was detected.
    pub fn has_udf(&self) -> bool {
        self.has_udf
    }

    /// Kind of the UDF partition referenced by the file set, if a UDF structure
    /// was parsed.  `Physical` resolves normally; `Virtual`/`Sparable`/`Metadata`
    /// (Type 2) require structures this crate does not yet follow.
    pub fn udf_partition_kind(&self) -> Option<UdfPartitionKind> {
        self.udf_state.as_ref().map(|s| s.partition_kind)
    }

    /// Number of UDF partition maps declared in the Logical Volume Descriptor.
    pub fn udf_partition_map_count(&self) -> Option<u32> {
        self.udf_state.as_ref().map(|s| s.partition_map_count)
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
            read_sector_data(&mut self.inner, self.mode, lba as u64 + i as u64, &mut sector_buf)?;
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
                    read_sector_data(&mut self.inner, self.mode, ce.lba as u64, &mut ce_buf)?;
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
                    let next = iter.next().unwrap();
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
            read_sector_data(&mut self.inner, self.mode, lba as u64 + i as u64, &mut sector_buf)?;
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
        self.walk_dir(root_lba, root_size, String::new(), 0, &mut out)?;
        Ok(out)
    }

    fn walk_dir(
        &mut self,
        lba: u32,
        size: u32,
        prefix: String,
        depth: usize,
        out: &mut Vec<WalkEntry>,
    ) -> Result<(), IsoError> {
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
                self.walk_dir(child_lba, child_size, path, depth + 1, out)?;
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
    /// Like [`find_entry`] but returns `Ok(None)` instead of `Err(NotFound)`.
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
        read_sector_data(&mut self.inner, self.mode, cat_lba as u64, &mut buf)?;
        Ok(parse_boot_catalog(&buf))
    }

    // ── UDF traversal ─────────────────────────────────────────────────────────

    /// List the UDF root directory. Requires the image to have a parseable UDF structure.
    pub fn read_udf_root_dir(&mut self) -> Result<Vec<UdfFileEntry>, IsoError> {
        let (partition_start, root_lba) = self
            .udf_state
            .as_ref()
            .map(|s| (s.partition_start, s.root_fe_lba))
            .ok_or_else(|| IsoError::BadDescriptor("UDF structure not available".into()))?;
        read_dir_at_lba(&mut self.inner, partition_start, root_lba)
            .ok_or_else(|| IsoError::BadDescriptor("UDF root directory unreadable".into()))
    }

    /// List the children of a UDF directory entry.
    pub fn read_udf_dir(&mut self, entry: &UdfFileEntry) -> Result<Vec<UdfFileEntry>, IsoError> {
        let partition_start = self
            .udf_state
            .as_ref()
            .map(|s| s.partition_start)
            .ok_or_else(|| IsoError::BadDescriptor("UDF structure not available".into()))?;
        read_dir_at_lba(&mut self.inner, partition_start, entry.fe_lba)
            .ok_or_else(|| IsoError::BadDescriptor("UDF directory unreadable".into()))
    }

    /// Read the full data of a UDF file entry.
    pub fn read_udf_file(&mut self, entry: &UdfFileEntry) -> Result<Vec<u8>, IsoError> {
        let partition_start = self
            .udf_state
            .as_ref()
            .map(|s| s.partition_start)
            .ok_or_else(|| IsoError::BadDescriptor("UDF structure not available".into()))?;
        read_fe_data(&mut self.inner, partition_start, entry.fe_lba)
            .ok_or_else(|| IsoError::NotFound("UDF file data unreadable".into()))
    }

    // ── Forensic audit methods ────────────────────────────────────────────────

    /// Identify the mastering tool from PVD metadata patterns.
    ///
    /// Inspects `data_preparer_id` and `application_id` for known tool
    /// signatures (xorriso, mkisofs, genisoimage, ImgBurn, hdiutil, etc.).
    pub fn fingerprint_tool(&self) -> ToolFingerprint {
        const SIGS: &[(&str, &str, &str)] = &[
            ("XORRISO", "xorriso", "HIGH"),
            ("xorriso", "xorriso", "HIGH"),
            ("MKISOFS", "mkisofs", "HIGH"),
            ("mkisofs", "mkisofs", "HIGH"),
            ("GENISOIMAGE", "genisoimage", "HIGH"),
            ("genisoimage", "genisoimage", "HIGH"),
            ("IMGBURN", "ImgBurn", "HIGH"),
            ("ImgBurn", "ImgBurn", "HIGH"),
            ("HDIUTIL", "hdiutil (macOS)", "HIGH"),
            ("hdiutil", "hdiutil (macOS)", "HIGH"),
            ("ISOMASTER", "IsoMaster", "HIGH"),
            ("NERO", "Nero", "MEDIUM"),
        ];
        let haystack = format!("{} {}", self.data_preparer_id(), self.application_id());
        for (needle, name, conf) in SIGS {
            if let Some(pos) = haystack.find(needle) {
                // Extract the version that follows the tool name: scan forward from
                // the end of the matched needle for the first run of [0-9.] that
                // contains a dot (e.g. "XORRISO-1.5.8" -> "1.5.8").  This avoids
                // picking up a trailing build date like "2026.05.22".
                let after = &haystack[pos + needle.len()..];
                let version = extract_version(after).or_else(|| extract_version(&haystack));
                let conf: &'static str = match *conf {
                    "HIGH" => "HIGH",
                    "MEDIUM" => "MEDIUM",
                    _ => "LOW",
                };
                return ToolFingerprint {
                    tool: (*name).to_owned(),
                    version,
                    confidence: conf,
                    evidence: vec![format!("PVD field contains '{needle}'")],
                };
            }
        }
        ToolFingerprint {
            tool: "unknown".to_owned(),
            version: None,
            confidence: "LOW",
            evidence: Vec::new(),
        }
    }

    /// Compare the L-path table against the directory tree.
    ///
    /// Returns LBAs that appear only in the path table (`phantom`) or only
    /// in the tree (`ghost`).  Either indicates inconsistency or tampering.
    pub fn audit_path_table(&mut self) -> Result<PathTableAudit, IsoError> {
        use path_table::parse_l_path_table;
        use std::collections::HashSet;

        // Read the L-path table (may span several sectors for large images).
        let pt_lba = self.pvd.l_path_table_lba;
        let pt_size = self.pvd.path_table_size as usize;
        let sectors = pt_size.div_ceil(2048).max(1);
        let mut pt_data = Vec::with_capacity(sectors * 2048);
        for i in 0..sectors {
            let raw = self.read_sector_raw(pt_lba as u64 + i as u64)?;
            pt_data.extend_from_slice(&raw);
        }
        let pt_slice = &pt_data[..pt_size.min(pt_data.len())];
        let pt_entries = parse_l_path_table(pt_slice).unwrap_or_default();
        let path_table_lbas: Vec<u32> = pt_entries.iter().map(|e| e.lba).collect();
        let pt_set: HashSet<u32> = path_table_lbas.iter().copied().collect();

        // Collect directory LBAs from the tree (always include the root).
        let tree_entries = self.walk()?;
        let mut tree_set: HashSet<u32> =
            tree_entries.iter().filter(|e| e.record.is_dir()).map(|e| e.record.lba).collect();
        tree_set.insert(self.pvd.root_dir_lba);

        let mut tree_lbas: Vec<u32> = tree_set.iter().copied().collect();
        tree_lbas.sort_unstable();

        let mut phantom_lbas: Vec<u32> = pt_set.difference(&tree_set).copied().collect();
        let mut ghost_lbas: Vec<u32> = tree_set.difference(&pt_set).copied().collect();
        phantom_lbas.sort_unstable();
        ghost_lbas.sort_unstable();

        Ok(PathTableAudit { path_table_lbas, tree_lbas, phantom_lbas, ghost_lbas })
    }

    pub fn audit_both_endian(&mut self) -> Result<Vec<audit::BothEndianMismatch>, IsoError> {
        use audit::BothEndianMismatch;
        let mut out: Vec<BothEndianMismatch> = Vec::new();

        // ── PVD (sector 16) ──
        let pvd_raw = self.read_sector_raw(16)?;
        let pvd_off = self.mode.user_data_pos(16);

        macro_rules! chk32 {
            ($off:expr, $name:expr) => {{
                let le = u32::from_le_bytes(pvd_raw[$off..$off + 4].try_into().unwrap()) as u64;
                let be = u32::from_be_bytes(pvd_raw[$off + 4..$off + 8].try_into().unwrap()) as u64;
                if le != be {
                    out.push(BothEndianMismatch {
                        context: "PVD".into(),
                        field: $name.into(),
                        byte_offset: pvd_off + $off as u64,
                        le_val: le,
                        be_val: be,
                    });
                }
            }};
        }
        macro_rules! chk16 {
            ($off:expr, $name:expr) => {{
                let le = u16::from_le_bytes(pvd_raw[$off..$off + 2].try_into().unwrap()) as u64;
                let be = u16::from_be_bytes(pvd_raw[$off + 2..$off + 4].try_into().unwrap()) as u64;
                if le != be {
                    out.push(BothEndianMismatch {
                        context: "PVD".into(),
                        field: $name.into(),
                        byte_offset: pvd_off + $off as u64,
                        le_val: le,
                        be_val: be,
                    });
                }
            }};
        }
        chk32!(80, "volume_space_size");
        chk16!(120, "volume_set_size");
        chk16!(124, "volume_sequence_number");
        chk16!(128, "logical_block_size");
        chk32!(132, "path_table_size");

        // ── Directory sectors ──
        let entries = self.walk()?;
        let mut seen = std::collections::HashSet::new();
        // Always include root dir lba
        seen.insert(self.pvd.root_dir_lba);
        for e in &entries {
            if e.record.is_dir() {
                seen.insert(e.record.lba);
            }
        }
        for dir_lba in seen {
            let raw = self.read_sector_raw(dir_lba as u64)?;
            let sec_off = self.mode.user_data_pos(dir_lba as u64);
            let ctx = format!("dir:lba={dir_lba}");
            let mut pos = 0usize;
            while pos < raw.len() {
                let rl = raw[pos] as usize;
                if rl == 0 {
                    pos += 1;
                    continue;
                }
                if rl < 33 || pos + rl > raw.len() {
                    break;
                }
                // lba
                let le = u32::from_le_bytes(raw[pos + 2..pos + 6].try_into().unwrap()) as u64;
                let be = u32::from_be_bytes(raw[pos + 6..pos + 10].try_into().unwrap()) as u64;
                if le != be {
                    out.push(BothEndianMismatch {
                        context: ctx.clone(),
                        field: "entry_lba".into(),
                        byte_offset: sec_off + pos as u64 + 2,
                        le_val: le,
                        be_val: be,
                    });
                }
                // size
                let le = u32::from_le_bytes(raw[pos + 10..pos + 14].try_into().unwrap()) as u64;
                let be = u32::from_be_bytes(raw[pos + 14..pos + 18].try_into().unwrap()) as u64;
                if le != be {
                    out.push(BothEndianMismatch {
                        context: ctx.clone(),
                        field: "entry_size".into(),
                        byte_offset: sec_off + pos as u64 + 10,
                        le_val: le,
                        be_val: be,
                    });
                }
                pos += rl;
            }
        }
        Ok(out)
    }

    pub fn audit_pre_system(&mut self) -> Result<Vec<audit::PreSysHit>, IsoError> {
        const MAGIC: &[(&[u8], &str)] = &[
            (b"MZ", "MZ/PE"),
            (&[0x7F, b'E', b'L', b'F'], "ELF"),
            (&[b'P', b'K', 0x03, 0x04], "ZIP"),
            (b"%PDF", "PDF"),
            (&[0x37, 0x7A, 0xBC, 0xAF], "7z"),
        ];
        let mut out = Vec::new();
        for sector in 0u8..16 {
            let raw = self.read_sector_raw(sector as u64)?;
            if raw.iter().all(|&b| b == 0) {
                continue;
            }
            let kind = MAGIC
                .iter()
                .find(|(sig, _)| raw.starts_with(sig))
                .map(|(_, k)| *k)
                .unwrap_or("non-zero");
            out.push(audit::PreSysHit { sector, kind });
        }
        Ok(out)
    }

    pub fn audit_symlinks(&mut self) -> Result<Vec<audit::SymlinkIssue>, IsoError> {
        let entries = self.walk()?;
        let mut out = Vec::new();
        for e in entries {
            if e.record.is_dir() {
                continue;
            }
            if let Some(target) = rock_ridge::symlink_target(&e.record.system_use) {
                let issue = if target.contains("..") {
                    "path-traversal"
                } else if target.starts_with('/') {
                    "absolute"
                } else {
                    continue;
                };
                out.push(audit::SymlinkIssue { entry_path: e.path, target, issue });
            }
        }
        Ok(out)
    }

    pub fn audit_file_slack(&mut self) -> Result<Vec<audit::SlackHit>, IsoError> {
        let entries = self.walk()?;
        let mut out = Vec::new();
        for e in entries {
            if e.record.is_dir() {
                continue;
            }
            let size = e.record.size;
            let remainder = size % 2048;
            let slack_bytes = if remainder == 0 { 0 } else { 2048 - remainder };
            if slack_bytes == 0 {
                out.push(audit::SlackHit {
                    entry_path: e.path,
                    lba: e.record.lba,
                    file_size: size,
                    slack_bytes: 0,
                    nonzero: false,
                });
                continue;
            }
            let sectors = (size as u64).div_ceil(2048);
            let last_lba = e.record.lba as u64 + sectors - 1;
            let raw = self.read_sector_raw(last_lba)?;
            let data_end = remainder as usize;
            let nonzero = raw[data_end..].iter().any(|&b| b != 0);
            out.push(audit::SlackHit {
                entry_path: e.path,
                lba: e.record.lba,
                file_size: size,
                slack_bytes,
                nonzero,
            });
        }
        Ok(out)
    }

    /// Sort all directory entries by Rock Ridge modification timestamp.
    ///
    /// Entries without a timestamp appear last.  Detects `"epoch-date"`
    /// anomalies (year 1970, month 1, day 1).
    pub fn timeline(&mut self) -> Result<Vec<TimelineEntry>, IsoError> {
        let entries = self.walk()?;
        let mut out: Vec<TimelineEntry> = entries
            .into_iter()
            .filter(|e| !e.record.is_dir())
            .map(|e| {
                let modify_ts =
                    rock_ridge::timestamps(&e.record.system_use).and_then(|ts| ts.modify);
                let anomaly = modify_ts.and_then(|ts| {
                    if ts[0] == 70
                        && ts[1] == 1
                        && ts[2] == 1
                        && ts[3] == 0
                        && ts[4] == 0
                        && ts[5] == 0
                    {
                        Some("epoch-date".to_string())
                    } else {
                        None
                    }
                });
                TimelineEntry {
                    path: e.path,
                    is_dir: false,
                    size: e.record.size,
                    modify_ts,
                    anomaly,
                }
            })
            .collect();
        // Sort by modify_ts ascending; None (no timestamp) goes last.
        out.sort_by_key(|a| a.modify_ts);
        Ok(out)
    }

    pub fn hashlist(&mut self) -> Result<Vec<FileHash>, IsoError> {
        use sha2::{Digest, Sha256};
        let entries = self.walk()?;
        let mut out: Vec<FileHash> = Vec::new();
        for e in entries {
            if e.record.is_dir() {
                continue;
            }
            let data = self.read_file_entry(&e.record)?;
            let hash = Sha256::digest(&data);
            let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
            out.push(FileHash { path: e.path, size: e.record.size, sha256_hex: hex });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    pub fn audit_sector_gaps(&mut self) -> Result<Vec<audit::GapHit>, IsoError> {
        let total = self.volume_space_size();
        let entries = self.walk()?;

        // Pre-system area (0-15) plus the volume-descriptor chain (16 → the
        // terminator, inclusive).  Scanning the chain handles images with extra
        // descriptors (Boot Record VD, SVD) that push the terminator past 18.
        let mut alloc: std::collections::HashSet<u32> = (0..=15).collect();
        for lba in 16u32..512 {
            let raw = match self.read_sector_raw(lba as u64) {
                Ok(r) => r,
                Err(_) => break,
            };
            if &raw[1..6] != b"CD001" {
                break;
            }
            alloc.insert(lba);
            if raw[0] == 0xFF {
                break; // VD Terminator
            }
        }
        alloc.insert(self.pvd.root_dir_lba);

        // Both path tables (L little-endian and M big-endian) are legitimate
        // structures.  Each may span several sectors; mark all of them so the
        // standard M-path table is not mistaken for hidden data.
        let pt_sectors = (self.pvd.path_table_size as u64).div_ceil(2048).max(1) as u32;
        for base in [self.pvd.l_path_table_lba, self.pvd.m_path_table_lba] {
            for s in 0..pt_sectors {
                alloc.insert(base + s);
            }
        }

        // Helper: mark all sectors spanned by a CE (Continuation Area) pointer.
        let mark_ce = |alloc: &mut std::collections::HashSet<u32>, su: &[u8]| {
            if let Some(ce) = rock_ridge::continuation(su) {
                let end = ce.offset.saturating_add(ce.len);
                let ce_sectors = (end as u64).div_ceil(2048).max(1) as u32;
                for s in 0..ce_sectors {
                    alloc.insert(ce.lba + s);
                }
            }
        };

        for e in &entries {
            let sectors = (e.record.size as u64).div_ceil(2048) as u32;
            for s in 0..sectors.max(1) {
                alloc.insert(e.record.lba + s);
            }
            // Rock Ridge CE sectors referenced from this entry are legitimate.
            mark_ce(&mut alloc, &e.record.system_use);
        }

        // The root directory's "." record carries the Rock Ridge ER (Extensions
        // Reference), usually via a CE continuation area.  walk() skips dot
        // entries, so read the root dir records directly and mark their CEs.
        if let Ok(root_records) = self.read_dir(self.pvd.root_dir_lba, self.pvd.root_dir_size) {
            for rec in &root_records {
                mark_ce(&mut alloc, &rec.system_use);
            }
        }
        // read_dir already follows and appends the root "." CE, but the dot
        // record itself is filtered out; read its raw System Use too.
        if let Ok(raw) = self.read_sector_raw(self.pvd.root_dir_lba as u64) {
            let len = raw[0] as usize;
            if len >= 34 && len <= raw.len() {
                let name_len = raw[32] as usize;
                let su_start = 33 + name_len + (if name_len % 2 == 0 { 1 } else { 0 });
                if su_start < len {
                    mark_ce(&mut alloc, &raw[su_start..len]);
                }
            }
        }

        // ── Supplementary (Joliet) volume structures ──
        // The SVD has its own path tables and a parallel directory tree (the
        // file *data* is shared with the PVD tree, but the directory sectors
        // and path tables are distinct).  Mark them all as legitimate.
        if let Some(svd) = self.svd.as_ref() {
            let svd_root_lba = svd.root_dir_lba;
            let svd_root_size = svd.root_dir_size;
            let svd_pt_sectors = (svd.path_table_size as u64).div_ceil(2048).max(1) as u32;
            let svd_l = svd.l_path_table_lba;
            let svd_m = svd.m_path_table_lba;
            for base in [svd_l, svd_m] {
                if base != 0 {
                    for s in 0..svd_pt_sectors {
                        alloc.insert(base + s);
                    }
                }
            }
            // BFS over the Joliet directory tree, marking directory sectors.
            let mut worklist = vec![(svd_root_lba, svd_root_size)];
            let mut visited = std::collections::HashSet::new();
            while let Some((lba, size)) = worklist.pop() {
                if !visited.insert(lba) {
                    continue;
                }
                let dir_sectors = (size as u64).div_ceil(2048).max(1) as u32;
                for s in 0..dir_sectors {
                    alloc.insert(lba + s);
                }
                if let Ok(children) = self.read_dir(lba, size) {
                    for c in children {
                        if c.is_dir() {
                            worklist.push((c.lba, c.size));
                        } else {
                            let fs = (c.size as u64).div_ceil(2048).max(1) as u32;
                            for s in 0..fs {
                                alloc.insert(c.lba + s);
                            }
                        }
                    }
                }
            }
        }

        // ── El Torito boot catalog + boot images ──
        if let Some(cat) = self.boot_catalog_lba {
            alloc.insert(cat);
        }
        if let Ok(boot) = self.boot_entries() {
            for b in &boot {
                // sector_count is in 512-byte virtual sectors; convert to
                // 2048-byte logical sectors (round up, minimum one).
                let bytes = b.sector_count as u64 * 512;
                let bs = bytes.div_ceil(2048).max(1) as u32;
                for s in 0..bs {
                    alloc.insert(b.lba + s);
                }
            }
        }

        let cap = total.min(512);
        let mut out = Vec::new();
        for lba in 0..cap {
            if alloc.contains(&lba) {
                continue;
            }
            let raw = self.read_sector_raw(lba as u64)?;
            let nonzero = raw.iter().any(|&b| b != 0);
            out.push(audit::GapHit { lba, nonzero });
        }
        Ok(out)
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Extract the first dotted version run (e.g. "1.5.8") from `s`.
///
/// Returns the longest leading `[0-9.]` run that contains at least one dot,
/// after skipping any leading non-version characters up to the first digit.
fn extract_version(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let run = &s[start..i];
            if run.contains('.') {
                return Some(run.trim_end_matches('.').to_owned());
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Scan for all PVD LBAs by reading every sector starting from 16.
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
        if buf[0] == 0x01 && &buf[1..6] == b"CD001" && buf[6] == 0x01 {
            lbas.push(lba);
        }
        if buf[0] == TERMINATOR_TYPE && &buf[1..6] == b"CD001" {
            // Terminator found — but there may be more sessions after a gap.
            // Continue scanning until EOF.
        }
    }
    Ok(lbas)
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
                    if s.is_joliet {
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
/// Returns `(has_rock_ridge, sp_skip)` — the skip is the SUSP LEN_SKP value
/// from the SP entry (IEEE P1282 §5.3), or 0 if no SP entry is found.
fn check_rock_ridge<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    root_dir_lba: u32,
) -> Result<(bool, usize), IsoError> {
    let mut buf = [0u8; 2048];
    read_sector_data(reader, mode, root_dir_lba as u64, &mut buf)?;
    let offset = 0usize;
    if buf[offset] == 0 {
        return Ok((false, 0));
    }
    let len = buf[offset] as usize;
    if len < 34 {
        return Ok((false, 0));
    }
    let name_len = buf[offset + 32] as usize;
    let su_start = 33 + name_len + (if name_len % 2 == 0 { 1 } else { 0 });
    if su_start >= len {
        return Ok((false, 0));
    }
    let su = &buf[offset + su_start..offset + len];
    let found = has_sp_entry(su);
    let skip = if found { extract_sp_skip(su) } else { 0 };
    Ok((found, skip))
}
