//! Pure-Rust forensic ISO 9660 reader.
//!
//! Handles multi-session discs, UDF bridge discs, Rock Ridge (RRIP), Joliet
//! (UCS-2 filenames), El Torito boot images, and 2352-byte raw CD sectors.

pub mod dir;
pub mod el_torito;
pub mod error;
pub mod pvd;
pub mod rock_ridge;
pub mod sector;
pub mod session;
pub mod udf;

pub use error::IsoError;
pub use pvd::IsoDateTime;
pub use sector::SectorMode;

use std::io::{Read, Seek, SeekFrom};

use dir::{parse_dir_records, DirRecord};
use el_torito::{boot_catalog_lba, parse_boot_catalog, BootEntry};
use pvd::{
    PrimaryVolumeDescriptor, SupplementaryVolumeDescriptor, BOOT_RECORD_TYPE, PVD_TYPE, SVD_TYPE,
    TERMINATOR_TYPE,
};
use rock_ridge::{continuation, has_sp_entry};
use sector::read_sector_data;
use udf::{detect_udf, parse_udf_state, read_dir_at_lba, read_fe_data, UdfState};
pub use udf::UdfFileEntry;

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
    udf_state: Option<UdfState>,
}

impl<R: Read + Seek> IsoReader<R> {
    /// Open an ISO image, detecting sector mode and parsing the active session.
    pub fn open(mut reader: R) -> Result<Self, IsoError> {
        let mode = SectorMode::detect(&mut reader)?;

        // Scan for all sessions (PVD LBAs). We need the full image bytes for
        // the session scanner, but we want to avoid loading the whole image
        // into memory. Instead we scan sector-by-sector.
        let session_pvd_lbas = scan_sessions(&mut reader, mode)?;

        // Use the last session's PVD as authoritative.
        let active_pvd_lba = session_pvd_lbas.last().copied().ok_or(IsoError::NotAnIso)?;

        // Read and parse all volume descriptors starting at the active session.
        let (pvd, svd, boot_cat_lba, has_rock_ridge) =
            read_volume_descriptors(&mut reader, mode, active_pvd_lba)?;

        let has_udf = detect_udf(&mut reader);
        let udf_state = if has_udf {
            parse_udf_state(&mut reader)
        } else {
            None
        };

        Ok(Self {
            inner: reader,
            mode,
            pvd,
            svd,
            boot_catalog_lba: boot_cat_lba,
            session_pvd_lbas,
            has_udf,
            has_rock_ridge,
            udf_state,
        })
    }

    /// Sector mode of the image (2048-byte ISO or 2352-byte raw CD-ROM).
    pub fn sector_mode(&self) -> SectorMode {
        self.mode
    }

    /// Volume label from the Primary Volume Descriptor (trimmed).
    pub fn volume_label(&self) -> &str {
        &self.pvd.volume_label
    }

    // ── PVD metadata getters (ECMA-119 §8.4) ─────────────────────────────────

    pub fn system_id(&self) -> &str             { &self.pvd.system_id }
    pub fn volume_set_id(&self) -> &str         { &self.pvd.volume_set_id }
    pub fn publisher_id(&self) -> &str          { &self.pvd.publisher_id }
    pub fn data_preparer_id(&self) -> &str      { &self.pvd.data_preparer_id }
    pub fn application_id(&self) -> &str        { &self.pvd.application_id }
    pub fn copyright_file_id(&self) -> &str     { &self.pvd.copyright_file_id }
    pub fn abstract_file_id(&self) -> &str      { &self.pvd.abstract_file_id }
    pub fn bibliographic_file_id(&self) -> &str { &self.pvd.bibliographic_file_id }
    pub fn volume_creation_time(&self) -> Option<&IsoDateTime>     { self.pvd.volume_creation_time.as_ref() }
    pub fn volume_modification_time(&self) -> Option<&IsoDateTime> { self.pvd.volume_modification_time.as_ref() }
    pub fn volume_expiration_time(&self) -> Option<&IsoDateTime>   { self.pvd.volume_expiration_time.as_ref() }
    pub fn volume_effective_time(&self) -> Option<&IsoDateTime>    { self.pvd.volume_effective_time.as_ref() }
    pub fn volume_space_size(&self) -> u32  { self.pvd.volume_space_size }
    pub fn logical_block_size(&self) -> u16 { self.pvd.logical_block_size }
    pub fn path_table_size(&self) -> u32    { self.pvd.path_table_size }
    pub fn l_path_table_lba(&self) -> u32   { self.pvd.l_path_table_lba }
    pub fn m_path_table_lba(&self) -> u32   { self.pvd.m_path_table_lba }

    /// Joliet volume label from the Supplementary VD, if present.
    pub fn joliet_label(&self) -> Option<&str> {
        self.svd
            .as_ref()
            .filter(|s| s.is_joliet)
            .map(|s| s.volume_label.as_str())
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

    /// Read the root directory of the active session.
    pub fn read_root_dir(&mut self) -> Result<Vec<DirRecord>, IsoError> {
        self.read_dir(self.pvd.root_dir_lba, self.pvd.root_dir_size)
    }

    /// Read a directory given its LBA and size in bytes.
    pub fn read_dir(&mut self, lba: u32, size: u32) -> Result<Vec<DirRecord>, IsoError> {
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
                lba as u64 + i as u64,
                &mut sector_buf,
            )?;
            data[offset..end].copy_from_slice(&sector_buf[..end - offset]);
        }
        let mut records = parse_dir_records(&data)?;

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

        Ok(records)
    }

    /// Read the full contents of a file entry.
    pub fn read_file_entry(&mut self, entry: &DirRecord) -> Result<Vec<u8>, IsoError> {
        if entry.is_dir() {
            return Err(IsoError::NotFound("entry is a directory".into()));
        }
        let mut data = vec![0u8; entry.size as usize];
        let sector_size = 2048usize;
        let sectors = (entry.size as usize).div_ceil(sector_size);
        for i in 0..sectors {
            let offset = i * sector_size;
            let end = (offset + sector_size).min(entry.size as usize);
            let mut sector_buf = [0u8; 2048];
            read_sector_data(
                &mut self.inner,
                self.mode,
                entry.lba as u64 + i as u64,
                &mut sector_buf,
            )?;
            data[offset..end].copy_from_slice(&sector_buf[..end - offset]);
        }
        Ok(data)
    }

    /// Find a file or directory by path (e.g. `"docs/readme.txt"`).
    ///
    /// Rejects path components that escape the root (`..`).
    pub fn find_entry(&mut self, path: &str) -> Result<DirRecord, IsoError> {
        let parts: Vec<&str> = path
            .trim_matches('/')
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();

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
}

// ── Private helpers ──────────────────────────────────────────────────────────

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

/// Read the VD chain starting at `first_pvd_lba`, extracting PVD, SVD, boot.
fn read_volume_descriptors<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    first_pvd_lba: u64,
) -> Result<
    (
        PrimaryVolumeDescriptor,
        Option<SupplementaryVolumeDescriptor>,
        Option<u32>,
        bool,
    ),
    IsoError,
> {
    let mut buf = [0u8; 2048];
    let mut pvd: Option<PrimaryVolumeDescriptor> = None;
    let mut svd: Option<SupplementaryVolumeDescriptor> = None;
    let mut boot_cat: Option<u32> = None;
    let mut has_rr = false;

    let mut lba = first_pvd_lba;
    loop {
        read_sector_data(reader, mode, lba, &mut buf)?;
        match buf[0] {
            PVD_TYPE => {
                let p = PrimaryVolumeDescriptor::parse(&buf)?;
                // Check the root dir's System Use for the Rock Ridge SP entry.
                if !has_rr {
                    has_rr = check_rock_ridge(reader, mode, p.root_dir_lba)?;
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
        .map(|p| (p, svd, boot_cat, has_rr))
}

/// Check the root directory's first (dot) record for a Rock Ridge SP entry.
fn check_rock_ridge<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    root_dir_lba: u32,
) -> Result<bool, IsoError> {
    let mut buf = [0u8; 2048];
    read_sector_data(reader, mode, root_dir_lba as u64, &mut buf)?;
    let offset = 0usize;
    if buf[offset] == 0 {
        return Ok(false);
    }
    let len = buf[offset] as usize;
    if len < 34 {
        return Ok(false);
    }
    let name_len = buf[offset + 32] as usize;
    let su_start = 33 + name_len + (if name_len % 2 == 0 { 1 } else { 0 });
    if su_start >= len {
        return Ok(false);
    }
    Ok(has_sp_entry(&buf[offset + su_start..offset + len]))
}
