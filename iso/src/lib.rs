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

use std::io::{Read, Seek, SeekFrom};

use dir::{DirRecord, parse_dir_records};
use el_torito::{BootEntry, boot_catalog_lba, parse_boot_catalog};
use pvd::{
    BOOT_RECORD_TYPE, PVD_TYPE, SVD_TYPE, TERMINATOR_TYPE, PrimaryVolumeDescriptor,
    SupplementaryVolumeDescriptor,
};
use rock_ridge::has_sp_entry;
use sector::{SectorMode, read_sector_data};
use udf::detect_udf;

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
        let active_pvd_lba = session_pvd_lbas
            .last()
            .copied()
            .ok_or(IsoError::NotAnIso)?;

        // Read and parse all volume descriptors starting at the active session.
        let (pvd, svd, boot_cat_lba, has_rock_ridge) =
            read_volume_descriptors(&mut reader, mode, active_pvd_lba)?;

        let has_udf = detect_udf(&mut reader);

        Ok(Self {
            inner: reader,
            mode,
            pvd,
            svd,
            boot_catalog_lba: boot_cat_lba,
            session_pvd_lbas,
            has_udf,
            has_rock_ridge,
        })
    }

    /// Volume label from the Primary Volume Descriptor (trimmed).
    pub fn volume_label(&self) -> &str {
        &self.pvd.volume_label
    }

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
        let sectors = (size as usize + sector_size - 1) / sector_size;
        for i in 0..sectors {
            let offset = i * sector_size;
            let end = (offset + sector_size).min(size as usize);
            let mut sector_buf = [0u8; 2048];
            read_sector_data(&mut self.inner, self.mode, lba as u64 + i as u64, &mut sector_buf)?;
            data[offset..end].copy_from_slice(&sector_buf[..end - offset]);
        }
        parse_dir_records(&data)
    }

    /// Read the full contents of a file entry.
    pub fn read_file_entry(&mut self, entry: &DirRecord) -> Result<Vec<u8>, IsoError> {
        if entry.is_dir() {
            return Err(IsoError::NotFound("entry is a directory".into()));
        }
        let mut data = vec![0u8; entry.size as usize];
        let sector_size = 2048usize;
        let sectors = (entry.size as usize + sector_size - 1) / sector_size;
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
                    let rr = rock_ridge::alternate_name(&e.system_use)
                        .map(|n| n.to_ascii_uppercase());
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
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Scan for all PVD LBAs by reading every sector starting from 16.
fn scan_sessions<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
) -> Result<Vec<u64>, IsoError> {
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
) -> Result<(PrimaryVolumeDescriptor, Option<SupplementaryVolumeDescriptor>, Option<u32>, bool), IsoError>
{
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
