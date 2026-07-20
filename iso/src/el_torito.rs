//! El Torito boot specification — CD bootable images.
//!
//! The Boot Record Volume Descriptor at type 0x00 contains a pointer to the
//! Boot Catalog sector. The catalog contains a Validation Entry (32 bytes)
//! followed by one or more boot entries (32 bytes each).
//!
//! Spec: El Torito Bootable CD-ROM Format Specification v1.0 §2.3.

/// Boot platform identifier (El Torito §2.2, Validation Entry byte 1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BootPlatform {
    /// 80x86 / x86_64.
    X86,
    /// PowerPC.
    PowerPC,
    /// Apple Macintosh.
    Mac,
    /// UEFI (EFI System Partition boot).
    EFI,
    /// Any other platform ID byte.
    Other(u8),
}

impl BootPlatform {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x00 => Self::X86,
            0x01 => Self::PowerPC,
            0x02 => Self::Mac,
            0xEF => Self::EFI,
            v => Self::Other(v),
        }
    }
}

/// A single El Torito boot entry, including the platform context inferred from
/// the Validation Entry (for the default entry) or Section Header (for section
/// entries).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BootEntry {
    pub bootable: bool,
    /// Media type: 0=no-emulation, 1=1.2M floppy, 2=1.44M floppy, 3=2.88M floppy, 4=HDD.
    pub media_type: u8,
    /// LBA of the boot image data.
    pub lba: u32,
    /// Number of 512-byte virtual sectors to load.
    pub sector_count: u16,
    /// Platform this entry targets, inherited from the Validation Entry or Section Header.
    pub platform: BootPlatform,
}

/// Parse the El Torito boot catalog from its raw sector bytes.
///
/// Handles the default (initial) entry plus multi-section catalogs
/// (Section Header IDs 0x90 = more sections follow, 0x91 = last section).
pub fn parse_boot_catalog(catalog: &[u8]) -> Vec<BootEntry> {
    let mut entries = Vec::new();
    if catalog.len() < 64 {
        return entries;
    }
    // Validation Entry: byte 0 = 0x01, bytes 30–31 = 0x55 0xAA.
    if catalog[0] != 0x01 || catalog[30] != 0x55 || catalog[31] != 0xAA {
        return entries;
    }
    // Platform for the default (initial) entry comes from the Validation Entry byte 1.
    let default_platform = BootPlatform::from_byte(catalog[1]);

    let mut offset = 32;

    // Default/initial boot entry.
    if offset + 32 > catalog.len() {
        return entries;
    }
    {
        let e = &catalog[offset..offset + 32];
        let boot_indicator = e[0];
        if boot_indicator == 0x88 || boot_indicator == 0x00 {
            entries.push(BootEntry {
                bootable: boot_indicator == 0x88,
                media_type: e[1] & 0x0F,
                lba: safe_read::le_u32(e, 8),
                sector_count: safe_read::le_u16(e, 6),
                platform: default_platform,
            });
        }
    }
    offset += 32;

    // Section headers and their entries.
    while offset + 32 <= catalog.len() {
        let h = &catalog[offset..offset + 32];
        let header_id = h[0];
        if header_id != 0x90 && header_id != 0x91 {
            break;
        }
        let section_platform = BootPlatform::from_byte(h[1]);
        let count = safe_read::le_u16(h, 2) as usize;
        offset += 32;

        for _ in 0..count {
            if offset + 32 > catalog.len() {
                break;
            }
            let e = &catalog[offset..offset + 32];
            let boot_indicator = e[0];
            entries.push(BootEntry {
                bootable: boot_indicator == 0x88,
                media_type: e[1] & 0x0F,
                lba: safe_read::le_u32(e, 8),
                sector_count: safe_read::le_u16(e, 6),
                platform: section_platform.clone(),
            });
            offset += 32;
        }

        if header_id == 0x91 {
            break;
        }
    }

    entries
}

/// Boot Information Table — optional structure embedded at offset 8 of the
/// boot image sector (El Torito spec §4.1 / ISOLINUX boot info table).
///
/// Written by `mkisofs -b` when `--boot-info-table` is requested.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BootInfoTable {
    /// LBA of the Primary Volume Descriptor.
    pub pvd_lba: u32,
    /// LBA of the boot file itself.
    pub boot_file_lba: u32,
    /// Length of the boot file in bytes.
    pub boot_file_len: u32,
    /// 32-bit checksum of the boot file (all-zero bytes treated as unset).
    pub checksum: u32,
}

impl BootInfoTable {
    /// Parse a Boot Information Table from a boot image sector.
    ///
    /// Returns `None` if all four fields are zero (structure not present or unset).
    pub fn parse(sector: &[u8]) -> Option<Self> {
        if sector.len() < 24 {
            return None;
        }
        let le32 = |i: usize| safe_read::le_u32(sector, i);
        let pvd_lba = le32(8);
        let boot_file_lba = le32(12);
        let boot_file_len = le32(16);
        let checksum = le32(20);
        if pvd_lba == 0 && boot_file_lba == 0 && boot_file_len == 0 && checksum == 0 {
            return None;
        }
        Some(Self { pvd_lba, boot_file_lba, boot_file_len, checksum })
    }
}

/// Extract the Boot Catalog LBA from a Boot Record Volume Descriptor sector.
///
/// The BRVD has type 0x00, signature "CD001", version 0x01, and the catalog
/// LBA at bytes 71-74 (little-endian u32).
pub fn boot_catalog_lba(sector: &[u8]) -> Option<u32> {
    if sector.len() < 75 {
        return None;
    }
    if sector[0] != 0x00 || &sector[1..6] != b"CD001" || sector[6] != 0x01 {
        return None;
    }
    // Boot system identifier: "EL TORITO SPECIFICATION" at offset 7.
    if !sector[7..39].starts_with(b"EL TORITO SPECIFICATION") {
        return None;
    }
    Some(safe_read::le_u32(sector, 71))
}
