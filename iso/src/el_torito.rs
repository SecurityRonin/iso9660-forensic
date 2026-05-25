//! El Torito boot specification — CD bootable images.
//!
//! The Boot Record Volume Descriptor at type 0x00 contains a pointer to the
//! Boot Catalog sector. The catalog contains a Validation Entry (32 bytes)
//! followed by one or more boot entries (32 bytes each).

/// A single El Torito boot entry.
#[derive(Debug, Clone)]
pub struct BootEntry {
    pub bootable: bool,
    /// Media type: 0=no-emulation, 1=1.2M floppy, 2=1.44M floppy, 3=2.88M floppy, 4=HDD.
    pub media_type: u8,
    /// LBA of the boot image data.
    pub lba: u32,
    /// Number of 512-byte virtual sectors to load.
    pub sector_count: u16,
}

/// Parse the El Torito boot catalog from its raw sector bytes.
///
/// Returns the list of boot entries (skipping the validation header).
pub fn parse_boot_catalog(catalog: &[u8]) -> Vec<BootEntry> {
    let mut entries = Vec::new();
    // First 32 bytes: Validation Entry (signature 0x01, creator-id, checksum, 0x55, 0xAA)
    if catalog.len() < 64 {
        return entries;
    }
    // Validate the catalog header: byte 0 must be 0x01 (header ID), bytes 30-31 must be 55 AA
    if catalog[0] != 0x01 || catalog[30] != 0x55 || catalog[31] != 0xAA {
        return entries;
    }

    // Initial/default boot entry at offset 32.
    let mut offset = 32;
    while offset + 32 <= catalog.len() {
        let e = &catalog[offset..offset + 32];
        let boot_indicator = e[0];
        if boot_indicator != 0x88 && boot_indicator != 0x00 {
            // Section header or extension — stop for now.
            break;
        }
        entries.push(BootEntry {
            bootable: boot_indicator == 0x88,
            media_type: e[1] & 0x0F,
            lba: u32::from_le_bytes(e[8..12].try_into().unwrap()),
            sector_count: u16::from_le_bytes(e[6..8].try_into().unwrap()),
        });
        offset += 32;
    }
    entries
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
    Some(u32::from_le_bytes(sector[71..75].try_into().unwrap()))
}
