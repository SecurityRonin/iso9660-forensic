// El Torito advanced — multi-section, BootPlatform, BootInfoTable.
// Spec: El Torito Bootable CD-ROM Format Specification v1.0 §2.3.
// Refs: hadris-iso el_torito.rs + iso9660-rs (Poprdi) boot.rs.

use iso9660_forensic::el_torito::{
    parse_boot_catalog, BootInfoTable, BootPlatform,
};

// ── BootPlatform ──────────────────────────────────────────────────────────────

#[test]
fn boot_platform_x86() {
    assert_eq!(BootPlatform::from_byte(0x00), BootPlatform::X86);
}

#[test]
fn boot_platform_powerpc() {
    assert_eq!(BootPlatform::from_byte(0x01), BootPlatform::PowerPC);
}

#[test]
fn boot_platform_mac() {
    assert_eq!(BootPlatform::from_byte(0x02), BootPlatform::Mac);
}

#[test]
fn boot_platform_efi() {
    assert_eq!(BootPlatform::from_byte(0xEF), BootPlatform::EFI);
}

#[test]
fn boot_platform_other() {
    assert_eq!(BootPlatform::from_byte(0x42), BootPlatform::Other(0x42));
}

// ── Multi-section catalog parsing ────────────────────────────────────────────

/// Build a minimal validation entry (32 bytes) for use in catalog tests.
fn validation_entry() -> [u8; 32] {
    let mut v = [0u8; 32];
    v[0] = 0x01;     // header_id
    v[30] = 0x55;    // boot record signature
    v[31] = 0xAA;
    v
}

/// Build a boot entry (32 bytes).
fn boot_entry(bootable: bool, platform_id: u8, lba: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = if bootable { 0x88 } else { 0x00 };
    e[1] = 0x00; // no-emulation
    e[8..12].copy_from_slice(&lba.to_le_bytes());
    e[6..8].copy_from_slice(&1u16.to_le_bytes()); // sector_count
    // store platform_id in criteria field (byte 28) for section entries
    e[28] = platform_id;
    e
}

/// Build a section header entry (32 bytes).
/// header_id: 0x90 = more sections, 0x91 = last section.
fn section_header(header_id: u8, platform_id: u8, count: u16) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[0] = header_id;
    h[1] = platform_id;
    h[2..4].copy_from_slice(&count.to_le_bytes());
    h
}

#[test]
fn parse_default_entry_has_x86_platform() {
    let mut catalog = vec![0u8; 2048];
    catalog[..32].copy_from_slice(&validation_entry());
    let entry_bytes = boot_entry(true, 0x00, 42);
    catalog[32..64].copy_from_slice(&entry_bytes);

    let entries = parse_boot_catalog(&catalog);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].platform, BootPlatform::X86);
    assert_eq!(entries[0].lba, 42);
    assert!(entries[0].bootable);
}

#[test]
fn parse_multi_section_two_entries() {
    let mut catalog = vec![0u8; 2048];
    catalog[..32].copy_from_slice(&validation_entry());

    // Default entry (x86)
    let e1 = boot_entry(true, 0x00, 100);
    catalog[32..64].copy_from_slice(&e1);

    // Section header: one more section, EFI
    let sh = section_header(0x91, 0xEF, 1);
    catalog[64..96].copy_from_slice(&sh);

    // EFI boot entry
    let e2 = boot_entry(true, 0xEF, 200);
    catalog[96..128].copy_from_slice(&e2);

    let entries = parse_boot_catalog(&catalog);
    assert_eq!(entries.len(), 2, "should find 2 entries (x86 + EFI)");
    assert_eq!(entries[0].lba, 100);
    assert_eq!(entries[1].lba, 200);
    assert_eq!(entries[1].platform, BootPlatform::EFI);
}

#[test]
fn parse_two_sections_0x90_then_0x91() {
    let mut catalog = vec![0u8; 2048];
    catalog[..32].copy_from_slice(&validation_entry());
    let e1 = boot_entry(true, 0x00, 10);
    catalog[32..64].copy_from_slice(&e1);

    // Section header: more sections follow (0x90), platform PowerPC, 1 entry
    let sh1 = section_header(0x90, 0x01, 1);
    catalog[64..96].copy_from_slice(&sh1);
    let e2 = boot_entry(true, 0x01, 20);
    catalog[96..128].copy_from_slice(&e2);

    // Last section header (0x91), EFI, 1 entry
    let sh2 = section_header(0x91, 0xEF, 1);
    catalog[128..160].copy_from_slice(&sh2);
    let e3 = boot_entry(true, 0xEF, 30);
    catalog[160..192].copy_from_slice(&e3);

    let entries = parse_boot_catalog(&catalog);
    assert_eq!(entries.len(), 3, "should parse all 3 entries");
    assert_eq!(entries[1].platform, BootPlatform::PowerPC);
    assert_eq!(entries[2].platform, BootPlatform::EFI);
}

// ── BootInfoTable ─────────────────────────────────────────────────────────────

fn make_bit_sector(pvd_lba: u32, boot_lba: u32, boot_len: u32, checksum: u32) -> Vec<u8> {
    let mut sector = vec![0u8; 2048];
    // BIT lives at offset 8 of the boot image sector (El Torito spec §4.1).
    sector[8..12].copy_from_slice(&pvd_lba.to_le_bytes());
    sector[12..16].copy_from_slice(&boot_lba.to_le_bytes());
    sector[16..20].copy_from_slice(&boot_len.to_le_bytes());
    sector[20..24].copy_from_slice(&checksum.to_le_bytes());
    sector
}

#[test]
fn boot_info_table_parse_known() {
    let sector = make_bit_sector(16, 42, 8192, 0xDEADBEEF);
    let bit = BootInfoTable::parse(&sector).expect("must parse BIT");
    assert_eq!(bit.pvd_lba,       16);
    assert_eq!(bit.boot_file_lba, 42);
    assert_eq!(bit.boot_file_len, 8192);
    assert_eq!(bit.checksum,      0xDEAD_BEEF);
}

#[test]
fn boot_info_table_all_zeros_returns_none() {
    let sector = vec![0u8; 2048];
    assert!(BootInfoTable::parse(&sector).is_none());
}

#[test]
fn boot_info_table_struct_fields() {
    let bit = BootInfoTable { pvd_lba: 1, boot_file_lba: 2, boot_file_len: 3, checksum: 4 };
    assert_eq!(bit.pvd_lba, 1);
    assert_eq!(bit.boot_file_lba, 2);
}
