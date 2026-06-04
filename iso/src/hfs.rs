//! HFS+ / HFSX volume-header detection (Apple TN1150).
//!
//! Apple optical discs are frequently *hybrids*: an ISO 9660 filesystem and an
//! HFS/HFS+ volume sharing the same disc, so a Mac and a PC each see their own
//! filesystem.  The HFS+ volume header sits at a fixed 1024-byte offset from the
//! volume start (TN1150 §"Volume Header"), with a big-endian `H+` (HFS+) or `HX`
//! (HFSX) signature.
//!
//! This module reads the volume header for *detection and volume geometry*
//! (signature, version, allocation block size, block counts).  Full HFS+
//! catalog (B-tree) traversal — listing files — is not implemented.  Validated
//! against a real `hdiutil`-created HFS+ volume header.

/// Byte offset of the HFS+ volume header from the start of the volume.
const VOLUME_HEADER_OFFSET: usize = 1024;
/// HFS+ signature `H+` (TN1150).
const SIG_HFS_PLUS: u16 = 0x482B;
/// HFSX signature `HX` (case-sensitive variant).
const SIG_HFSX: u16 = 0x4858;

/// Which Apple volume signature was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HfsKind {
    /// `H+` — standard HFS Plus.
    HfsPlus,
    /// `HX` — case-sensitive HFSX.
    Hfsx,
}

/// Parsed HFS+ volume header fields (geometry only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HfsVolume {
    pub kind: HfsKind,
    /// Volume format version (4 for HFS+, 5 for HFSX).
    pub version: u16,
    /// Number of files in the volume's catalog.
    pub file_count: u32,
    /// Number of folders in the volume's catalog.
    pub folder_count: u32,
    /// Allocation block size in bytes.
    pub block_size: u32,
    /// Total allocation blocks in the volume.
    pub total_blocks: u32,
    /// Free allocation blocks.
    pub free_blocks: u32,
}

impl HfsVolume {
    /// Total volume size in bytes (`block_size * total_blocks`).
    #[must_use]
    pub fn volume_size(&self) -> u64 {
        u64::from(self.block_size) * u64::from(self.total_blocks)
    }
}

/// Parse the HFS+/HFSX volume header from a buffer that begins at the volume
/// start (the header is read at offset 1024).  Returns `None` if the buffer is
/// too short or carries no HFS+ signature.
#[must_use]
pub fn parse(volume: &[u8]) -> Option<HfsVolume> {
    let h = VOLUME_HEADER_OFFSET;
    if volume.len() < h + 52 {
        return None;
    }
    let hdr = &volume[h..];
    let kind = match be16(&hdr[0..2]) {
        SIG_HFS_PLUS => HfsKind::HfsPlus,
        SIG_HFSX => HfsKind::Hfsx,
        _ => return None,
    };
    Some(HfsVolume {
        kind,
        version: be16(&hdr[2..4]),
        file_count: be32(&hdr[32..36]),
        folder_count: be32(&hdr[36..40]),
        block_size: be32(&hdr[40..44]),
        total_blocks: be32(&hdr[44..48]),
        free_blocks: be32(&hdr[48..52]),
    })
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
