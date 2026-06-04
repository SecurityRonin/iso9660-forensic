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

/// Catalog node ID of the root folder (TN1150).
const ROOT_FOLDER_CNID: u32 = 2;
/// Catalog record types (TN1150): folder / file leaf records.
const RECORD_FOLDER: i16 = 1;
const RECORD_FILE: i16 = 2;
/// Bound on catalog leaf nodes walked, guarding against a corrupt `fLink` chain.
const MAX_LEAF_NODES: u32 = 65536;

/// An entry in an HFS+ directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HfsEntry {
    /// File or folder name (decoded from UTF-16).
    pub name: String,
    /// True for a folder, false for a file.
    pub is_dir: bool,
    /// Catalog node ID (CNID) of this entry.
    pub cnid: u32,
}

/// List the root directory of an HFS+ volume by walking its catalog B-tree.
///
/// `volume` must contain the whole HFS+ volume starting at its first byte (the
/// volume header is at offset 1024).  Returns the root folder's file and folder
/// entries — including HFS+ private metadata directories, which are real and
/// surfaced rather than hidden — or `None` if this is not an HFS+ volume or the
/// catalog cannot be located.  Assumes the catalog fits in its first extent
/// (true for typical optical/hybrid volumes); thread records are skipped.
#[must_use]
pub fn list_root(volume: &[u8]) -> Option<Vec<HfsEntry>> {
    let h = VOLUME_HEADER_OFFSET;
    if volume.len() < h + 352 {
        return None;
    }
    match be16(&volume[h..h + 2]) {
        SIG_HFS_PLUS | SIG_HFSX => {}
        _ => return None,
    }
    let block_size = be32(&volume[h + 40..h + 44]) as usize;
    // catalogFile fork is at header offset 272; its first extent at +16.
    let cat_fork = h + 272;
    let start_block = be32(&volume[cat_fork + 16..cat_fork + 20]) as usize;
    if block_size == 0 {
        return None;
    }
    let cat_base = start_block.checked_mul(block_size)?;

    // B-tree header record follows the 14-byte node descriptor of node 0.
    let hdr = cat_base.checked_add(14)?;
    if volume.len() < hdr + 20 {
        return None;
    }
    let first_leaf = be32(&volume[hdr + 10..hdr + 14]);
    let node_size = be16(&volume[hdr + 18..hdr + 20]) as usize;
    if node_size < 14 {
        return None;
    }

    let mut entries = Vec::new();
    let mut node = first_leaf;
    let mut walked = 0u32;
    while node != 0 && walked < MAX_LEAF_NODES {
        walked += 1;
        let node_off = (node as usize).checked_mul(node_size)?.checked_add(cat_base)?;
        if volume.len() < node_off + node_size {
            break;
        }
        let nd = &volume[node_off..node_off + node_size];
        let f_link = be32(&nd[0..4]);
        let num_records = be16(&nd[10..12]) as usize;
        for i in 0..num_records {
            // Record offsets are stored backwards from the node end.
            let slot = node_size.checked_sub(2 * (i + 1))?;
            let rec = be16(&nd[slot..slot + 2]) as usize;
            if rec + 8 > node_size {
                continue;
            }
            if let Some(entry) = parse_catalog_record(&nd[rec..]) {
                entries.push(entry);
            }
        }
        node = f_link;
    }
    Some(entries)
}

/// Parse one catalog leaf record, returning a root-folder file/folder entry.
fn parse_catalog_record(rec: &[u8]) -> Option<HfsEntry> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let parent_id = be32(&rec[2..6]);
    if parent_id != ROOT_FOLDER_CNID {
        return None;
    }
    let name_len = be16(&rec[6..8]) as usize;
    let name_end = 8 + name_len * 2;
    if name_end > rec.len() {
        return None;
    }
    let name = decode_utf16(&rec[8..name_end]);

    // Catalog data follows the key (keyLength field excludes itself).
    let data = 2 + key_len;
    if data + 12 > rec.len() {
        return None;
    }
    let record_type = i16::from_be_bytes([rec[data], rec[data + 1]]);
    let is_dir = match record_type {
        RECORD_FOLDER => true,
        RECORD_FILE => false,
        _ => return None, // thread records and anything else
    };
    // CNID: folderID/fileID at offset 8 of the folder/file record.
    let cnid = be32(&rec[data + 8..data + 12]);
    Some(HfsEntry { name, is_dir, cnid })
}

/// Decode a big-endian UTF-16 byte slice to a `String` (lossy).
fn decode_utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
