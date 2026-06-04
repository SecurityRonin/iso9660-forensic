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

/// Located catalog B-tree geometry within an HFS+ volume.
struct CatalogLoc {
    cat_base: usize,
    node_size: usize,
    first_leaf: u32,
    block_size: usize,
}

/// Locate the catalog B-tree from the volume header (its first extent).
fn locate_catalog(volume: &[u8]) -> Option<CatalogLoc> {
    let h = VOLUME_HEADER_OFFSET;
    if volume.len() < h + 352 {
        return None;
    }
    match be16(&volume[h..h + 2]) {
        SIG_HFS_PLUS | SIG_HFSX => {}
        _ => return None,
    }
    let block_size = be32(&volume[h + 40..h + 44]) as usize;
    if block_size == 0 {
        return None;
    }
    // catalogFile fork is at header offset 272; its first extent's start at +16.
    let cat_fork = h + 272;
    let start_block = be32(&volume[cat_fork + 16..cat_fork + 20]) as usize;
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
    Some(CatalogLoc { cat_base, node_size, first_leaf, block_size })
}

/// Walk the catalog leaf-node chain, invoking `f` with each record slice.
fn for_each_record(volume: &[u8], loc: &CatalogLoc, mut f: impl FnMut(&[u8])) {
    let mut node = loc.first_leaf;
    let mut walked = 0u32;
    while node != 0 && walked < MAX_LEAF_NODES {
        walked += 1;
        let Some(node_off) =
            (node as usize).checked_mul(loc.node_size).and_then(|x| x.checked_add(loc.cat_base))
        else {
            break;
        };
        if volume.len() < node_off + loc.node_size {
            break;
        }
        let nd = &volume[node_off..node_off + loc.node_size];
        let f_link = be32(&nd[0..4]);
        let num_records = be16(&nd[10..12]) as usize;
        for i in 0..num_records {
            // Record offsets are stored backwards from the node end.
            let Some(slot) = loc.node_size.checked_sub(2 * (i + 1)) else { break };
            let rec = be16(&nd[slot..slot + 2]) as usize;
            if rec + 8 <= loc.node_size {
                f(&nd[rec..]);
            }
        }
        node = f_link;
    }
}

/// List the root directory of an HFS+ volume.  See [`list_dir`].
#[must_use]
pub fn list_root(volume: &[u8]) -> Option<Vec<HfsEntry>> {
    list_dir(volume, ROOT_FOLDER_CNID)
}

/// List the immediate children of the folder `parent_cnid` by walking the HFS+
/// catalog B-tree.
///
/// `volume` must contain the whole HFS+ volume from its first byte (header at
/// offset 1024).  Entries include HFS+ private metadata directories (real, not
/// hidden); thread records are skipped.  Returns `None` if this is not an HFS+
/// volume or the catalog cannot be located.  Assumes the catalog fits in its
/// first extent (true for typical optical/hybrid volumes).
#[must_use]
pub fn list_dir(volume: &[u8], parent_cnid: u32) -> Option<Vec<HfsEntry>> {
    let loc = locate_catalog(volume)?;
    let mut entries = Vec::new();
    for_each_record(volume, &loc, |rec| {
        if let Some((parent, entry)) = record_entry(rec) {
            if parent == parent_cnid {
                entries.push(entry);
            }
        }
    });
    Some(entries)
}

/// Read a file's data-fork contents by catalog node ID.
///
/// Returns the file's bytes (concatenated from its data-fork extents, truncated
/// to the logical size), or `None` if `cnid` is not a file in this volume.
#[must_use]
pub fn read_file(volume: &[u8], cnid: u32) -> Option<Vec<u8>> {
    let loc = locate_catalog(volume)?;
    let mut found: Option<(u64, Vec<(u32, u32)>)> = None;
    for_each_record(volume, &loc, |rec| {
        if found.is_none() {
            found = file_data_fork(rec, cnid);
        }
    });
    let (logical, extents) = found?;
    let logical = logical as usize;
    let mut data = Vec::with_capacity(logical.min(1 << 20));
    for (start, count) in extents {
        if data.len() >= logical {
            break;
        }
        let begin = (start as usize).checked_mul(loc.block_size)?;
        let len = (count as usize).checked_mul(loc.block_size)?;
        let end = begin.checked_add(len)?.min(volume.len());
        if begin >= volume.len() {
            break;
        }
        data.extend_from_slice(&volume[begin..end]);
    }
    data.truncate(logical);
    Some(data)
}

/// Parse a catalog record into `(parentID, entry)` for file/folder records.
fn record_entry(rec: &[u8]) -> Option<(u32, HfsEntry)> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let parent_id = be32(&rec[2..6]);
    let name_len = be16(&rec[6..8]) as usize;
    let name_end = 8 + name_len * 2;
    if name_end > rec.len() {
        return None;
    }
    let name = decode_utf16(&rec[8..name_end]);
    let data = 2 + key_len;
    if data + 12 > rec.len() {
        return None;
    }
    let is_dir = match i16::from_be_bytes([rec[data], rec[data + 1]]) {
        RECORD_FOLDER => true,
        RECORD_FILE => false,
        _ => return None, // thread records and anything else
    };
    // folderID / fileID at offset 8 of the folder/file record.
    let cnid = be32(&rec[data + 8..data + 12]);
    Some((parent_id, HfsEntry { name, is_dir, cnid }))
}

/// If `rec` is the file record for `cnid`, return its data fork as
/// `(logical_size, extents)`.
fn file_data_fork(rec: &[u8], cnid: u32) -> Option<(u64, Vec<(u32, u32)>)> {
    if rec.len() < 8 {
        return None;
    }
    let key_len = be16(&rec[0..2]) as usize;
    let data = 2 + key_len;
    // File record + data fork (HFSPlusForkData at +88, 80 bytes).
    if data + 168 > rec.len() {
        return None;
    }
    if i16::from_be_bytes([rec[data], rec[data + 1]]) != RECORD_FILE {
        return None;
    }
    if be32(&rec[data + 8..data + 12]) != cnid {
        return None;
    }
    let fork = data + 88;
    let logical = u64::from_be_bytes(rec[fork..fork + 8].try_into().ok()?);
    let mut extents = Vec::new();
    for i in 0..8 {
        let e = fork + 16 + i * 8;
        let start = be32(&rec[e..e + 4]);
        let count = be32(&rec[e + 4..e + 8]);
        if count != 0 {
            extents.push((start, count));
        }
    }
    Some((logical, extents))
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
