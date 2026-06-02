//! Forensic audit types for ISO 9660 structural integrity checks.

/// A discrepancy between the LE and BE copies of a both-endian field.
///
/// ECMA-119 stores every multi-byte integer in both little-endian and
/// big-endian form consecutively.  When LE ≠ BE the field has been manually
/// edited — no standards-compliant mastering tool produces mismatches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BothEndianMismatch {
    /// Short description of where the field lives (e.g. "PVD", "dir:lba=18").
    pub context: String,
    /// ECMA-119 field name (e.g. "volume_space_size", "entry_lba").
    pub field: String,
    /// Absolute file byte offset of the LE copy of the field.
    pub byte_offset: u64,
    /// Little-endian value.
    pub le_val: u64,
    /// Big-endian value.
    pub be_val: u64,
}

/// A file-magic hit found in the pre-system area (sectors 0–15).
///
/// These sectors precede the PVD and are often used for bootloaders or,
/// in malicious ISOs, to embed hidden executables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreSysHit {
    /// Sector number (0–15).
    pub sector: u8,
    /// Human-readable magic type: "non-zero", "MZ/PE", "ELF", "ZIP", "PDF", "7z".
    pub kind: &'static str,
}

/// A potentially dangerous Rock Ridge symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymlinkIssue {
    /// Full path of the directory entry that contains the symlink.
    pub entry_path: String,
    /// Resolved symlink target string.
    pub target: String,
    /// Issue category: "path-traversal" or "absolute".
    pub issue: &'static str,
}

/// Sector slack-space analysis result for one file.
///
/// A file occupies `ceil(size/2048)` sectors.  The bytes after `size` in
/// the last sector are slack — they may contain residual data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackHit {
    pub entry_path: String,
    pub lba: u32,
    pub file_size: u32,
    /// Number of slack bytes in the last sector (0 when size is sector-aligned).
    pub slack_bytes: u32,
    /// `true` if any slack byte is non-zero.
    pub nonzero: bool,
}

/// An unallocated sector that may contain hidden content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapHit {
    pub lba: u32,
    /// `true` if any byte in this sector is non-zero.
    pub nonzero: bool,
}
