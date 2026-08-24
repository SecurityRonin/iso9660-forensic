//! ISO 9660 forensic analyzer, and the reader it grades over.
//!
//! This crate is the redundancy-and-slack auditor: it diffs the copies ISO 9660
//! keeps of everything (both-endian fields, L/M path tables, primary vs Joliet
//! trees, per-session descriptors) and carves bytes no file claims, over the
//! parsed model produced by the [`iso9660_core`] reader.
//!
//! # Reader access is re-exported unchanged
//!
//! The reader now lives in the standalone [`iso9660_core`], which carries no
//! `forensicnomicon::report` usage so a consumer that only reads an ISO 9660
//! volume (a mount adapter, an archiver) can depend on it alone. For source
//! compatibility this crate **re-exports the entire reader surface**, so
//! existing `iso9660_forensic::{IsoReader, open, walk}` paths keep resolving.
//! The audit operations that were methods on `IsoReader` are now **free
//! functions** here (matching `udf-forensic` / `hfsplus-forensic`): call
//! `iso9660_forensic::audit_both_endian(&mut reader)` rather than
//! `reader.audit_both_endian()`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::io::{Read, Seek};

// `IsoReader`, `IsoError`, `path_table`, etc. are reachable through the reader
// re-export below (`pub use iso9660_core::*`).

pub mod analysis;
pub mod audit;
pub mod findings;

/// The complete `iso9660-core` reader surface, re-exported so this crate stays a
/// drop-in for consumers that depended on the reader when it lived here.
pub use iso9660_core::*;

pub use analysis::{
    analyse, analyse_with_options, AnalyseOptions, BootRecord, IsoAnalysis, IsoVolumeInfo,
};

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

/// A file found inside an orphaned directory extent — present on the disc but
/// not reachable from the active directory tree (a recovered "lost" file).
#[derive(Debug, Clone)]
pub struct LostFile {
    /// ISO 9660 name of the file.
    pub name: String,
    /// LBA of the file's data extent.
    pub lba: u32,
    /// File size in bytes.
    pub size: u32,
    /// LBA of the orphaned directory extent the file was found in.
    pub parent_lba: u32,
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

// ── Forensic audit operations (free functions over the reader) ──────────────

/// Identify the mastering tool from PVD metadata patterns.
///
/// Inspects `data_preparer_id` and `application_id` for known tool
/// signatures (xorriso, mkisofs, genisoimage, `ImgBurn`, hdiutil, etc.).
pub fn fingerprint_tool<R: Read + Seek>(reader: &IsoReader<R>) -> ToolFingerprint {
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
    let haystack = format!("{} {}", reader.data_preparer_id(), reader.application_id());
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
pub fn audit_path_table<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<PathTableAudit, IsoError> {
    use path_table::parse_l_path_table;
    use std::collections::HashSet;

    // Read the L-path table (may span several sectors for large images).
    let pt_data = reader.read_path_table_bytes(reader.pvd().l_path_table_lba)?;
    let pt_entries = parse_l_path_table(&pt_data).unwrap_or_default();
    let path_table_lbas: Vec<u32> = pt_entries.iter().map(|e| e.lba).collect();
    let pt_set: HashSet<u32> = path_table_lbas.iter().copied().collect();

    // Collect directory LBAs from the tree (always include the root).
    let tree_entries = reader.walk()?;
    let mut tree_set: HashSet<u32> =
        tree_entries.iter().filter(|e| e.record.is_dir()).map(|e| e.record.lba).collect();
    tree_set.insert(reader.pvd().root_dir_lba);

    let mut tree_lbas: Vec<u32> = tree_set.iter().copied().collect();
    tree_lbas.sort_unstable();

    let mut phantom_lbas: Vec<u32> = pt_set.difference(&tree_set).copied().collect();
    let mut ghost_lbas: Vec<u32> = tree_set.difference(&pt_set).copied().collect();
    phantom_lbas.sort_unstable();
    ghost_lbas.sort_unstable();

    Ok(PathTableAudit { path_table_lbas, tree_lbas, phantom_lbas, ghost_lbas })
}

/// Cross-validate the Type-L (little-endian) and Type-M (big-endian) path
/// tables.
///
/// ECMA-119 stores the path table twice in opposite byte orders; the two
/// copies must describe an identical directory hierarchy. Returns any
/// content discrepancy (entry count, extent LBA, parent, or name) between
/// them — a disagreement is consistent with editing one copy (an OS-specific
/// view, since tools differ on which table they trust) or corruption.
///
/// Returns empty when either table pointer is zero (the table is absent);
/// a missing mandatory path table is a separate structural concern, not an
/// L↔M content divergence.
pub fn audit_path_table_endian<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<path_table::PathTableMismatch>, IsoError> {
    use path_table::{parse_l_path_table, parse_m_path_table, validate_path_tables};

    let l_lba = reader.pvd().l_path_table_lba;
    let m_lba = reader.pvd().m_path_table_lba;
    if l_lba == 0 || m_lba == 0 {
        return Ok(Vec::new());
    }
    let l_bytes = reader.read_path_table_bytes(l_lba)?;
    let m_bytes = reader.read_path_table_bytes(m_lba)?;
    let l = parse_l_path_table(&l_bytes).unwrap_or_default();
    let m = parse_m_path_table(&m_bytes).unwrap_or_default();
    Ok(validate_path_tables(&l, &m))
}

/// Recover files from orphaned directory extents — directories the path
/// table references but the active directory tree cannot reach (e.g.
/// unlinked or superseded folders).  `IsoBuster`'s "find missing files and
/// folders" for ISO 9660.
///
/// Reads each phantom directory extent (sized from its own `.` record) and
/// returns the files within it.  Nested phantom subdirectories are reported
/// by the path-table audit in their own right.
pub fn recover_lost_files<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<LostFile>, IsoError> {
    let phantom = audit_path_table(reader)?.phantom_lbas;
    let mut lost = Vec::new();
    for dir_lba in phantom {
        // The directory's own `.` record carries its extent size.
        let probe = reader.read_dir(dir_lba, 2048)?;
        let dir_size = probe.first().map_or(2048, |r| r.size.max(2048));
        let records = if dir_size > 2048 { reader.read_dir(dir_lba, dir_size)? } else { probe };
        for r in records {
            if !r.is_dir() {
                lost.push(LostFile {
                    name: r.iso_name(),
                    lba: r.lba,
                    size: r.size,
                    parent_lba: dir_lba,
                });
            }
        }
    }
    Ok(lost)
}

pub fn audit_both_endian<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<audit::BothEndianMismatch>, IsoError> {
    use audit::BothEndianMismatch;
    let mut out: Vec<BothEndianMismatch> = Vec::new();

    // ── PVD (sector 16) ──
    let pvd_raw = reader.read_sector_raw(16)?;
    let pvd_off = reader.sector_mode().user_data_pos(16);

    macro_rules! chk32 {
        ($off:expr, $name:expr) => {{
            let le = u64::from(safe_read::le_u32(&pvd_raw, $off));
            let be = u64::from(safe_read::be_u32(&pvd_raw, $off + 4));
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
            let le = u64::from(safe_read::le_u16(&pvd_raw, $off));
            let be = u64::from(safe_read::be_u16(&pvd_raw, $off + 2));
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
    let entries = reader.walk()?;
    let mut seen = std::collections::HashSet::new();
    // Always include root dir lba
    seen.insert(reader.pvd().root_dir_lba);
    for e in &entries {
        if e.record.is_dir() {
            seen.insert(e.record.lba);
        }
    }
    for dir_lba in seen {
        // A directory whose extent lies past the image (truncation /
        // corruption) has no readable records to reconcile; skip it. The
        // out-of-bounds extent is surfaced separately. Real errors propagate.
        let raw = match reader.read_sector_raw(u64::from(dir_lba)) {
            Ok(raw) => raw,
            Err(IsoError::Io(io)) if io.kind() == std::io::ErrorKind::UnexpectedEof => continue,
            Err(e) => return Err(e),
        };
        let sec_off = reader.sector_mode().user_data_pos(u64::from(dir_lba));
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
            // lba — `rl >= 33` and `pos + rl <= raw.len()` keep pos+18 in range.
            let le = u64::from(safe_read::le_u32(&raw, pos + 2));
            let be = u64::from(safe_read::be_u32(&raw, pos + 6));
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
            let le = u64::from(safe_read::le_u32(&raw, pos + 10));
            let be = u64::from(safe_read::be_u32(&raw, pos + 14));
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

pub fn audit_pre_system<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<audit::PreSysHit>, IsoError> {
    const MAGIC: &[(&[u8], &str)] = &[
        (b"MZ", "MZ/PE"),
        (&[0x7F, b'E', b'L', b'F'], "ELF"),
        (&[b'P', b'K', 0x03, 0x04], "ZIP"),
        (b"%PDF", "PDF"),
        (&[0x37, 0x7A, 0xBC, 0xAF], "7z"),
    ];
    let mut out = Vec::new();
    for sector in 0u8..16 {
        let raw = reader.read_sector_raw(u64::from(sector))?;
        if raw.iter().all(|&b| b == 0) {
            continue;
        }
        let kind =
            MAGIC.iter().find(|(sig, _)| raw.starts_with(sig)).map_or("non-zero", |(_, k)| *k);
        out.push(audit::PreSysHit { sector, kind });
    }
    Ok(out)
}

pub fn audit_symlinks<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<audit::SymlinkIssue>, IsoError> {
    let entries = reader.walk()?;
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

pub fn audit_file_slack<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<audit::SlackHit>, IsoError> {
    let entries = reader.walk()?;
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
        let sectors = u64::from(size).div_ceil(2048);
        let last_lba = u64::from(e.record.lba) + sectors - 1;
        // An extent whose final sector lies past the image (truncation /
        // corruption / dangling reference) has no readable slack to audit;
        // skip it. The out-of-bounds extent itself is surfaced separately
        // (analyse()'s ISO-OOB-EXTENT). Genuine I/O errors still propagate.
        let raw = match reader.read_sector_raw(last_lba) {
            Ok(raw) => raw,
            Err(IsoError::Io(io)) if io.kind() == std::io::ErrorKind::UnexpectedEof => continue,
            Err(e) => return Err(e),
        };
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
pub fn timeline<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<Vec<TimelineEntry>, IsoError> {
    let entries = reader.walk()?;
    let mut out: Vec<TimelineEntry> = entries
        .into_iter()
        .filter(|e| !e.record.is_dir())
        .map(|e| {
            let modify_ts = rock_ridge::timestamps(&e.record.system_use).and_then(|ts| ts.modify);
            let anomaly = modify_ts.and_then(|ts| {
                if ts[0] == 70 && ts[1] == 1 && ts[2] == 1 && ts[3] == 0 && ts[4] == 0 && ts[5] == 0
                {
                    Some("epoch-date".to_string())
                } else {
                    None
                }
            });
            TimelineEntry { path: e.path, is_dir: false, size: e.record.size, modify_ts, anomaly }
        })
        .collect();
    // Sort by modify_ts ascending; None (no timestamp) goes last.
    out.sort_by_key(|a| a.modify_ts);
    Ok(out)
}

pub fn hashlist<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<Vec<FileHash>, IsoError> {
    use sha2::{Digest, Sha256};
    let entries = reader.walk()?;
    let mut out: Vec<FileHash> = Vec::new();
    for e in entries {
        if e.record.is_dir() {
            continue;
        }
        let data = reader.read_file_entry(&e.record)?;
        let hash = Sha256::digest(&data);
        let hex: String = hash.iter().fold(String::with_capacity(hash.len() * 2), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });
        out.push(FileHash { path: e.path, size: e.record.size, sha256_hex: hex });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub fn audit_sector_gaps<R: Read + Seek>(
    reader: &mut IsoReader<R>,
) -> Result<Vec<audit::GapHit>, IsoError> {
    let total = reader.volume_space_size();
    let entries = reader.walk()?;

    // Pre-system area (0-15) plus the volume-descriptor chain (16 → the
    // terminator, inclusive).  Scanning the chain handles images with extra
    // descriptors (Boot Record VD, SVD) that push the terminator past 18.
    let mut alloc: std::collections::HashSet<u32> = (0..=15).collect();
    for lba in 16u32..512 {
        let raw = match reader.read_sector_raw(u64::from(lba)) {
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
    alloc.insert(reader.pvd().root_dir_lba);

    // Both path tables (L little-endian and M big-endian) are legitimate
    // structures.  Each may span several sectors; mark all of them so the
    // standard M-path table is not mistaken for hidden data.
    let pt_sectors = u64::from(reader.pvd().path_table_size).div_ceil(2048).max(1) as u32;
    for base in [reader.pvd().l_path_table_lba, reader.pvd().m_path_table_lba] {
        for s in 0..pt_sectors {
            alloc.insert(base + s);
        }
    }

    // Helper: mark all sectors spanned by a CE (Continuation Area) pointer.
    let mark_ce = |alloc: &mut std::collections::HashSet<u32>, su: &[u8]| {
        if let Some(ce) = rock_ridge::continuation(su) {
            let end = ce.offset.saturating_add(ce.len);
            let ce_sectors = u64::from(end).div_ceil(2048).max(1) as u32;
            for s in 0..ce_sectors {
                alloc.insert(ce.lba + s);
            }
        }
    };

    for e in &entries {
        let sectors = u64::from(e.record.size).div_ceil(2048) as u32;
        for s in 0..sectors.max(1) {
            alloc.insert(e.record.lba + s);
        }
        // Rock Ridge CE sectors referenced from this entry are legitimate.
        mark_ce(&mut alloc, &e.record.system_use);
    }

    // The root directory's "." record carries the Rock Ridge ER (Extensions
    // Reference), usually via a CE continuation area.  walk() skips dot
    // entries, so read the root dir records directly and mark their CEs.
    if let Ok(root_records) = reader.read_dir(reader.pvd().root_dir_lba, reader.pvd().root_dir_size)
    {
        for rec in &root_records {
            mark_ce(&mut alloc, &rec.system_use);
        }
    }
    // read_dir already follows and appends the root "." CE, but the dot
    // record itself is filtered out; read its raw System Use too.
    if let Ok(raw) = reader.read_sector_raw(u64::from(reader.pvd().root_dir_lba)) {
        let len = raw[0] as usize;
        if len >= 34 && len <= raw.len() {
            let name_len = raw[32] as usize;
            let su_start = 33 + name_len + usize::from(name_len % 2 == 0);
            if su_start < len {
                mark_ce(&mut alloc, &raw[su_start..len]);
            }
        }
    }

    // ── Supplementary (Joliet) volume structures ──
    // The SVD has its own path tables and a parallel directory tree (the
    // file *data* is shared with the PVD tree, but the directory sectors
    // and path tables are distinct).  Mark them all as legitimate.
    if let Some(svd) = reader.svd() {
        let svd_root_lba = svd.root_dir_lba;
        let svd_root_size = svd.root_dir_size;
        let svd_pt_sectors = u64::from(svd.path_table_size).div_ceil(2048).max(1) as u32;
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
            let dir_sectors = u64::from(size).div_ceil(2048).max(1) as u32;
            for s in 0..dir_sectors {
                alloc.insert(lba + s);
            }
            if let Ok(children) = reader.read_dir(lba, size) {
                for c in children {
                    if c.is_dir() {
                        worklist.push((c.lba, c.size));
                    } else {
                        let fs = u64::from(c.size).div_ceil(2048).max(1) as u32;
                        for s in 0..fs {
                            alloc.insert(c.lba + s);
                        }
                    }
                }
            }
        }
    }

    // ── El Torito boot catalog + boot images ──
    if let Some(cat) = reader.boot_catalog_lba() {
        alloc.insert(cat);
    }
    if let Ok(boot) = reader.boot_entries() {
        for b in &boot {
            // sector_count is in 512-byte virtual sectors; convert to
            // 2048-byte logical sectors (round up, minimum one).
            let bytes = u64::from(b.sector_count) * 512;
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
        let raw = reader.read_sector_raw(u64::from(lba))?;
        let nonzero = raw.iter().any(|&b| b != 0);
        out.push(audit::GapHit { lba, nonzero });
    }
    Ok(out)
}

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
