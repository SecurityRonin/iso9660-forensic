//! Rock Ridge Interchange Protocol (RRIP) — IEEE P1282 System Use extensions.
//!
//! Rock Ridge entries live in the System Use field of each directory record.
//! The `SP` entry (Sharing Protocol indicator) at the root `.` record announces
//! that Rock Ridge is in use. Subsequent records contain `NM` (alternate name),
//! `PX` (POSIX attributes), `TF` (timestamps), `SL` (symlink), etc.

/// Maximum byte length of a Rock Ridge alternate name assembled from NM entries.
///
/// Caps the total string to prevent unbounded allocation from crafted SUSP data.
pub const MAX_NM_LEN: usize = 4096;

// ── TF — timestamps ───────────────────────────────────────────────────────────

/// 7-byte short timestamp: [year_since_1900, month, day, hour, min, sec, tz_offset_15min].
pub type ShortTimestamp = [u8; 7];

/// Timestamps from a Rock Ridge `TF` System Use entry (short 7-byte format).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RockRidgeTimestamps {
    /// Time of creation (TF bit 0).
    pub creation: Option<ShortTimestamp>,
    /// Time of last modification (TF bit 1).
    pub modify: Option<ShortTimestamp>,
    /// Time of last access (TF bit 2).
    pub access: Option<ShortTimestamp>,
    /// Time of last attribute change (TF bit 3).
    pub attributes: Option<ShortTimestamp>,
    /// Time of last backup (TF bit 4).
    pub backup: Option<ShortTimestamp>,
    /// Expiration time (TF bit 5).
    pub expiration: Option<ShortTimestamp>,
    /// Effective time (TF bit 6).
    pub effective: Option<ShortTimestamp>,
}

/// Extract timestamps from a `TF` System Use entry (short 7-byte format only).
///
/// Returns `None` if no `TF` entry is found or the entry uses long (17-byte) format.
pub fn timestamps(system_use: &[u8]) -> Option<RockRidgeTimestamps> {
    let mut offset = 0;
    while offset + 3 <= system_use.len() {
        let sig = &system_use[offset..offset + 2];
        let len = system_use[offset + 2] as usize;
        if len < 3 || offset + len > system_use.len() {
            break;
        }
        if sig == b"TF" && len >= 5 {
            let flags = system_use[offset + 4];
            // Bit 7: 0 = short (7-byte), 1 = long (17-byte). Long not supported.
            if flags & 0x80 != 0 {
                offset += len.max(1);
                continue;
            }
            let mut result = RockRidgeTimestamps::default();
            let mut pos = offset + 5;
            for bit in 0..7u8 {
                if flags & (1 << bit) != 0 {
                    if pos + 7 > offset + len {
                        break;
                    }
                    // The bound above makes this slice exactly 7 bytes; `else` is unreachable.
                    let Ok(ts): Result<ShortTimestamp, _> = system_use[pos..pos + 7].try_into()
                    else {
                        break;
                    };
                    match bit {
                        0 => result.creation = Some(ts),
                        1 => result.modify = Some(ts),
                        2 => result.access = Some(ts),
                        3 => result.attributes = Some(ts),
                        4 => result.backup = Some(ts),
                        5 => result.expiration = Some(ts),
                        6 => result.effective = Some(ts),
                        _ => {}
                    }
                    pos += 7;
                }
            }
            return Some(result);
        }
        offset += len.max(1);
    }
    None
}

// ── SL — symbolic link ────────────────────────────────────────────────────────

/// Extract the symlink target path from `SL` System Use entries.
///
/// Assembles component records in order into a POSIX path string.
/// Returns `None` if no `SL` entry is found.
pub fn symlink_target(system_use: &[u8]) -> Option<String> {
    const COMP_CONTINUE: u8 = 0x01;
    const COMP_CURRENT: u8 = 0x02;
    const COMP_PARENT: u8 = 0x04;
    const COMP_ROOT: u8 = 0x08;

    let mut path = String::new();
    let mut found = false;
    // `needs_sep` tracks whether to insert '/' before the next component.
    // ROOT already writes '/' so it resets to false; all other components set it.
    let mut needs_sep = false;
    let mut in_cont = false;

    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if sig == b"SL" && len >= 5 {
            found = true;
            let comp_area = &system_use[off + 5..off + len];
            let mut ci = 0;
            while ci + 2 <= comp_area.len() {
                let cf = comp_area[ci];
                let cl = comp_area[ci + 1] as usize;
                let cd = if ci + 2 + cl <= comp_area.len() {
                    &comp_area[ci + 2..ci + 2 + cl]
                } else {
                    break;
                };
                if !in_cont {
                    if cf & COMP_ROOT != 0 {
                        path.push('/');
                        needs_sep = false; // ROOT is itself the separator
                    } else {
                        if needs_sep {
                            path.push('/');
                        }
                        needs_sep = true;
                        if cf & COMP_PARENT != 0 {
                            path.push_str("..");
                        } else if cf & COMP_CURRENT != 0 {
                            path.push('.');
                        } else {
                            path.push_str(std::str::from_utf8(cd).unwrap_or(""));
                        }
                    }
                } else {
                    path.push_str(std::str::from_utf8(cd).unwrap_or(""));
                }
                in_cont = cf & COMP_CONTINUE != 0;
                ci += 2 + cl;
            }
        }
        off += len.max(1);
    }
    if found {
        Some(path)
    } else {
        None
    }
}

// ── CL / PL — directory relocation links ─────────────────────────────────────

/// LBA of the actual (relocated) directory, from a `CL` System Use entry.
///
/// Used to redirect traversal when a directory has been relocated via Rock
/// Ridge deep directory relocation.
pub fn child_link(system_use: &[u8]) -> Option<u32> {
    lba_entry(system_use, b"CL")
}

/// LBA of the parent directory, from a `PL` System Use entry.
///
/// Identifies the parent of a relocated directory (the directory that contains
/// the `CL` placeholder).
pub fn parent_link(system_use: &[u8]) -> Option<u32> {
    lba_entry(system_use, b"PL")
}

/// True if a `RE` (Relocated Entry) marker is present in the System Use field.
///
/// `RE` marks the placeholder entry in the RR_MOVED directory; the real
/// directory entry has the corresponding `CL` entry.
pub fn is_relocated(system_use: &[u8]) -> bool {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if sig == b"RE" {
            return true;
        }
        off += len.max(1);
    }
    false
}

fn lba_entry(system_use: &[u8], target: &[u8; 2]) -> Option<u32> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if &sig[..2] == target && len >= 12 {
            return Some(safe_read::le_u32(system_use, off + 4));
        }
        off += len.max(1);
    }
    None
}

// ── PX — POSIX file attributes ────────────────────────────────────────────────

/// POSIX file attributes from a `PX` System Use entry (IEEE P1282 §4.1.1).
///
/// PX v1 (len=44) includes `ino`; PX v2 (len=36) omits it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PosixAttrs {
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Serial number (inode). Present only when PX entry length ≥ 44.
    pub ino: Option<u64>,
}

/// Extract POSIX attributes from a `PX` System Use entry.
pub fn posix_attrs(system_use: &[u8]) -> Option<PosixAttrs> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if sig == b"PX" && len >= 36 {
            let le32 = |i: usize| safe_read::le_u32(system_use, i);
            return Some(PosixAttrs {
                mode: le32(off + 4),
                nlink: le32(off + 12),
                uid: le32(off + 20),
                gid: le32(off + 28),
                ino: if len >= 44 { Some(le32(off + 36) as u64) } else { None },
            });
        }
        off += len.max(1);
    }
    None
}

// ── TF extended — long (17-byte) timestamp support ────────────────────────────

/// A Rock Ridge timestamp in either short (7-byte) or long (17-byte) form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyTimestamp {
    /// 7-byte short: [year_since_1900, month, day, hour, min, sec, tz_offset_15min].
    Short([u8; 7]),
    /// 17-byte long: 16 ASCII decimal digits + 1 signed tz byte (ECMA-119 format).
    Long([u8; 17]),
}

/// Timestamps from a `TF` entry, supporting both short and long formats.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RockRidgeAnyTimestamps {
    pub creation: Option<AnyTimestamp>,
    pub modify: Option<AnyTimestamp>,
    pub access: Option<AnyTimestamp>,
    pub attributes: Option<AnyTimestamp>,
    pub backup: Option<AnyTimestamp>,
    pub expiration: Option<AnyTimestamp>,
    pub effective: Option<AnyTimestamp>,
}

/// Extract timestamps from a `TF` System Use entry, handling both short (flag
/// bit 7 = 0) and long (flag bit 7 = 1) timestamp formats.
pub fn timestamps_any(system_use: &[u8]) -> Option<RockRidgeAnyTimestamps> {
    let mut offset = 0;
    while offset + 3 <= system_use.len() {
        let sig = &system_use[offset..offset + 2];
        let len = system_use[offset + 2] as usize;
        if len < 3 || offset + len > system_use.len() {
            break;
        }
        if sig == b"TF" && len >= 5 {
            let flags = system_use[offset + 4];
            let long_fmt = flags & 0x80 != 0;
            let ts_size = if long_fmt { 17 } else { 7 };
            let mut result = RockRidgeAnyTimestamps::default();
            let mut pos = offset + 5;
            for bit in 0..7u8 {
                if flags & (1 << bit) != 0 {
                    if pos + ts_size > offset + len {
                        break;
                    }
                    let slot: &mut Option<AnyTimestamp> = match bit {
                        0 => &mut result.creation,
                        1 => &mut result.modify,
                        2 => &mut result.access,
                        3 => &mut result.attributes,
                        4 => &mut result.backup,
                        5 => &mut result.expiration,
                        6 => &mut result.effective,
                        _ => unreachable!(),
                    };
                    // The `pos + ts_size > offset + len` bound above makes each slice
                    // exactly its declared width, so `else` is unreachable.
                    let stamp = if long_fmt {
                        let Ok(a): Result<[u8; 17], _> = system_use[pos..pos + 17].try_into()
                        else {
                            break;
                        };
                        AnyTimestamp::Long(a)
                    } else {
                        let Ok(a): Result<[u8; 7], _> = system_use[pos..pos + 7].try_into() else {
                            break;
                        };
                        AnyTimestamp::Short(a)
                    };
                    *slot = Some(stamp);
                    pos += ts_size;
                }
            }
            return Some(result);
        }
        offset += len.max(1);
    }
    None
}

// ── CE — Continuation Area pointer ───────────────────────────────────────────

/// Location of a Rock Ridge Continuation Area (`CE` System Use entry).
///
/// To follow: seek to `lba * 2048 + offset`, read `len` bytes, then
/// concatenate them to the current System Use field before re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ContinuationArea {
    pub lba: u32,
    pub offset: u32,
    pub len: u32,
}

/// Extract the first `CE` Continuation Area pointer from a System Use field.
pub fn continuation(system_use: &[u8]) -> Option<ContinuationArea> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if sig == b"CE" && len >= 28 {
            let le32 = |i: usize| safe_read::le_u32(system_use, i);
            return Some(ContinuationArea {
                lba: le32(off + 4),
                offset: le32(off + 12),
                len: le32(off + 20),
            });
        }
        off += len.max(1);
    }
    None
}

// ── NM — alternate name ───────────────────────────────────────────────────────

/// Extract the Rock Ridge alternate name from a System Use field.
///
/// Scans for `NM` entries and concatenates their name component bytes.
/// Returns `None` if no `NM` entry is found.
pub fn alternate_name(system_use: &[u8]) -> Option<String> {
    let mut name = String::new();
    let mut offset = 0;
    while offset + 3 <= system_use.len() {
        let sig = &system_use[offset..offset + 2];
        let len = system_use[offset + 2] as usize;
        if len < 3 || offset + len > system_use.len() {
            break;
        }
        if sig == b"NM" && len >= 6 {
            // NM entry: [sig(2), len(1), ver(1), flags(1), name_bytes...]
            let flags = system_use[offset + 4];
            let component = &system_use[offset + 5..offset + len];
            let fragment = std::str::from_utf8(component).unwrap_or("");
            // Cap total name to prevent unbounded allocation from crafted SUSP data.
            let remaining = MAX_NM_LEN.saturating_sub(name.len());
            if remaining > 0 {
                let take = fragment.len().min(remaining);
                name.push_str(&fragment[..take]);
            }
            // If flags bit 0 is NOT set, this is the final component.
            if flags & 0x01 == 0 {
                return if name.is_empty() { None } else { Some(name) };
            }
        }
        offset += len.max(1);
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Extract only the POSIX file mode from a `PX` System Use entry.
///
/// Backward-compat wrapper around [`posix_attrs`].
pub fn posix_mode(system_use: &[u8]) -> Option<u32> {
    posix_attrs(system_use).map(|a| a.mode)
}

/// True if the directory record at sector 16+0 has an `SP` System Use entry,
/// indicating Rock Ridge is in use on this volume.
pub fn has_sp_entry(system_use: &[u8]) -> bool {
    system_use.windows(7).any(|w| w[0..2] == *b"SP" && w[4..6] == [0xBE, 0xEF])
}

/// Return the SUSP SP `LEN_SKP` skip value from the System Use field.
///
/// IEEE P1282 §5.3: the `SP` entry's byte at offset 6 specifies how many
/// bytes to skip at the start of the System Use Area in every directory
/// record before the first SUSP entry begins.  Returns 0 if no valid `SP`
/// entry is found.
///
/// Uses `.windows()` rather than a structured SUSP scan so the entry is
/// found even when it is itself preceded by skip-region bytes.
pub fn sp_skip(system_use: &[u8]) -> usize {
    system_use
        .windows(7)
        .find(|w| w[0..2] == *b"SP" && w[4..6] == [0xBE, 0xEF])
        .map(|w| w[6] as usize)
        .unwrap_or(0)
}

// ── ER — Extensions Reference (SUSP IEEE P1281 §5.5) ─────────────────────────

/// A SUSP `ER` (Extensions Reference) entry — identifies an extension protocol
/// (e.g. Rock Ridge) recorded in the System Use Area.
///
/// For Rock Ridge the identifier is `IEEE_P1282` (RRIP 1.12) or `RRIP_1991A`
/// (RRIP 1.10).  Lets a forensic tool positively name the protocol on disc
/// rather than inferring it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtensionsReference {
    /// Extension Identifier (e.g. `IEEE_P1282`).
    pub id: String,
    /// Extension Descriptor (human-readable, may be empty).
    pub descriptor: String,
    /// Extension Source (citation, may be empty).
    pub source: String,
    /// Extension version byte.
    pub version: u8,
}

/// Extract the first `ER` Extensions Reference entry from a System Use field.
pub fn extensions_reference(system_use: &[u8]) -> Option<ExtensionsReference> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        // ER: sig(2) ver-of-... actually: sig(2) len(1) ver(1) len_id(1)
        // len_des(1) len_src(1) ext_ver(1) then id|des|src.
        if sig == b"ER" && len >= 8 {
            let len_id = system_use[off + 4] as usize;
            let len_des = system_use[off + 5] as usize;
            let len_src = system_use[off + 6] as usize;
            let ext_ver = system_use[off + 7];
            let mut p = off + 8;
            let take = |start: usize, n: usize| -> String {
                let end = (start + n).min(off + len);
                if start >= end {
                    String::new()
                } else {
                    String::from_utf8_lossy(&system_use[start..end]).trim_end().to_string()
                }
            };
            let id = take(p, len_id);
            p += len_id;
            let descriptor = take(p, len_des);
            p += len_des;
            let source = take(p, len_src);
            return Some(ExtensionsReference { id, descriptor, source, version: ext_ver });
        }
        off += len.max(1);
    }
    None
}

// ── PN — POSIX device number (RRIP IEEE P1282 §4.1.2) ────────────────────────

/// POSIX device number from a `PN` System Use entry (for character/block
/// device nodes).  `dev_high`/`dev_low` are the high/low 32 bits of `dev_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PosixDevice {
    pub dev_high: u32,
    pub dev_low: u32,
}

impl PosixDevice {
    /// Combined 64-bit device number.
    #[must_use]
    pub fn dev(self) -> u64 {
        (u64::from(self.dev_high) << 32) | u64::from(self.dev_low)
    }
}

/// Extract the `PN` POSIX device number from a System Use field.
pub fn posix_device(system_use: &[u8]) -> Option<PosixDevice> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if sig == b"PN" && len >= 20 {
            // BP5-12 Dev_t High (both-endian), BP13-20 Dev_t Low (both-endian).
            let le32 = |i: usize| safe_read::le_u32(system_use, i);
            return Some(PosixDevice { dev_high: le32(off + 4), dev_low: le32(off + 12) });
        }
        off += len.max(1);
    }
    None
}

// ── SF — sparse file (RRIP IEEE P1282 §4.1.7) ────────────────────────────────

/// Sparse-file metadata from an `SF` System Use entry.
///
/// Records the 64-bit virtual (logical) file size and the index-block table
/// depth.  This crate exposes the metadata only; it does not reconstruct the
/// sparse index blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SparseFile {
    /// 64-bit virtual file size (POSIX `st_size`).
    pub virtual_size: u64,
    /// Depth of the first index block.
    pub table_depth: u8,
}

/// Extract the `SF` sparse-file entry from a System Use field.
pub fn sparse_file(system_use: &[u8]) -> Option<SparseFile> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() {
            break;
        }
        if sig == b"SF" && len >= 21 {
            // BP5-12 Virtual Size High (both-endian), BP13-20 Low, BP21 depth.
            let le32 = |i: usize| safe_read::le_u32(system_use, i);
            let high = u64::from(le32(off + 4));
            let low = u64::from(le32(off + 12));
            return Some(SparseFile {
                virtual_size: (high << 32) | low,
                table_depth: system_use[off + 20],
            });
        }
        off += len.max(1);
    }
    None
}
