//! Rock Ridge Interchange Protocol (RRIP) — IEEE P1282 System Use extensions.
//!
//! Rock Ridge entries live in the System Use field of each directory record.
//! The `SP` entry (Sharing Protocol indicator) at the root `.` record announces
//! that Rock Ridge is in use. Subsequent records contain `NM` (alternate name),
//! `PX` (POSIX attributes), `TF` (timestamps), `SL` (symlink), etc.

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
                    let ts: ShortTimestamp = system_use[pos..pos + 7].try_into().unwrap();
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
    if found { Some(path) } else { None }
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
            return Some(u32::from_le_bytes(
                system_use[off + 4..off + 8].try_into().unwrap(),
            ));
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
        if len < 3 || off + len > system_use.len() { break; }
        if sig == b"PX" && len >= 36 {
            let le32 = |i: usize| u32::from_le_bytes(system_use[i..i + 4].try_into().unwrap());
            return Some(PosixAttrs {
                mode:  le32(off + 4),
                nlink: le32(off + 12),
                uid:   le32(off + 20),
                gid:   le32(off + 28),
                ino:   if len >= 44 { Some(le32(off + 36) as u64) } else { None },
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
    pub creation:   Option<AnyTimestamp>,
    pub modify:     Option<AnyTimestamp>,
    pub access:     Option<AnyTimestamp>,
    pub attributes: Option<AnyTimestamp>,
    pub backup:     Option<AnyTimestamp>,
    pub expiration: Option<AnyTimestamp>,
    pub effective:  Option<AnyTimestamp>,
}

/// Extract timestamps from a `TF` System Use entry, handling both short (flag
/// bit 7 = 0) and long (flag bit 7 = 1) timestamp formats.
pub fn timestamps_any(system_use: &[u8]) -> Option<RockRidgeAnyTimestamps> {
    let mut offset = 0;
    while offset + 3 <= system_use.len() {
        let sig = &system_use[offset..offset + 2];
        let len = system_use[offset + 2] as usize;
        if len < 3 || offset + len > system_use.len() { break; }
        if sig == b"TF" && len >= 5 {
            let flags    = system_use[offset + 4];
            let long_fmt = flags & 0x80 != 0;
            let ts_size  = if long_fmt { 17 } else { 7 };
            let mut result = RockRidgeAnyTimestamps::default();
            let mut pos = offset + 5;
            for bit in 0..7u8 {
                if flags & (1 << bit) != 0 {
                    if pos + ts_size > offset + len { break; }
                    let slot: &mut Option<AnyTimestamp> = match bit {
                        0 => &mut result.creation,   1 => &mut result.modify,
                        2 => &mut result.access,     3 => &mut result.attributes,
                        4 => &mut result.backup,     5 => &mut result.expiration,
                        6 => &mut result.effective,  _ => unreachable!(),
                    };
                    *slot = Some(if long_fmt {
                        AnyTimestamp::Long(system_use[pos..pos + 17].try_into().unwrap())
                    } else {
                        AnyTimestamp::Short(system_use[pos..pos + 7].try_into().unwrap())
                    });
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
    pub lba:    u32,
    pub offset: u32,
    pub len:    u32,
}

/// Extract the first `CE` Continuation Area pointer from a System Use field.
pub fn continuation(system_use: &[u8]) -> Option<ContinuationArea> {
    let mut off = 0;
    while off + 3 <= system_use.len() {
        let sig = &system_use[off..off + 2];
        let len = system_use[off + 2] as usize;
        if len < 3 || off + len > system_use.len() { break; }
        if sig == b"CE" && len >= 28 {
            let le32 = |i: usize| u32::from_le_bytes(system_use[i..i + 4].try_into().unwrap());
            return Some(ContinuationArea {
                lba:    le32(off + 4),
                offset: le32(off + 12),
                len:    le32(off + 20),
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
            name.push_str(std::str::from_utf8(component).unwrap_or(""));
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
    system_use
        .windows(7)
        .any(|w| w[0..2] == *b"SP" && w[4..6] == [0xBE, 0xEF])
}
