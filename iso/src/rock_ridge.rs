//! Rock Ridge Interchange Protocol (RRIP) — IEEE P1282 System Use extensions.
//!
//! Rock Ridge entries live in the System Use field of each directory record.
//! The `SP` entry (Sharing Protocol indicator) at the root `.` record announces
//! that Rock Ridge is in use. Subsequent records contain `NM` (alternate name),
//! `PX` (POSIX attributes), `TF` (timestamps), `SL` (symlink), etc.

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

/// Extract POSIX file mode from a `PX` System Use entry.
///
/// Returns `None` if no `PX` entry is found.
pub fn posix_mode(system_use: &[u8]) -> Option<u32> {
    let mut offset = 0;
    while offset + 3 <= system_use.len() {
        let sig = &system_use[offset..offset + 2];
        let len = system_use[offset + 2] as usize;
        if len < 3 || offset + len > system_use.len() {
            break;
        }
        if sig == b"PX" && len >= 12 {
            // PX v1: [sig(2), len(1), ver(1), mode_le(4), mode_be(4), ...]
            let mode = u32::from_le_bytes(system_use[offset + 4..offset + 8].try_into().unwrap());
            return Some(mode);
        }
        offset += len.max(1);
    }
    None
}

/// True if the directory record at sector 16+0 has an `SP` System Use entry,
/// indicating Rock Ridge is in use on this volume.
pub fn has_sp_entry(system_use: &[u8]) -> bool {
    system_use
        .windows(7)
        .any(|w| w[0..2] == *b"SP" && w[4..6] == [0xBE, 0xEF])
}
