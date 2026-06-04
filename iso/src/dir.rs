//! ISO 9660 Directory Record parsing and iteration.
//!
//! Directory records are variable-length structures packed sequentially
//! into one or more sectors. Each record is padded to an even byte boundary.

use crate::pvd::decode_ucs2be;
use crate::IsoError;

pub const FILE_FLAG_DIRECTORY: u8 = 0x02;
pub const FILE_FLAG_ASSOCIATED: u8 = 0x04;
/// ECMA-119 §9.1.6: more directory records for this file follow in this directory.
pub const FILE_FLAG_MULTI_EXTENT: u8 = 0x80;

/// A single parsed directory record.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DirRecord {
    /// LBA of file data (or subdirectory).
    pub lba: u32,
    /// Size in bytes of file data (or directory region).
    pub size: u32,
    /// Raw ISO 9660 file identifier (may end with `;1` for versioned files).
    pub name_bytes: Vec<u8>,
    /// File flags byte.
    pub flags: u8,
    /// Raw System Use area bytes (used by Rock Ridge).
    pub system_use: Vec<u8>,
    /// Additional extents for multi-extent files (ECMA-119 §9.1.6).
    /// Empty for single-extent files. Populated by `read_dir()` when it
    /// merges consecutive same-name records with `FILE_FLAG_MULTI_EXTENT`.
    /// Each entry is `(lba, size_bytes)`.
    pub extra_extents: Vec<(u32, u32)>,
}

impl DirRecord {
    /// Parse one directory record from `data[offset..]`.
    ///
    /// Returns `None` when the record length byte is 0 (padding to sector boundary).
    pub fn parse(data: &[u8], offset: usize) -> Result<Option<(Self, usize)>, IsoError> {
        if offset >= data.len() {
            return Ok(None);
        }
        let len = data[offset] as usize;
        if len == 0 {
            return Ok(None); // padding
        }
        if offset + len > data.len() || len < 33 {
            return Err(IsoError::BadDirRecord(format!(
                "record at offset {offset} claims length {len} but only {} bytes remain",
                data.len() - offset
            )));
        }

        let rec = &data[offset..offset + len];
        let lba = u32::from_le_bytes(rec[2..6].try_into().unwrap());
        let size = u32::from_le_bytes(rec[10..14].try_into().unwrap());
        let flags = rec[25];
        let name_len = rec[32] as usize;

        if 33 + name_len > len {
            return Err(IsoError::BadDirRecord("name extends past record".into()));
        }
        let name_bytes = rec[33..33 + name_len].to_vec();

        // System Use field starts after name, padded to even offset.
        let su_start = 33 + name_len + (if name_len % 2 == 0 { 1 } else { 0 });
        let system_use = if su_start < len { rec[su_start..len].to_vec() } else { Vec::new() };

        Ok(Some((
            DirRecord { lba, size, name_bytes, flags, system_use, extra_extents: Vec::new() },
            len,
        )))
    }

    /// True if this entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.flags & FILE_FLAG_DIRECTORY != 0
    }

    /// True if this record still has the multi-extent flag set (FILE_FLAG_MULTI_EXTENT).
    ///
    /// After `read_dir()` merges extent chains, the final merged record has this
    /// flag cleared and `extra_extents` populated instead.
    pub fn is_multi_extent(&self) -> bool {
        self.flags & FILE_FLAG_MULTI_EXTENT != 0
    }

    /// True if this is the dot (`.`) or dotdot (`..`) entry.
    pub fn is_dot(&self) -> bool {
        self.name_bytes == [0x00] || self.name_bytes == [0x01]
    }

    /// ISO 9660 filename, stripped of the `;1` version suffix.
    pub fn iso_name(&self) -> String {
        let raw = std::str::from_utf8(&self.name_bytes).unwrap_or("").trim_end_matches('\0');
        // Strip version number (`;1`, `;2`, etc.) from file names.
        if let Some(pos) = raw.rfind(';') {
            raw[..pos].to_string()
        } else {
            raw.to_string()
        }
    }

    /// Joliet filename decoded from the UCS-2BE name bytes, if this is a
    /// Joliet directory.
    pub fn joliet_name(&self) -> String {
        decode_ucs2be(&self.name_bytes)
    }
}

/// Parse all non-dot directory records from a directory sector buffer.
pub fn parse_dir_records(data: &[u8]) -> Result<Vec<DirRecord>, IsoError> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        // Zero-length records mark padding to the sector boundary; skip to next sector.
        if data[offset] == 0 {
            offset = (offset + 2047) & !2047;
            continue;
        }
        match DirRecord::parse(data, offset)? {
            Some((rec, advance)) => {
                if !rec.is_dot() {
                    records.push(rec);
                }
                offset += advance;
                // Records must advance by at least 1 to avoid infinite loops.
                if advance == 0 {
                    break;
                }
            }
            None => break,
        }
    }
    Ok(records)
}
