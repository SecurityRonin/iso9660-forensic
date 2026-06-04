//! ISO 9660 Path Table parsing and Type-L ↔ Type-M cross-validation.
//!
//! ECMA-119 §8.4.19–§8.4.20 mandates two path table copies:
//! - Type-L: all multi-byte integers in little-endian form.
//! - Type-M: all multi-byte integers in big-endian form.
//!
//! Path table record (ECMA-119 §9.4):
//!   [0]    dir_id_len   (u8) — length of the directory identifier
//!   [1]    ext_attr_len (u8) — always 0
//!   [2..6] lba          (u32, LE or BE depending on table type)
//!   [6..8] parent_dir_num (u16, 1-based index into the path table)
//!   [8..]  dir_id       (dir_id_len bytes, padded to even with 0x00)

use crate::IsoError;

/// A parsed entry from a Type-L or Type-M path table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathTableEntry {
    /// Logical Block Address of this directory.
    pub lba: u32,
    /// 1-based index of the parent directory in this path table.
    pub parent_dir_num: u16,
    /// Directory identifier bytes (the directory name).
    pub dir_id: Vec<u8>,
}

fn parse_table(data: &[u8], big_endian: bool) -> Result<Vec<PathTableEntry>, IsoError> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        if offset + 8 > data.len() {
            break;
        }
        let id_len = data[offset] as usize;
        if id_len == 0 {
            break;
        }
        let record_len = 8 + id_len + (id_len % 2); // padded to even total
        if offset + record_len > data.len() {
            break;
        }
        let lba = if big_endian {
            u32::from_be_bytes(data[offset + 2..offset + 6].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[offset + 2..offset + 6].try_into().unwrap())
        };
        let parent = if big_endian {
            u16::from_be_bytes(data[offset + 6..offset + 8].try_into().unwrap())
        } else {
            u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap())
        };
        let dir_id = data[offset + 8..offset + 8 + id_len].to_vec();
        entries.push(PathTableEntry { lba, parent_dir_num: parent, dir_id });
        offset += record_len;
    }
    Ok(entries)
}

/// Parse a Type-L (little-endian) path table.
pub fn parse_l_path_table(data: &[u8]) -> Result<Vec<PathTableEntry>, IsoError> {
    parse_table(data, false)
}

/// Parse a Type-M (big-endian) path table.
pub fn parse_m_path_table(data: &[u8]) -> Result<Vec<PathTableEntry>, IsoError> {
    parse_table(data, true)
}

/// A discrepancy found during Type-L ↔ Type-M cross-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathTableMismatch {
    /// 0-based index of the entry with the mismatch.
    pub index: usize,
    pub description: String,
}

/// Cross-validate two path tables, returning any discrepancies.
///
/// Checks that both tables have the same entry count, and for each paired
/// entry that `lba`, `parent_dir_num`, and `dir_id` all match.
pub fn validate_path_tables(l: &[PathTableEntry], m: &[PathTableEntry]) -> Vec<PathTableMismatch> {
    let mut out = Vec::new();
    if l.len() != m.len() {
        out.push(PathTableMismatch {
            index: 0,
            description: format!("entry count mismatch: L={} M={}", l.len(), m.len()),
        });
        // Still check the overlapping prefix.
    }
    for (i, (le, me)) in l.iter().zip(m.iter()).enumerate() {
        if le.lba != me.lba {
            out.push(PathTableMismatch {
                index: i,
                description: format!("LBA mismatch: L={} M={}", le.lba, me.lba),
            });
        }
        if le.parent_dir_num != me.parent_dir_num {
            out.push(PathTableMismatch {
                index: i,
                description: format!(
                    "parent mismatch: L={} M={}",
                    le.parent_dir_num, me.parent_dir_num
                ),
            });
        }
        if le.dir_id != me.dir_id {
            out.push(PathTableMismatch {
                index: i,
                description: format!("dir_id mismatch: L={:?} M={:?}", le.dir_id, me.dir_id),
            });
        }
    }
    out
}
