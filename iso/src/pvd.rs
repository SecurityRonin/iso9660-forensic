//! ISO 9660 Volume Descriptor parsing.
//!
//! Each Volume Descriptor occupies exactly one sector (2048 bytes).
//! Sector 16 is always the first VD; subsequent VDs follow until the
//! Volume Descriptor Set Terminator (type 0xFF).

use crate::IsoError;

pub const PVD_TYPE: u8 = 0x01;
pub const SVD_TYPE: u8 = 0x02; // Supplementary VD (Joliet)
pub const TERMINATOR_TYPE: u8 = 0xFF;
pub const BOOT_RECORD_TYPE: u8 = 0x00;

/// A decoded ISO 9660 date/time field (17-byte decimal format, ECMA-119 §8.4.26).
///
/// The on-disc representation is 16 ASCII decimal digits followed by 1 signed
/// byte for the UTC offset in 15-minute units.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IsoDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub centisecond: u8,
    /// UTC offset in 15-minute increments (signed). Range −48…+52.
    pub tz_offset_15min: i8,
}

/// Parse a 17-byte ECMA-119 datetime field. Returns `None` when all digits are
/// zero (the "not specified" sentinel).
pub(crate) fn parse_iso_datetime(b: &[u8]) -> Option<IsoDateTime> {
    if b.len() < 17 {
        return None;
    }
    // All-zero or all-space bytes means "not set".
    if b[..16].iter().all(|&x| x == b'0' || x == 0) {
        return None;
    }
    let d = |i: usize| (b[i].wrapping_sub(b'0')) as u16;
    let year = d(0) * 1000 + d(1) * 100 + d(2) * 10 + d(3);
    if year == 0 {
        return None;
    }
    let month = (d(4) * 10 + d(5)) as u8;
    let day = (d(6) * 10 + d(7)) as u8;
    let hour = (d(8) * 10 + d(9)) as u8;
    let minute = (d(10) * 10 + d(11)) as u8;
    let second = (d(12) * 10 + d(13)) as u8;
    let centisecond = (d(14) * 10 + d(15)) as u8;
    let tz_offset_15min = b[16] as i8;
    Some(IsoDateTime { year, month, day, hour, minute, second, centisecond, tz_offset_15min })
}

/// Trim null bytes and trailing spaces from a d-char / a-char field.
fn trim_field(bytes: &[u8]) -> String {
    let s = std::str::from_utf8(bytes).unwrap_or("");
    s.trim_end_matches(['\0', ' ']).to_string()
}

/// Parsed Primary Volume Descriptor (ECMA-119 §8.4).
#[derive(Debug, Clone, Default)]
pub struct PrimaryVolumeDescriptor {
    /// Volume label, stripped of trailing spaces. Up to 32 ASCII characters.
    pub volume_label: String,
    /// LBA of the root directory record.
    pub root_dir_lba: u32,
    /// Size of the root directory in bytes.
    pub root_dir_size: u32,
    /// Total number of logical blocks on the volume (ECMA-119 §8.4.8).
    pub volume_space_size: u32,

    // ── Additional metadata fields (ECMA-119 §8.4) ───────────────────────────
    pub system_id: String,
    pub volume_set_id: String,
    pub publisher_id: String,
    pub data_preparer_id: String,
    pub application_id: String,
    pub copyright_file_id: String,
    pub abstract_file_id: String,
    pub bibliographic_file_id: String,
    pub volume_creation_time: Option<IsoDateTime>,
    pub volume_modification_time: Option<IsoDateTime>,
    pub volume_expiration_time: Option<IsoDateTime>,
    pub volume_effective_time: Option<IsoDateTime>,
    /// Logical block size in bytes (almost always 2048).
    pub logical_block_size: u16,
    /// Size of the path table in bytes.
    pub path_table_size: u32,
    /// LBA of the Type-L (little-endian) path table.
    pub l_path_table_lba: u32,
    /// LBA of the Type-M (big-endian) path table.
    pub m_path_table_lba: u32,
}

impl PrimaryVolumeDescriptor {
    /// Parse a 2048-byte sector as a Primary Volume Descriptor.
    pub fn parse(sector: &[u8]) -> Result<Self, IsoError> {
        if sector.len() < 883 {
            return Err(IsoError::BadDescriptor("sector too short for PVD".into()));
        }
        if &sector[1..6] != b"CD001" {
            return Err(IsoError::BadDescriptor("missing CD001 signature".into()));
        }
        if sector[0] != PVD_TYPE {
            return Err(IsoError::BadDescriptor(format!(
                "expected type 0x01, got 0x{:02x}",
                sector[0]
            )));
        }
        if sector[6] != 0x01 {
            return Err(IsoError::BadDescriptor(format!(
                "expected version 0x01, got 0x{:02x}",
                sector[6]
            )));
        }

        let le16 = |i: usize| u16::from_le_bytes(sector[i..i + 2].try_into().unwrap());
        let le32 = |i: usize| u32::from_le_bytes(sector[i..i + 4].try_into().unwrap());
        let be32 = |i: usize| u32::from_be_bytes(sector[i..i + 4].try_into().unwrap());

        let volume_label = trim_field(&sector[40..72]);
        let volume_space_size = le32(80);

        let root_dir_lba = le32(158); // root dir record[2..6]  (offset 156+2)
        let root_dir_size = le32(166); // root dir record[10..14] (offset 156+10)

        Ok(Self {
            volume_label,
            root_dir_lba,
            root_dir_size,
            volume_space_size,
            system_id: trim_field(&sector[8..40]),
            volume_set_id: trim_field(&sector[190..318]),
            publisher_id: trim_field(&sector[318..446]),
            data_preparer_id: trim_field(&sector[446..574]),
            application_id: trim_field(&sector[574..702]),
            copyright_file_id: trim_field(&sector[702..739]),
            abstract_file_id: trim_field(&sector[739..775]),
            bibliographic_file_id: trim_field(&sector[775..812]),
            volume_creation_time: parse_iso_datetime(&sector[813..830]),
            volume_modification_time: parse_iso_datetime(&sector[830..847]),
            volume_expiration_time: parse_iso_datetime(&sector[847..864]),
            volume_effective_time: parse_iso_datetime(&sector[864..881]),
            logical_block_size: le16(128),
            path_table_size: le32(132),
            l_path_table_lba: le32(140),
            m_path_table_lba: be32(148),
        })
    }
}

/// Minimal Supplementary Volume Descriptor — what we need for Joliet detection
/// and to distinguish an Enhanced Volume Descriptor (ISO 9660:1999).
#[derive(Debug, Clone)]
pub struct SupplementaryVolumeDescriptor {
    /// Volume Descriptor version byte (BP 7). `1` for a standard SVD / Joliet;
    /// `2` marks an Enhanced Volume Descriptor (ISO 9660:1999, "Level 4").
    pub version: u8,
    /// True when the escape sequences indicate Joliet (UCS-2 Level 1/2/3).
    pub is_joliet: bool,
    pub volume_label: String,
    pub root_dir_lba: u32,
    pub root_dir_size: u32,
    /// LBA of the Type-L path table for this supplementary volume.
    pub l_path_table_lba: u32,
    /// LBA of the Type-M path table for this supplementary volume.
    pub m_path_table_lba: u32,
    /// Path table size in bytes.
    pub path_table_size: u32,
}

impl SupplementaryVolumeDescriptor {
    /// True for an Enhanced Volume Descriptor (ISO 9660:1999): a type-2
    /// descriptor with version byte 2 and no Joliet escape sequence.
    #[must_use]
    pub fn is_enhanced(&self) -> bool {
        self.version >= 2 && !self.is_joliet
    }

    pub fn parse(sector: &[u8]) -> Result<Self, IsoError> {
        if sector.len() < 190 {
            return Err(IsoError::BadDescriptor("SVD sector too short".into()));
        }
        if &sector[1..6] != b"CD001" || sector[0] != SVD_TYPE {
            return Err(IsoError::BadDescriptor("not a Supplementary VD".into()));
        }

        // Joliet escape sequences at offset 88 (3 bytes each):
        //   %/@  → UCS-2 Level 1
        //   %/B  → UCS-2 Level 2
        //   %/C  → UCS-2 Level 3
        let esc = &sector[88..120];
        // Joliet Level 1="%/@", Level 2="%/B"/"%/C", Level 3="%/C"/"%/E".
        // hadris-iso uses %/E for Level 3; mkisofs uses %/C. Accept all known variants.
        let is_joliet =
            esc.windows(3).any(|w| w == b"%/@" || w == b"%/B" || w == b"%/C" || w == b"%/E");

        // Joliet volume label is UCS-2BE at offset 40 (32 bytes = 16 code units).
        let volume_label = if is_joliet {
            decode_ucs2be(&sector[40..72])
        } else {
            std::str::from_utf8(&sector[40..72]).unwrap_or("").trim_end().to_string()
        };

        let root = &sector[156..190];
        let root_dir_lba = u32::from_le_bytes(root[2..6].try_into().unwrap());
        let root_dir_size = u32::from_le_bytes(root[10..14].try_into().unwrap());

        // Path table fields share the PVD layout: size (BEBO) at 132,
        // L-path table LBA (LE) at 140, M-path table LBA (BE) at 148.
        let path_table_size = u32::from_le_bytes(sector[132..136].try_into().unwrap());
        let l_path_table_lba = u32::from_le_bytes(sector[140..144].try_into().unwrap());
        let m_path_table_lba = u32::from_be_bytes(sector[148..152].try_into().unwrap());

        Ok(Self {
            version: sector[6], // BP 7: 1 = SVD/Joliet, 2 = Enhanced VD (ISO 9660:1999)
            is_joliet,
            volume_label,
            root_dir_lba,
            root_dir_size,
            l_path_table_lba,
            m_path_table_lba,
            path_table_size,
        })
    }
}

/// Decode a UCS-2BE byte slice into a `String`, stopping at NUL pairs.
pub(crate) fn decode_ucs2be(bytes: &[u8]) -> String {
    bytes
        .chunks_exact(2)
        .map_while(|w| {
            let cp = u16::from_be_bytes([w[0], w[1]]);
            if cp == 0 {
                None
            } else {
                char::from_u32(u32::from(cp))
            }
        })
        .collect::<String>()
        .trim_end()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::parse_iso_datetime;

    #[test]
    fn datetime_too_short_is_none() {
        // Fewer than 17 bytes -> None.
        assert!(parse_iso_datetime(b"2024").is_none());
    }

    #[test]
    fn datetime_zero_year_is_none() {
        // 17 bytes: a non-zero digit past the year field skips the all-'0'
        // sentinel, but the year field decodes to 0 -> None.
        let mut b = [b'0'; 17];
        b[7] = b'1';
        assert!(parse_iso_datetime(&b).is_none());
    }
}
