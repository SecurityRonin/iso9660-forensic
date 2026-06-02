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

/// Parsed Primary Volume Descriptor.
#[derive(Debug, Clone)]
pub struct PrimaryVolumeDescriptor {
    /// Volume label, stripped of trailing spaces. Up to 32 ASCII characters.
    pub volume_label: String,
    /// LBA of the root directory record.
    pub root_dir_lba: u32,
    /// Size of the root directory in bytes.
    pub root_dir_size: u32,
    /// Total number of logical blocks on the volume.
    pub volume_space_size: u32,
}

impl PrimaryVolumeDescriptor {
    /// Parse a 2048-byte sector as a Primary Volume Descriptor.
    pub fn parse(sector: &[u8]) -> Result<Self, IsoError> {
        if sector.len() < 156 + 34 {
            return Err(IsoError::BadDescriptor("sector too short".into()));
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

        let volume_label = std::str::from_utf8(&sector[40..72])
            .unwrap_or("")
            .trim_end()
            .to_string();

        let volume_space_size = u32::from_le_bytes(sector[80..84].try_into().unwrap());

        // Root directory record is embedded at offset 156 (34 bytes).
        let root = &sector[156..190];
        let root_dir_lba = u32::from_le_bytes(root[2..6].try_into().unwrap());
        let root_dir_size = u32::from_le_bytes(root[10..14].try_into().unwrap());

        Ok(Self {
            volume_label,
            root_dir_lba,
            root_dir_size,
            volume_space_size,
        })
    }
}

/// Minimal Supplementary Volume Descriptor — only what we need for Joliet detection.
#[derive(Debug, Clone)]
pub struct SupplementaryVolumeDescriptor {
    /// True when the escape sequences indicate Joliet (UCS-2 Level 1/2/3).
    pub is_joliet: bool,
    pub volume_label: String,
    pub root_dir_lba: u32,
    pub root_dir_size: u32,
}

impl SupplementaryVolumeDescriptor {
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
        let is_joliet = esc
            .windows(3)
            .any(|w| w == b"%/@" || w == b"%/B" || w == b"%/C" || w == b"%/E");

        // Joliet volume label is UCS-2BE at offset 40 (32 bytes = 16 code units).
        let volume_label = if is_joliet {
            decode_ucs2be(&sector[40..72])
        } else {
            std::str::from_utf8(&sector[40..72])
                .unwrap_or("")
                .trim_end()
                .to_string()
        };

        let root = &sector[156..190];
        let root_dir_lba = u32::from_le_bytes(root[2..6].try_into().unwrap());
        let root_dir_size = u32::from_le_bytes(root[10..14].try_into().unwrap());

        Ok(Self {
            is_joliet,
            volume_label,
            root_dir_lba,
            root_dir_size,
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
