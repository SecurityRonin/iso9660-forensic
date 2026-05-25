//! Sector abstraction: 2048-byte ISO mode and 2352-byte raw CD mode.
//!
//! A 2352-byte raw sector layout (Mode 1 CD-ROM, ISO/IEC 10149):
//!   bytes   0-11  : sync pattern (00 FF*10 00)
//!   bytes  12-14  : MSF address
//!   byte   15     : mode (01 = Mode 1)
//!   bytes  16-2063: 2048 bytes of user data
//!   bytes 2064-2067: EDC (CRC-32)
//!   bytes 2068-2075: 8 zero bytes
//!   bytes 2076-2351: ECC (P and Q parity, 276 bytes)

use std::io::{self, Read, Seek, SeekFrom};

use crate::IsoError;

/// How sectors are stored in the image file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorMode {
    /// Standard ISO 9660: each sector is 2048 bytes of pure user data.
    Iso2048,
    /// Raw Mode-1 CD-ROM sectors: 2352 bytes with sync, header, and ECC.
    /// User data starts at byte 16 of each sector.
    Raw2352,
}

impl SectorMode {
    /// Detect the sector mode by probing for the CD001 signature.
    ///
    /// Tries 2048-byte sectors first (the common case), then 2352-byte raw.
    pub fn detect<R: Read + Seek>(reader: &mut R) -> Result<Self, IsoError> {
        // Probe at 2048-byte-sector offset: sector 16 → byte 32768, magic at +1
        if probe_cd001(reader, 16 * 2048 + 1)? {
            return Ok(Self::Iso2048);
        }
        // Probe at 2352-byte-sector offset: sector 16 → byte 37632, data starts at +16
        if probe_cd001(reader, 16 * 2352 + 16 + 1)? {
            // Also verify the sync pattern at byte 0 of the first sector.
            if has_sync_pattern(reader, 0)? {
                return Ok(Self::Raw2352);
            }
        }
        Err(IsoError::NotAnIso)
    }

    /// Physical bytes per sector in the image file.
    pub const fn physical_sector_size(self) -> u64 {
        match self {
            Self::Iso2048 => 2048,
            Self::Raw2352 => 2352,
        }
    }

    /// Offset of the 2048-byte user data within a physical sector.
    pub const fn data_offset(self) -> u64 {
        match self {
            Self::Iso2048 => 0,
            Self::Raw2352 => 16, // skip 12 sync + 4 header bytes
        }
    }

    /// Byte position in the file where the user data for `lba` begins.
    pub fn user_data_pos(self, lba: u64) -> u64 {
        lba * self.physical_sector_size() + self.data_offset()
    }
}

/// Read `len` bytes of user data from logical sector `lba`.
pub fn read_sector_data<R: Read + Seek>(
    reader: &mut R,
    mode: SectorMode,
    lba: u64,
    buf: &mut [u8],
) -> io::Result<()> {
    debug_assert!(buf.len() <= 2048, "cannot read more than one sector at a time");
    reader.seek(SeekFrom::Start(mode.user_data_pos(lba)))?;
    reader.read_exact(buf)
}

fn probe_cd001<R: Read + Seek>(reader: &mut R, pos: u64) -> io::Result<bool> {
    let mut sig = [0u8; 5];
    reader.seek(SeekFrom::Start(pos))?;
    match reader.read_exact(&mut sig) {
        Ok(()) => Ok(&sig == b"CD001"),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

fn has_sync_pattern<R: Read + Seek>(reader: &mut R, sector_start: u64) -> io::Result<bool> {
    const SYNC: [u8; 12] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
    let mut buf = [0u8; 12];
    reader.seek(SeekFrom::Start(sector_start))?;
    match reader.read_exact(&mut buf) {
        Ok(()) => Ok(buf == SYNC),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}
