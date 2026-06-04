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
///
/// The 2048-byte ISO 9660 user data sits at a mode-dependent offset within each
/// physical sector (ECMA-130 §14): Mode 1 places it at byte 16 (after 12 sync +
/// 4 header); CD-ROM XA Mode 2 Form 1 inserts an 8-byte subheader, pushing it to
/// byte 24.  2448-byte sectors append 96 bytes of subchannel after the 2352-byte
/// frame; 2336-byte sectors omit sync+header and start at the subheader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorMode {
    /// Standard ISO 9660: 2048 bytes of pure user data.
    Iso2048,
    /// Raw Mode-1 CD-ROM: 2352 bytes; user data at byte 16.
    Raw2352,
    /// Raw CD-ROM XA Mode-2 Form-1: 2352 bytes; user data at byte 24.
    Raw2352Mode2,
    /// Raw Mode-1 + subchannel: 2448 bytes (2352 + 96); user data at byte 16.
    Raw2448,
    /// Raw XA Mode-2 Form-1 + subchannel: 2448 bytes; user data at byte 24.
    Raw2448Mode2,
    /// Mode-2 sector without sync/header: 2336 bytes; user data at byte 8.
    Mode2_2336,
}

impl SectorMode {
    /// Detect the sector mode by probing for the CD001 signature.
    ///
    /// Probes each candidate physical layout at sector 16, checking CD001 at
    /// the mode-specific user-data offset.  Sync-bearing layouts (2352/2448)
    /// additionally require the 12-byte sync pattern at the start of sector 0
    /// to avoid false positives; 2336 sectors have no sync field.
    pub fn detect<R: Read + Seek>(reader: &mut R) -> Result<Self, IsoError> {
        // 2048-byte pure ISO is by far the most common — probe first.
        if probe_cd001(reader, 16 * 2048 + 1)? {
            return Ok(Self::Iso2048);
        }
        // Sync-bearing raw layouts: (mode, physical, data_offset).
        let synced = [
            (Self::Raw2352, 2352u64, 16u64),
            (Self::Raw2352Mode2, 2352, 24),
            (Self::Raw2448, 2448, 16),
            (Self::Raw2448Mode2, 2448, 24),
        ];
        for (mode, phys, off) in synced {
            if probe_cd001(reader, 16 * phys + off + 1)? && has_sync_pattern(reader, 0)? {
                return Ok(mode);
            }
        }
        // 2336 Mode 2 (no sync field): rely on the CD001 match alone.
        if probe_cd001(reader, 16 * 2336 + 8 + 1)? {
            return Ok(Self::Mode2_2336);
        }
        Err(IsoError::NotAnIso)
    }

    /// Physical bytes per sector in the image file.
    pub const fn physical_sector_size(self) -> u64 {
        match self {
            Self::Iso2048 => 2048,
            Self::Raw2352 | Self::Raw2352Mode2 => 2352,
            Self::Raw2448 | Self::Raw2448Mode2 => 2448,
            Self::Mode2_2336 => 2336,
        }
    }

    /// Offset of the 2048-byte user data within a physical sector.
    pub const fn data_offset(self) -> u64 {
        match self {
            Self::Iso2048 => 0,
            // Mode 1: 12 sync + 4 header.
            Self::Raw2352 | Self::Raw2448 => 16,
            // XA Mode 2 Form 1: + 8-byte subheader.
            Self::Raw2352Mode2 | Self::Raw2448Mode2 => 24,
            // 2336 Mode 2: 8-byte subheader, no sync/header.
            Self::Mode2_2336 => 8,
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
