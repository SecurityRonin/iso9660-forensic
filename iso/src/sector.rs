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

/// CD-ROM EDC (ECMA-130 §14.3 / Annex A): a 32-bit CRC with the reflected
/// generator polynomial `0xD801_8001`, zero initial value, no final inversion,
/// emitted little-endian. For a Mode-1 sector it is computed over the first
/// 2064 bytes (12-byte sync + 4-byte header + 2048-byte user data) and stored at
/// offset 2064. Matches the reference implementations in cdrdao, libmirage, and
/// Aaru (`Edc.cs`).
pub fn cd_edc(data: &[u8]) -> u32 {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        let mut i = 0usize;
        while i < 256 {
            let mut e = i as u32;
            let mut bit = 0;
            while bit < 8 {
                e = if e & 1 != 0 { (e >> 1) ^ 0xD801_8001 } else { e >> 1 };
                bit += 1;
            }
            t[i] = e;
            i += 1;
        }
        t
    });
    let mut edc = 0u32;
    for &b in data {
        edc = table[((edc ^ u32::from(b)) & 0xFF) as usize] ^ (edc >> 8);
    }
    edc
}

/// GF(2^8) lookup tables for the CD-ROM ECC (primitive polynomial `x^8 + x^4 +
/// x^3 + x^2 + 1` = `0x11D`). `f` multiplies by the field generator; `b` is the
/// inverse used when finalising each parity byte.
fn ecc_luts() -> ([u8; 256], [u8; 256]) {
    let mut f = [0u8; 256];
    let mut b = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        let j = (i << 1) ^ (if i & 0x80 != 0 { 0x11D } else { 0 });
        f[i] = j as u8;
        b[(i ^ j) & 0xFF] = i as u8;
        i += 1;
    }
    (f, b)
}

/// Compute one ECC block (P or Q) over the sector starting at byte offset 12,
/// per ECMA-130 §14.3 / Annex A (Neill Corlett's canonical algorithm). Returns
/// `major_count * 2` parity bytes.
fn ecc_block(
    sector: &[u8],
    major_count: usize,
    minor_count: usize,
    major_mult: usize,
    minor_inc: usize,
    f: &[u8; 256],
    b: &[u8; 256],
) -> Vec<u8> {
    let size = major_count * minor_count;
    let mut dest = vec![0u8; major_count * 2];
    for major in 0..major_count {
        let mut index = (major >> 1) * major_mult + (major & 1);
        let mut ecc_a = 0u8;
        let mut ecc_b = 0u8;
        for _ in 0..minor_count {
            let temp = sector[12 + index];
            index += minor_inc;
            if index >= size {
                index -= size;
            }
            ecc_a ^= temp;
            ecc_b ^= temp;
            ecc_a = f[ecc_a as usize];
        }
        ecc_a = b[(f[ecc_a as usize] ^ ecc_b) as usize];
        dest[major] = ecc_a;
        dest[major + major_count] = ecc_a ^ ecc_b;
    }
    dest
}

/// Stamp the P (172 B @ 2076) and Q (104 B @ 2248) ECC of a Mode-1 sector.
/// P must be written before Q, since Q's input covers the P parity region.
pub fn cd_ecc_stamp(sector: &mut [u8]) {
    let (f, b) = ecc_luts();
    let p = ecc_block(sector, 86, 24, 2, 86, &f, &b);
    sector[2076..2248].copy_from_slice(&p);
    let q = ecc_block(sector, 52, 43, 86, 88, &f, &b);
    sector[2248..2352].copy_from_slice(&q);
}

/// Validate a Mode-1 sector's P and Q ECC (returns `false` if either parity
/// region disagrees with the recomputed value, or the sector is too short).
pub fn mode1_ecc_valid(sector: &[u8]) -> bool {
    if sector.len() < 2352 {
        return false;
    }
    let (f, b) = ecc_luts();
    let p = ecc_block(sector, 86, 24, 2, 86, &f, &b);
    if sector[2076..2248] != p[..] {
        return false;
    }
    let q = ecc_block(sector, 52, 43, 86, 88, &f, &b);
    sector[2248..2352] == q[..]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cd_ecc_validates_and_detects_tamper() {
        // Build a Mode-1 sector: sync, mode, data, EDC, then stamp P/Q ECC.
        let mut sector = vec![0u8; 2352];
        sector[1..11].fill(0xFF);
        sector[15] = 1;
        for (i, b) in sector[16..2064].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let edc = cd_edc(&sector[0..2064]);
        sector[2064..2068].copy_from_slice(&edc.to_le_bytes());
        cd_ecc_stamp(&mut sector);

        // A correctly stamped sector validates.
        assert!(mode1_ecc_valid(&sector), "stamped ECC must validate");
        // Tampering data invalidates the P/Q parity.
        sector[100] ^= 0xFF;
        assert!(!mode1_ecc_valid(&sector), "tamper must invalidate ECC");
    }

    #[test]
    fn cd_ecc_all_zero_sector_is_valid() {
        // A linear code over an all-zero ECC-covered region yields zero parity,
        // so an all-zero sector has (trivially) valid ECC.
        assert!(mode1_ecc_valid(&[0u8; 2352]));
    }

    #[test]
    fn cd_edc_validates_and_detects_tamper() {
        // Build a Mode-1 sector with arbitrary user data, then stamp the EDC.
        let mut sector = vec![0u8; 2352];
        sector[1..11].fill(0xFF); // sync
        sector[15] = 1; // mode 1
        for (i, b) in sector[16..2064].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let edc = cd_edc(&sector[0..2064]);
        sector[2064..2068].copy_from_slice(&edc.to_le_bytes());

        // A correctly stamped sector: recomputed EDC matches the stored value.
        let stored = u32::from_le_bytes(sector[2064..2068].try_into().unwrap());
        assert_eq!(cd_edc(&sector[0..2064]), stored, "valid EDC must match");
        // CRC property: EDC over (data || EDC) is zero.
        assert_eq!(cd_edc(&sector[0..2068]), 0, "EDC over data+EDC must be zero");

        // Tampering one data byte breaks the match (data changed, EDC stale).
        sector[100] ^= 0xFF;
        assert_ne!(cd_edc(&sector[0..2064]), stored, "tamper must invalidate EDC");
    }
}
