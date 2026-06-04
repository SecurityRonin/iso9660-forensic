//! Alcohol 120% MDS/MDF image parser.
//!
//! An Alcohol image is a pair: a `.mds` *descriptor* and a `.mdf` holding the
//! raw track data.  The descriptor is a little-endian forward tree — an
//! 88-byte header (`"MEDIA DESCRIPTOR"` + `0x01`) points at 24-byte session
//! blocks, each pointing at 80-byte track blocks, each linking to an 8-byte
//! extra block.  A track block carries the explicit sector size, the track's
//! byte offset within the `.mdf` (`start_offset`), and (via the extra block)
//! the track length in sectors.
//!
//! This parser reads the descriptor into a track table so the data track can be
//! located and sized within the `.mdf`.  Byte layout follows the libmirage
//! reference parser (cdemu `image-mds`).  No real `.mds` sample was available;
//! the layout is exercised with byte-faithful fixtures (real-sample validation
//! pending).

use std::io::{Read, Seek, SeekFrom};

use crate::sector::SectorMode;
use crate::IsoError;

const SIGNATURE: &[u8; 16] = b"MEDIA DESCRIPTOR";
const HEADER_LEN: usize = 88;
const SESSION_BLOCK_LEN: usize = 24;
const TRACK_BLOCK_LEN: usize = 80;
/// Cap on session/track counts, guarding against a corrupt descriptor.
const MAX_BLOCKS: usize = 4096;

/// One track described by an MDS descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdsTrack {
    /// TOC point / track number (1–99 for real tracks).
    pub point: u8,
    /// Alcohol track mode byte.
    pub mode: u8,
    /// Subchannel mode byte (0 = none).
    pub subchannel: u8,
    /// Stored bytes per sector.
    pub sector_size: u16,
    /// Track start LBA on the disc.
    pub start_sector: u32,
    /// Byte offset of the track's data within the `.mdf`.
    pub start_offset: u64,
    /// Track length in sectors (from the extra block).
    pub num_sectors: u32,
}

impl MdsTrack {
    /// The [`SectorMode`] for reading this track's data, or `None` for audio /
    /// unknown tracks.
    #[must_use]
    pub fn sector_mode(&self) -> Option<SectorMode> {
        sector_mode_for(self.mode, self.sector_size)
    }

    /// True for a filesystem-bearing data track (non-audio).
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.sector_mode().is_some()
    }

    /// Track data length in bytes within the `.mdf`.
    #[must_use]
    pub fn data_size(&self) -> u64 {
        u64::from(self.num_sectors) * u64::from(self.sector_size)
    }
}

/// A parsed MDS descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdsImage {
    /// Medium type code from the header.
    pub medium_type: u16,
    /// Tracks across all sessions, in declaration order.
    pub tracks: Vec<MdsTrack>,
}

impl MdsImage {
    /// Number of (real) tracks in the image.
    #[must_use]
    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }

    /// The first filesystem-bearing data track, for locating the ISO data.
    #[must_use]
    pub fn data_track(&self) -> Option<&MdsTrack> {
        self.tracks.iter().find(|t| t.is_data())
    }
}

/// Map an Alcohol mode byte and stored sector size to a [`SectorMode`], or
/// `None` for audio / unknown.
///
/// Mode `0x02` is CD-ROM Mode 1; `0x01` is audio; the rest (`0x00`, `0x03`–
/// `0x05`, `0x07`) are Mode 2 variants (libmirage `image-mds`).  The stored
/// sector size determines whether the user data is bare (2048/2336) or framed
/// (2352/2448).
#[must_use]
pub fn sector_mode_for(mode: u8, sector_size: u16) -> Option<SectorMode> {
    match sector_size {
        2048 => Some(SectorMode::Iso2048),
        2336 => Some(SectorMode::Mode2_2336),
        2352 => match mode {
            0x01 => None,                        // audio
            0x02 => Some(SectorMode::Raw2352),   // Mode 1
            _ => Some(SectorMode::Raw2352Mode2), // Mode 2 family
        },
        2448 => match mode {
            0x01 => None,
            0x02 => Some(SectorMode::Raw2448),
            _ => Some(SectorMode::Raw2448Mode2),
        },
        _ => None,
    }
}

/// Parse an MDS descriptor into an [`MdsImage`].
pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<MdsImage, IsoError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let header = read_at(reader, 0, HEADER_LEN)?;
    if &header[0..16] != SIGNATURE {
        return Err(IsoError::NotAnIso);
    }
    let medium_type = le16(&header[18..20]);
    let num_sessions = le16(&header[20..22]) as usize;
    let sessions_offset = u64::from(le32(&header[80..84]));

    let mut tracks = Vec::new();
    for s in 0..num_sessions.min(MAX_BLOCKS) {
        let off = sessions_offset + (s * SESSION_BLOCK_LEN) as u64;
        let Ok(session) = read_at(reader, off, SESSION_BLOCK_LEN) else {
            break;
        };
        let num_all_blocks = session[10] as usize;
        let tracks_offset = u64::from(le32(&session[20..24]));
        for b in 0..num_all_blocks.min(MAX_BLOCKS) {
            let toff = tracks_offset + (b * TRACK_BLOCK_LEN) as u64;
            let Ok(tb) = read_at(reader, toff, TRACK_BLOCK_LEN) else {
                break;
            };
            let point = tb[4];
            if !(1..=99).contains(&point) {
                continue; // lead-in / lead-out / control block
            }
            let extra_offset = u64::from(le32(&tb[12..16]));
            let num_sectors = read_extra_length(reader, extra_offset, file_size);
            tracks.push(MdsTrack {
                point,
                mode: tb[0],
                subchannel: tb[1],
                sector_size: le16(&tb[16..18]),
                start_sector: le32(&tb[36..40]),
                start_offset: le64(&tb[40..48]),
                num_sectors,
            });
        }
    }

    Ok(MdsImage { medium_type, tracks })
}

/// Read the track length (in sectors) from an 8-byte extra block, or 0 if the
/// offset is unset / out of range.
fn read_extra_length<R: Read + Seek>(reader: &mut R, offset: u64, file_size: u64) -> u32 {
    if offset == 0 || offset + 8 > file_size {
        return 0;
    }
    match read_at(reader, offset, 8) {
        Ok(extra) => le32(&extra[4..8]), // [0..4] pregap, [4..8] length
        Err(_) => 0,
    }
}

/// Read exactly `len` bytes at absolute `offset`.
fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> Result<Vec<u8>, IsoError> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[0..8].try_into().unwrap())
}
