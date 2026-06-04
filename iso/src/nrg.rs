//! Nero NRG image parser.
//!
//! An NRG image is a single binary file whose table of contents lives in a
//! **footer** at end-of-file: a magic plus a back-pointer to a list of chunks.
//! v2 footers are `"NER5"` + a 64-bit big-endian offset (12 bytes at EOF); v1
//! footers are `"NERO"` + a 32-bit offset (8 bytes).  From that offset a chunk
//! list runs `[4-byte ID][u32 BE size][data]…` until an `"END!"` chunk.
//!
//! The track geometry comes from either DAO chunks (`DAOX` 64-bit / `DAOI`
//! 32-bit — disc-at-once, carrying a 13-char MCN header and per-track
//! ISRC/sector-size/mode/offsets) or ETN chunks (`ETN2` 64-bit / `ETNF` 32-bit
//! — track-at-once).  Byte layout and the mode-code table follow the libmirage
//! reference parser (cdemu `image-nrg/parser.c`).
//!
//! This parser extracts the forensic essentials — version, MCN, and the track
//! table (file offset, size, mode, sector size, ISRC) — so the data track can
//! be located within the `.nrg` and matched against a known disc.  No real
//! `.nrg` sample was available; the layout is grounded in the reference parser
//! and exercised with byte-faithful fixtures (real-sample validation pending).

use std::io::{Read, Seek, SeekFrom};

use crate::sector::SectorMode;
use crate::IsoError;

/// Largest chunk this parser will buffer, guarding against a malformed size.
const MAX_CHUNK: usize = 16 * 1024 * 1024;

/// NRG container version, distinguished by the footer magic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NrgVersion {
    /// `"NERO"` footer with a 32-bit trailer offset (older images).
    V1,
    /// `"NER5"` footer with a 64-bit trailer offset.
    V2,
}

/// One track within an NRG image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrgTrack {
    /// 1-based track number in declaration order.
    pub number: u8,
    /// Nero mode code (see [`sector_mode_for`]).
    pub mode_code: u8,
    /// Byte offset of the track's data within the `.nrg` file.
    pub start_offset: u64,
    /// Track data length in bytes.
    pub size: u64,
    /// Stored bytes per sector (main + subchannel) for this track.
    pub sector_size: u16,
    /// Disc logical block address of the track start (ETN tracks; 0 for DAO).
    pub start_lba: u32,
    /// International Standard Recording Code, if present (DAO tracks).
    pub isrc: Option<String>,
}

impl NrgTrack {
    /// The [`SectorMode`] for reading this track's data, or `None` for audio /
    /// unknown tracks (no ISO 9660 filesystem).
    #[must_use]
    pub fn sector_mode(&self) -> Option<SectorMode> {
        sector_mode_for(self.mode_code)
    }

    /// True for a filesystem-bearing data track (non-audio).
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.sector_mode().is_some()
    }
}

/// A parsed NRG image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrgImage {
    pub version: NrgVersion,
    /// Disc Media Catalogue Number (from the DAO header), if present.
    pub catalog: Option<String>,
    /// Tracks in declaration order.
    pub tracks: Vec<NrgTrack>,
}

impl NrgImage {
    /// Number of tracks in the image.
    #[must_use]
    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }

    /// The first filesystem-bearing data track, for locating the ISO data.
    #[must_use]
    pub fn data_track(&self) -> Option<&NrgTrack> {
        self.tracks.iter().find(|t| t.is_data())
    }
}

/// Map a Nero mode code to the [`SectorMode`] used to read the track's data,
/// or `None` for audio / unknown modes (libmirage `nrg_decode_mode`).
///
/// CloneCD/Nero store the *full* sector for raw modes; the offset of the ISO
/// 9660 user data within each sector is handled by [`SectorMode`].
#[must_use]
pub fn sector_mode_for(mode_code: u8) -> Option<SectorMode> {
    match mode_code {
        0x00 | 0x02 => Some(SectorMode::Iso2048), // Mode 1 / Mode 2 Form 1, user data only
        0x03 => Some(SectorMode::Mode2_2336),     // Mode 2 Form 2, user data only
        0x05 => Some(SectorMode::Raw2352),        // Mode 1, full sector
        0x06 => Some(SectorMode::Raw2352Mode2),   // Mode 2, full sector
        0x0F => Some(SectorMode::Raw2448),        // Mode 1, full sector + subchannel
        0x11 => Some(SectorMode::Raw2448Mode2),   // Mode 2, full sector + subchannel
        _ => None,                                // 0x07/0x10 audio, or unknown
    }
}

/// Default stored sector size for a mode code (main + subchannel bytes).
fn sector_size_for(mode_code: u8) -> u16 {
    match mode_code {
        0x00 | 0x02 => 2048,
        0x03 => 2336,
        0x0F..=0x11 => 2448,
        _ => 2352, // 0x05/0x06/0x07 full sector, and unknown
    }
}

/// Parse an NRG image's footer and chunk list into an [`NrgImage`].
pub fn parse<R: Read + Seek>(reader: &mut R) -> Result<NrgImage, IsoError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let (version, trailer_offset) = read_footer(reader, file_size)?;
    if trailer_offset >= file_size {
        return Err(IsoError::NotAnIso);
    }

    let mut catalog = None;
    let mut tracks = Vec::new();
    let mut pos = trailer_offset;
    reader.seek(SeekFrom::Start(pos))?;

    // Walk chunks until END!, EOF, or the footer.
    let footer_len = if version == NrgVersion::V2 { 12 } else { 8 };
    while pos + 8 <= file_size - footer_len {
        let mut head = [0u8; 8];
        if reader.read_exact(&mut head).is_err() {
            break;
        }
        let id = [head[0], head[1], head[2], head[3]];
        let size = u32::from_be_bytes([head[4], head[5], head[6], head[7]]) as usize;
        pos += 8;
        if &id == b"END!" {
            break;
        }
        if size > MAX_CHUNK || pos + size as u64 > file_size {
            break;
        }
        let mut data = vec![0u8; size];
        reader.read_exact(&mut data)?;
        pos += size as u64;

        match &id {
            b"DAOX" => parse_dao(&data, true, &mut catalog, &mut tracks),
            b"DAOI" => parse_dao(&data, false, &mut catalog, &mut tracks),
            b"ETN2" => parse_etn(&data, true, &mut tracks),
            b"ETNF" => parse_etn(&data, false, &mut tracks),
            _ => {} // CUEX/CUES/SINF/MTYP/CDTX etc. — not needed here
        }
    }

    Ok(NrgImage { version, catalog, tracks })
}

/// Read the NRG footer, returning the version and trailer offset.
fn read_footer<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
) -> Result<(NrgVersion, u64), IsoError> {
    if file_size >= 12 {
        reader.seek(SeekFrom::End(-12))?;
        let mut buf = [0u8; 12];
        reader.read_exact(&mut buf)?;
        if &buf[0..4] == b"NER5" {
            let off = u64::from_be_bytes(buf[4..12].try_into().unwrap());
            return Ok((NrgVersion::V2, off));
        }
    }
    if file_size >= 8 {
        reader.seek(SeekFrom::End(-8))?;
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        if &buf[0..4] == b"NERO" {
            let off = u32::from_be_bytes(buf[4..8].try_into().unwrap());
            return Ok((NrgVersion::V1, u64::from(off)));
        }
    }
    Err(IsoError::NotAnIso)
}

/// Parse a DAO chunk: a 22-byte header (MCN) then fixed-size track subblocks.
fn parse_dao(data: &[u8], wide: bool, catalog: &mut Option<String>, tracks: &mut Vec<NrgTrack>) {
    if data.len() < 22 {
        return;
    }
    if catalog.is_none() {
        if let Some(mcn) = ascii_field(&data[0..13]) {
            *catalog = Some(mcn);
        }
    }
    let sub_len = if wide { 42 } else { 30 };
    for sub in data[22..].chunks_exact(sub_len) {
        let sector_size = u16::from_be_bytes([sub[12], sub[13]]);
        let mode_code = sub[14];
        let (start, end) = if wide {
            (be64(&sub[26..34]), be64(&sub[34..42]))
        } else {
            (u64::from(be32(&sub[22..26])), u64::from(be32(&sub[26..30])))
        };
        let number = (tracks.len() + 1) as u8;
        tracks.push(NrgTrack {
            number,
            mode_code,
            start_offset: start,
            size: end.saturating_sub(start),
            sector_size,
            start_lba: 0,
            isrc: ascii_field(&sub[0..12]),
        });
    }
}

/// Parse an ETN chunk: fixed-size track subblocks, no header.
fn parse_etn(data: &[u8], wide: bool, tracks: &mut Vec<NrgTrack>) {
    let sub_len = if wide { 32 } else { 20 };
    for sub in data.chunks_exact(sub_len) {
        let (offset, size, mode_code, lba) = if wide {
            (be64(&sub[0..8]), be64(&sub[8..16]), sub[19], be32(&sub[20..24]))
        } else {
            (u64::from(be32(&sub[0..4])), u64::from(be32(&sub[4..8])), sub[11], be32(&sub[12..16]))
        };
        let number = (tracks.len() + 1) as u8;
        tracks.push(NrgTrack {
            number,
            mode_code,
            start_offset: offset,
            size,
            sector_size: sector_size_for(mode_code),
            start_lba: lba,
            isrc: None,
        });
    }
}

/// Decode a fixed-width ASCII field (NUL/space padded) to a string, or `None`
/// if empty.
fn ascii_field(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s: String = bytes[..end].iter().map(|&b| b as char).collect();
    let trimmed = s.trim_end_matches([' ', '\0']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[0..8].try_into().unwrap())
}
