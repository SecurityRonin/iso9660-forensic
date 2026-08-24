//! `DiscJuggler` (CDI) image detection and track-table decoding.
//!
//! A `DiscJuggler` image stores its table of contents in a trailing descriptor:
//! the last 4 bytes are the descriptor length (little-endian `u32`), and the 4
//! bytes before that are the `DiscJuggler` version (`0x8000_0004`/`5`/`6`).
//! [`detect`] reads that footer alone.
//!
//! [`tracks`] decodes the descriptor's track table.  Unlike the offset-tree
//! formats (MDS), the CDI descriptor is a *self-delimiting* byte stream: a
//! session header, then one variable-length record per track (a length-prefixed
//! filename, `maxI` index longwords, `maxC`×18 CD-Text packs, then a fixed
//! geometry block).  Every field must be walked byte-exactly or all later tracks
//! misalign — there are no back-pointers.  The layout and the
//! `trackMode`/`readMode`→sector-size mapping are ported from the Aaru
//! (`DiscImageChef`) `DiscJuggler/Read.cs` reference reader and cross-validated,
//! byte-for-byte, against real Dreamcast `.cdi` images using `aaru image info`
//! as an independent oracle.  Reads are fully bounds-checked: a malformed or
//! truncated descriptor yields `None` rather than panicking.

use std::io::{Read, Seek, SeekFrom};

/// Known `DiscJuggler` descriptor version markers (libmirage `image-cdi`).
const VERSIONS: [u32; 3] = [0x8000_0004, 0x8000_0005, 0x8000_0006];

/// Detection result for a `DiscJuggler` image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdiInfo {
    /// `DiscJuggler` version marker (`0x8000_0004`/`5`/`6`).
    pub version: u32,
    /// Length of the trailing descriptor in bytes.
    pub descriptor_length: u32,
}

/// Detect a `DiscJuggler` image from its trailing footer.
///
/// Returns `None` unless the last 8 bytes carry a known version marker and a
/// descriptor length that fits within the file.
pub fn detect<R: Read + Seek>(reader: &mut R) -> Option<CdiInfo> {
    let size = reader.seek(SeekFrom::End(0)).ok()?;
    if size < 8 {
        return None;
    }
    reader.seek(SeekFrom::End(-8)).ok()?;
    let mut tail = [0u8; 8];
    reader.read_exact(&mut tail).ok()?;
    let version = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
    let descriptor_length = u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]);
    if !VERSIONS.contains(&version) {
        return None;
    }
    if descriptor_length == 0 || u64::from(descriptor_length) > size {
        return None;
    }
    Some(CdiInfo { version, descriptor_length })
}

/// CD track kind, decoded from a `DiscJuggler` `trackMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdiTrackKind {
    /// Red Book audio (`trackMode` 0).
    Audio,
    /// Yellow Book Mode 1 data, or a DVD track (`trackMode` 1).
    Mode1,
    /// Mode 2 formless / CD-ROM XA (`trackMode` 2).
    Mode2Formless,
}

/// One track decoded from a `DiscJuggler` descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdiTrack {
    /// 1-based session number this track belongs to.
    pub session: u16,
    /// 1-based track sequence across the whole image.
    pub sequence: u32,
    /// Track kind from `trackMode`.
    pub kind: CdiTrackKind,
    /// Track start LBA (`DiscJuggler`'s first-track pregap is normalised so the
    /// reported start matches MMC, as Aaru does).
    pub start_sector: u32,
    /// Track length in sectors.
    pub length_sectors: u32,
    /// Logical user-data bytes per sector (2048 / 2336 / 2352).
    pub bytes_per_sector: u16,
    /// Bytes stored per sector in the image (`readMode`-dependent).
    pub raw_bytes_per_sector: u16,
}

impl CdiTrack {
    /// Last LBA of the track (inclusive).
    #[must_use]
    pub fn end_sector(&self) -> u32 {
        self.start_sector.saturating_add(self.length_sectors).saturating_sub(1)
    }
}

/// Decode the track table of a `DiscJuggler` image.
///
/// Returns `None` if the image is not a recognised `DiscJuggler` container, if the
/// descriptor is truncated/malformed, or if it carries no decodable tracks.
pub fn tracks<R: Read + Seek>(reader: &mut R) -> Option<Vec<CdiTrack>> {
    let info = detect(reader)?;
    let size = reader.seek(SeekFrom::End(0)).ok()?;
    let dsc_len = u64::from(info.descriptor_length);
    if dsc_len > size {
        return None;
    }
    reader.seek(SeekFrom::Start(size - dsc_len)).ok()?;
    let mut descriptor = vec![0u8; info.descriptor_length as usize];
    reader.read_exact(&mut descriptor).ok()?;
    parse_descriptor(&descriptor)
}

/// True if a 15-byte `DiscJuggler` session header begins at `p`.  Byte 1 carries
/// the track count and is therefore unconstrained.
fn is_session_header(d: &[u8], p: usize) -> bool {
    let Some(s) = d.get(p..p + 15) else {
        return false;
    };
    s[0] == 0x00
        && s[2] == 0x00
        && s[3] == 0x00
        && s[4] == 0x00
        && s[5] == 0x00
        && s[6] == 0x00
        && s[7] == 0x00
        && s[8] == 0x00
        && s[9] == 0x01
        && s[10] == 0x00
        && s[11] == 0x00
        && s[12] == 0x00
        && s[13] == 0xFF
        && s[14] == 0xFF
}

fn rd_u16(d: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(p..p + 2)?.try_into().ok()?))
}

fn rd_u32(d: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?))
}

/// Walk the descriptor's session/track records into a track table.
fn parse_descriptor(d: &[u8]) -> Option<Vec<CdiTrack>> {
    let max_s = *d.first()?;
    if max_s == 0 || max_s > 99 {
        return None;
    }
    let mut pos = 1usize;
    let mut tracks: Vec<CdiTrack> = Vec::new();
    let mut session_no: u16 = 0;

    // Aaru iterates s in 0..=maxS: the trailing pass lands on the open/last
    // session terminator, which fails the header check and ends the walk.
    for _s in 0..=max_s {
        if !is_session_header(d, pos) {
            // A generated (non-dumped) image can pad between the last written
            // session and the next open one; scan forward for the next header.
            let mut found = false;
            while pos + 16 < d.len() {
                if is_session_header(d, pos) {
                    found = true;
                    break;
                }
                pos += 1;
            }
            if !found {
                break;
            }
            // A header found here marks the terminating open session; stop.
            break;
        }
        let max_t = d.get(pos + 1).copied()?;
        if max_t > 99 {
            return None;
        }
        session_no += 1;
        pos += 15;
        for _t in 0..max_t {
            let sequence = u32::try_from(tracks.len()).ok()?.checked_add(1)?;
            let track = parse_track(d, &mut pos, session_no, sequence)?;
            tracks.push(track);
        }
    }

    if tracks.is_empty() {
        None
    } else {
        Some(tracks)
    }
}

/// Parse one track record starting at `*pos`, advancing `*pos` past it.
///
/// Field order is taken verbatim from Aaru's `DiscJuggler/Read.cs`.  The two
/// length adjustments encode `DiscJuggler`'s quirk of counting the first track's
/// pregap from 0 instead of −150.
fn parse_track(d: &[u8], pos: &mut usize, session: u16, sequence: u32) -> Option<CdiTrack> {
    let mut p = pos.checked_add(16)?; // skip unknown
    let flen = *d.get(p)? as usize;
    p = p.checked_add(1)?.checked_add(flen)?; // length-prefixed filename
    p = p.checked_add(29)?; // skip unknown
    let _medium_type = rd_u16(d, p)?;
    p = p.checked_add(2)?;

    // Indices: a count, then that many longwords (index *lengths*, per Aaru).
    let max_i = rd_u16(d, p)? as usize;
    p = p.checked_add(2)?;
    p = p.checked_add(max_i.checked_mul(4)?)?;

    // CD-Text: maxC groups of 18 length-prefixed packs.
    let max_c = rd_u32(d, p)? as usize;
    p = p.checked_add(4)?;
    for _c in 0..max_c {
        for _cb in 0..18 {
            let b_len = *d.get(p)? as usize;
            p = p.checked_add(1)?;
            if b_len > 0 {
                p = p.checked_add(b_len)?;
            }
        }
    }

    p = p.checked_add(2)?;
    let track_mode = rd_u32(d, p)?;
    p = p.checked_add(4)?;
    p = p.checked_add(4)?; // skip unknown
    let _session_seq = rd_u32(d, p)?;
    p = p.checked_add(4)?;
    let _track_seq = rd_u32(d, p)?; // read in place; advanced below
    p = p.checked_add(4)?;
    let mut start_sector = rd_u32(d, p)?;
    p = p.checked_add(4)?;
    let mut track_len = rd_u32(d, p)?; // read in place; advanced below
    if start_sector == 0 {
        track_len = track_len.saturating_sub(150);
    } else {
        start_sector = start_sector.saturating_sub(150);
    }
    p = p.checked_add(4)?;
    p = p.checked_add(16)?; // skip unknown
    let read_mode = rd_u32(d, p)?;
    p = p.checked_add(4)?;
    let _track_ctl = rd_u32(d, p)?;
    p = p.checked_add(4)?;
    p = p.checked_add(9)?; // skip unknown
    p = p.checked_add(12)?; // ISRC
    let _isrc_valid = rd_u32(d, p)?;
    p = p.checked_add(4)?;
    p = p.checked_add(87)?; // skip unknown
    let _session_type = *d.get(p)?;
    p = p.checked_add(1)?;
    p = p.checked_add(5)?; // skip unknown
    let _track_follows = *d.get(p)?;
    p = p.checked_add(2)?;
    let _end_address = rd_u32(d, p)?;
    p = p.checked_add(4)?;

    let (kind, bytes_per_sector, raw_bytes_per_sector) = decode_mode(track_mode, read_mode)?;
    *pos = p;
    Some(CdiTrack {
        session,
        sequence,
        kind,
        start_sector,
        length_sectors: track_len,
        bytes_per_sector,
        raw_bytes_per_sector,
    })
}

/// Map a `DiscJuggler` `trackMode`/`readMode` pair to (kind, logical size, stored
/// size).  Mirrors the switch in Aaru's reader; unknown combinations yield
/// `None`.
fn decode_mode(track_mode: u32, read_mode: u32) -> Option<(CdiTrackKind, u16, u16)> {
    match track_mode {
        // Audio: always 2352 logical; subchannel (readMode 3/4) is stored
        // alongside but does not change the raw user-data sector size.
        0 => match read_mode {
            2..=4 => Some((CdiTrackKind::Audio, 2352, 2352)),
            _ => None,
        },
        // Mode 1 (or DVD): 2048 logical; stored 2048 (readMode 0) or 2352.
        1 => {
            let raw = match read_mode {
                0 => 2048,
                2..=4 => 2352,
                _ => return None,
            };
            Some((CdiTrackKind::Mode1, 2048, raw))
        }
        // Mode 2 formless: 2336 logical; stored 2336 (readMode 1) or 2352.
        2 => {
            let raw = match read_mode {
                1 => 2336,
                2..=4 => 2352,
                _ => return None,
            };
            Some((CdiTrackKind::Mode2Formless, 2336, raw))
        }
        _ => None,
    }
}
