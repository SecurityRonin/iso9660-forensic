//! CD subchannel Q decoding (ECMA-130 §22).
//!
//! The Q subchannel carries a disc's control information: per-section track /
//! index / timing (Q-mode 1), the disc Media Catalogue Number (Q-mode 2), and —
//! for audio tracks — ISRC (Q-mode 3, deferred to IEC 908 and not decoded here).
//!
//! Input is a **12-byte deinterleaved Q frame**: byte 0 = Control (high nibble)
//! plus ADR/Q-mode (low nibble); bytes 1–9 = the 9-byte Q-data field; bytes
//! 10–11 = the 16-bit CRC (`G(x) = x^16 + x^12 + x^5 + 1`, inverted, big-endian).

use crate::cue::Msf;

/// The 4-bit Control field (ECMA-130 §22.3.1; bit meanings per IEC 908).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control(pub u8);

impl Control {
    /// True if the track carries digital data (vs audio).
    #[must_use]
    pub fn is_data(self) -> bool {
        self.0 & 0b0100 != 0
    }
    /// True if digital copy is permitted.
    #[must_use]
    pub fn copy_permitted(self) -> bool {
        self.0 & 0b0010 != 0
    }
    /// True for four-channel audio (vs two-channel). Audio tracks only.
    #[must_use]
    pub fn four_channel(self) -> bool {
        self.0 & 0b1000 != 0
    }
    /// True if audio pre-emphasis is applied. Audio tracks only.
    #[must_use]
    pub fn pre_emphasis(self) -> bool {
        self.0 & 0b0001 != 0
    }
}

/// Track number in a Q-mode 1 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackNo {
    /// A numbered track (1–99).
    Track(u8),
    /// The lead-out track (TNO field = 0xAA).
    LeadOut,
}

/// Decoded Q-data, selected by the ADR / Q-mode field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QData {
    /// Q-mode 1: track/index position with relative and absolute timing.
    Position { track: TrackNo, index: u8, relative: Msf, absolute: Msf },
    /// Q-mode 2: 13-digit Media Catalogue Number (EAN/UPC).
    Catalog(String),
    /// Q-mode 3: 12-character International Standard Recording Code.
    Isrc(String),
    /// Any other ADR (e.g. Mode 5 TOC) — raw ADR value, not decoded.
    Other(u8),
}

/// A decoded Q-channel frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QFrame {
    pub control: Control,
    pub adr: u8,
    pub data: QData,
}

/// Extract the 12-byte Q subchannel from a raw 96-byte interleaved subcode
/// block (as found at offset 2352 of a 2448-byte sector).
///
/// ECMA-130 §18/§22: each subcode byte carries one bit of each of the eight
/// P–W channels — bit 7 = P, **bit 6 = Q**, bits 5–0 = R–W.  The 96 Q bits are
/// assembled MSB-first into 12 bytes (byte 0 = Control/ADR, … bytes 10–11 =
/// CRC).  Returns `None` if fewer than 96 bytes are supplied.
///
/// This is the de-facto interleaved ("raw P–W") layout used by most rippers;
/// fully de-interleaved/error-corrected R–W dumps are not handled here.
#[must_use]
pub fn extract_q(subchannel: &[u8]) -> Option<[u8; 12]> {
    if subchannel.len() < 96 {
        return None;
    }
    let mut q = [0u8; 12];
    for (bit, &byte) in subchannel[..96].iter().enumerate() {
        if byte & 0b0100_0000 != 0 {
            // bit 6 = Q; pack MSB-first into the 12-byte frame.
            q[bit / 8] |= 1 << (7 - (bit % 8));
        }
    }
    Some(q)
}

/// Disc-level identifiers gathered from a stream of Q frames.
///
/// The Media Catalogue Number (Q-mode 2) is a disc-wide value; ISRCs (Q-mode 3)
/// are per-track, but the frames carry no track number — the track is whichever
/// numbered track was current per the last Q-mode 1 position frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QSummary {
    /// The disc Media Catalogue Number (EAN/UPC), if any Q-mode 2 frame was seen.
    pub catalog: Option<String>,
    /// Per-track ISRCs, keyed by track number (1–99).
    pub isrcs: std::collections::BTreeMap<u8, String>,
}

/// Summarise the Q subchannel from a standalone subchannel file (CloneCD
/// `.sub`): 96 interleaved subcode bytes per sector, stored separately rather
/// than appended to each 2352-byte sector.
///
/// Each 96-byte block is deinterleaved via [`extract_q`], CRC-gated with
/// [`q_crc_valid`] so blank/garbage sectors are discarded, decoded, and folded
/// through [`summarize_q`].  Any trailing bytes shorter than one block are
/// ignored.  The interleaved P–W layout matches the 2448 in-sector subchannel.
#[must_use]
pub fn summarize_sub(sub: &[u8]) -> QSummary {
    let frames = sub
        .chunks_exact(96)
        .filter_map(extract_q)
        .filter(|raw| q_crc_valid(raw))
        .filter_map(|raw| decode_q(&raw));
    summarize_q(frames)
}

/// Collect disc-level identifiers from decoded Q frames **in disc order**.
///
/// Position frames (Q-mode 1) set the current track; an ISRC (Q-mode 3) is filed
/// under that track.  The lead-out (TNO 0xAA) is not a numbered track, so ISRCs
/// seen there are dropped.  The catalog (Q-mode 2) is disc-wide; the first seen
/// wins.  Order matters — pass frames as read from the disc.
#[must_use]
pub fn summarize_q<I: IntoIterator<Item = QFrame>>(frames: I) -> QSummary {
    let mut summary = QSummary::default();
    let mut current_track: Option<u8> = None;
    for frame in frames {
        match frame.data {
            QData::Position { track: TrackNo::Track(n), .. } => current_track = Some(n),
            QData::Position { track: TrackNo::LeadOut, .. } => current_track = None,
            QData::Catalog(mcn) => {
                summary.catalog.get_or_insert(mcn);
            }
            QData::Isrc(code) => {
                if let Some(n) = current_track {
                    summary.isrcs.entry(n).or_insert(code);
                }
            }
            QData::Other(_) => {}
        }
    }
    summary
}

/// Verify the 16-bit Q CRC (inverted CCITT, big-endian in bytes 10–11).
#[must_use]
pub fn q_crc_valid(frame: &[u8]) -> bool {
    if frame.len() < 12 {
        return false;
    }
    let computed = crate::cdtext::crc16_ccitt(&frame[0..10]) ^ 0xFFFF;
    let stored = u16::from_be_bytes([frame[10], frame[11]]);
    computed == stored
}

/// Decode a 12-byte (or ≥10-byte) deinterleaved Q frame.
///
/// Returns `None` if the frame is too short.  Does not require a valid CRC
/// (the CRC is optional on many dumps); check separately via [`q_crc_valid`].
#[must_use]
pub fn decode_q(frame: &[u8]) -> Option<QFrame> {
    if frame.len() < 10 {
        return None;
    }
    let control = Control(frame[0] >> 4);
    let adr = frame[0] & 0x0F;
    let q = &frame[1..10]; // 9-byte Q-data field

    let data = match adr {
        1 => {
            // Position: TNO, INDEX, rel MIN/SEC/FRAC, ZERO, abs MIN/SEC/FRAC (BCD).
            let track = if q[0] == 0xAA { TrackNo::LeadOut } else { TrackNo::Track(bcd(q[0])) };
            QData::Position {
                track,
                index: bcd(q[1]),
                relative: Msf { minutes: bcd(q[2]), seconds: bcd(q[3]), frames: bcd(q[4]) },
                absolute: Msf { minutes: bcd(q[6]), seconds: bcd(q[7]), frames: bcd(q[8]) },
            }
        }
        2 => {
            // Catalog: 13 BCD digits N1..N13 in the first 13 nibbles.
            let mut s = String::with_capacity(13);
            for i in 0..13 {
                let byte = q[i / 2];
                let nib = if i % 2 == 0 { byte >> 4 } else { byte & 0x0F };
                s.push((b'0' + (nib % 10)) as char);
            }
            QData::Catalog(s)
        }
        3 => QData::Isrc(decode_isrc(q)),
        other => QData::Other(other),
    };

    Some(QFrame { control, adr, data })
}

/// Decode a Q-mode 3 ISRC from the 9-byte Q-data field (MMC-3 Figure 5).
///
/// I1–I5 are 6-bit cells (Table 7); two zero bits follow; I6–I12 are BCD
/// digits.  Returns the 12-character ISRC.
fn decode_isrc(q: &[u8]) -> String {
    // I1..I5: 6-bit cells packed MSB-first across bytes 0–3 (bits 0..29).
    let cells = [
        q[0] >> 2,
        ((q[0] & 0x03) << 4) | (q[1] >> 4),
        ((q[1] & 0x0F) << 2) | (q[2] >> 6),
        q[2] & 0x3F,
        q[3] >> 2,
    ];
    let mut s = String::with_capacity(12);
    for &c in &cells {
        s.push(isrc_char(c));
    }
    // I6..I12: 4-bit BCD digits in the high/low nibbles of bytes 4–7.
    for &(byte, high) in
        &[(4, true), (4, false), (5, true), (5, false), (6, true), (6, false), (7, true)]
    {
        let nib = if high { q[byte] >> 4 } else { q[byte] & 0x0F };
        s.push((b'0' + (nib % 10)) as char);
    }
    s
}

/// Map a 6-bit ISRC cell to its character (MMC-3 Table 7).
fn isrc_char(code: u8) -> char {
    match code {
        0x00..=0x09 => (b'0' + code) as char,
        0x11..=0x2A => (b'A' + (code - 0x11)) as char,
        _ => '?',
    }
}

/// Decode one packed BCD byte to its decimal value (0–99).
fn bcd(b: u8) -> u8 {
    (b >> 4) * 10 + (b & 0x0F)
}
