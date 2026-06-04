//! CD subchannel Q decoding (ECMA-130 §22).
//!
//! The Q subchannel carries a disc's control information: per-section track /
//! index / timing (Q-mode 1), the disc Media Catalogue Number (Q-mode 2), and —
//! for audio tracks — ISRC (Q-mode 3, deferred to IEC 908 and not decoded here).
//!
//! Input is a **12-byte deinterleaved Q frame**: byte 0 = Control (high nibble)
//! + ADR/Q-mode (low nibble); bytes 1–9 = the 9-byte Q-data field; bytes 10–11 =
//! the 16-bit CRC (`G(x) = x^16 + x^12 + x^5 + 1`, inverted, big-endian).

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
    Position {
        track: TrackNo,
        index: u8,
        relative: Msf,
        absolute: Msf,
    },
    /// Q-mode 2: 13-digit Media Catalogue Number (EAN/UPC).
    Catalog(String),
    /// Q-mode 3 (ISRC) or any other ADR — raw ADR value, not decoded.
    Other(u8),
}

/// A decoded Q-channel frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QFrame {
    pub control: Control,
    pub adr: u8,
    pub data: QData,
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
            let track = if q[0] == 0xAA {
                TrackNo::LeadOut
            } else {
                TrackNo::Track(bcd(q[0]))
            };
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
        other => QData::Other(other),
    };

    Some(QFrame { control, adr, data })
}

/// Decode one packed BCD byte to its decimal value (0–99).
fn bcd(b: u8) -> u8 {
    (b >> 4) * 10 + (b & 0x0F)
}
