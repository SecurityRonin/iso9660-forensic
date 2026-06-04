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
    let _ = frame;
    false
}

/// Decode a 12-byte (or ≥10-byte) deinterleaved Q frame.
///
/// Returns `None` if the frame is too short.  Does not require a valid CRC
/// (the CRC is optional on many dumps); check separately via [`q_crc_valid`].
#[must_use]
pub fn decode_q(frame: &[u8]) -> Option<QFrame> {
    let _ = frame;
    None
}
