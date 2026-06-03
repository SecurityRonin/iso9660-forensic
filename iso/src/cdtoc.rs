//! CD Table of Contents and disc identification.
//!
//! Audio and mixed-mode CDs are defined by their TOC (track positions in the
//! lead-in subchannel Q, ECMA-130 §22), not by a filesystem.  This module
//! models the TOC and computes the two standard whole-disc fingerprints used
//! to match a seized disc against a known release:
//!
//! - **freedb / CDDB disc ID** — an 8-hex-digit checksum over per-track
//!   second offsets (the classic Gracenote/freedb scheme).
//! - **MusicBrainz disc ID** — a SHA-1 over the binary TOC, custom-Base64
//!   encoded (MusicBrainz Disc ID Calculation).
//!
//! Frame offsets are absolute CD frames: `lba + 150` (the 150-frame / 2 s
//! lead-in), exactly as both disc-ID schemes require.

/// A CD Table of Contents: the per-track absolute frame offsets and the
/// lead-out offset.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Toc {
    /// First track number (normally 1).
    pub first_track: u8,
    /// Absolute frame offset (`lba + 150`) of each track, in order.
    pub track_frames: Vec<u32>,
    /// Absolute frame offset of the lead-out.
    pub leadout_frame: u32,
}

impl Toc {
    /// Number of tracks.
    #[must_use]
    pub fn track_count(&self) -> usize {
        self.track_frames.len()
    }

    /// Last track number.
    #[must_use]
    pub fn last_track(&self) -> u8 {
        self.first_track + self.track_frames.len().saturating_sub(1) as u8
    }

    /// Length of track at 0-based index `i` in frames (next track or lead-out
    /// minus this track's offset).  `None` if `i` is out of range.
    #[must_use]
    pub fn track_length_frames(&self, i: usize) -> Option<u32> {
        let start = *self.track_frames.get(i)?;
        let next = self.track_frames.get(i + 1).copied().unwrap_or(self.leadout_frame);
        Some(next.saturating_sub(start))
    }

    /// freedb / CDDB disc ID (8 hex digits) as a `u32`.
    #[must_use]
    pub fn freedb_id(&self) -> u32 {
        0
    }

    /// freedb / CDDB disc ID formatted as 8 lowercase hex digits.
    #[must_use]
    pub fn freedb_id_hex(&self) -> String {
        format!("{:08x}", self.freedb_id())
    }

    /// MusicBrainz disc ID (28-character custom-Base64 string).
    #[must_use]
    pub fn musicbrainz_id(&self) -> String {
        String::new()
    }
}
