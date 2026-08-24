//! CD Table of Contents and disc identification.
//!
//! Audio and mixed-mode CDs are defined by their TOC (track positions in the
//! lead-in subchannel Q, ECMA-130 §22), not by a filesystem.  This module
//! models the TOC and computes the two standard whole-disc fingerprints used
//! to match a seized disc against a known release:
//!
//! - **freedb / CDDB disc ID** — an 8-hex-digit checksum over per-track
//!   second offsets (the classic Gracenote/freedb scheme).
//! - **`MusicBrainz` disc ID** — a SHA-1 over the binary TOC, custom-Base64
//!   encoded (`MusicBrainz` Disc ID Calculation).
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
    /// Build a TOC from a parsed CUE sheet and the total disc length in frames.
    ///
    /// Uses each track's `INDEX 01` timecode as its absolute disc LBA (the
    /// single-FILE CUE convention) and adds the 150-frame lead-in to obtain
    /// disc-ID frame offsets; the lead-out is `total_frames + 150`.
    /// `total_frames` is the `.bin` size in CD frames (`bytes / 2352` for raw
    /// audio).  Returns `None` if the sheet has no tracks.
    #[must_use]
    pub fn from_cue(sheet: &crate::cue::CueSheet, total_frames: u32) -> Option<Self> {
        const LEAD_IN: u32 = 150;
        // Collect tracks across all files in declaration order, using INDEX 01
        // (the track start; falls back to INDEX 00 / pregap if no 01).
        let mut numbers = Vec::new();
        let mut frames = Vec::new();
        for file in &sheet.files {
            for track in &file.tracks {
                let idx = track
                    .indices
                    .iter()
                    .find(|(n, _)| *n == 1)
                    .or_else(|| track.indices.first())?;
                numbers.push(track.number);
                frames.push(idx.1.to_lba() + LEAD_IN);
            }
        }
        if frames.is_empty() {
            return None;
        }
        Some(Self {
            first_track: numbers[0],
            track_frames: frames,
            leadout_frame: total_frames + LEAD_IN,
        })
    }

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
    ///
    /// `id = ((Σ digitsum(track_secs) % 255) << 24) | (total_secs << 8) | n`,
    /// where `track_secs = frame / 75` and `total_secs = leadout/75 −
    /// track1/75` (the classic freedb scheme).
    #[must_use]
    pub fn freedb_id(&self) -> u32 {
        let digit_sum = |mut n: u32| -> u32 {
            let mut s = 0;
            while n > 0 {
                s += n % 10;
                n /= 10;
            }
            s
        };
        let n: u32 = self.track_frames.iter().map(|&f| digit_sum(f / 75)).sum();
        let first = self.track_frames.first().copied().unwrap_or(0);
        let total = (self.leadout_frame / 75).saturating_sub(first / 75);
        ((n % 255) << 24) | (total << 8) | (self.track_count() as u32 & 0xff)
    }

    /// freedb / CDDB disc ID formatted as 8 lowercase hex digits.
    #[must_use]
    pub fn freedb_id_hex(&self) -> String {
        format!("{:08x}", self.freedb_id())
    }

    /// `MusicBrainz` disc ID (28-character custom-Base64 string).
    ///
    /// SHA-1 over the upper-case-hex TOC string — `%02X` first track, `%02X`
    /// last track, then 100 `%08X` frame offsets (offset 0 = lead-out, 1..=99
    /// = tracks, padded with 0) — then Base64 with `+/=` mapped to `._-`.
    #[must_use]
    pub fn musicbrainz_id(&self) -> String {
        use std::fmt::Write as _;

        use sha1::{Digest, Sha1};

        let mut fo = [0u32; 100];
        fo[0] = self.leadout_frame;
        let first = self.first_track as usize;
        for (k, &f) in self.track_frames.iter().enumerate() {
            let idx = first + k;
            if idx < fo.len() {
                fo[idx] = f;
            }
        }

        let mut s = format!("{:02X}{:02X}", self.first_track, self.last_track());
        for v in fo {
            let _ = write!(s, "{v:08X}");
        }

        let digest = Sha1::digest(s.as_bytes());
        base64_musicbrainz(&digest)
    }
}

/// Base64-encode 20 SHA-1 bytes using `MusicBrainz`'s alphabet (`+/=` → `._-`).
fn base64_musicbrainz(data: &[u8]) -> String {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(STD[(n >> 18 & 63) as usize] as char);
        out.push(STD[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { STD[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { STD[(n & 63) as usize] as char } else { '=' });
    }
    // MusicBrainz substitutes the URL-unsafe characters.
    out.replace('+', ".").replace('/', "_").replace('=', "-")
}
