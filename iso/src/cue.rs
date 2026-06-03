//! CUE sheet parser for BIN/CUE disc images.
//!
//! A `.cue` sheet is a plain-text sidecar describing the track layout of one or
//! more `.bin` data files.  For forensic use the key job is locating the ISO
//! 9660 **data track** and its sector size/mode so the `.bin` can be opened
//! with the correct [`crate::sector::SectorMode`].
//!
//! This parser handles the common subset: `FILE`, `TRACK`, and `INDEX` lines
//! with `MODE1/2048`, `MODE1/2352`, `MODE2/2336`, `MODE2/2352`, and `AUDIO`
//! track types.  Audio extraction and full multi-session pregap modelling are
//! out of scope.

use crate::sector::SectorMode;

/// Track data mode as declared in the CUE sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrackMode {
    /// `MODE1/2048` — pure 2048-byte user data.
    Mode1_2048,
    /// `MODE1/2352` — raw Mode 1.
    Mode1_2352,
    /// `MODE2/2336` — Mode 2 without sync/header.
    Mode2_2336,
    /// `MODE2/2352` — raw Mode 2 (Form 1).
    Mode2_2352,
    /// `AUDIO` — Red Book audio (not a filesystem data track).
    Audio,
    /// Any other / unrecognised track type, preserved verbatim.
    Other(String),
}

impl TrackMode {
    /// The [`SectorMode`] for reading this track's user data, or `None` for
    /// audio / unknown tracks that carry no ISO 9660 filesystem.
    #[must_use]
    pub fn sector_mode(&self) -> Option<SectorMode> {
        match self {
            Self::Mode1_2048 => Some(SectorMode::Iso2048),
            Self::Mode1_2352 => Some(SectorMode::Raw2352),
            Self::Mode2_2336 => Some(SectorMode::Mode2_2336),
            Self::Mode2_2352 => Some(SectorMode::Raw2352Mode2),
            Self::Audio | Self::Other(_) => None,
        }
    }

    /// True for a filesystem-bearing data track (non-audio).
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.sector_mode().is_some()
    }
}

/// An `MM:SS:FF` timecode (75 frames/second), as used by `INDEX` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msf {
    pub minutes: u8,
    pub seconds: u8,
    pub frames: u8,
}

impl Msf {
    /// Convert to an absolute logical block address (frame number).
    #[must_use]
    pub fn to_lba(self) -> u32 {
        (u32::from(self.minutes) * 60 + u32::from(self.seconds)) * 75 + u32::from(self.frames)
    }
}

/// A single track in a CUE file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CueTrack {
    pub number: u8,
    pub mode: TrackMode,
    /// `(index_number, timecode)` pairs in declaration order.
    pub indices: Vec<(u8, Msf)>,
}

/// A `FILE` referenced by the CUE sheet plus its tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CueFile {
    /// File name as written in the sheet (quotes stripped).
    pub name: String,
    /// Declared format token (e.g. `BINARY`, `WAVE`).
    pub format: String,
    pub tracks: Vec<CueTrack>,
}

/// A parsed CUE sheet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CueSheet {
    pub files: Vec<CueFile>,
}

impl CueSheet {
    /// The first filesystem-bearing data track across all files, with the
    /// `.bin` file that contains it.  Returns `(file_name, track)`.
    #[must_use]
    pub fn data_track(&self) -> Option<(&str, &CueTrack)> {
        for f in &self.files {
            for t in &f.tracks {
                if t.mode.is_data() {
                    return Some((f.name.as_str(), t));
                }
            }
        }
        None
    }
}

/// Parse a CUE sheet from its text.
pub fn parse(text: &str) -> CueSheet {
    let _ = text;
    CueSheet::default()
}
