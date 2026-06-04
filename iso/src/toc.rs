//! CDRDAO `.toc` parser for TOC/BIN optical images.
//!
//! A `.toc` file is the plain-text sidecar written by `cdrdao` (and by Aaru's
//! CDRDAO writer): an optional disc-type line (`CD_ROM` / `CD_DA` /
//! `CD_ROM_XA`), then one block per track introduced by a `TRACK <mode>` line
//! and pointing at its data via a `DATAFILE`/`AUDIOFILE` line.  It is the same
//! role as a `.cue` sheet — for forensic use the job is locating the ISO 9660
//! **data track**, its sector mode, and its byte offset within the data file.
//!
//! This parser handles the common subset: the disc type, `TRACK` modes
//! (`MODE1`, `MODE1_RAW`, `MODE2`, `MODE2_RAW`, `MODE2_FORM1`, `MODE2_FORM2`,
//! `AUDIO`), and `DATAFILE`/`AUDIOFILE` with an optional `#byte-offset` and an
//! `MM:SS:FF` length.  Track flags, `CD_TEXT`, `PREGAP`/`START`/`INDEX`,
//! `SILENCE`/`ZERO`/`FIFO`, and audio extraction are out of scope.  Field layout
//! validated against a real Aaru-produced TOC.

use crate::cue::Msf;
use crate::sector::SectorMode;

/// Track data mode as declared by a CDRDAO `TRACK` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TocMode {
    /// `MODE1` — 2048-byte cooked Mode 1.
    Mode1,
    /// `MODE1_RAW` — raw 2352-byte Mode 1.
    Mode1Raw,
    /// `MODE2` — 2336-byte Mode 2 (no sync/header).
    Mode2,
    /// `MODE2_RAW` — raw 2352-byte Mode 2.
    Mode2Raw,
    /// `MODE2_FORM1` — 2048-byte user data (XA Form 1).
    Mode2Form1,
    /// `MODE2_FORM2` — 2324-byte user data (XA Form 2).
    Mode2Form2,
    /// `AUDIO` — Red Book audio (no filesystem).
    Audio,
    /// Any other / unrecognised mode, preserved verbatim.
    Other(String),
}

impl TocMode {
    /// The [`SectorMode`] for reading this track's user data, or `None` for
    /// audio / Form 2 / unknown tracks that carry no ISO 9660 filesystem.
    #[must_use]
    pub fn sector_mode(&self) -> Option<SectorMode> {
        match self {
            Self::Mode1 | Self::Mode2Form1 => Some(SectorMode::Iso2048),
            Self::Mode1Raw => Some(SectorMode::Raw2352),
            Self::Mode2 => Some(SectorMode::Mode2_2336),
            Self::Mode2Raw => Some(SectorMode::Raw2352Mode2),
            Self::Mode2Form2 | Self::Audio | Self::Other(_) => None,
        }
    }

    /// True for a filesystem-bearing data track (non-audio).
    #[must_use]
    pub fn is_data(&self) -> bool {
        self.sector_mode().is_some()
    }
}

/// A single track in a `.toc` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TocTrack {
    /// 1-based track number (sequential in declaration order).
    pub number: u8,
    /// Track data mode.
    pub mode: TocMode,
    /// Data file holding the track (quotes stripped), if any.
    pub datafile: Option<String>,
    /// Byte offset of the track within the data file (`#N`, default 0).
    pub file_offset: u64,
    /// Track length in sectors (from the `MM:SS:FF` length, default 0).
    pub length_sectors: u32,
}

/// A parsed CDRDAO `.toc` sheet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TocSheet {
    /// Disc type from the leading line (`CD_ROM`, `CD_DA`, `CD_ROM_XA`).
    pub disc_type: Option<String>,
    /// Tracks in declaration order.
    pub tracks: Vec<TocTrack>,
}

impl TocSheet {
    /// The first filesystem-bearing data track.
    #[must_use]
    pub fn data_track(&self) -> Option<&TocTrack> {
        self.tracks.iter().find(|t| t.mode.is_data())
    }
}

/// Parse a CDRDAO `.toc` from its text.
///
/// Lenient: trailing `//` comments and unrecognised lines are ignored; a
/// `DATAFILE`/`AUDIOFILE` applies to the most recent `TRACK`.
#[must_use]
pub fn parse(text: &str) -> TocSheet {
    let mut sheet = TocSheet::default();
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let mut tok = line.split_whitespace();
        match tok.next() {
            Some(t @ ("CD_ROM" | "CD_DA" | "CD_ROM_XA")) if sheet.disc_type.is_none() => {
                sheet.disc_type = Some(t.to_string());
            }
            Some("TRACK") => {
                let mode = tok.next().map_or(TocMode::Other(String::new()), parse_mode);
                let number = u8::try_from(sheet.tracks.len() + 1).unwrap_or(u8::MAX);
                sheet.tracks.push(TocTrack {
                    number,
                    mode,
                    datafile: None,
                    file_offset: 0,
                    length_sectors: 0,
                });
            }
            Some("DATAFILE" | "AUDIOFILE" | "FILE") => {
                if let Some(track) = sheet.tracks.last_mut() {
                    apply_file_line(track, line);
                }
            }
            _ => {} // flags, CD_TEXT, INDEX, blank, unknown
        }
    }
    sheet
}

/// Strip a trailing `//` line comment (CDRDAO/Aaru style).
fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Apply a `DATAFILE`/`AUDIOFILE` line to `track`: quoted name, optional
/// `#byte-offset`, optional `MM:SS:FF` length.
fn apply_file_line(track: &mut TocTrack, line: &str) {
    // Quoted file name.
    if let Some(rest) = line.split_once('"').map(|(_, r)| r) {
        if let Some((name, after)) = rest.split_once('"') {
            track.datafile = Some(name.to_string());
            for word in after.split_whitespace() {
                if let Some(off) = word.strip_prefix('#') {
                    if let Ok(v) = off.parse::<u64>() {
                        track.file_offset = v;
                    }
                } else if let Some(msf) = parse_msf(word) {
                    track.length_sectors = msf.to_lba();
                }
            }
        }
    }
}

fn parse_mode(token: &str) -> TocMode {
    match token.to_ascii_uppercase().as_str() {
        "MODE1" => TocMode::Mode1,
        "MODE1_RAW" => TocMode::Mode1Raw,
        "MODE2" => TocMode::Mode2,
        "MODE2_RAW" => TocMode::Mode2Raw,
        "MODE2_FORM1" => TocMode::Mode2Form1,
        "MODE2_FORM2" => TocMode::Mode2Form2,
        "AUDIO" => TocMode::Audio,
        other => TocMode::Other(other.to_string()),
    }
}

/// Parse an `MM:SS:FF` timecode (reusing the CUE [`Msf`]).
fn parse_msf(token: &str) -> Option<Msf> {
    let mut parts = token.split(':');
    let m = parts.next()?.parse().ok()?;
    let s = parts.next()?.parse().ok()?;
    let f = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(Msf { minutes: m, seconds: s, frames: f })
}
