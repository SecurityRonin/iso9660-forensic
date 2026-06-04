//! CloneCD `.ccd` control-file parser.
//!
//! A CloneCD image is a set of sidecar files sharing one basename: `.img`
//! (raw 2352-byte sectors), an optional `.sub` (96 bytes of subchannel per
//! sector), and a `.ccd` text control file holding the disc's table of
//! contents.  The `.ccd` is INI-structured; this parser extracts the forensic
//! essentials — the Media Catalogue Number, the track layout (number, mode,
//! start LBA), per-track ISRC, and the lead-out — so the paired `.img` can be
//! opened with the right [`SectorMode`] and matched against a known release.
//!
//! Field set and TOC semantics follow the libmirage reference parser
//! (cdemu `image-ccd/parser.c`).  The TOC lives in `[Entry N]` sections keyed
//! by a `Point` field: `0xA0` carries the first track number, `0xA1` the last,
//! `0xA2` the lead-out position, and `0x01`–`0x63` each track's start.  Track
//! `MODE` and `ISRC` come from the parallel `[TRACK N]` sections.

use std::collections::BTreeMap;

use crate::cue::Msf;
use crate::sector::SectorMode;

/// Frames of lead-in (2 seconds at 75 fps) preceding the program area; an
/// absolute MSF address is this many frames ahead of its logical block address.
const LEAD_IN_FRAMES: u32 = 150;

/// CloneCD track `MODE` field (libmirage `image-ccd/parser.c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcdMode {
    /// `MODE 0` — Red Book audio.
    Audio,
    /// `MODE 1` — CD-ROM Mode 1 (the `.img` stores the full 2352-byte sector).
    Mode1,
    /// `MODE 2` — CD-ROM XA Mode 2 (full 2352-byte sector in the `.img`).
    Mode2,
    /// Any other / unrecognised mode value, preserved verbatim.
    Other(u32),
}

impl CcdMode {
    /// Map a numeric `MODE` value to a [`CcdMode`].
    #[must_use]
    pub fn from_value(v: u32) -> Self {
        match v {
            0 => Self::Audio,
            1 => Self::Mode1,
            2 => Self::Mode2,
            other => Self::Other(other),
        }
    }

    /// The [`SectorMode`] for reading this track's user data from the paired
    /// `.img`, or `None` for audio / unknown tracks (no ISO 9660 filesystem).
    ///
    /// CloneCD `.img` files always store full 2352-byte raw sectors, so a data
    /// track is `Raw2352` (Mode 1) or `Raw2352Mode2` (Mode 2 / XA).
    #[must_use]
    pub fn sector_mode(self) -> Option<SectorMode> {
        match self {
            Self::Mode1 => Some(SectorMode::Raw2352),
            Self::Mode2 => Some(SectorMode::Raw2352Mode2),
            Self::Audio | Self::Other(_) => None,
        }
    }

    /// True for a filesystem-bearing data track (non-audio).
    #[must_use]
    pub fn is_data(self) -> bool {
        self.sector_mode().is_some()
    }
}

/// A track in a CloneCD image, assembled from `[Entry]` + `[TRACK]` sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcdTrack {
    pub number: u8,
    pub mode: CcdMode,
    /// Logical block address of the track's start within the `.img`.
    pub start_lba: u32,
    /// International Standard Recording Code, if present (audio tracks).
    pub isrc: Option<String>,
}

/// A parsed CloneCD control file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CcdToc {
    /// Disc Media Catalogue Number (EAN/UPC), from `[Disc] CATALOG`.
    pub catalog: Option<String>,
    /// First track number (from the `0xA0` TOC entry).
    pub first_track: u8,
    /// Last track number (from the `0xA1` TOC entry).
    pub last_track: u8,
    /// Lead-out start LBA (from the `0xA2` TOC entry).
    pub leadout_lba: u32,
    /// Tracks in ascending track-number order.
    pub tracks: Vec<CcdTrack>,
    /// Concatenated 18-byte CD-Text packs from the `[CDText]` section, if any
    /// (decode with [`crate::cdtext`]).
    pub cdtext: Vec<u8>,
}

impl CcdToc {
    /// Number of tracks on the disc.
    #[must_use]
    pub fn track_count(&self) -> usize {
        self.tracks.len()
    }

    /// The first filesystem-bearing data track, for opening the paired `.img`.
    #[must_use]
    pub fn data_track(&self) -> Option<&CcdTrack> {
        self.tracks.iter().find(|t| t.mode.is_data())
    }
}

/// One `[Entry N]` section's fields, accumulated as lines are read.
#[derive(Default)]
struct Entry {
    point: Option<u32>,
    pmin: u32,
    psec: u32,
    pframe: u32,
    plba: Option<u32>,
}

/// Which INI section the parser is currently inside.
enum Section {
    Disc,
    Entry(Entry),
    Track(u8),
    CdText,
    Other,
}

/// Parse a CloneCD `.ccd` control file from its text.
///
/// Lenient: unrecognised sections and keys are ignored, and entries with an
/// unparseable `Point` are dropped.
#[must_use]
pub fn parse(text: &str) -> CcdToc {
    let mut toc = CcdToc::default();
    // TOC-entry positions keyed by track number, and [TRACK] metadata.
    let mut starts: BTreeMap<u8, u32> = BTreeMap::new();
    let mut track_meta: BTreeMap<u8, (CcdMode, Option<String>)> = BTreeMap::new();

    // CD-Text packs keyed by entry number (each is 18 bytes), concatenated in
    // order at the end.
    let mut cdtext: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

    let mut section = Section::Other;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // Section boundary: finalise the entry we were accumulating.
            finish_entry(&mut section, &mut toc, &mut starts);
            section = classify_section(name);
            continue;
        }
        let Some((key, value)) = split_kv(line) else { continue };
        match &mut section {
            Section::Disc => {
                if key.eq_ignore_ascii_case("CATALOG") {
                    toc.catalog = Some(value.to_string());
                }
            }
            Section::Entry(entry) => apply_entry_field(entry, key, value),
            Section::Track(num) => apply_track_field(*num, key, value, &mut track_meta),
            Section::CdText => apply_cdtext_field(key, value, &mut cdtext),
            Section::Other => {}
        }
    }
    finish_entry(&mut section, &mut toc, &mut starts);

    for bytes in cdtext.into_values() {
        toc.cdtext.extend_from_slice(&bytes);
    }

    // Merge TOC starts with [TRACK] mode/ISRC metadata into ordered tracks.
    for (&number, &start_lba) in &starts {
        let (mode, isrc) =
            track_meta.get(&number).cloned().unwrap_or((CcdMode::Other(u32::MAX), None));
        toc.tracks.push(CcdTrack { number, mode, start_lba, isrc });
    }
    toc
}

/// Classify a `[Section]` header name into the parser's current state.
fn classify_section(name: &str) -> Section {
    if name.eq_ignore_ascii_case("Disc") {
        Section::Disc
    } else if name.eq_ignore_ascii_case("Entry") || starts_with_word(name, "Entry") {
        Section::Entry(Entry::default())
    } else if let Some(n) = track_number(name) {
        Section::Track(n)
    } else if name.eq_ignore_ascii_case("CDText") {
        Section::CdText
    } else {
        Section::Other
    }
}

/// Apply a `[CDText]` line: `Entry N = hh hh …` is one 18-byte pack (hex), keyed
/// by entry number; `Entries=N` (a count) is ignored.
fn apply_cdtext_field(key: &str, value: &str, packs: &mut BTreeMap<u32, Vec<u8>>) {
    let Some(rest) = key.strip_prefix("Entry").or_else(|| key.strip_prefix("entry")) else {
        return; // "Entries=N" and anything else
    };
    let Ok(number) = rest.trim().parse::<u32>() else { return };
    let bytes: Vec<u8> =
        value.split_whitespace().filter_map(|t| u8::from_str_radix(t, 16).ok()).collect();
    if !bytes.is_empty() {
        packs.insert(number, bytes);
    }
}

/// Apply a finished `[Entry]` to the TOC: special points set track range /
/// lead-out; numbered points (1–99) record a track start.
fn finish_entry(section: &mut Section, toc: &mut CcdToc, starts: &mut BTreeMap<u8, u32>) {
    let Section::Entry(entry) = section else { return };
    let Some(point) = entry.point else { return };
    let lba = entry.plba.unwrap_or_else(|| msf_to_lba(entry.pmin, entry.psec, entry.pframe));
    match point {
        0xA0 => toc.first_track = entry.pmin as u8,
        0xA1 => toc.last_track = entry.pmin as u8,
        0xA2 => toc.leadout_lba = lba,
        1..=99 => {
            starts.insert(point as u8, lba);
        }
        _ => {}
    }
    *section = Section::Other;
}

fn apply_entry_field(entry: &mut Entry, key: &str, value: &str) {
    match key.to_ascii_uppercase().as_str() {
        "POINT" => entry.point = parse_int(value),
        "PMIN" => entry.pmin = parse_int(value).unwrap_or(0),
        "PSEC" => entry.psec = parse_int(value).unwrap_or(0),
        "PFRAME" => entry.pframe = parse_int(value).unwrap_or(0),
        "PLBA" => entry.plba = parse_int(value),
        _ => {}
    }
}

fn apply_track_field(
    num: u8,
    key: &str,
    value: &str,
    meta: &mut BTreeMap<u8, (CcdMode, Option<String>)>,
) {
    let slot = meta.entry(num).or_insert((CcdMode::Other(u32::MAX), None));
    if key.eq_ignore_ascii_case("MODE") {
        if let Some(v) = parse_int(value) {
            slot.0 = CcdMode::from_value(v);
        }
    } else if key.eq_ignore_ascii_case("ISRC") {
        slot.1 = Some(value.to_string());
    }
}

/// Split a `KEY=VALUE` line, trimming whitespace; `None` if no `=`.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// True if `name` is `word` optionally followed by a space + index, e.g.
/// `Entry 3` matches word `Entry`.
fn starts_with_word(name: &str, word: &str) -> bool {
    name.len() > word.len()
        && name[..word.len()].eq_ignore_ascii_case(word)
        && name.as_bytes()[word.len()] == b' '
}

/// Extract the track number from a `TRACK N` section header.
fn track_number(name: &str) -> Option<u8> {
    let rest = name.strip_prefix("TRACK").or_else(|| name.strip_prefix("track"))?;
    rest.trim().parse().ok()
}

/// Parse an integer that may be hex (`0x..`) or decimal.
fn parse_int(value: &str) -> Option<u32> {
    let v = value.trim();
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        v.parse().ok()
    }
}

/// Convert an absolute `MM:SS:FF` address to a logical block address, removing
/// the 150-frame lead-in (program area starts at MSF 00:02:00 = LBA 0).
fn msf_to_lba(min: u32, sec: u32, frame: u32) -> u32 {
    let abs = Msf { minutes: min as u8, seconds: sec as u8, frames: frame as u8 }.to_lba();
    abs.saturating_sub(LEAD_IN_FRAMES)
}
