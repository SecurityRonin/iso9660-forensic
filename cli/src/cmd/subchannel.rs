use iso9660_forensic::subq::{summarize_sub, QSummary};
use iso9660_forensic::{IsoError, IsoReader};
use std::io::{Read, Seek};

/// Report the disc's Q-subchannel identifiers: the Media Catalogue Number and
/// per-track ISRCs, recovered from a 2448-byte (subchannel-bearing) image.
///
/// Only CRC-valid Q frames are trusted (see [`IsoReader::scan_subchannel_q`]),
/// so blank or garbage subchannel produces an explicit "none" report rather
/// than spurious identifiers.  Images without a 96-byte subchannel (plain 2048
/// ISO, 2352 raw) yield the same "none" report instead of an error.
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>) -> Result<String, IsoError> {
    Ok(format_summary(&reader.scan_subchannel_q()?))
}

/// Report Q-subchannel identifiers from a standalone subchannel file (CloneCD
/// `.sub`): 96 interleaved subcode bytes per sector in a separate file.
#[must_use]
pub fn run_sub(sub: &[u8]) -> String {
    format_summary(&summarize_sub(sub))
}

/// Format a [`QSummary`] as the human-readable subchannel report.
fn format_summary(summary: &QSummary) -> String {
    let mut out = String::from("Subchannel Q (MCN / ISRC)\n");
    match &summary.catalog {
        Some(mcn) => out.push_str(&format!("Media Catalog Number: {mcn}\n")),
        None => out.push_str("Media Catalog Number: (none)\n"),
    }
    if summary.isrcs.is_empty() {
        out.push_str("ISRC:                 (none)\n");
    } else {
        for (track, isrc) in &summary.isrcs {
            out.push_str(&format!("Track {track:>2} ISRC:        {isrc}\n"));
        }
    }
    out
}
