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
    let summary = reader.scan_subchannel_q()?;
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
    Ok(out)
}
