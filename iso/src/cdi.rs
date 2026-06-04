//! DiscJuggler (CDI) image **detection**.
//!
//! A DiscJuggler image stores its table of contents in a trailing descriptor:
//! the last 4 bytes are the descriptor length (little-endian `u32`), and the 4
//! bytes before that are the DiscJuggler version (`0x8000_0004`/`5`/`6`).  The
//! descriptor's internal track layout is reverse-engineered and marked
//! "undeciphered" in the reference implementation (libmirage `image-cdi`), so
//! this module deliberately does **detection only** — it identifies the image
//! and its version/descriptor size without guessing track internals it cannot
//! verify.  Validated against a real DiscJuggler 3.5 image.

use std::io::{Read, Seek, SeekFrom};

/// Known DiscJuggler descriptor version markers (libmirage `image-cdi`).
const VERSIONS: [u32; 3] = [0x8000_0004, 0x8000_0005, 0x8000_0006];

/// Detection result for a DiscJuggler image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdiInfo {
    /// DiscJuggler version marker (`0x8000_0004`/`5`/`6`).
    pub version: u32,
    /// Length of the trailing descriptor in bytes.
    pub descriptor_length: u32,
}

/// Detect a DiscJuggler image from its trailing footer.
///
/// Returns `None` unless the last 8 bytes carry a known version marker and a
/// descriptor length that fits within the file.
pub fn detect<R: Read + Seek>(reader: &mut R) -> Option<CdiInfo> {
    let size = reader.seek(SeekFrom::End(0)).ok()?;
    if size < 8 {
        return None;
    }
    reader.seek(SeekFrom::End(-8)).ok()?;
    let mut tail = [0u8; 8];
    reader.read_exact(&mut tail).ok()?;
    let version = u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
    let descriptor_length = u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]);
    if !VERSIONS.contains(&version) {
        return None;
    }
    if descriptor_length == 0 || u64::from(descriptor_length) > size {
        return None;
    }
    Some(CdiInfo { version, descriptor_length })
}
