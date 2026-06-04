//! BlindWrite 5/6/7 (`.b5t`/`.b6t`) TOC image **detection**.
//!
//! BlindWrite stores a disc as a pair: a small `.b5t`/`.b6t` TOC descriptor and
//! a `.b5i`/`.b6i` data file (analogous to CUE/BIN or MDS/MDF). The TOC begins
//! with the 16-byte signature `"BWT5 STREAM SIGN"` and ends with the 16-byte
//! footer `"BWT5 STREAM FOOT"` — shared by BlindWrite 5, 6 and 7 — with a
//! minimum size of 276 bytes (Aaru `BlindWrite5/Identify.cs`).
//!
//! This module performs **detection only**. The signature/footer contract is
//! confirmed identically by six independent reverse-engineering efforts (Aaru
//! `BlindWrite5`, cdemu libmirage `image-b6t`, the `disc-xplorer` Rust parser,
//! Aaru's ImHex pattern, and Aaru's 010-editor template), so detection is
//! reliable. Track-layout decode is deliberately deferred: no real `.b5t` sample
//! is publicly available to validate a decoder against (doer-checker), and
//! Aaru/libmirage are read-only so one cannot be self-generated as was done for
//! the Alcohol `.mds` fixture. When a real sample is sourced, the per-track
//! layout can be ported from Aaru's `BlindWrite5/Read.cs` and validated
//! byte-exact, exactly as was done for the DiscJuggler [`crate::cdi`] module.

use std::io::{Read, Seek, SeekFrom};

/// Header signature at offset 0.
const SIGNATURE: &[u8; 16] = b"BWT5 STREAM SIGN";
/// Footer signature at end-of-file − 16.
const FOOTER: &[u8; 16] = b"BWT5 STREAM FOOT";
/// Minimum size of a BlindWrite TOC (Aaru `BlindWrite5/Identify.cs`).
const MIN_LEN: u64 = 276;

/// Detection marker for a BlindWrite 5/6/7 TOC.
///
/// Carries no decoded fields yet: the format is identified by its signature and
/// footer alone. (Whether a TOC is BlindWrite 5 vs 6 vs 7 is not distinguishable
/// from the shared signature; callers use the `.b5t`/`.b6t` file extension.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bw5Info;

/// Detect a BlindWrite 5/6/7 TOC from its signature and footer.
///
/// Returns `None` unless the file is at least 276 bytes, begins with
/// `"BWT5 STREAM SIGN"`, and ends with `"BWT5 STREAM FOOT"`.
pub fn detect<R: Read + Seek>(reader: &mut R) -> Option<Bw5Info> {
    let size = reader.seek(SeekFrom::End(0)).ok()?;
    if size < MIN_LEN {
        return None;
    }
    reader.seek(SeekFrom::Start(0)).ok()?;
    let mut head = [0u8; 16];
    reader.read_exact(&mut head).ok()?;
    if &head != SIGNATURE {
        return None;
    }
    reader.seek(SeekFrom::End(-16)).ok()?;
    let mut foot = [0u8; 16];
    reader.read_exact(&mut foot).ok()?;
    if &foot != FOOTER {
        return None;
    }
    Some(Bw5Info)
}
