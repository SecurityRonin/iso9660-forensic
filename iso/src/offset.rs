//! A windowing adapter that presents a byte sub-range of a `Read + Seek` as a
//! standalone stream starting at offset 0.
//!
//! Container formats store the ISO 9660 data track at a byte offset *within* a
//! larger file (e.g. a Nero `.nrg` track, with chunk/footer data after it).
//! Wrapping the file in an [`OffsetReader`] over `[base, base + len)` lets the
//! existing [`crate::IsoReader`] open that track unchanged: sector positions
//! resolve relative to the track start, and reads hit a clean EOF at the track
//! end rather than spilling into trailing container metadata.

use std::io::{self, Read, Seek, SeekFrom};

/// A bounded `[base, base + len)` window over an inner `Read + Seek`, presented
/// as a stream addressed from 0.
#[derive(Debug)]
pub struct OffsetReader<R> {
    inner: R,
    base: u64,
    len: u64,
    pos: u64,
}

impl<R: Read + Seek> OffsetReader<R> {
    /// Wrap `inner`, exposing the `len` bytes starting at `base`.
    ///
    /// The inner stream is positioned at `base`; the window's logical position
    /// starts at 0.
    pub fn new(mut inner: R, base: u64, len: u64) -> io::Result<Self> {
        inner.seek(SeekFrom::Start(base))?;
        Ok(Self { inner, base, len, pos: 0 })
    }

    /// The length of the window in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// True if the window is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<R: Read + Seek> Read for OffsetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos);
        if remaining == 0 {
            return Ok(0);
        }
        let cap = remaining.min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..cap])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for OffsetReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Resolve to a logical position within the window, then map to the
        // inner stream. A negative result is an error (matches std semantics).
        let target = match pos {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::Current(d) => self.pos as i64 + d,
            SeekFrom::End(d) => self.len as i64 + d,
        };
        if target < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start of window"));
        }
        let target = target as u64;
        self.inner.seek(SeekFrom::Start(self.base + target))?;
        self.pos = target;
        Ok(target)
    }
}
