//! Streaming file reader (`IsoFileReader`) implementing `std::io::Read`.
//!
//! Reads one sector (2048 bytes) at a time to avoid loading the entire file
//! into memory. Supports multi-extent files via `extra_extents`.

use std::io::{self, Read, Seek, SeekFrom};

use crate::sector::{read_sector_data, SectorMode};

/// A single extent: `(lba, total_bytes)`.
type Extent = (u32, u32);

/// Streaming reader for a single ISO 9660 file entry.
///
/// Obtained from [`crate::IsoReader::open_file`]. Implements [`Read`].
pub struct IsoFileReader<R> {
    inner: R,
    mode: SectorMode,
    extents: Vec<Extent>, // [primary] ++ extra_extents
    total: u32,           // sum of all extent sizes

    // read cursor state
    ext_idx: usize, // which extent we're reading
    ext_pos: u32,   // bytes consumed within the current extent
    sector_buf: [u8; 2048],
    buf_start: u32,   // byte offset in current extent where sector_buf starts
    buf_valid: usize, // bytes in sector_buf that are valid (can be < 2048 at last sector)
    buf_pos: usize,   // read cursor within sector_buf
}

impl<R: Read + Seek> IsoFileReader<R> {
    pub(crate) fn new(
        inner: R,
        mode: SectorMode,
        primary_lba: u32,
        primary_size: u32,
        extra_extents: Vec<Extent>,
    ) -> Self {
        let total = primary_size + extra_extents.iter().map(|e| e.1).sum::<u32>();
        let mut extents = Vec::with_capacity(1 + extra_extents.len());
        extents.push((primary_lba, primary_size));
        extents.extend_from_slice(&extra_extents);

        Self {
            inner,
            mode,
            extents,
            total,
            ext_idx: 0,
            ext_pos: 0,
            sector_buf: [0u8; 2048],
            buf_start: u32::MAX, // sentinel: no sector loaded yet
            buf_valid: 0,
            buf_pos: 0,
        }
    }

    /// Total file size in bytes across all extents.
    pub fn size(&self) -> u32 {
        self.total
    }

    /// Ensure `sector_buf` is loaded for `ext_pos` within the current extent.
    fn ensure_buf(&mut self) -> io::Result<()> {
        if self.ext_idx >= self.extents.len() {
            return Ok(());
        }
        let (lba, size) = self.extents[self.ext_idx];
        if size == 0 {
            return Ok(());
        }
        let sector_start = (self.ext_pos / 2048) * 2048;
        if self.buf_start == sector_start {
            return Ok(()); // already loaded
        }
        let sector_idx = sector_start / 2048;
        read_sector_data(
            &mut self.inner,
            self.mode,
            lba as u64 + sector_idx as u64,
            &mut self.sector_buf,
        )
        .map_err(|e| io::Error::other(e.to_string()))?;

        let remaining_in_extent = size - sector_start;
        self.buf_valid = remaining_in_extent.min(2048) as usize;
        self.buf_start = sector_start;
        self.buf_pos = (self.ext_pos - sector_start) as usize;
        Ok(())
    }
}

impl<R: Read + Seek> Seek for IsoFileReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let current_abs: i64 = {
            let before: u32 = self.extents[..self.ext_idx].iter().map(|e| e.1).sum();
            before as i64 + self.ext_pos as i64
        };
        let new_abs = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.total as i64 + p,
            SeekFrom::Current(p) => current_abs + p,
        };
        let new_abs = new_abs.clamp(0, self.total as i64) as u32;

        // Walk extents to find the new (ext_idx, ext_pos).
        let mut remaining = new_abs;
        let mut new_idx = self.extents.len(); // sentinel: at/past end
        let mut new_pos = 0u32;
        for (i, &(_, size)) in self.extents.iter().enumerate() {
            if remaining < size || (remaining == size && i + 1 == self.extents.len()) {
                new_idx = i;
                new_pos = remaining;
                break;
            }
            remaining -= size;
        }

        self.ext_idx = new_idx;
        self.ext_pos = new_pos;
        self.buf_start = u32::MAX; // invalidate buffer
        self.buf_valid = 0;
        self.buf_pos = 0;

        Ok(new_abs as u64)
    }
}

impl<R: Read + Seek> Read for IsoFileReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buf.len() {
            if self.ext_idx >= self.extents.len() {
                break;
            }
            let (_, size) = self.extents[self.ext_idx];
            if self.ext_pos >= size {
                // Advance to next extent.
                self.ext_idx += 1;
                self.ext_pos = 0;
                self.buf_start = u32::MAX;
                continue;
            }
            self.ensure_buf()?;
            let available = self.buf_valid - self.buf_pos;
            if available == 0 {
                break;
            }
            let to_copy = available.min(buf.len() - written);
            buf[written..written + to_copy]
                .copy_from_slice(&self.sector_buf[self.buf_pos..self.buf_pos + to_copy]);
            written += to_copy;
            self.buf_pos += to_copy;
            self.ext_pos += to_copy as u32;
        }
        Ok(written)
    }
}
