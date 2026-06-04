//! CD-Text decoding (MMC-3 Annex J).
//!
//! CD-Text stores album/track metadata in the lead-in R–W subchannel as a
//! sequence of 18-byte **packs**: a 4-byte header (pack type, track/element
//! number, sequence number, Block-Number-and-Character-Position byte), 12 text
//! bytes, and a 2-byte CRC.  Text strings are NUL-separated and span packs;
//! element 0 of a text type is the album-level value, elements 1..n are tracks.
//!
//! CRC: CRC-16-CCITT (polynomial `X^16 + X^12 + X^5 + 1` = 0x1021, initial
//! value 0) over the 16 header+text bytes, **all bits inverted**, stored
//! big-endian (MMC-3 Annex J).  This module decodes single-byte character
//! packs; double-byte (DBCC) and multi-block (multi-language) packs are not yet
//! interpreted.

/// Pack type indicator (MMC-3 Annex J, Table J.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackType {
    Title,       // 0x80
    Performer,   // 0x81
    Songwriter,  // 0x82
    Composer,    // 0x83
    Arranger,    // 0x84
    Message,     // 0x85
    DiscId,      // 0x86
    Genre,       // 0x87
    Toc,         // 0x88
    Toc2,        // 0x89
    UpcEanIsrc,  // 0x8E (album UPC/EAN, per-track ISRC)
    SizeInfo,    // 0x8F
    Reserved(u8),
}

impl PackType {
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x80 => Self::Title,
            0x81 => Self::Performer,
            0x82 => Self::Songwriter,
            0x83 => Self::Composer,
            0x84 => Self::Arranger,
            0x85 => Self::Message,
            0x86 => Self::DiscId,
            0x87 => Self::Genre,
            0x88 => Self::Toc,
            0x89 => Self::Toc2,
            0x8E => Self::UpcEanIsrc,
            0x8F => Self::SizeInfo,
            other => Self::Reserved(other),
        }
    }

    /// True for a text-bearing (single-byte ASCII) pack type.
    #[must_use]
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Self::Title | Self::Performer | Self::Songwriter | Self::Composer
                | Self::Arranger | Self::Message | Self::UpcEanIsrc
        )
    }
}

/// CRC-16-CCITT (polynomial 0x1021, initial value 0, no final XOR) — the
/// CRC-16/XMODEM variant.  The CD-Text stored CRC is this value inverted.
#[must_use]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let _ = data;
    0
}

/// Decoded CD-Text: album-level and per-track text fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CdText {
    /// `(pack_type, element/track number, decoded string)` in decode order.
    fields: Vec<(PackType, u8, String)>,
}

impl CdText {
    /// All decoded `(pack_type, track, text)` entries.
    #[must_use]
    pub fn entries(&self) -> &[(PackType, u8, String)] {
        &self.fields
    }

    fn get(&self, pt: PackType, track: u8) -> Option<&str> {
        self.fields
            .iter()
            .find(|(t, n, _)| *t == pt && *n == track)
            .map(|(_, _, s)| s.as_str())
    }

    #[must_use]
    pub fn album_title(&self) -> Option<&str> {
        self.get(PackType::Title, 0)
    }
    #[must_use]
    pub fn track_title(&self, track: u8) -> Option<&str> {
        self.get(PackType::Title, track)
    }
    #[must_use]
    pub fn album_performer(&self) -> Option<&str> {
        self.get(PackType::Performer, 0)
    }
    #[must_use]
    pub fn track_performer(&self, track: u8) -> Option<&str> {
        self.get(PackType::Performer, track)
    }
}

/// Decode a CD-Text blob (a contiguous sequence of 18-byte packs) into text.
///
/// Packs whose length isn't a multiple of 18 have any trailing bytes ignored.
/// Only block 0, single-byte packs are interpreted.
#[must_use]
pub fn decode(blob: &[u8]) -> CdText {
    let _ = blob;
    CdText::default()
}
