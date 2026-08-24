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
    Title,      // 0x80
    Performer,  // 0x81
    Songwriter, // 0x82
    Composer,   // 0x83
    Arranger,   // 0x84
    Message,    // 0x85
    DiscId,     // 0x86
    Genre,      // 0x87
    Toc,        // 0x88
    Toc2,       // 0x89
    UpcEanIsrc, // 0x8E (album UPC/EAN, per-track ISRC)
    SizeInfo,   // 0x8F
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
            Self::Title
                | Self::Performer
                | Self::Songwriter
                | Self::Composer
                | Self::Arranger
                | Self::Message
                | Self::UpcEanIsrc
        )
    }
}

/// CRC-16-CCITT (polynomial 0x1021, initial value 0, no final XOR) — the
/// CRC-16/XMODEM variant.  The CD-Text stored CRC is this value inverted.
#[must_use]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
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
        self.fields.iter().find(|(t, n, _)| *t == pt && *n == track).map(|(_, _, s)| s.as_str())
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
    use std::collections::BTreeMap;

    // Accumulate the 12 text bytes per pack type (block 0, single-byte only),
    // recording the base track of each type's first pack and first-seen order.
    let mut groups: BTreeMap<u8, (u8, Vec<u8>)> = BTreeMap::new();
    let mut order: Vec<u8> = Vec::new();
    for chunk in blob.chunks_exact(18) {
        let type_byte = chunk[0];
        if !PackType::from_byte(type_byte).is_text() {
            continue;
        }
        let bncpi = chunk[3];
        let double_byte = bncpi & 0x80 != 0;
        let block = (bncpi >> 4) & 0x07;
        if double_byte || block != 0 {
            continue; // only single-byte, block 0 handled
        }
        let track = chunk[1] & 0x7F; // strip the extension flag (MSB)
        let entry = groups.entry(type_byte).or_insert_with(|| {
            order.push(type_byte);
            (track, Vec::new())
        });
        entry.1.extend_from_slice(&chunk[4..16]);
    }

    let mut fields = Vec::new();
    for type_byte in order {
        let (base, bytes) = &groups[&type_byte];
        let pt = PackType::from_byte(type_byte);
        // NUL-separated strings; element 0 = album/disc, then consecutive tracks.
        let mut track = *base;
        let mut cur: Vec<u8> = Vec::new();
        let push = |t: &mut u8, cur: &mut Vec<u8>, fields: &mut Vec<(PackType, u8, String)>| {
            if !cur.is_empty() {
                // Single-byte CD-Text is ISO-8859-1; map each byte to a char.
                let s: String = cur.iter().map(|&c| c as char).collect();
                fields.push((pt, *t, s));
            }
            cur.clear();
            *t = t.wrapping_add(1);
        };
        for &b in bytes {
            if b == 0 {
                push(&mut track, &mut cur, &mut fields);
            } else {
                cur.push(b);
            }
        }
        // Bytes after the final NUL with no terminator: keep as a final string.
        if !cur.is_empty() {
            let s: String = cur.iter().map(|&c| c as char).collect();
            fields.push((pt, track, s));
        }
    }

    CdText { fields }
}
