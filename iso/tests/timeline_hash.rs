// Timeline and hashlist method tests.
// Detection/content tests fail with stubs (which return Ok(vec![])).

use std::io::Cursor;
use iso9660_forensic::IsoReader;

const S: usize = 2048;

fn minimal_iso() -> Vec<u8> {
    let mut img = vec![0u8; 19 * S];
    let p = &mut img[16 * S..17 * S];
    p[0] = 0x01; p[1..6].copy_from_slice(b"CD001"); p[6] = 0x01;
    p[80..84].copy_from_slice(&19u32.to_le_bytes());
    p[84..88].copy_from_slice(&19u32.to_be_bytes());
    p[120..122].copy_from_slice(&1u16.to_le_bytes()); p[122..124].copy_from_slice(&1u16.to_be_bytes());
    p[124..126].copy_from_slice(&1u16.to_le_bytes()); p[126..128].copy_from_slice(&1u16.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes()); p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); p[148..152].copy_from_slice(&1u32.to_be_bytes());
    p[156] = 34; p[158..162].copy_from_slice(&18u32.to_le_bytes()); p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes()); p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181] = 0x02; p[188] = 1;
    let t = &mut img[17 * S..18 * S];
    t[0] = 0xFF; t[1..6].copy_from_slice(b"CD001"); t[6] = 0x01;
    let d = &mut img[18 * S..19 * S];
    d[0]=34; d[2..6].copy_from_slice(&18u32.to_le_bytes()); d[6..10].copy_from_slice(&18u32.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes()); d[14..18].copy_from_slice(&2048u32.to_be_bytes());
    d[25]=0x02; d[32]=1;
    d[34]=34; d[36..40].copy_from_slice(&18u32.to_le_bytes()); d[40..44].copy_from_slice(&18u32.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes()); d[48..52].copy_from_slice(&2048u32.to_be_bytes());
    d[59]=0x02; d[66]=1; d[67]=0x01;
    img
}

/// ISO with one file "FILE" containing `content` at lba=19.
fn iso_with_file(content: &[u8]) -> Vec<u8> {
    let mut img = vec![0u8; 20 * S];
    let total = 20u32;
    let p = &mut img[16 * S..17 * S];
    p[0]=0x01; p[1..6].copy_from_slice(b"CD001"); p[6]=0x01;
    p[80..84].copy_from_slice(&total.to_le_bytes()); p[84..88].copy_from_slice(&total.to_be_bytes());
    p[120..122].copy_from_slice(&1u16.to_le_bytes()); p[122..124].copy_from_slice(&1u16.to_be_bytes());
    p[124..126].copy_from_slice(&1u16.to_le_bytes()); p[126..128].copy_from_slice(&1u16.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes()); p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); p[148..152].copy_from_slice(&1u32.to_be_bytes());
    p[156]=34; p[158..162].copy_from_slice(&18u32.to_le_bytes()); p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes()); p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181]=0x02; p[188]=1;
    let t = &mut img[17 * S..18 * S];
    t[0]=0xFF; t[1..6].copy_from_slice(b"CD001"); t[6]=0x01;
    let d = &mut img[18 * S..19 * S];
    // dot
    d[0]=34; d[2..6].copy_from_slice(&18u32.to_le_bytes()); d[6..10].copy_from_slice(&18u32.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes()); d[14..18].copy_from_slice(&2048u32.to_be_bytes());
    d[25]=0x02; d[32]=1;
    // dotdot
    d[34]=34; d[36..40].copy_from_slice(&18u32.to_le_bytes()); d[40..44].copy_from_slice(&18u32.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes()); d[48..52].copy_from_slice(&2048u32.to_be_bytes());
    d[59]=0x02; d[66]=1; d[67]=0x01;
    // "FILE": name_len=4, even -> pad=1, rec_len=38
    let sz = content.len() as u32;
    d[68]=38; d[70..74].copy_from_slice(&19u32.to_le_bytes()); d[74..78].copy_from_slice(&19u32.to_be_bytes());
    d[78..82].copy_from_slice(&sz.to_le_bytes()); d[82..86].copy_from_slice(&sz.to_be_bytes());
    d[100]=4; d[101..105].copy_from_slice(b"FILE");
    // file data
    let n = content.len().min(S);
    img[19 * S..19 * S + n].copy_from_slice(&content[..n]);
    img
}

// ── timeline ──────────────────────────────────────────────────────────────────

#[test]
fn timeline_empty_iso_returns_empty() {
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let t = reader.timeline().unwrap();
    assert!(t.is_empty(), "empty ISO must have empty timeline");
}

#[test]
fn timeline_returns_entry_for_each_file() {
    // ISO with one file — timeline must have exactly one entry.
    let img = iso_with_file(b"hello");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let t = reader.timeline().unwrap();
    assert_eq!(t.len(), 1, "one file -> one timeline entry: {t:?}");
}

#[test]
fn timeline_entry_has_correct_path() {
    let img = iso_with_file(b"hello");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let t = reader.timeline().unwrap();
    assert!(
        t.iter().any(|e| e.path.to_uppercase().contains("FILE")),
        "timeline must include FILE entry: {t:?}"
    );
}

#[test]
fn timeline_is_not_dir() {
    let img = iso_with_file(b"hello");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let t = reader.timeline().unwrap();
    assert!(t.iter().all(|e| !e.is_dir), "walk returns no dirs in this ISO");
}

// ── hashlist ──────────────────────────────────────────────────────────────────

#[test]
fn hashlist_empty_iso_returns_empty() {
    let img = minimal_iso();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = reader.hashlist().unwrap();
    assert!(h.is_empty(), "no files -> empty hashlist");
}

#[test]
fn hashlist_known_content_sha256() {
    // SHA-256 of b"hello world" is known.
    let img = iso_with_file(b"hello world");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = reader.hashlist().unwrap();
    assert_eq!(h.len(), 1, "one file -> one hash");
    assert_eq!(
        h[0].sha256_hex,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "SHA-256 of 'hello world' must match"
    );
}

#[test]
fn hashlist_result_sorted_by_path() {
    // Build ISO with two files: "ZFILE" (lba=19) and "AFILE" (lba=20).
    // The hashlist must be sorted alphabetically by path.
    let mut img = vec![0u8; 22 * S];
    let total = 22u32;
    let p = &mut img[16 * S..17 * S];
    p[0]=0x01; p[1..6].copy_from_slice(b"CD001"); p[6]=0x01;
    p[80..84].copy_from_slice(&total.to_le_bytes()); p[84..88].copy_from_slice(&total.to_be_bytes());
    p[120..122].copy_from_slice(&1u16.to_le_bytes()); p[122..124].copy_from_slice(&1u16.to_be_bytes());
    p[124..126].copy_from_slice(&1u16.to_le_bytes()); p[126..128].copy_from_slice(&1u16.to_be_bytes());
    p[128..130].copy_from_slice(&2048u16.to_le_bytes()); p[130..132].copy_from_slice(&2048u16.to_be_bytes());
    p[132..136].copy_from_slice(&10u32.to_le_bytes()); p[136..140].copy_from_slice(&10u32.to_be_bytes());
    p[140..144].copy_from_slice(&1u32.to_le_bytes()); p[148..152].copy_from_slice(&1u32.to_be_bytes());
    p[156]=34; p[158..162].copy_from_slice(&18u32.to_le_bytes()); p[162..166].copy_from_slice(&18u32.to_be_bytes());
    p[166..170].copy_from_slice(&2048u32.to_le_bytes()); p[170..174].copy_from_slice(&2048u32.to_be_bytes());
    p[181]=0x02; p[188]=1;
    img[17*S] = 0xFF; img[17*S+1..17*S+6].copy_from_slice(b"CD001"); img[17*S+6] = 0x01;
    let d = &mut img[18 * S..19 * S];
    d[0]=34; d[2..6].copy_from_slice(&18u32.to_le_bytes()); d[6..10].copy_from_slice(&18u32.to_be_bytes());
    d[10..14].copy_from_slice(&2048u32.to_le_bytes()); d[14..18].copy_from_slice(&2048u32.to_be_bytes());
    d[25]=0x02; d[32]=1;
    d[34]=34; d[36..40].copy_from_slice(&18u32.to_le_bytes()); d[40..44].copy_from_slice(&18u32.to_be_bytes());
    d[44..48].copy_from_slice(&2048u32.to_le_bytes()); d[48..52].copy_from_slice(&2048u32.to_be_bytes());
    d[59]=0x02; d[66]=1; d[67]=0x01;
    // "ZFILE": name_len=5 odd -> pad=0, rec_len=38
    d[68]=38; d[70..74].copy_from_slice(&19u32.to_le_bytes()); d[74..78].copy_from_slice(&19u32.to_be_bytes());
    d[78..82].copy_from_slice(&1u32.to_le_bytes()); d[82..86].copy_from_slice(&1u32.to_be_bytes());
    d[100]=5; d[101..106].copy_from_slice(b"ZFILE");
    // "AFILE": name_len=5 odd -> rec_len=38
    d[106]=38; d[108..112].copy_from_slice(&20u32.to_le_bytes()); d[112..116].copy_from_slice(&20u32.to_be_bytes());
    d[116..120].copy_from_slice(&1u32.to_le_bytes()); d[120..124].copy_from_slice(&1u32.to_be_bytes());
    d[138]=5; d[139..144].copy_from_slice(b"AFILE");
    img[19*S] = b'Z';
    img[20*S] = b'A';
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = reader.hashlist().unwrap();
    assert_eq!(h.len(), 2, "two files -> two hashes: {h:?}");
    // Sorted alphabetically
    assert!(h[0].path <= h[1].path, "hashlist must be sorted: {:?} > {:?}", h[0].path, h[1].path);
}

#[test]
fn hashlist_sha256_is_64_hex_chars() {
    let img = iso_with_file(b"test");
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let h = reader.hashlist().unwrap();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].sha256_hex.len(), 64, "SHA-256 hex must be 64 chars");
    assert!(h[0].sha256_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "SHA-256 hex must be all hex digits: {}", h[0].sha256_hex);
}
