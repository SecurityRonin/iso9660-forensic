// BlindWrite 5/6/7 (.b5t/.b6t) TOC detection tests.
//
// The detection contract is a fixed 16-byte header signature "BWT5 STREAM SIGN"
// at offset 0 plus a 16-byte footer "BWT5 STREAM FOOT" at EOF-16, with a minimum
// file length of 276 bytes (Aaru BlindWrite5/Identify.cs). The same contract is
// confirmed identically by six independent reverse-engineering efforts — Aaru
// BlindWrite5, cdemu libmirage image-b6t, the disc-xplorer Rust parser, Aaru's
// ImHex pattern, and Aaru's 010-editor template — so a synthetic-signature
// fixture is sufficient for the detection layer. Track-layout decode is deferred
// pending a real .b5t/.b5i sample to validate against (doer-checker).

use iso9660_forensic::bw5;
use std::io::Cursor;

const SIG: &[u8; 16] = b"BWT5 STREAM SIGN";
const FOOT: &[u8; 16] = b"BWT5 STREAM FOOT";

/// Build a synthetic `BlindWrite` TOC: signature, `body` zero bytes, footer.
fn build(body: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + body);
    v.extend_from_slice(SIG);
    v.resize(16 + body, 0);
    v.extend_from_slice(FOOT);
    v
}

#[test]
fn detects_valid_blindwrite_toc() {
    // 16 sig + 244 body + 16 footer = 276, the documented minimum length.
    let img = build(244);
    assert_eq!(img.len(), 276);
    assert!(bw5::detect(&mut Cursor::new(img)).is_some());
}

#[test]
fn rejects_missing_signature() {
    let mut img = build(244);
    img[0] = b'X';
    assert!(bw5::detect(&mut Cursor::new(img)).is_none());
}

#[test]
fn rejects_missing_footer() {
    let mut img = build(244);
    let last = img.len() - 1;
    img[last] = b'X';
    assert!(bw5::detect(&mut Cursor::new(img)).is_none());
}

#[test]
fn rejects_too_short() {
    // Signatures present but under 276 bytes: rejected.
    let mut v = Vec::new();
    v.extend_from_slice(SIG);
    v.extend_from_slice(FOOT);
    assert_eq!(v.len(), 32);
    assert!(bw5::detect(&mut Cursor::new(v)).is_none());
}

#[test]
fn rejects_non_blindwrite() {
    assert!(bw5::detect(&mut Cursor::new(vec![0u8; 512])).is_none());
}
