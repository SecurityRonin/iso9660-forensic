// SUSP/RRIP entry parsers: ER (Extensions Reference), PN (POSIX device),
// SF (sparse file).  Byte layouts verified against IEEE P1282 RRIP draft 1.12
// (§4.1.2 PN, §4.1.7 SF, §4.3 ER) and SUSP IEEE P1281 (ER structure).

use iso9660_forensic::rock_ridge::{extensions_reference, posix_device, sparse_file};

// ── ER ──────────────────────────────────────────────────────────────────────

#[test]
fn er_extracts_rrip_identifier() {
    // ER: "ER" len ver len_id len_des len_src ext_ver  id...
    // id = "RRIP_1991A" (10 bytes), no descriptor, no source. len = 8 + 10 = 18.
    let mut su = vec![b'E', b'R', 18, 1, 10, 0, 0, 1];
    su.extend_from_slice(b"RRIP_1991A");
    let er = extensions_reference(&su).expect("ER must be parsed");
    assert_eq!(er.id, "RRIP_1991A");
    assert_eq!(er.version, 1);
    assert!(er.descriptor.is_empty());
    assert!(er.source.is_empty());
}

#[test]
fn er_extracts_id_descriptor_source() {
    // id="IEEE_P1282" (10), des="RRIP" (4), src="X" (1). len = 8+10+4+1 = 23.
    let mut su = vec![b'E', b'R', 23, 1, 10, 4, 1, 1];
    su.extend_from_slice(b"IEEE_P1282");
    su.extend_from_slice(b"RRIP");
    su.extend_from_slice(b"X");
    let er = extensions_reference(&su).unwrap();
    assert_eq!(er.id, "IEEE_P1282");
    assert_eq!(er.descriptor, "RRIP");
    assert_eq!(er.source, "X");
}

#[test]
fn er_absent_returns_none() {
    assert!(extensions_reference(b"NM\x06\x01\x00hi").is_none());
    assert!(extensions_reference(&[]).is_none());
}

#[test]
fn er_truncated_is_safe() {
    // Claims len_id=10 but only 4 id bytes present — must not panic/over-read.
    let su = vec![b'E', b'R', 18, 1, 10, 0, 0, 1, b'R', b'R', b'I', b'P'];
    let _ = extensions_reference(&su); // just must not panic
}

// ── PN ──────────────────────────────────────────────────────────────────────

#[test]
fn pn_extracts_device_number() {
    // PN len=20: high both-endian, low both-endian.
    let mut su = vec![b'P', b'N', 20, 1];
    su.extend_from_slice(&0x12u32.to_le_bytes());
    su.extend_from_slice(&0x12u32.to_be_bytes());
    su.extend_from_slice(&0x34u32.to_le_bytes());
    su.extend_from_slice(&0x34u32.to_be_bytes());
    let pn = posix_device(&su).expect("PN must be parsed");
    assert_eq!(pn.dev_high, 0x12);
    assert_eq!(pn.dev_low, 0x34);
    assert_eq!(pn.dev(), 0x0000_0012_0000_0034);
}

#[test]
fn pn_absent_returns_none() {
    assert!(posix_device(b"PX\x24\x01").is_none());
    assert!(posix_device(&[]).is_none());
}

// ── SF ──────────────────────────────────────────────────────────────────────

#[test]
fn sf_extracts_virtual_size_and_depth() {
    // SF len=21: vsize high both-endian, vsize low both-endian, table_depth.
    let mut su = vec![b'S', b'F', 21, 1];
    su.extend_from_slice(&1u32.to_le_bytes()); // high LE
    su.extend_from_slice(&1u32.to_be_bytes()); // high BE
    su.extend_from_slice(&2u32.to_le_bytes()); // low LE
    su.extend_from_slice(&2u32.to_be_bytes()); // low BE
    su.push(3); // table depth
    let sf = sparse_file(&su).expect("SF must be parsed");
    assert_eq!(sf.virtual_size, (1u64 << 32) | 2);
    assert_eq!(sf.table_depth, 3);
}

#[test]
fn sf_absent_returns_none() {
    assert!(sparse_file(b"TF\x05\x01\x0e").is_none());
    assert!(sparse_file(&[]).is_none());
}
