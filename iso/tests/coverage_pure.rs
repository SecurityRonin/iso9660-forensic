//! Coverage-completion tests for the pure text/binary parser helpers.
//!
//! These modules (offset windowing, CUE/TOC/CCD sheets, path-table cross-check,
//! CD-Text, El Torito boot catalog, subchannel Q, session scan, PVD/SVD parse)
//! are exercised end-to-end elsewhere against real and hadris-built images, but
//! several branches — degenerate windows, malformed sheets, unrecognised TOC
//! points, all-zero descriptors, error returns — need a synthetic input to
//! reach. Each test below constructs the exact input that drives one such
//! branch and asserts the observable result, so the branch is genuinely
//! exercised rather than merely touched.

use std::io::{Cursor, Seek, SeekFrom};

use iso9660_forensic::offset::OffsetReader;

// --- offset.rs: len / is_empty / seek-before-start -------------------------

#[test]
fn offset_reader_len_and_is_empty() {
    let r = OffsetReader::new(Cursor::new(vec![0u8; 10]), 2, 5).unwrap();
    assert_eq!(r.len(), 5);
    assert!(!r.is_empty());

    let empty = OffsetReader::new(Cursor::new(vec![0u8; 10]), 2, 0).unwrap();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}

#[test]
fn offset_reader_seek_before_window_start_errors() {
    let mut r = OffsetReader::new(Cursor::new(b"0123456789".to_vec()), 3, 4).unwrap();
    // Current(-1) from position 0 resolves to a negative logical target.
    let err = r.seek(SeekFrom::Current(-1)).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    // End(-100) is also before the window start.
    assert!(r.seek(SeekFrom::End(-100)).is_err());
}

// --- cue.rs: unquoted FILE, unknown mode, malformed INDEX ------------------

#[test]
fn cue_unquoted_file_and_unknown_mode() {
    use iso9660_forensic::cue::{parse, TrackMode};
    // Unquoted FILE name (drives the else-branch of parse_file_line), an
    // unrecognised track type (TrackMode::Other), and a MODE1/2352 data track.
    let sheet = parse(
        "FILE image.bin BINARY\nTRACK 01 CDG\nINDEX 01 00:00:00\nTRACK 02 MODE1/2352\nINDEX 01 00:02:00\n",
    );
    assert_eq!(sheet.files.len(), 1);
    assert_eq!(sheet.files[0].name, "image.bin");
    assert_eq!(sheet.files[0].format, "BINARY");
    let modes: Vec<&TrackMode> = sheet.files[0].tracks.iter().map(|t| &t.mode).collect();
    assert_eq!(modes[0], &TrackMode::Other("CDG".to_string()));
    assert_eq!(modes[1], &TrackMode::Mode1_2352);
    assert!(!modes[0].is_data());
    assert!(modes[1].is_data());
    assert_eq!(modes[1].sector_mode(), Some(iso9660_forensic::SectorMode::Raw2352));
    // The data track is track 2.
    let (name, _t) = sheet.data_track().expect("data track");
    assert_eq!(name, "image.bin");
}

#[test]
fn cue_malformed_index_is_ignored() {
    use iso9660_forensic::cue::parse;
    // A non-numeric index number and a 4-field timecode are both rejected by
    // the INDEX arm without pushing an entry.
    let sheet =
        parse("FILE a.bin BINARY\nTRACK 01 MODE1/2048\nINDEX xx 00:00:00\nINDEX 01 0:0:0:0\n");
    assert_eq!(sheet.files[0].tracks[0].indices.len(), 0);
    // INDEX / TRACK before any FILE/TRACK are dropped (no last_mut()).
    let orphan = parse("TRACK 01 AUDIO\nINDEX 01 00:00:00\n");
    assert!(orphan.files.is_empty());
}

// --- toc.rs: DATAFILE with byte-offset + length, unknown mode, comments ----

#[test]
fn toc_datafile_offset_length_and_unknown_mode() {
    use iso9660_forensic::toc::{parse, TocMode};
    let sheet = parse(
        "// a CDRDAO cue\nCD_ROM\nTRACK MODE1\nDATAFILE \"data.bin\" #1024 00:02:00\nTRACK FOO\nTRACK AUDIO\nAUDIOFILE \"a.wav\" 00:03:00\n",
    );
    // First data track carries the parsed offset and length.
    let dt = sheet.data_track().expect("data track");
    assert_eq!(dt.mode, TocMode::Mode1);
    assert_eq!(dt.datafile.as_deref(), Some("data.bin"));
    assert_eq!(dt.file_offset, 1024);
    assert!(dt.length_sectors > 0);
    // Unknown mode preserved; audio is not a data track.
    assert!(matches!(sheet.tracks[1].mode, TocMode::Other(ref s) if s == "FOO"));
    assert_eq!(sheet.tracks[2].mode, TocMode::Audio);
    assert!(!TocMode::Audio.is_data());
    assert!(TocMode::Mode1.is_data());
    assert!(TocMode::Mode1.sector_mode().is_some());
}

// --- path_table.rs: parse + validate mismatches ----------------------------

fn pt_entry(id_len: u8, lba: u32, parent: u16, name: &[u8], big: bool) -> Vec<u8> {
    let mut v = vec![id_len, 0];
    if big {
        v.extend_from_slice(&lba.to_be_bytes());
        v.extend_from_slice(&parent.to_be_bytes());
    } else {
        v.extend_from_slice(&lba.to_le_bytes());
        v.extend_from_slice(&parent.to_le_bytes());
    }
    v.extend_from_slice(name);
    if id_len % 2 == 1 {
        v.push(0); // pad to even
    }
    v
}

#[test]
fn path_table_parse_and_validate_all_mismatch_kinds() {
    use iso9660_forensic::path_table::{
        parse_l_path_table, parse_m_path_table, validate_path_tables,
    };
    // Type-L table: root (id_len 1, "\0") + "DIR" (id_len 3, padded).
    let mut l = pt_entry(1, 20, 1, &[0], false);
    l.extend(pt_entry(3, 25, 1, b"DIR", false));
    let le = parse_l_path_table(&l).unwrap();
    assert_eq!(le.len(), 2);
    assert_eq!(le[1].lba, 25);
    assert_eq!(le[1].dir_id, b"DIR");

    // Big-endian copy that agrees.
    let mut m = pt_entry(1, 20, 1, &[0], true);
    m.extend(pt_entry(3, 25, 1, b"DIR", true));
    let me = parse_m_path_table(&m).unwrap();
    assert!(validate_path_tables(&le, &me).is_empty());

    // Divergent copy: LBA, parent, dir_id, and count all differ.
    let mut bad = pt_entry(1, 20, 1, &[0], true);
    bad.extend(pt_entry(3, 999, 7, b"XYZ", true)); // lba+parent+dir_id mismatch
    bad.extend(pt_entry(3, 30, 1, b"EXTRA", true)); // extra entry -> count mismatch
    let bad_e = parse_m_path_table(&bad).unwrap();
    let mism = validate_path_tables(&le, &bad_e);
    let descs: String = mism.iter().map(|m| m.description.clone()).collect::<Vec<_>>().join(";");
    assert!(descs.contains("entry count mismatch"), "{descs}");
    assert!(descs.contains("LBA mismatch"), "{descs}");
    assert!(descs.contains("parent mismatch"), "{descs}");
    assert!(descs.contains("dir_id mismatch"), "{descs}");
}

#[test]
fn path_table_truncated_record_stops() {
    use iso9660_forensic::path_table::parse_l_path_table;
    // id_len claims 10 but only a few bytes follow -> record_len overruns, break.
    let data = vec![10u8, 0, 1, 0, 0, 0, 1, 0, b'A'];
    assert!(parse_l_path_table(&data).unwrap().is_empty());
    // Trailing < 8 bytes after a valid entry -> the offset+8 guard breaks.
    let mut d = pt_entry(1, 20, 1, &[0], false);
    d.extend_from_slice(&[1, 0, 0]); // 3 dangling bytes
    assert_eq!(parse_l_path_table(&d).unwrap().len(), 1);
}

// --- session.rs: scan finds a PVD at LBA 16 --------------------------------

#[test]
fn session_scan_finds_pvd_lba() {
    use iso9660_forensic::session::scan_pvd_lbas;
    let sector_size = 2048;
    let mut img = vec![0u8; sector_size * 20];
    // A valid PVD signature at LBA 16.
    let off = 16 * sector_size;
    img[off] = 0x01;
    img[off + 1..off + 6].copy_from_slice(b"CD001");
    img[off + 6] = 0x01;
    let lbas = scan_pvd_lbas(&img, sector_size);
    assert_eq!(lbas, vec![16]);
    // A short image (last sector truncated) hits the offset+7 guard.
    let short = vec![0u8; sector_size * 16 + 3];
    assert!(scan_pvd_lbas(&short, sector_size).is_empty());
}

// --- cdtext.rs: PackType coverage + a text pack past the final NUL ----------

#[test]
fn cdtext_pack_type_all_variants_and_is_text() {
    use iso9660_forensic::cdtext::PackType;
    for (b, text) in [
        (0x80u8, true), // Title
        (0x81, true),   // Performer
        (0x82, true),   // Songwriter
        (0x83, true),   // Composer
        (0x84, true),   // Arranger
        (0x85, true),   // Message
        (0x86, false),  // DiscId
        (0x87, false),  // Genre
        (0x88, false),  // Toc
        (0x89, false),  // Toc2
        (0x8E, true),   // UpcEanIsrc
        (0x8F, false),  // SizeInfo
        (0xAB, false),  // Reserved
    ] {
        assert_eq!(PackType::from_byte(b).is_text(), text, "byte {b:#x}");
    }
    assert_eq!(PackType::from_byte(0xAB), PackType::Reserved(0xAB));
}

#[test]
fn cdtext_final_string_without_terminator() {
    use iso9660_forensic::cdtext::decode;
    // A Title pack whose 12 text bytes carry a trailing string with NO closing
    // NUL: "ALBUM\0TAIL" (10 bytes) then two more filler chars, no final NUL.
    // This drives the "bytes after the final NUL with no terminator" arm.
    let mut pack = [0u8; 18];
    pack[0] = 0x80; // Title
    pack[4..14].copy_from_slice(b"ALBUM\0TAIL");
    pack[14] = b'X';
    pack[15] = b'Y';
    // CRC bytes (16,17) are ignored by decode(); leave zero.
    let ct = decode(&pack);
    assert_eq!(ct.album_title(), Some("ALBUM"));
    // The un-terminated remainder is kept as the next track's string.
    assert_eq!(ct.track_title(1), Some("TAILXY"));
    // get() miss returns None (drives the find() None arm).
    assert_eq!(ct.track_title(9), None);
}

// --- findings.rs: Anomaly Display -----------------------------------------

#[test]
fn anomaly_display_format() {
    use iso9660_forensic::findings::{Anomaly, AnomalyKind};
    let a = Anomaly::new(AnomalyKind::MixedTimezones { offsets: vec![0, 4] });
    let s = format!("{a}");
    assert!(s.starts_with('['), "{s}");
    assert!(s.contains(a.code), "{s}");
    assert!(s.contains(&a.note), "{s}");
}

// --- el_torito.rs: BootInfoTable all-zero/short, boot_catalog_lba negatives -

#[test]
fn el_torito_boot_info_table_and_catalog_lba() {
    use iso9660_forensic::el_torito::{boot_catalog_lba, BootInfoTable, BootPlatform};

    // All-zero 24-byte structure => "not present".
    assert!(BootInfoTable::parse(&[0u8; 24]).is_none());
    // Too short => None.
    assert!(BootInfoTable::parse(&[0u8; 10]).is_none());
    // A populated table parses.
    let mut sec = [0u8; 24];
    sec[8..12].copy_from_slice(&16u32.to_le_bytes()); // pvd_lba
    let bit = BootInfoTable::parse(&sec).expect("table present");
    assert_eq!(bit.pvd_lba, 16);

    // boot_catalog_lba: too short, wrong signature, missing EL TORITO text.
    assert!(boot_catalog_lba(&[0u8; 10]).is_none());
    let mut brvd = vec![0u8; 2048];
    brvd[1..6].copy_from_slice(b"CD002"); // wrong signature
    brvd[6] = 0x01;
    assert!(boot_catalog_lba(&brvd).is_none());
    brvd[1..6].copy_from_slice(b"CD001");
    // No EL TORITO SPECIFICATION at offset 7 -> None.
    assert!(boot_catalog_lba(&brvd).is_none());
    brvd[7..7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
    brvd[71..75].copy_from_slice(&27u32.to_le_bytes());
    assert_eq!(boot_catalog_lba(&brvd), Some(27));

    // Platform byte mapping (drives from_byte arms).
    assert_eq!(BootPlatform::from_byte(0x00), BootPlatform::X86);
    assert!(matches!(BootPlatform::from_byte(0xFE), BootPlatform::Other(0xFE)));
}

// --- ccd.rs: an unrecognised TOC Point falls through -----------------------

#[test]
fn ccd_unrecognised_point_is_dropped() {
    use iso9660_forensic::ccd::parse;
    // Point 0xB0 is neither A0/A1/A2 nor 1..=99: the finish_entry match _ arm.
    let text = "\
[Disc]
CATALOG=1234567890123
[Entry 0]
Point=0xb0
PLBA=100
[Entry 1]
Point=0x01
PLBA=0
[TRACK 1]
MODE=1
";
    let toc = parse(text);
    // The 0xB0 entry contributed no track; only the Mode-1 track 1 exists.
    assert_eq!(toc.catalog.as_deref(), Some("1234567890123"));
    assert!(toc.leadout_lba == 0);
}

// --- dir.rs: zero-length padding record returns None -----------------------

#[test]
fn dir_record_zero_length_is_padding() {
    use iso9660_forensic::dir::DirRecord;
    // A length byte of 0 is sector padding -> Ok(None).
    assert!(DirRecord::parse(&[0u8; 8], 0).unwrap().is_none());
    // offset past the end -> Ok(None).
    assert!(DirRecord::parse(&[0x22u8; 4], 100).unwrap().is_none());
    // A length < 33 is a malformed record -> Err.
    assert!(DirRecord::parse(&[10u8; 40], 0).is_err());
}

// --- subq.rs: extract_q / summarize_sub / decode_q over a synthetic block ---

/// Encode a 12-byte Q frame into a 96-byte interleaved subchannel block, bit 6
/// of each byte carrying the frame (MSB-first), matching `extract_q`.
fn q_to_sub(q: &[u8; 12]) -> Vec<u8> {
    let mut sub = vec![0u8; 96];
    for (bit, out) in sub.iter_mut().enumerate() {
        let set = (q[bit / 8] >> (7 - (bit % 8))) & 1 != 0;
        if set {
            *out |= 0b0100_0000; // bit 6 = Q
        }
    }
    sub
}

#[test]
fn subq_extract_and_summarize_position_frame() {
    use iso9660_forensic::subq::{decode_q, extract_q, q_crc_valid, summarize_sub};

    // Too-short subchannel -> None.
    assert!(extract_q(&[0u8; 10]).is_none());

    // Build a Q-mode-1 (position) frame for track 3, then CRC-seal it.
    // Q layout: [0]=control/adr, [1]=TNO(BCD), [2]=index, ... CRC in [10..12].
    let mut q = [0u8; 12];
    q[0] = 0x01; // ADR=1 (position), control=0
    q[1] = 0x03; // track 3 (BCD)
    let crc = iso9660_forensic::cdtext::crc16_ccitt(&q[0..10]) ^ 0xFFFF;
    q[10] = (crc >> 8) as u8;
    q[11] = crc as u8;
    assert!(q_crc_valid(&q));
    assert!(decode_q(&q).is_some());

    let sub = q_to_sub(&q);
    // Round-trips through extract_q.
    assert_eq!(extract_q(&sub).unwrap(), q);
    // summarize_sub walks the whole pipeline (extract -> crc-gate -> decode).
    let _summary = summarize_sub(&sub);
}

// --- cdi.rs: decode a synthetic DiscJuggler descriptor ---------------------

/// A 15-byte DiscJuggler session header (`is_session_header`): byte 1 = track
/// count, byte 9 = 0x01, bytes 13-14 = 0xFFFF, the rest zero.
fn cdi_session_header(max_t: u8) -> [u8; 15] {
    let mut h = [0u8; 15];
    h[1] = max_t;
    h[9] = 0x01;
    h[13] = 0xFF;
    h[14] = 0xFF;
    h
}

/// One DiscJuggler track record, laid out byte-for-byte as `parse_track` walks
/// it (Aaru `DiscJuggler/Read.cs`): filename length 0, no indices, no CD-Text.
fn cdi_track_record(track_mode: u32, read_mode: u32, start_sector: u32, track_len: u32) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&[0u8; 16]); // skip
    r.push(0); // filename length = 0
    r.extend_from_slice(&[0u8; 29]); // skip
    r.extend_from_slice(&0u16.to_le_bytes()); // medium_type
    r.extend_from_slice(&0u16.to_le_bytes()); // max_i = 0
    r.extend_from_slice(&0u32.to_le_bytes()); // max_c = 0
    r.extend_from_slice(&[0u8; 2]); // skip
    r.extend_from_slice(&track_mode.to_le_bytes());
    r.extend_from_slice(&[0u8; 4]); // skip
    r.extend_from_slice(&0u32.to_le_bytes()); // session_seq
    r.extend_from_slice(&0u32.to_le_bytes()); // track_seq
    r.extend_from_slice(&start_sector.to_le_bytes());
    r.extend_from_slice(&track_len.to_le_bytes());
    r.extend_from_slice(&[0u8; 16]); // skip
    r.extend_from_slice(&read_mode.to_le_bytes());
    r.extend_from_slice(&0u32.to_le_bytes()); // track_ctl
    r.extend_from_slice(&[0u8; 9]); // skip
    r.extend_from_slice(&[0u8; 12]); // ISRC
    r.extend_from_slice(&0u32.to_le_bytes()); // isrc_valid
    r.extend_from_slice(&[0u8; 87]); // skip
    r.push(0); // session_type
    r.extend_from_slice(&[0u8; 5]); // skip
    r.extend_from_slice(&[0u8; 2]); // track_follows (read at p, +2)
    r.extend_from_slice(&0u32.to_le_bytes()); // end_address
    r
}

/// Assemble a full CDI image: `body` padding + descriptor + the 8-byte footer.
fn cdi_image(descriptor: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; 4096]; // program-area padding
    v.extend_from_slice(descriptor);
    // The DiscJuggler descriptor_length counts the descriptor bytes PLUS the
    // 8-byte version/length footer, so `tracks()` reads the trailing
    // (descriptor + footer) region starting at the descriptor's first byte.
    let dlen = descriptor.len() as u32 + 8;
    v.extend_from_slice(&0x8000_0006u32.to_le_bytes()); // version marker
    v.extend_from_slice(&dlen.to_le_bytes()); // descriptor length
    v
}

#[test]
fn cdi_decodes_synthetic_descriptor_all_modes() {
    use iso9660_forensic::cdi::{tracks, CdiTrackKind};

    // A one-session, two-track descriptor: track 1 Mode-1 (2048/2048) with a
    // first-track pregap (start_sector 0 -> length adjusted), track 2 Audio.
    let mut desc = vec![1u8]; // maxS = 1
    desc.extend_from_slice(&cdi_session_header(2));
    desc.extend(cdi_track_record(1, 0, 0, 200)); // Mode1, readMode 0 -> 2048/2048
    desc.extend(cdi_track_record(0, 2, 11330, 452)); // Audio 2352/2352
                                                     // Aaru walks maxS+1 sessions; a trailing terminator header ends the walk.
    desc.extend_from_slice(&cdi_session_header(0));

    let img = cdi_image(&desc);
    let ts = tracks(&mut Cursor::new(img)).expect("decode synthetic CDI");
    assert_eq!(ts.len(), 2, "{ts:?}");
    assert_eq!(ts[0].kind, CdiTrackKind::Mode1);
    assert_eq!(ts[0].bytes_per_sector, 2048);
    assert_eq!(ts[0].start_sector, 0);
    assert_eq!(ts[0].length_sectors, 50); // 200 - 150 pregap
    assert_eq!(ts[1].kind, CdiTrackKind::Audio);
    assert_eq!(ts[1].start_sector, 11180); // 11330 - 150
    assert_eq!(ts[1].end_sector(), ts[1].start_sector + ts[1].length_sectors - 1);
}

#[test]
fn cdi_mode2_and_unknown_modes() {
    use iso9660_forensic::cdi::{tracks, CdiTrackKind};

    // Mode 2 formless, readMode 1 -> 2336/2336.
    let mut desc = vec![1u8];
    desc.extend_from_slice(&cdi_session_header(1));
    desc.extend(cdi_track_record(2, 1, 500, 100));
    desc.extend_from_slice(&cdi_session_header(0));
    let ts = tracks(&mut Cursor::new(cdi_image(&desc))).expect("mode2");
    assert_eq!(ts[0].kind, CdiTrackKind::Mode2Formless);
    assert_eq!(ts[0].bytes_per_sector, 2336);

    // An unknown (trackMode, readMode) pair -> decode_mode None -> whole decode
    // aborts (parse_track returns None).
    let mut bad = vec![1u8];
    bad.extend_from_slice(&cdi_session_header(1));
    bad.extend(cdi_track_record(9, 9, 0, 10)); // trackMode 9 is unknown
    bad.extend_from_slice(&cdi_session_header(0));
    assert!(tracks(&mut Cursor::new(cdi_image(&bad))).is_none());

    // maxS byte out of range (0) -> parse_descriptor None.
    let zero = cdi_image(&[0u8]);
    assert!(tracks(&mut Cursor::new(zero)).is_none());
}

// --- cdtoc.rs: Toc::from_cue over a synthetic CUE sheet --------------------

#[test]
fn cdtoc_from_cue_builds_toc() {
    use iso9660_forensic::cdtoc::Toc;
    use iso9660_forensic::cue::parse;

    // A 2-track CUE with INDEX 01 markers -> from_cue collects track frames.
    let sheet = parse(
        "FILE \"a.bin\" BINARY\nTRACK 01 MODE1/2048\nINDEX 01 00:00:00\nTRACK 02 AUDIO\nINDEX 00 00:01:00\nINDEX 01 00:02:00\n",
    );
    let toc = Toc::from_cue(&sheet, 10_000).expect("from_cue");
    assert_eq!(toc.first_track, 1);
    assert_eq!(toc.track_frames.len(), 2);
    // Track 1 start = INDEX 01 (0 frames) + 150 lead-in.
    assert_eq!(toc.track_frames[0], 150);
    // A sheet with a track carrying no INDEX at all -> None.
    let no_index = parse("FILE \"b.bin\" BINARY\nTRACK 01 MODE1/2048\n");
    assert!(Toc::from_cue(&no_index, 100).is_none());
}

// --- file_reader.rs: streaming read + seek across a multi-extent file ------

/// A 2-extent ISO: file "BIG" = extent(LBA 20, 2048 bytes of 0xAA) +
/// extent(LBA 21, 2048 bytes of 0xBB), so a stream crosses the extent boundary.
fn make_iso_multi_extent() -> Vec<u8> {
    const S: usize = 2048;
    let mut img = vec![0u8; 22 * S];
    {
        let p = &mut img[16 * S..17 * S];
        p[0] = 0x01;
        p[1..6].copy_from_slice(b"CD001");
        p[6] = 0x01;
        p[80..84].copy_from_slice(&22u32.to_le_bytes());
        p[84..88].copy_from_slice(&22u32.to_be_bytes());
        p[128..130].copy_from_slice(&2048u16.to_le_bytes());
        p[130..132].copy_from_slice(&2048u16.to_be_bytes());
        p[132..136].copy_from_slice(&10u32.to_le_bytes());
        p[140..144].copy_from_slice(&1u32.to_le_bytes());
        p[148..152].copy_from_slice(&1u32.to_be_bytes());
        p[156] = 34;
        p[158..162].copy_from_slice(&18u32.to_le_bytes());
        p[162..166].copy_from_slice(&18u32.to_be_bytes());
        p[166..170].copy_from_slice(&2048u32.to_le_bytes());
        p[170..174].copy_from_slice(&2048u32.to_be_bytes());
        p[181] = 0x02;
        p[188] = 1;
    }
    {
        let t = &mut img[17 * S..18 * S];
        t[0] = 0xFF;
        t[1..6].copy_from_slice(b"CD001");
        t[6] = 0x01;
    }
    {
        let d = &mut img[18 * S..19 * S];
        d[0] = 34;
        d[2..6].copy_from_slice(&18u32.to_le_bytes());
        d[10..14].copy_from_slice(&2048u32.to_le_bytes());
        d[25] = 0x02;
        d[32] = 1;
        let o = 34;
        d[o] = 34;
        d[o + 2..o + 6].copy_from_slice(&18u32.to_le_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 25] = 0x02;
        d[o + 32] = 1;
        d[o + 33] = 0x01;
        let o = 68; // "BIG" extent 1, MULTI_EXTENT flag set
        d[o] = 36;
        d[o + 2..o + 6].copy_from_slice(&20u32.to_le_bytes());
        d[o + 6..o + 10].copy_from_slice(&20u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 14..o + 18].copy_from_slice(&2048u32.to_be_bytes());
        d[o + 25] = 0x80;
        d[o + 32] = 3;
        d[o + 33..o + 36].copy_from_slice(b"BIG");
        let o = 104; // "BIG" extent 2, last
        d[o] = 36;
        d[o + 2..o + 6].copy_from_slice(&21u32.to_le_bytes());
        d[o + 6..o + 10].copy_from_slice(&21u32.to_be_bytes());
        d[o + 10..o + 14].copy_from_slice(&2048u32.to_le_bytes());
        d[o + 14..o + 18].copy_from_slice(&2048u32.to_be_bytes());
        d[o + 25] = 0x00;
        d[o + 32] = 3;
        d[o + 33..o + 36].copy_from_slice(b"BIG");
    }
    img[20 * S..21 * S].fill(0xAA);
    img[21 * S..22 * S].fill(0xBB);
    img
}

#[test]
fn iso_file_reader_streams_and_seeks_across_extents() {
    use iso9660_forensic::IsoReader;
    use std::io::Read;

    let img = make_iso_multi_extent();
    let mut reader = IsoReader::open(Cursor::new(img)).unwrap();
    let records = reader.read_root_dir().unwrap();
    let big = &records[0];

    let mut fr = reader.open_file(big).unwrap();
    assert_eq!(fr.size(), 4096);

    // Read the whole file in 1000-byte chunks: this advances across the
    // extent-1 -> extent-2 boundary (the read()-side extent-advance arm) and
    // reads at EOF after the last byte (the ensure_buf past-end guard).
    let mut all = Vec::new();
    let mut chunk = [0u8; 1000];
    loop {
        let n = fr.read(&mut chunk).unwrap();
        if n == 0 {
            break;
        }
        all.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(all.len(), 4096);
    assert!(all[..2048].iter().all(|&b| b == 0xAA));
    assert!(all[2048..].iter().all(|&b| b == 0xBB));

    // Seek into the SECOND extent (past extent 1's 2048 bytes): drives the
    // seek()-side extent-walk that subtracts a full extent's size.
    fr.seek(SeekFrom::Start(3000)).unwrap();
    let mut one = [0u8; 1];
    fr.read_exact(&mut one).unwrap();
    assert_eq!(one[0], 0xBB, "byte 3000 is in extent 2");

    // Seek to exact EOF, then read -> 0 (ensure_buf past-end / available==0).
    fr.seek(SeekFrom::End(0)).unwrap();
    assert_eq!(fr.read(&mut chunk).unwrap(), 0);
}
