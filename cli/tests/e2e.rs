// End-to-end tests for the `iso9660` binary.
//
// Exercises every subcommand and the main.rs dispatch / error paths by
// invoking the compiled binary against the real sample ISO images.

use assert_cmd::Command;
use predicates::prelude::*;

/// Path to a sample ISO in the sibling `iso` crate's test data.
fn iso(name: &str) -> String {
    format!("{}/../iso/tests/data/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn bin() -> Command {
    Command::cargo_bin("iso9660").unwrap()
}

fn rr_exists() -> bool {
    std::path::Path::new(&iso("rock_ridge.iso")).exists()
}

// ── top-level ─────────────────────────────────────────────────────────────────

#[test]
fn help_prints_usage() {
    bin().arg("--help").assert().success().stdout(predicate::str::contains("Forensic inspection"));
}

#[test]
fn version_prints() {
    bin().arg("--version").assert().success().stdout(predicate::str::contains("iso9660"));
}

#[test]
fn no_args_is_error() {
    bin().assert().failure();
}

#[test]
fn unknown_subcommand_is_error() {
    bin().arg("frobnicate").assert().failure();
}

// ── info ──────────────────────────────────────────────────────────────────────

#[test]
fn info_valid_iso_exits_zero() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["info", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("ROCK_RIDGE"))
        .stdout(predicate::str::contains("Rock Ridge"))
        .stdout(predicate::str::contains("Boot Catalog"));
}

#[test]
fn info_missing_file_is_error() {
    bin()
        .args(["info", "/nonexistent/xyz.iso"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot open"));
}

#[test]
fn info_not_an_iso_is_error() {
    // A real file that is not an ISO.
    bin().args(["info", env!("CARGO_MANIFEST_DIR")]).assert().failure();
}

// ── ls ────────────────────────────────────────────────────────────────────────

#[test]
fn ls_lists_root() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["ls", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"))
        .stdout(predicate::str::contains("subdir"));
}

#[test]
fn ls_recursive() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["ls", &iso("rock_ridge.iso"), "-R"])
        .assert()
        .success()
        .stdout(predicate::str::contains("subdir/deep.txt"));
}

#[test]
fn ls_subdir_path() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["ls", &iso("rock_ridge.iso"), "subdir"])
        .assert()
        .success()
        .stdout(predicate::str::contains("deep.txt"));
}

#[test]
fn ls_missing_path_errors() {
    if !rr_exists() {
        return;
    }
    bin().args(["ls", &iso("rock_ridge.iso"), "nope"]).assert().failure();
}

// ── extract (canonical + x/e aliases) ───────────────────────────────────────

#[test]
fn extract_to_stdout() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["extract", &iso("rock_ridge.iso"), "hello.txt", "--stdout"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello from iso corpus"));
}

#[test]
fn extract_flat_strips_path() {
    if !rr_exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args([
            "extract",
            &iso("rock_ridge.iso"),
            "subdir/deep.txt",
            "--flat",
            "-C",
            dir.path().to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(dir.path().join("deep.txt").exists());
}

#[test]
fn x_alias_to_stdout() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["x", &iso("rock_ridge.iso"), "hello.txt", "--stdout"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello from iso corpus"));
}

#[test]
fn x_alias_to_output_dir() {
    if !rr_exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["x", &iso("rock_ridge.iso"), "hello.txt", "-C", dir.path().to_str().unwrap()])
        .assert()
        .success();
    let content = std::fs::read_to_string(dir.path().join("hello.txt")).unwrap();
    assert!(content.contains("hello from iso corpus"));
}

#[test]
fn extract_stdout_multiple_files_errors() {
    if !rr_exists() {
        return;
    }
    bin().args(["extract", &iso("rock_ridge.iso"), "--stdout"]).assert().failure();
}

#[test]
fn extract_missing_path_errors() {
    if !rr_exists() {
        return;
    }
    bin().args(["extract", &iso("rock_ridge.iso"), "nope.txt", "--stdout"]).assert().failure();
}

#[test]
fn e_alias_flat_to_output_dir() {
    if !rr_exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    bin()
        .args(["e", &iso("rock_ridge.iso"), "subdir/deep.txt", "-C", dir.path().to_str().unwrap()])
        .assert()
        .success();
    // `e` is shorthand for `extract --flat`: stored as deep.txt, not subdir/deep.txt
    assert!(dir.path().join("deep.txt").exists());
}

// ── hexdump ───────────────────────────────────────────────────────────────────

#[test]
fn dump_default_lba() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["dump", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("CD001").or(predicate::str::contains("43 44 30 30 31")));
}

#[test]
fn dump_explicit_lba() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["dump", &iso("rock_ridge.iso"), "--lba", "16"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sector 16"));
}

#[test]
fn hexdump_is_not_a_command() {
    // `dump` is the only name; there is no `hexdump` alias.
    bin().args(["hexdump", &iso("rock_ridge.iso")]).assert().failure();
}

#[test]
fn dump_raw_emits_binary_sector() {
    if !rr_exists() {
        return;
    }
    let out =
        bin().args(["dump", &iso("rock_ridge.iso"), "--lba", "16", "--raw"]).assert().success();
    let bytes = &out.get_output().stdout;
    assert_eq!(bytes.len(), 2048, "raw dump must be exactly one 2048-byte sector");
    assert_eq!(&bytes[0..6], &[0x01, b'C', b'D', b'0', b'0', b'1']);
}

// ── help / version flags (no redundant `help` subcommand) ─────────────────────

#[test]
fn no_help_subcommand() {
    // The auto-generated `help` subcommand is disabled; `iso9660 help` must
    // error because -h/--help cover it.
    bin().arg("help").assert().failure();
}

#[test]
fn short_help_and_version_flags() {
    bin().arg("-h").assert().success().stdout(predicate::str::contains("Forensic inspection"));
    bin().arg("-V").assert().success().stdout(predicate::str::contains("iso9660"));
}

// ── map ───────────────────────────────────────────────────────────────────────

#[test]
fn map_renders() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["map", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sector Map"))
        .stdout(predicate::str::contains("PVD"));
}

// ── forensic audit ──────────────────────────────────────────────────────────

#[test]
fn forensic_audit_clean_iso() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "audit", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Forensic Audit"))
        .stdout(predicate::str::contains("[PASS]"))
        .stdout(predicate::str::contains("Result:"));
}

// ── forensic timeline ─────────────────────────────────────────────────────────

#[test]
fn forensic_timeline_renders() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "timeline", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("TIMESTAMP"))
        .stdout(predicate::str::contains("hello.txt"));
}

// ── forensic hash (all formats) ───────────────────────────────────────────────

#[test]
fn forensic_hash_default_hashdeep() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "hash", &iso("rock_ridge.iso")])
        .assert()
        .success()
        .stdout(predicate::str::contains("%%%% HASHDEEP"));
}

#[test]
fn forensic_hash_csv() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "csv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("path,size,sha256"));
}

#[test]
fn forensic_hash_tsv() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "tsv"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sha256"));
}

#[test]
fn forensic_hash_mactime() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "mactime"])
        .assert()
        .success()
        .stdout(predicate::str::contains("|"));
}

#[test]
fn forensic_hash_dfxml() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["forensic", "hash", &iso("rock_ridge.iso"), "--format", "dfxml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("<dfxml"))
        .stdout(predicate::str::contains("fileobject"));
}

// ── search: metadata mode (find) — --name is a regex ──────────────────────────

#[test]
fn search_name_regex_suffix() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--name", r"\.txt$"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"));
}

#[test]
fn search_name_regex_anchored_excludes() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--name", r"^hello\.txt$"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"))
        .stdout(predicate::str::contains("rockridge.txt").not());
}

#[test]
fn search_type_dir() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--type", "d"])
        .assert()
        .success()
        .stdout(predicate::str::contains("subdir"));
}

#[test]
fn search_min_size() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--type", "f", "--min-size", "1"])
        .assert()
        .success();
}

#[test]
fn search_max_size() {
    if !rr_exists() {
        return;
    }
    bin().args(["search", &iso("rock_ridge.iso"), "--max-size", "1000000"]).assert().success();
}

// ── search: content mode (grep) — --content is a regex ────────────────────────

#[test]
fn search_content_finds_match() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--content", "rock"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_content_regex_metachar() {
    if !rr_exists() {
        return;
    }
    // `r.ck` matches "rock" via regex.
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--content", "r.ck"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_content_ignore_case() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--content", "ROCK", "-i"])
        .assert()
        .success()
        .stdout(predicate::str::contains("rockridge.txt"));
}

#[test]
fn search_content_with_name_include() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--content", "rock", "--name", r"\.txt$"])
        .assert()
        .success();
}

#[test]
fn search_content_no_match_empty() {
    if !rr_exists() {
        return;
    }
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--content", "zzznotthereatall"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ── search: invalid regex and glob-vs-regex behavior ──────────────────────────

#[test]
fn search_invalid_regex_errors() {
    if !rr_exists() {
        return;
    }
    // Unbalanced bracket is an invalid regex -> friendly error, nonzero exit.
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--content", "["])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid regex"));
}

#[test]
fn search_leading_star_is_invalid_regex() {
    if !rr_exists() {
        return;
    }
    // A shell glob `*.txt` is NOT a valid regex (leading repetition) -> error.
    bin()
        .args(["search", &iso("rock_ridge.iso"), "--name", "*.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid regex"));
}

// ── info: UDF partition kind (v0.3-dev) ───────────────────────────────────────

#[test]
fn info_reports_udf_partition_kind() {
    let p = format!("{}/../iso/tests/data/udf_bridge.iso", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&p).exists() {
        return;
    }
    bin()
        .args(["info", &p])
        .assert()
        .success()
        .stdout(predicate::str::contains("UDF"))
        .stdout(predicate::str::contains("Physical"));
}

// ── BIN/CUE open path (v0.3-dev) ──────────────────────────────────────────────

#[test]
fn opens_bin_via_cue_sheet() {
    let src = iso("rock_ridge.iso");
    if !std::path::Path::new(&src).exists() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // Real data track: a copy of rock_ridge.iso as the .bin (MODE1/2048).
    std::fs::copy(&src, dir.path().join("disc.bin")).unwrap();
    std::fs::write(
        dir.path().join("disc.cue"),
        "FILE \"disc.bin\" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n",
    )
    .unwrap();
    let cue = dir.path().join("disc.cue");
    bin()
        .args(["ls", cue.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt"));
}

#[test]
fn cue_missing_bin_errors() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("x.cue"),
        "FILE \"nope.bin\" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n",
    )
    .unwrap();
    let cue = dir.path().join("x.cue");
    bin().args(["info", cue.to_str().unwrap()]).assert().failure();
}

// ── forensic discid (v0.3-dev) ────────────────────────────────────────────────

#[test]
fn forensic_discid_from_audio_cue() {
    let dir = tempfile::tempdir().unwrap();
    // 1000-frame disc: 1000 * 2352 = 2_352_000 bytes of (zeroed) audio.
    std::fs::write(dir.path().join("audio.bin"), vec![0u8; 1000 * 2352]).unwrap();
    std::fs::write(
        dir.path().join("audio.cue"),
        "FILE \"audio.bin\" BINARY\n  TRACK 01 AUDIO\n    INDEX 01 00:00:00\n\
         \x20 TRACK 02 AUDIO\n    INDEX 01 00:06:50\n",
    )
    .unwrap();
    let cue = dir.path().join("audio.cue");
    bin()
        .args(["forensic", "discid", cue.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("tCEz1oNRWc20xpCzN1CjG_7AOdM-")) // MusicBrainz
        .stdout(predicate::str::contains("0a000d02")); // freedb
}

// ── forensic subchannel (v0.3-dev) ────────────────────────────────────────────

fn interleave_q_e2e(q: &[u8; 12]) -> [u8; 96] {
    let mut sub = [0u8; 96];
    for bit in 0..96 {
        let set = (q[bit / 8] >> (7 - (bit % 8))) & 1;
        sub[bit] = set << 6;
    }
    sub
}

#[test]
fn forensic_subchannel_reports_mcn_and_isrc() {
    const P: usize = 2448;
    const SYNC: [u8; 12] = [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0];
    const POS1: [u8; 12] = [0x41, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0xD4];
    const ISRC: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    const MCN: [u8; 12] = [0x42, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x99, 0xCB];
    let n = 24usize;
    let mut img = vec![0u8; n * P];
    for s in 0..n {
        img[s * P..s * P + 12].copy_from_slice(&SYNC);
        img[s * P + 15] = 0x01;
    }
    let pvd = 16 * P + 16;
    img[pvd] = 0x01;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    img[pvd + 6] = 0x01;
    let term = 17 * P + 16;
    img[term] = 0xFF;
    img[term + 1..term + 6].copy_from_slice(b"CD001");
    img[term + 6] = 0x01;
    for (sector, q) in [(18usize, POS1), (19, ISRC), (20, MCN)] {
        let off = sector * P + 2352;
        img[off..off + 96].copy_from_slice(&interleave_q_e2e(&q));
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub.bin");
    std::fs::write(&path, &img).unwrap();
    bin()
        .args(["forensic", "subchannel", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("1234567890123"))
        .stdout(predicate::str::contains("USRC17607839"));
}

#[test]
fn forensic_subchannel_reads_clonecd_sub_sidecar() {
    const POS1: [u8; 12] = [0x41, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x09, 0xD4];
    const ISRC: [u8; 12] = [0x43, 0x96, 0x38, 0x93, 0x04, 0x76, 0x07, 0x83, 0x90, 0x00, 0x6B, 0x86];
    const MCN: [u8; 12] = [0x42, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x30, 0x00, 0x00, 0x99, 0xCB];
    let dir = tempfile::tempdir().unwrap();
    let mut sub = Vec::new();
    for q in [POS1, ISRC, MCN] {
        sub.extend_from_slice(&interleave_q_e2e(&q));
    }
    std::fs::write(dir.path().join("disc.sub"), &sub).unwrap();
    // The .ccd/.img need not be valid ISOs; subchannel comes from the .sub.
    std::fs::write(dir.path().join("disc.ccd"), "[CloneCD]\nVersion=3\n").unwrap();
    let ccd = dir.path().join("disc.ccd");
    bin()
        .args(["forensic", "subchannel", ccd.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("1234567890123"))
        .stdout(predicate::str::contains("USRC17607839"));
}

// ── CloneCD .ccd/.img open resolution (v0.3-dev) ──────────────────────────────

/// Re-wrap a 2048-byte/sector ISO into a raw 2352-byte/sector CD image
/// (sync + Mode-1 header + 2048 data + zeroed EDC/ECC), as a CloneCD .img holds.
fn wrap_2352(iso2048: &[u8]) -> Vec<u8> {
    const SYNC: [u8; 12] = [0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0];
    let mut out = Vec::with_capacity(iso2048.len() / 2048 * 2352);
    for chunk in iso2048.chunks(2048) {
        let mut sector = vec![0u8; 2352];
        sector[..12].copy_from_slice(&SYNC);
        sector[15] = 0x01; // Mode 1
        sector[16..16 + chunk.len()].copy_from_slice(chunk);
        out.extend_from_slice(&sector);
    }
    out
}

#[test]
fn info_opens_clonecd_ccd_set_via_img_sibling() {
    if !rr_exists() {
        return;
    }
    let iso2048 = std::fs::read(iso("rock_ridge.iso")).unwrap();
    let img = wrap_2352(&iso2048);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("disc.img"), &img).unwrap();
    // The .ccd content is irrelevant to opening — the .img sibling is resolved
    // by basename, mirroring .cue -> .bin.
    std::fs::write(dir.path().join("disc.ccd"), "[CloneCD]\nVersion=3\n").unwrap();
    let ccd = dir.path().join("disc.ccd");
    bin()
        .args(["info", ccd.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("ROCK_RIDGE"));
}

#[test]
fn ls_opens_raw_img_directly() {
    if !rr_exists() {
        return;
    }
    let iso2048 = std::fs::read(iso("rock_ridge.iso")).unwrap();
    let img = wrap_2352(&iso2048);
    let dir = tempfile::tempdir().unwrap();
    let img_path = dir.path().join("disc.img");
    std::fs::write(&img_path, &img).unwrap();
    // A raw .img opens directly (Raw2352 autodetect) with no sidecar.
    bin().args(["ls", img_path.to_str().unwrap()]).assert().success();
}

// ── NRG (Nero) open (v0.3-dev) ────────────────────────────────────────────────

/// Wrap a 2048-byte/sector ISO as a v2 NRG with one DAOX mode-0 (user-data)
/// track at file offset 0, so the window opens directly as a 2048 ISO.
fn build_nrg_mode0(iso2048: &[u8]) -> Vec<u8> {
    // A non-zero preamble before the track data ensures the .nrg cannot be
    // opened as a plain ISO (no CD001 at the expected offset) — the NRG footer
    // and the data track's byte offset must be parsed.
    const PREAMBLE: u64 = 4096;
    let mut img = vec![0u8; PREAMBLE as usize];
    img.extend_from_slice(iso2048);
    let trailer = img.len() as u64;
    let mut dao = vec![0u8; 22]; // DAO header (MCN area, left blank)
    let mut sub = Vec::new();
    sub.extend_from_slice(&[0u8; 12]); // ISRC (blank)
    sub.extend_from_slice(&2048u16.to_be_bytes()); // sector_size
    sub.push(0x00); // mode_code = Mode 1, user data only
    sub.extend_from_slice(&[0u8; 3]); // pad
    sub.extend_from_slice(&0u64.to_be_bytes()); // pregap
    sub.extend_from_slice(&PREAMBLE.to_be_bytes()); // start_offset
    sub.extend_from_slice(&(PREAMBLE + iso2048.len() as u64).to_be_bytes()); // end_offset
    dao.extend_from_slice(&sub);
    img.extend_from_slice(b"DAOX");
    img.extend_from_slice(&(dao.len() as u32).to_be_bytes());
    img.extend_from_slice(&dao);
    img.extend_from_slice(b"END!");
    img.extend_from_slice(&0u32.to_be_bytes());
    img.extend_from_slice(b"NER5");
    img.extend_from_slice(&trailer.to_be_bytes());
    img
}

#[test]
fn info_opens_nrg_image() {
    if !rr_exists() {
        return;
    }
    let iso2048 = std::fs::read(iso("rock_ridge.iso")).unwrap();
    let nrg = build_nrg_mode0(&iso2048);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disc.nrg");
    std::fs::write(&path, &nrg).unwrap();
    bin()
        .args(["info", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("ROCK_RIDGE"));
}

// ── MDS/MDF (Alcohol 120%) open (v0.3-dev) ────────────────────────────────────

/// Build a one-track MDS descriptor pointing at a mode-0x02 (Mode 1) track in
/// the sibling .mdf at `start_offset`, `num_sectors` sectors of `sector_size`.
fn build_mds_desc(start_offset: u64, sector_size: u16, num_sectors: u32) -> Vec<u8> {
    let mut img = vec![0u8; 200];
    img[0..16].copy_from_slice(b"MEDIA DESCRIPTOR");
    img[16] = 0x01;
    img[20..22].copy_from_slice(&1u16.to_le_bytes()); // num_sessions
    img[80..84].copy_from_slice(&88u32.to_le_bytes()); // sessions_blocks_offset
    let s = 88;
    img[s + 10] = 1; // num_all_blocks
    img[s + 20..s + 24].copy_from_slice(&112u32.to_le_bytes()); // tracks_blocks_offset
    let t = 112;
    img[t] = 0x02; // Mode 1
    img[t + 4] = 1; // point
    img[t + 12..t + 16].copy_from_slice(&192u32.to_le_bytes()); // extra_offset
    img[t + 16..t + 18].copy_from_slice(&sector_size.to_le_bytes());
    img[t + 40..t + 48].copy_from_slice(&start_offset.to_le_bytes());
    let e = 192;
    img[e + 4..e + 8].copy_from_slice(&num_sectors.to_le_bytes()); // length
    img
}

#[test]
fn info_opens_mds_mdf_set() {
    const PREAMBLE: u64 = 4096;
    if !rr_exists() {
        return;
    }
    let iso2048 = std::fs::read(iso("rock_ridge.iso")).unwrap();
    assert_eq!(iso2048.len() % 2048, 0);
    let num_sectors = (iso2048.len() / 2048) as u32;
    let mut mdf = vec![0u8; PREAMBLE as usize];
    mdf.extend_from_slice(&iso2048);
    let mds = build_mds_desc(PREAMBLE, 2048, num_sectors);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("disc.mdf"), &mdf).unwrap();
    std::fs::write(dir.path().join("disc.mds"), &mds).unwrap();
    let path = dir.path().join("disc.mds");
    bin()
        .args(["info", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("ROCK_RIDGE"));
}

// ── tracks (container TOC view) (v0.3-dev) ────────────────────────────────────

#[test]
fn tracks_lists_nrg_toc() {
    let nrg = build_nrg_mode0(&vec![0u8; 8192]); // dummy 4-sector track
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disc.nrg");
    std::fs::write(&path, &nrg).unwrap();
    bin()
        .args(["tracks", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Track"))
        .stdout(predicate::str::contains("NRG"));
}

#[test]
fn tracks_lists_mds_toc() {
    let mds = build_mds_desc(0, 2048, 4);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disc.mds");
    std::fs::write(&path, &mds).unwrap();
    bin()
        .args(["tracks", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Track"));
}

#[test]
fn tracks_lists_ccd_toc_with_mcn() {
    let ccd = "[CloneCD]\nVersion=3\n[Disc]\nTocEntries=4\nSessions=1\nCATALOG=1234567890123\n\
        [Entry 0]\nSession=1\nPoint=0xa0\nPMin=1\nPLBA=0\n\
        [Entry 1]\nSession=1\nPoint=0xa1\nPMin=1\nPLBA=0\n\
        [Entry 2]\nSession=1\nPoint=0xa2\nPLBA=47250\n\
        [Entry 3]\nSession=1\nPoint=0x01\nTrackNo=1\nPLBA=0\n\
        [TRACK 1]\nMODE=1\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("disc.ccd");
    std::fs::write(&path, ccd).unwrap();
    bin()
        .args(["tracks", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("1234567890123"))
        .stdout(predicate::str::contains("Track"));
}

// ── hfs (Apple HFS+ browsing) (v0.3-dev) ──────────────────────────────────────

fn hfs_fixture() -> String {
    // Real layout-NONE HFS+ volume: TOP.TXT, SUB/, SUB/NESTED.TXT ("nested data").
    format!("{}/../iso/tests/data/hfs_plus_nested.bin", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn hfs_lists_root() {
    let path = hfs_fixture();
    if !std::path::Path::new(&path).exists() {
        return;
    }
    bin()
        .args(["hfs", &path])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOP.TXT"))
        .stdout(predicate::str::contains("SUB"));
}

#[test]
fn hfs_recursive_lists_nested_paths() {
    let path = hfs_fixture();
    if !std::path::Path::new(&path).exists() {
        return;
    }
    bin()
        .args(["hfs", &path, "-R"])
        .assert()
        .success()
        .stdout(predicate::str::contains("SUB/NESTED.TXT"));
}

#[test]
fn hfs_extracts_root_file_to_stdout() {
    let path = hfs_fixture();
    if !std::path::Path::new(&path).exists() {
        return;
    }
    bin().args(["hfs", &path, "--extract", "TOP.TXT"]).assert().success().stdout(predicate::eq("top"));
}

#[test]
fn hfs_extracts_nested_file_by_path() {
    let path = hfs_fixture();
    if !std::path::Path::new(&path).exists() {
        return;
    }
    bin()
        .args(["hfs", &path, "--extract", "SUB/NESTED.TXT"])
        .assert()
        .success()
        .stdout(predicate::eq("nested data"));
}

#[test]
fn hfs_on_non_hfs_errors() {
    if !rr_exists() {
        return;
    }
    // rock_ridge.iso has no HFS+ volume.
    bin().args(["hfs", &iso("rock_ridge.iso")]).assert().failure();
}
