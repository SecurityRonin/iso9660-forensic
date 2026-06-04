//! Validation tests against large real-world ISO images that are not committed
//! to the repository.
//!
//! Each test silently skips when the file is absent (CI / fresh checkouts).
//! To run locally: place the image in `iso/tests/data/` and run
//! `cargo test --test real_world_large`.
//!
//! Large images are listed in `iso/tests/data/.gitignore` — they live alongside
//! the committed fixtures but are excluded from version control by size.
//!
//! ## Provenance
//!
//! | File | Source | SHA-256 |
//! |------|--------|---------|
//! | `zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso` | Microsoft Volume License (x14-74070), mirrored at archive.org | `39430c2b8dd5c21bbd5af9116573f8c574ae896ce31d47280914ef268f01e33f` |
//! | `TinyCore-14.0.iso` | <http://distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso> | `62e78d715dfa86d7d486e3286b0215383dbeb99966bf0ceef7efb18f88caea21` |
//! | `debian-13.5.0-amd64-netinst.iso` | <https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso> | `95838884f5ea6c82421dfe6baaa5a639dbbe6756c1e380f9fe7a7cb0c1949d2a` |
//! | `17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso` | Microsoft Windows Server 2019 Features on Demand, <https://software-download.microsoft.com/download/pr/17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso> | `691a57879da249170400574a4919150c9b11f64f97f92f405dd36dcefcf33701` |

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use iso9660_forensic::IsoReader;

// ── Path helpers ──────────────────────────────────────────────────────────────

const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");

/// Return `Some(path)` if the file exists in `tests/data/`, `None` otherwise.
fn optional(name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(DATA_DIR).join(name);
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Open an ISO from `path`, returning `None` if the file is absent.
fn try_open(path: &Path) -> Option<IsoReader<BufReader<File>>> {
    let f = File::open(path).ok()?;
    IsoReader::open(BufReader::new(f)).ok()
}

// ── zh-hans Windows XP Professional SP3 x86 VL (x14-74070) ──────────────────
//
// Microsoft Volume License disc: ISO 9660 + Joliet, El Torito bootable.
// Microsoft never ships Rock Ridge or UDF on Windows install CDs.

const XP_ZH_HANS: &str =
    "zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso";

fn xp_path() -> Option<PathBuf> {
    optional(XP_ZH_HANS)
}

#[test]
fn winxp_opens_without_error() {
    let Some(path) = xp_path() else { return };
    let f = File::open(&path).expect("open ISO");
    IsoReader::open(BufReader::new(f)).expect("IsoReader::open must succeed on WinXP SP3 image");
}

#[test]
fn winxp_has_no_joliet() {
    // The Simplified Chinese VL edition (GRTMPVOL_CN, x14-74070) ships without
    // a Joliet SVD — only PVD + Boot Record + Terminator in its VD chain.
    // Retail/MSDN editions of XP do carry Joliet; VL presses do not.
    let Some(path) = xp_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(
        !r.has_joliet(),
        "zh-hans VL disc (GRTMPVOL_CN) must NOT report Joliet — no SVD in VD chain"
    );
}

#[test]
fn winxp_has_no_rock_ridge() {
    let Some(path) = xp_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(!r.has_rock_ridge(), "Microsoft install discs never carry Rock Ridge extensions");
}

#[test]
fn winxp_has_no_udf() {
    let Some(path) = xp_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(!r.has_udf(), "Windows XP install CD is not a UDF disc");
}

#[test]
fn winxp_is_single_session() {
    let Some(path) = xp_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(r.session_count(), 1, "Windows XP install disc is pressed single-session");
}

#[test]
fn winxp_has_boot_entries() {
    let Some(path) = xp_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(
        !entries.is_empty(),
        "Windows XP install disc must have at least one El Torito boot entry"
    );
}

#[test]
fn winxp_first_boot_entry_is_bootable() {
    let Some(path) = xp_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(!entries.is_empty(), "no boot entries found — cannot check bootable flag");
    assert!(entries[0].bootable, "first El Torito entry must be marked bootable");
}

#[test]
fn winxp_volume_label_is_grtmpvol_cn() {
    // "GRTM" = Golden RTM, "P" = Professional, "VOL" = Volume License, "CN" = Chinese.
    let Some(path) = xp_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(r.volume_label(), "GRTMPVOL_CN", "PVD volume label must be GRTMPVOL_CN");
}

#[test]
fn winxp_root_dir_has_entries() {
    let Some(path) = xp_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty(), "Windows XP root dir must contain at least one entry");
}

#[test]
fn winxp_root_dir_contains_i386() {
    let Some(path) = xp_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.read_root_dir().expect("read_root_dir");
    let has_i386 = entries.iter().any(|e| e.iso_name().eq_ignore_ascii_case("I386"));
    assert!(
        has_i386,
        "Windows XP root dir must contain I386 directory; got: {:?}",
        entries.iter().map(|e| e.iso_name()).collect::<Vec<_>>()
    );
}

#[test]
fn winxp_find_entry_i386_is_directory() {
    let Some(path) = xp_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entry = r.find_entry("I386").expect("find_entry(I386)");
    assert!(entry.is_dir(), "I386 must be a directory entry");
}

// ── TinyCore Linux 14.0 (x86) ────────────────────────────────────────────────
//
// Plain Linux live CD: ISO 9660 + Rock Ridge (RRIP, SP entry confirmed) +
// Joliet (%/E UCS-2 Level 3) + El Torito bootable. No UDF.
// Download: http://distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso
// SHA-256:  62e78d715dfa86d7d486e3286b0215383dbeb99966bf0ceef7efb18f88caea21

const TINYCORE: &str = "TinyCore-14.0.iso";

fn tc_path() -> Option<PathBuf> {
    optional(TINYCORE)
}

#[test]
fn tinycore_opens_without_error() {
    let Some(path) = tc_path() else { return };
    let f = File::open(&path).expect("open ISO");
    IsoReader::open(BufReader::new(f)).expect("IsoReader::open must succeed on TinyCore 14.0");
}

#[test]
fn tinycore_has_rock_ridge() {
    // Rock Ridge SP entry (magic 0xBEEF) confirmed in the dot-record System Use area.
    let Some(path) = tc_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(
        r.has_rock_ridge(),
        "TinyCore 14.0 must report Rock Ridge (SP entry present in root dir)"
    );
}

#[test]
fn tinycore_has_joliet() {
    // Joliet SVD at LBA 18 with escape sequence %/E (UCS-2 Level 3).
    let Some(path) = tc_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(r.has_joliet(), "TinyCore 14.0 must report Joliet (SVD with %/E escape present)");
}

#[test]
fn tinycore_has_no_udf() {
    let Some(path) = tc_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(
        !r.has_udf(),
        "TinyCore 14.0 is a plain ISO 9660 disc with no UDF recognition sequence"
    );
}

#[test]
fn tinycore_is_single_session() {
    let Some(path) = tc_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(r.session_count(), 1, "TinyCore 14.0 is a single-session pressed disc");
}

#[test]
fn tinycore_has_boot_entries() {
    let Some(path) = tc_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(!entries.is_empty(), "TinyCore 14.0 must have at least one El Torito boot entry");
}

#[test]
fn tinycore_first_boot_entry_is_bootable() {
    let Some(path) = tc_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(!entries.is_empty(), "no boot entries — cannot check bootable flag");
    assert!(entries[0].bootable, "first El Torito entry must be marked bootable");
}

#[test]
fn tinycore_volume_label_is_tinycore() {
    let Some(path) = tc_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(r.volume_label(), "TinyCore", "PVD volume label must be 'TinyCore'");
}

#[test]
fn tinycore_root_dir_contains_boot() {
    let Some(path) = tc_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.read_root_dir().expect("read_root_dir");
    let has_boot = entries.iter().any(|e| e.iso_name().eq_ignore_ascii_case("BOOT"));
    assert!(
        has_boot,
        "TinyCore root must contain BOOT directory; got: {:?}",
        entries.iter().map(|e| e.iso_name()).collect::<Vec<_>>()
    );
}

#[test]
fn tinycore_find_boot_is_directory() {
    let Some(path) = tc_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entry = r.find_entry("BOOT").expect("find_entry(BOOT)");
    assert!(entry.is_dir(), "BOOT must be a directory entry");
}

// ── Debian 13.5.0 amd64 netinst ──────────────────────────────────────────────
//
// Official Debian installer: ISO 9660 + Rock Ridge (SP confirmed) + Joliet
// (%/E, UCS-2 Level 3) + El Torito (no-emulation, bootable). No UDF.
// PVD label is truncated to 21 chars by the Debian build system.
//
// Download: https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso
// SHA-256:  95838884f5ea6c82421dfe6baaa5a639dbbe6756c1e380f9fe7a7cb0c1949d2a
// Size:     755 MB  (791,674,880 bytes)

const DEBIAN_NETINST: &str = "debian-13.5.0-amd64-netinst.iso";

fn debian_path() -> Option<PathBuf> {
    optional(DEBIAN_NETINST)
}

#[test]
fn debian_opens_without_error() {
    let Some(path) = debian_path() else { return };
    let f = File::open(&path).expect("open ISO");
    IsoReader::open(BufReader::new(f))
        .expect("IsoReader::open must succeed on Debian 13.5.0 amd64 netinst");
}

#[test]
fn debian_has_rock_ridge() {
    let Some(path) = debian_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(
        r.has_rock_ridge(),
        "Debian netinst must have Rock Ridge (SP entry confirmed in root dir dot record)"
    );
}

#[test]
fn debian_has_joliet() {
    // Joliet SVD at LBA 18 with escape sequence %/E (UCS-2 Level 3).
    let Some(path) = debian_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(r.has_joliet(), "Debian netinst must have Joliet SVD (%/E escape at LBA 18)");
}

#[test]
fn debian_has_no_udf() {
    // No NSR02/NSR03 recognition sequence in the standard Extended Area sectors.
    let Some(path) = debian_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(!r.has_udf(), "Debian 13.5.0 netinst is not a UDF disc");
}

#[test]
fn debian_is_single_session() {
    let Some(path) = debian_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(r.session_count(), 1, "Debian netinst is a single-session disc");
}

#[test]
fn debian_has_boot_entries() {
    let Some(path) = debian_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(!entries.is_empty(), "Debian netinst must have at least one El Torito boot entry");
}

#[test]
fn debian_first_boot_entry_is_bootable() {
    let Some(path) = debian_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(!entries.is_empty(), "no boot entries — cannot check bootable flag");
    assert!(entries[0].bootable, "first El Torito entry must be marked bootable (0x88)");
}

#[test]
fn debian_pvd_volume_label() {
    // Debian's build system truncates the PVD label to 21 chars.
    let Some(path) = debian_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(
        r.volume_label(),
        "Debian 13.5.0 amd64 n",
        "PVD label must be exactly 'Debian 13.5.0 amd64 n' (21 chars, Debian build truncation)"
    );
}

#[test]
fn debian_joliet_label_present() {
    let Some(path) = debian_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    let jlabel = r.joliet_label().expect("joliet_label must be Some — Joliet SVD is present");
    assert!(!jlabel.trim().is_empty(), "Joliet volume label must not be blank");
}

#[test]
fn debian_root_dir_has_entries() {
    let Some(path) = debian_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.read_root_dir().expect("read_root_dir");
    assert!(!entries.is_empty(), "Debian netinst root dir must have entries");
}

#[test]
fn debian_root_dir_contains_install() {
    let Some(path) = debian_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.read_root_dir().expect("read_root_dir");
    let has_install =
        entries.iter().any(|e| e.iso_name().to_ascii_uppercase().starts_with("INSTALL"));
    assert!(
        has_install,
        "Debian root dir must contain an INSTALL directory; got: {:?}",
        entries.iter().map(|e| e.iso_name()).collect::<Vec<_>>()
    );
}

#[test]
fn debian_find_boot_is_directory() {
    let Some(path) = debian_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entry = r.find_entry("BOOT").expect("find_entry(BOOT)");
    assert!(entry.is_dir(), "BOOT must be a directory entry");
}

#[test]
fn debian_find_efi_is_directory() {
    let Some(path) = debian_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entry = r.find_entry("EFI").expect("find_entry(EFI)");
    assert!(entry.is_dir(), "EFI must be a directory entry");
}

// ── Windows Server 2019 Features on Demand (FOD) ─────────────────────────────
//
// Real Microsoft disc with UDF NSR02 at LBA 19. Plain ISO 9660 + UDF bridge:
// no Rock Ridge, no Joliet, no El Torito (it is a package disc, not a bootable
// installer). Root dir visible via ISO 9660 contains only README.TXT.
//
// Source:  Microsoft software-download CDN (official, no login required)
// URL:     https://software-download.microsoft.com/download/pr/17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso
// SHA-256: 691a57879da249170400574a4919150c9b11f64f97f92f405dd36dcefcf33701
// Size:    334.5 MB (350,771,200 bytes)
// Label:   SFOD_X64FRE_SDL_DV9

const WIN_FOD: &str =
    "17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso";

fn fod_path() -> Option<PathBuf> {
    optional(WIN_FOD)
}

#[test]
fn win_fod_opens_without_error() {
    let Some(path) = fod_path() else { return };
    let f = File::open(&path).expect("open ISO");
    IsoReader::open(BufReader::new(f))
        .expect("IsoReader::open must succeed on Windows Server 2019 FOD disc");
}

#[test]
fn win_fod_has_udf() {
    // UDF VRS confirmed: BEA01 at LBA 18, NSR02 at LBA 19, TEA01 at LBA 20.
    let Some(path) = fod_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(r.has_udf(), "Windows Server 2019 FOD disc must report UDF (NSR02 at LBA 19)");
}

#[test]
fn win_fod_has_no_rock_ridge() {
    let Some(path) = fod_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(!r.has_rock_ridge(), "Microsoft FOD disc has no Rock Ridge extensions");
}

#[test]
fn win_fod_has_no_joliet() {
    // VD chain is PVD → Terminator (no SVD).
    let Some(path) = fod_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert!(!r.has_joliet(), "Windows Server 2019 FOD disc has no Joliet SVD");
}

#[test]
fn win_fod_is_single_session() {
    let Some(path) = fod_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(r.session_count(), 1);
}

#[test]
fn win_fod_has_no_boot_entries() {
    // FOD is a package disc, not a bootable installer — no El Torito boot record.
    let Some(path) = fod_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.boot_entries().expect("boot_entries");
    assert!(
        entries.is_empty(),
        "FOD disc has no El Torito boot record; got {} entries",
        entries.len()
    );
}

#[test]
fn win_fod_volume_label() {
    let Some(path) = fod_path() else { return };
    let r = try_open(&path).expect("IsoReader::open");
    assert_eq!(
        r.volume_label(),
        "SFOD_X64FRE_SDL_DV9",
        "PVD volume label must be SFOD_X64FRE_SDL_DV9"
    );
}

#[test]
fn win_fod_root_dir_has_readme() {
    // ISO 9660 root contains only README.TXT; package files live in the UDF volume.
    let Some(path) = fod_path() else { return };
    let mut r = try_open(&path).expect("IsoReader::open");
    let entries = r.read_root_dir().expect("read_root_dir");
    let has_readme =
        entries.iter().any(|e| e.iso_name().to_ascii_uppercase().starts_with("README"));
    assert!(
        has_readme,
        "FOD root dir must contain README.TXT; got: {:?}",
        entries.iter().map(|e| e.iso_name()).collect::<Vec<_>>()
    );
}
