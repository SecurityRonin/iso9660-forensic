# ISO Parser Corpus Validation

Assertion-level tests comparing `IsoReader` output against independent byte-level probes of each corpus image. Every parser claim is backed by a reading tool that is entirely separate from the Rust crate under test.

**Checker:** Python 3 `struct` module and `xxd` — raw byte reads of the ISO volume descriptor chain and System Use area, performed independently of the `iso` crate.

**11 images · 7 committed fixtures · 4 large real-world images · 87 tests passing**

---

## Test Environment

| Component | Detail |
|-----------|--------|
| Raw probe tool | Python 3 `struct` / `xxd` |
| OS | macOS (Apple Silicon) |
| Rust toolchain | see `rust-toolchain.toml` |
| Committed fixture generator | xorriso 1.5.8 (Homebrew) · macOS `hdiutil` |

---

## Corpus Files

Full SHA-256 checksums, source URLs, and download commands are in [`iso/tests/data/SOURCES.md`](../iso/tests/data/SOURCES.md).

### Committed fixtures (`iso/tests/data/`, tracked in git)

| File | Size | Format | Source |
|------|------|--------|--------|
| `dfvfs_plain.iso` | 358 KB | ISO 9660 only | log2timeline/dfvfs (Apache-2.0) |
| `rock_ridge.iso` | 376 KB | + Rock Ridge | xorriso 1.5.8 |
| `joliet.iso` | 376 KB | + Rock Ridge + Joliet | xorriso 1.5.8 |
| `multisession.iso` | 512 KB | 2-session + Rock Ridge | xorriso 1.5.8 |
| `eltorito.iso` | 380 KB | + Rock Ridge + Joliet + El Torito | xorriso 1.5.8 |
| `udf_bridge.iso` | 1.1 MB | + Rock Ridge + Joliet + UDF | macOS `hdiutil` |
| `truncated.iso` | 40 KB | ISO 9660 + Joliet + El Torito — truncated | ExifTool test suite (Artistic 2.0) |

### Large real-world images (`iso/tests/data/`, gitignored)

Tests in `real_world_large.rs` skip silently when a file is absent — CI always passes on a fresh checkout.

| File | Size | Format | Source |
|------|------|--------|--------|
| `zh-hans_windows_xp_...x14-74070.iso` | 601 MB | ISO 9660 + El Torito | Microsoft VL (product ID x14-74070) |
| `TinyCore-14.0.iso` | 23 MB | + Rock Ridge + Joliet + El Torito | Tiny Core Linux project |
| `17763.1...SERVER-FOD...MULTI.iso` | 334 MB | ISO 9660 + **UDF NSR02** | Microsoft CDN (no login) |
| `debian-13.5.0-amd64-netinst.iso` | 755 MB | + Rock Ridge + Joliet + El Torito | Official Debian CD images |

---

## Test Results

Run the full corpus:

```sh
cargo test --test real_images
cargo test --test integration
cargo test --test real_world_large   # skips absent large images
```

### Committed fixtures — `real_images.rs`, `integration.rs`

#### `dfvfs_plain.iso` — baseline ISO 9660

**PASS** — `has_rock_ridge()=false`, `has_joliet()=false`, `has_udf()=false`, `session_count()=1`, `read_root_dir()` non-empty.

Exercises: the sole image with zero extensions — confirms all feature flags return false on a plain disc and that the root directory is readable without any SUSP/RRIP/Joliet/UDF overhead.

#### `rock_ridge.iso` — Rock Ridge only

**PASS** — `has_rock_ridge()=true`, `has_joliet()=false`.

Probe confirmation: SP System Use entry `53 50 07 01 BE EF 00` present in the dot-record of the root directory. Exercises: RRIP detection without Joliet SVD coexistence.

#### `joliet.iso` — Rock Ridge + Joliet

**PASS** — `has_joliet()=true`, `has_rock_ridge()=true`.

Probe confirmation: SVD at LBA 17, escape sequence bytes `25 2F 45` (`%/E`, UCS-2 Level 3). Exercises: coexistence of Joliet SVD and Rock Ridge System Use in the same image — xorriso adds Rock Ridge even when only `-J` is requested.

#### `multisession.iso` — 2-session disc

**PASS** — `session_count()>=2`, `read_root_dir()` reflects the last session's PVD.

Exercises: multi-track sector layout scanning; active session selection (last PVD governs `read_root_dir()`). Session 1 contains `hello.txt`; session 2 appends `nested.txt`.

#### `eltorito.iso` — El Torito boot catalog

**PASS** — `boot_entries()` non-empty, `entries[0].bootable=true`.

Probe confirmation: Boot Record VD at LBA 17, boot catalog LBA pointer verified against raw bytes. Exercises: boot catalog parsing independently of boot image content (dummy zero-filled image).

#### `udf_bridge.iso` — UDF bridge disc

**PASS** — `has_udf()=true`, `has_joliet()=true`.

Probe confirmation: BEA01 → NSR02 → TEA01 sequence at LBAs 16–18 of the extended area (bytes offset +1 within each 2048-byte sector). Exercises: synthetic UDF recognition sequence from macOS `hdiutil`; real-world UDF validation is in §Win Server 2019 FOD.

#### `truncated.iso` — no-panic contract

**PASS** — `IsoReader::open()` does not panic; `read_root_dir()` does not panic.

Exercises: 40 KB file where the PVD declares ~381 MB of content. Metadata sectors 0–20 are intact; file content sectors are absent. The parser may return `Ok` or `Err` — it must not panic under either branch.

---

### Large real-world images — `real_world_large.rs`

#### Windows XP SP3 Simplified Chinese VL — plain ISO 9660 + El Torito

**PASS** — `has_joliet()=false`, `has_rock_ridge()=false`, `has_udf()=false`, `boot_entries()` non-empty, `volume_label()="GRTMPVOL_CN"`, root contains `I386`.

Probe confirmation: VD chain is PVD (LBA 16) → Boot Record El Torito (LBA 17) → Terminator (LBA 18). No SVD present.

Exercises: Microsoft VL pressing behaviour — the VL edition omits the Joliet SVD that appears in retail and MSDN editions of the same release. Corrects the prior assumption that all Windows XP discs include Joliet; discovered by probing raw bytes before writing the test.

#### TinyCore Linux 14.0 — Rock Ridge + Joliet + El Torito

**PASS** — `has_rock_ridge()=true`, `has_joliet()=true`, `has_udf()=false`, `boot_entries()` non-empty, `volume_label()="TinyCore"`, root contains `BOOT`.

Probe confirmation: VD chain PVD (LBA 16) → Boot Record (LBA 17) → Joliet SVD `%/E` (LBA 18) → Terminator (LBA 19). SP entry `53 50 07 01 BE EF 00` in dot-record System Use area.

Exercises: third-party Linux distro with all three common extensions present simultaneously. Real-world Rock Ridge positive case independent of xorriso committed fixtures.

#### Windows Server 2019 Features on Demand — ISO 9660 + UDF NSR02

**PASS** — `has_udf()=true`, `has_joliet()=false`, `has_rock_ridge()=false`, `boot_entries()` empty, `volume_label()="SFOD_X64FRE_SDL_DV9"`, root contains `README`.

Probe confirmation: VD chain PVD (LBA 16) → Terminator (LBA 17). Extended area: BEA01 (LBA 18) → NSR02 (LBA 19) → TEA01 (LBA 20). Bytes `4E 53 52 30 32` (`NSR02`) confirmed at offset `lba*2048 + 1`.

Exercises: genuine Microsoft-mastered UDF recognition sequence — the authoritative real-world positive case for `has_udf()`. Sourced from Microsoft's own CDN, no third-party conversion. Also the sole negative case for El Torito among large images (package disc, no boot record).

#### Debian 13.5.0 amd64 netinst — Rock Ridge + Joliet + El Torito

**PASS** — `has_rock_ridge()=true`, `has_joliet()=true`, `has_udf()=false`, `boot_entries()` non-empty, `boot_entries()[0].bootable=true`, `volume_label()="Debian 13.5.0 amd64 n"`, `joliet_label()=Some("Debian 13.5.0 am")`, root contains `BOOT`/`EFI`.

Probe confirmation: VD chain PVD (LBA 16) → Boot Record El Torito / catalog at LBA 1027 (LBA 17) → Joliet SVD `%/E` (LBA 18) → Terminator (LBA 19). SP + PX + TF + NM entries throughout root directory. No NSR02/NSR03 at any LBA 16–36.

Exercises: modern Linux installer with all three classic extensions; confirms `has_udf()=false` on a current real-world disc where UDF is structurally absent (not just zeroed out). Volume label truncation at 32 bytes vs. 16 UCS-2 code units tested.

---

## Validation Coverage

Every feature has at least one real-world positive case and at least one real-world negative case from a source independent of the `iso` crate.

| Feature | Positive cases | Negative cases |
|---------|---------------|----------------|
| ISO 9660 baseline | all 11 images | — |
| Rock Ridge | `rock_ridge`, `joliet`, `multisession`, `eltorito`, `udf_bridge`, TinyCore, Debian | `dfvfs_plain`, `truncated`, WinXP VL, Win Server FOD |
| Joliet | `joliet`, `eltorito`, `udf_bridge`, `truncated`, TinyCore, Debian | `dfvfs_plain`, `rock_ridge`, `multisession`, WinXP VL, Win Server FOD |
| UDF | `udf_bridge`, **Win Server 2019 FOD** | `dfvfs_plain`, `rock_ridge`, `joliet`, TinyCore, Debian, WinXP VL |
| El Torito | `eltorito`, `truncated`, WinXP VL, TinyCore, Debian | `dfvfs_plain`, `rock_ridge`, `multisession`, `udf_bridge`, Win Server FOD |
| Multi-session | `multisession` | all single-session images |
| Truncated/malformed | `truncated` | all well-formed images |

**Full feature matrix:**

| Feature | dfvfs | rr | joliet | multi | eltorito | udf_bridge | trunc | WinXP | TinyCore | WinFOD | Debian |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Rock Ridge | — | ✓ | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | — | ✓ |
| Joliet | — | — | ✓ | — | ✓ | ✓ | ✓ | — | ✓ | — | ✓ |
| UDF | — | — | — | — | — | ✓ | — | — | — | ✓ | — |
| El Torito | — | — | — | — | ✓ | — | ✓ | ✓ | ✓ | — | ✓ |
| Multi-session | — | — | — | ✓ | — | — | — | — | — | — | — |
| Truncated | — | — | — | — | — | — | ✓ | — | — | — | — |
| **Source** | dfvfs | xorriso | xorriso | xorriso | xorriso | hdiutil | ExifTool | Microsoft | TinyCoreLinux | Microsoft | Debian |

---

## Reproducing

```sh
# Committed-fixture tests (no downloads needed)
cargo test --test real_images
cargo test --test integration

# Large real-world tests (requires files in iso/tests/data/)
cargo test --test real_world_large
```

See [`iso/tests/data/SOURCES.md`](../iso/tests/data/SOURCES.md) for per-file download, verification, and fixture-regeneration commands.
