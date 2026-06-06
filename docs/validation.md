# ISO Parser Validation Report

Assertion-level tests comparing `IsoReader` output against independent byte-level probes of each image. Every parser claim is backed by a reading tool that is entirely separate from the Rust crate under test.

**Checker:** Python 3 `struct` module and `xxd` — raw byte reads of the ISO volume descriptor chain and System Use area, performed independently of the `iso` crate.

**11 images · 7 committed fixtures · 4 large real-world images · 84 tests**

> **Scope note (v0.4):** This report covers the **reader** surface (`IsoReader`
> extension detection). UDF detection is no longer this crate's concern — it
> moved to the sibling [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic)
> crate — so the "UDF" rows below record what the *disc structure* contains (per
> independent byte probes), not a `has_udf()` API call. The **analyzer** surface
> (`analyse()` → `IsoAnalysis` findings) has its own validation: every anomaly is
> proven silent on this clean corpus and exercised by a tampered positive in
> `iso/tests/analyse.rs`.

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

### Committed fixtures (`iso/tests/data/`, tracked in git)

| File | Size | Format | Source |
|------|------|--------|--------|
| `dfvfs_plain.iso` | 358 KB | ISO 9660 only | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Apache-2.0) |
| `rock_ridge.iso` | 376 KB | ISO 9660 + Rock Ridge | xorriso 1.5.8 |
| `joliet.iso` | 376 KB | ISO 9660 + Rock Ridge + Joliet | xorriso 1.5.8 |
| `multisession.iso` | 512 KB | ISO 9660 + Rock Ridge, 2 sessions | xorriso 1.5.8 |
| `eltorito.iso` | 380 KB | ISO 9660 + Rock Ridge + Joliet + El Torito | xorriso 1.5.8 |
| `udf_bridge.iso` | 1.1 MB | ISO 9660 + Rock Ridge + Joliet + UDF | macOS `hdiutil` |
| `truncated.iso` | 40 KB | ISO 9660 + Joliet + El Torito — truncated | [ExifTool test suite](https://github.com/exiftool/exiftool) (Artistic 2.0) |

#### `dfvfs_plain.iso`

- **Origin:** [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) reference test corpus (Apache-2.0)
- **Download:** [github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw](https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw)
- **File size:** 358 KB (366,592 bytes)
- **SHA-256:** `7b9d0c5fbd5a22458eeb2288f2076d65b3541c6e27df449f96e372270fce7720`
- **Format:** ISO 9660 only — zero extensions

#### `rock_ridge.iso`

- **Origin:** Generated locally with xorriso 1.5.8 (Homebrew, macOS)
- **Command:** `xorriso -as mkisofs -o rock_ridge.iso -V ROCK_RIDGE -r <src>`
- **File size:** 376 KB
- **SHA-256:** `f740db513c1a09ec29c5c3092e5bf9a354b795bb15a02c068be20b2634df8f1a`
- **Format:** ISO 9660 + Rock Ridge

#### `joliet.iso`

- **Origin:** Generated locally with xorriso 1.5.8
- **Command:** `xorriso -as mkisofs -o joliet.iso -V JOLIET -J <src>`
- **File size:** 376 KB
- **SHA-256:** `ae29a73c7b090de7e7770247710735b6ae84a69c43ec6c1be5370ad5d5674207`
- **Format:** ISO 9660 + Rock Ridge + Joliet (xorriso adds Rock Ridge by default with `-J`)

#### `multisession.iso`

- **Origin:** Generated locally with xorriso 1.5.8 (two successive `-commit` runs)
- **Commands:**
  ```
  xorriso -outdev multisession.iso -volid SESSION1 -add hello.txt  -- -commit -end
  xorriso -dev    multisession.iso -volid SESSION2 -add nested.txt -- -commit -end
  ```
- **File size:** 512 KB
- **SHA-256:** `f26787ce1ac14e59539307c9e031bc91ec2ae03ea19b97ac84bf5d040e5ab95e`
- **Format:** ISO 9660 + Rock Ridge, 2 sessions

#### `eltorito.iso`

- **Origin:** Generated locally with xorriso 1.5.8
- **Command:** `xorriso -as mkisofs -o eltorito.iso -V EL_TORITO -b boot.img -c boot.catalog -no-emul-boot -r -J -graft-points boot.img=/tmp/boot.img <src>`
- **File size:** 380 KB
- **SHA-256:** `3e4f51b4b96e966d8793f4308e04963191c5783d1b0466efbcd80545936ecff2`
- **Format:** ISO 9660 + Rock Ridge + Joliet + El Torito

#### `udf_bridge.iso`

- **Origin:** Generated locally with macOS `hdiutil makehybrid -iso -joliet -udf`
- **File size:** 1.1 MB
- **SHA-256:** `8f4fe8f6768baad8eaa1fef643a6cecaca3fecad162f553e65ff1f7b95aeee95`
- **Format:** ISO 9660 + Rock Ridge + Joliet + UDF bridge (BEA01, NSR02, TEA01)

#### `truncated.iso`

- **Origin:** [ExifTool test suite](https://github.com/exiftool/exiftool) — `t/images/ISO.iso` (Artistic License 2.0)
- **Download:** [github.com/exiftool/exiftool/raw/master/t/images/ISO.iso](https://github.com/exiftool/exiftool/raw/master/t/images/ISO.iso)
- **File size:** 40 KB (40,960 bytes)
- **SHA-256:** `e8a435bb0dd2920d0aadd46cdc120b320c8a18b2e0fd7551587708addc12d783`
- **Format:** ISO 9660 + Joliet + El Torito — truncated (PVD declares ~381 MB, file is 40 KB)

---

### Large real-world images (`iso/tests/data/`, gitignored)

Tests in `real_world_large.rs` skip silently when a file is absent — CI always passes on a fresh checkout. Run `bash corpus/fetch.sh` to download.

| File | Size | Format | Source |
|------|------|--------|--------|
| `zh-hans_windows_xp_…x14-74070.iso` | 601 MB | ISO 9660 + El Torito | [archive.org](https://archive.org/search?query=x14-74070) (verify SHA-256) |
| `TinyCore-14.0.iso` | 23 MB | ISO 9660 + Rock Ridge + Joliet + El Torito | [distro.ibiblio.org](http://distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso) |
| `17763.1…SERVER-FOD…MULTI.iso` | 334 MB | ISO 9660 + UDF NSR02 | [Microsoft CDN](https://software-download.microsoft.com/download/pr/17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso) |
| `debian-13.5.0-amd64-netinst.iso` | 755 MB | ISO 9660 + Rock Ridge + Joliet + El Torito | [cdimage.debian.org](https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso) |

#### `zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso`

- **Origin:** Microsoft Volume License pressing (product ID x14-74070)
- **Archive:** [archive.org — search x14-74070](https://archive.org/search?query=x14-74070) — verify SHA-256 before use
- **File size:** 601 MB (630,106,112 bytes)
- **SHA-256:** `39430c2b8dd5c21bbd5af9116573f8c574ae896ce31d47280914ef268f01e33f`
- **License:** Microsoft proprietary — interoperability research and forensic tool validation
- **PVD label:** `GRTMPVOL_CN`
- **Format:** ISO 9660 + El Torito — no Joliet, no Rock Ridge, no UDF

#### `TinyCore-14.0.iso`

- **Origin:** Tiny Core Linux project, official ibiblio.org mirror
- **Download:** [distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso](http://distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso)
- **File size:** 23 MB (24,121,344 bytes)
- **SHA-256:** `62e78d715dfa86d7d486e3286b0215383dbeb99966bf0ceef7efb18f88caea21`
- **License:** GPL-2.0 (kernel) / various open-source (userland)
- **PVD label:** `TinyCore`
- **Format:** ISO 9660 + Rock Ridge + Joliet + El Torito

#### `17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso`

- **Origin:** Microsoft software-download CDN — direct download, no login required
- **Download:** [software-download.microsoft.com — Windows Server 2019 FOD](https://software-download.microsoft.com/download/pr/17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso)
- **File size:** 334 MB (350,771,200 bytes)
- **SHA-256:** `691a57879da249170400574a4919150c9b11f64f97f92f405dd36dcefcf33701`
- **License:** Microsoft proprietary — downloaded from official Microsoft CDN for interoperability/testing
- **PVD label:** `SFOD_X64FRE_SDL_DV9`
- **Format:** ISO 9660 + **UDF NSR02** — no Joliet, no Rock Ridge, no El Torito

#### `debian-13.5.0-amd64-netinst.iso`

- **Origin:** Official Debian CD image server
- **Download:** [cdimage.debian.org — debian-13.5.0-amd64-netinst.iso](https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso)
- **Checksums:** [cdimage.debian.org — SHA256SUMS](https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS)
- **File size:** 755 MB (791,674,880 bytes)
- **SHA-256:** `95838884f5ea6c82421dfe6baaa5a639dbbe6756c1e380f9fe7a7cb0c1949d2a`
- **License:** DFSG-free (Debian Free Software Guidelines)
- **PVD label:** `Debian 13.5.0 amd64 n` (build system truncates to 32 bytes)
- **Joliet label:** `Debian 13.5.0 am` (16 UCS-2 code units = 32 bytes)
- **Format:** ISO 9660 + Rock Ridge + Joliet + El Torito

---

## Test Results

### Committed fixtures — `real_images.rs`, `integration.rs`

#### `dfvfs_plain.iso` — baseline ISO 9660

**PASS** — `has_rock_ridge()=false`, `has_joliet()=false`, `session_count()=1`, `read_root_dir()` non-empty.

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

**PASS** — `has_joliet()=true`.

Probe confirmation: BEA01 → NSR02 → TEA01 sequence at LBAs 16–18 of the extended area (bytes offset +1 within each 2048-byte sector). Exercises: synthetic UDF recognition sequence from macOS `hdiutil`; real-world UDF validation is in §Win Server 2019 FOD below.

#### `truncated.iso` — no-panic contract

**PASS** — `IsoReader::open()` does not panic; `read_root_dir()` does not panic.

Exercises: 40 KB file where the PVD declares ~381 MB of content. Metadata sectors 0–20 are intact; file content sectors are absent. The parser may return `Ok` or `Err` — it must not panic under either branch.

---

### Large real-world images — `real_world_large.rs`

#### Windows XP SP3 Simplified Chinese VL — plain ISO 9660 + El Torito

**PASS** — `has_joliet()=false`, `has_rock_ridge()=false`, `boot_entries()` non-empty, `volume_label()="GRTMPVOL_CN"`, root contains `I386`.

Probe confirmation: VD chain is PVD (LBA 16) → Boot Record El Torito (LBA 17) → Terminator (LBA 18). No SVD present.

Exercises: Microsoft VL pressing behaviour — the VL edition omits the Joliet SVD that appears in retail and MSDN editions of the same release. Corrects the prior assumption that all Windows XP discs include Joliet; discovered by probing raw bytes before writing the test.

#### TinyCore Linux 14.0 — Rock Ridge + Joliet + El Torito

**PASS** — `has_rock_ridge()=true`, `has_joliet()=true`, `boot_entries()` non-empty, `volume_label()="TinyCore"`, root contains `BOOT`.

Probe confirmation: VD chain PVD (LBA 16) → Boot Record (LBA 17) → Joliet SVD `%/E` (LBA 18) → Terminator (LBA 19). SP entry `53 50 07 01 BE EF 00` in dot-record System Use area.

Exercises: third-party Linux distro with all three common extensions present simultaneously. Real-world Rock Ridge positive case independent of xorriso committed fixtures.

#### Windows Server 2019 Features on Demand — ISO 9660 + UDF NSR02

**PASS** — `has_joliet()=false`, `has_rock_ridge()=false`, `boot_entries()` empty, `volume_label()="SFOD_X64FRE_SDL_DV9"`, root contains `README`.

Probe confirmation: VD chain PVD (LBA 16) → Terminator (LBA 17). Extended area: BEA01 (LBA 18) → NSR02 (LBA 19) → TEA01 (LBA 20). Bytes `4E 53 52 30 32` (`NSR02`) confirmed at offset `lba*2048 + 1`.

Exercises: a genuine Microsoft-mastered UDF recognition sequence — read by the sibling `udf-forensic` crate, out of scope here. For *this* crate it is a strong real-world negative case (no Joliet, no Rock Ridge) and the sole negative case for El Torito among large images (package disc, no boot record). Sourced from Microsoft's own CDN, no third-party conversion.

#### Debian 13.5.0 amd64 netinst — Rock Ridge + Joliet + El Torito

**PASS** — `has_rock_ridge()=true`, `has_joliet()=true`, `boot_entries()` non-empty, `boot_entries()[0].bootable=true`, `volume_label()="Debian 13.5.0 amd64 n"`, `joliet_label()=Some("Debian 13.5.0 am")`, root contains `BOOT`/`EFI`.

Probe confirmation: VD chain PVD (LBA 16) → Boot Record El Torito / catalog at LBA 1027 (LBA 17) → Joliet SVD `%/E` (LBA 18) → Terminator (LBA 19). SP + PX + TF + NM entries throughout root directory. No NSR02/NSR03 at any LBA 16–36.

Exercises: modern Linux installer with all three classic extensions; UDF is structurally absent (no NSR02/NSR03 at any LBA 16–36, not just zeroed out). Volume label truncation at 32 bytes vs. 16 UCS-2 code units tested.

---

## Validation Coverage

Every feature has at least one real-world positive case and at least one real-world negative case from a source independent of the `iso` crate.

| Feature | Positive cases | Negative cases |
|---------|---------------|----------------|
| ISO 9660 baseline | all 11 images | — |
| Rock Ridge | `rock_ridge`, `joliet`, `multisession`, `eltorito`, `udf_bridge`, TinyCore, Debian | `dfvfs_plain`, `truncated`, WinXP VL, Win Server FOD |
| Joliet | `joliet`, `eltorito`, `udf_bridge`, `truncated`, TinyCore, Debian | `dfvfs_plain`, `rock_ridge`, `multisession`, WinXP VL, Win Server FOD |
| UDF *(disc structure; read by [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic))* | `udf_bridge`, **Win Server 2019 FOD** | `dfvfs_plain`, `rock_ridge`, `joliet`, TinyCore, Debian, WinXP VL |
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

### Running tests

```sh
# Committed-fixture tests (no downloads needed — files are in git)
cargo test --test real_images
cargo test --test integration

# Large real-world tests (skip silently if files are absent)
cargo test --test real_world_large
```

### Downloading large images

Run the fetch script from the repo root:

```bash
bash corpus/fetch.sh
```

Then verify checksums:

```bash
shasum -a 256 iso/tests/data/*.iso
```

The Windows XP VL image is no longer distributed by Microsoft. Search [archive.org for product ID x14-74070](https://archive.org/search?query=x14-74070) and verify the SHA-256 before use.

### Regenerating committed fixtures

```bash
SRC=/tmp/iso_src && mkdir -p "$SRC/subdir"
printf 'hello\n'  > "$SRC/hello.txt"
printf 'world\n'  > "$SRC/world.txt"
printf 'nested\n' > "$SRC/subdir/nested.txt"

# dfvfs plain ISO (external download)
curl -L https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw \
  -o iso/tests/data/dfvfs_plain.iso

# Rock Ridge
xorriso -as mkisofs -o iso/tests/data/rock_ridge.iso -V ROCK_RIDGE -r "$SRC"

# Joliet (xorriso adds Rock Ridge by default with -J)
xorriso -as mkisofs -o iso/tests/data/joliet.iso -V JOLIET -J "$SRC"

# Multi-session
xorriso -outdev iso/tests/data/multisession.iso -volid SESSION1 -add "$SRC"/hello.txt  -- -commit -end
xorriso -dev    iso/tests/data/multisession.iso -volid SESSION2 -add "$SRC"/subdir/nested.txt -- -commit -end

# El Torito
dd if=/dev/zero of=/tmp/boot.img bs=512 count=4
xorriso -as mkisofs -o iso/tests/data/eltorito.iso -V EL_TORITO \
  -b boot.img -c boot.catalog -no-emul-boot -r -J \
  -graft-points boot.img=/tmp/boot.img "$SRC"

# UDF bridge (macOS only)
hdiutil makehybrid -o iso/tests/data/udf_bridge.iso -iso -joliet -udf "$SRC"

# Truncated (external download)
curl -L https://github.com/exiftool/exiftool/raw/master/t/images/ISO.iso \
  -o iso/tests/data/truncated.iso
```
