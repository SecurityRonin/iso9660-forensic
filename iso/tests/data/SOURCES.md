# ISO Test Data — Provenance

Real ISO images from independent third-party sources used to validate the `iso` crate.

These exist to catch parser bugs that synthetic fixtures (built by this library) cannot detect — a doer-checker violation where both the fixture builder and the parser encode the same incorrect assumption.

All files verified against the checksums below.

---

## Summary Table

| Filename | Size | Source | License |
|----------|------|--------|---------|
| `dfvfs_plain.iso` | 358 KB | log2timeline/dfvfs | Apache-2.0 |
| `rock_ridge.iso` | 376 KB | Generated locally (xorriso 1.5.8) | — |
| `joliet.iso` | 376 KB | Generated locally (xorriso 1.5.8) | — |
| `multisession.iso` | 512 KB | Generated locally (xorriso 1.5.8) | — |
| `eltorito.iso` | 380 KB | Generated locally (xorriso 1.5.8) | — |
| `udf_bridge.iso` | 1.1 MB | Generated locally (macOS hdiutil) | — |
| `truncated.iso` | 40 KB | ExifTool test suite | Artistic 2.0 |
| `zh-hans_windows_xp_...x14-74070.iso` | 601 MB | Microsoft VL (x14-74070) | Microsoft proprietary |
| `TinyCore-14.0.iso` | 23 MB | Tiny Core Linux project | GPL-2.0/various |
| `17763.1...SERVER-FOD...MULTI.iso` | 334 MB | Microsoft CDN (no login) | Microsoft proprietary |
| `debian-13.5.0-amd64-netinst.iso` | 755 MB | Official Debian CD images | DFSG-free |

Large images (last 4) are gitignored. Run `corpus/fetch.sh` to download them.

---

## Files

### dfvfs_plain.iso

- **Origin:** log2timeline/dfvfs — reference test corpus
- **Source URL:** <https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw>
- **File size:** 358 KB (366,592 bytes)
- **SHA-256:** `7b9d0c5fbd5a22458eeb2288f2076d65b3541c6e27df449f96e372270fce7720`
- **License:** Apache-2.0
- **Notes:** Pure ISO 9660, no extensions. The only corpus image with zero Rock Ridge, Joliet, UDF, or El Torito overhead. Validates the baseline parse path.

### rock_ridge.iso

- **Origin:** Generated locally with xorriso 1.5.8 (Homebrew, macOS)
- **Command:** `xorriso -as mkisofs -o rock_ridge.iso -V ROCK_RIDGE -r <src>`
- **File size:** 376 KB
- **SHA-256:** `f740db513c1a09ec29c5c3092e5bf9a354b795bb15a02c068be20b2634df8f1a`
- **Notes:** xorriso is a distinct POSIX implementation from the genisoimage/mkisofs lineage. RRIP System Use extensions (SP, RR, PX, TF, NM). No Joliet SVD.

### joliet.iso

- **Origin:** Generated locally with xorriso 1.5.8
- **Command:** `xorriso -as mkisofs -o joliet.iso -V JOLIET -J <src>`
- **File size:** 376 KB
- **SHA-256:** `ae29a73c7b090de7e7770247710735b6ae84a69c43ec6c1be5370ad5d5674207`
- **Notes:** xorriso adds Rock Ridge by default even when only `-J` is specified — tests Joliet SVD and Rock Ridge SUSP coexistence in the same image.

### multisession.iso

- **Origin:** Generated locally with xorriso 1.5.8 (two successive `-commit` runs)
- **Commands:**
  ```
  xorriso -outdev multisession.iso -volid SESSION1 -add hello.txt  -- -commit -end
  xorriso -dev    multisession.iso -volid SESSION2 -add nested.txt -- -commit -end
  ```
- **File size:** 512 KB
- **SHA-256:** `f26787ce1ac14e59539307c9e031bc91ec2ae03ea19b97ac84bf5d040e5ab95e`
- **Notes:** Session 1 contains `hello.txt`; session 2 appends `nested.txt`. The active (last) session's PVD governs `read_root_dir()`.

### eltorito.iso

- **Origin:** Generated locally with xorriso 1.5.8
- **Command:** `xorriso -as mkisofs -o eltorito.iso -V EL_TORITO -b boot.img -c boot.catalog -no-emul-boot -r -J -graft-points boot.img=/tmp/boot.img <src>`
- **File size:** 380 KB
- **SHA-256:** `3e4f51b4b96e966d8793f4308e04963191c5783d1b0466efbcd80545936ecff2`
- **Notes:** Dummy zero-filled 2048-byte boot image — tests that boot catalog parsing is content-agnostic.

### udf_bridge.iso

- **Origin:** Generated locally with macOS `hdiutil makehybrid -iso -joliet -udf`
- **File size:** 1.1 MB
- **SHA-256:** `8f4fe8f6768baad8eaa1fef643a6cecaca3fecad162f553e65ff1f7b95aeee95`
- **Notes:** Contains ISO 9660 PVD + Joliet SVD + UDF recognition sequence (BEA01, NSR02, TEA01). Tests synthetic UDF detection; real-world UDF validation is provided by the Win Server 2019 FOD image.

### truncated.iso

- **Origin:** ExifTool test suite (`t/images/ISO.iso`)
- **Source URL:** <https://github.com/exiftool/exiftool/raw/master/t/images/ISO.iso>
- **File size:** 40 KB (40,960 bytes)
- **SHA-256:** `e8a435bb0dd2920d0aadd46cdc120b320c8a18b2e0fd7551587708addc12d783`
- **License:** Artistic License 2.0
- **Notes:** 40 KB file where the PVD declares ~381 MB. Metadata sectors 0–20 are intact (valid PVD, El Torito boot record, Joliet SVD). File content sectors are absent. Validates the no-panic contract on malformed images.

---

### zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso

- **Origin:** Microsoft Volume License (product ID x14-74070); archived at [archive.org](https://archive.org/search?query=x14-74070)
- **File size:** 601 MB (630,106,112 bytes)
- **SHA-256:** `39430c2b8dd5c21bbd5af9116573f8c574ae896ce31d47280914ef268f01e33f`
- **License:** Microsoft proprietary — use for interoperability research and forensic tool validation
- **PVD label:** `GRTMPVOL_CN`
- **Notes:** The VL pressing has no Joliet SVD — PVD + Boot Record + Terminator only. Retail and MSDN editions of the same release do include a Joliet SVD; this VL pressing does not. Discovered by probing raw bytes; prior assumption (XP always has Joliet) was wrong and corrected by this image.

### TinyCore-14.0.iso

- **Origin:** Tiny Core Linux project, official ibiblio.org mirror
- **Source URL:** <http://distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso>
- **File size:** 23 MB (24,121,344 bytes)
- **SHA-256:** `62e78d715dfa86d7d486e3286b0215383dbeb99966bf0ceef7efb18f88caea21`
- **License:** GPL-2.0 (kernel) / various open-source (userland)
- **PVD label:** `TinyCore`
- **Notes:** VD chain: PVD → Boot Record (El Torito) → Joliet SVD (`%/E`) → Terminator. SP entry `53 50 07 01 BE EF 00` in dot-record System Use area. Real-world Rock Ridge + Joliet + El Torito positive case independent of xorriso committed fixtures.

### 17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso

- **Origin:** Microsoft software-download CDN — direct download, no login or form required
- **Source URL:** <https://software-download.microsoft.com/download/pr/17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso>
- **File size:** 334 MB (350,771,200 bytes)
- **SHA-256:** `691a57879da249170400574a4919150c9b11f64f97f92f405dd36dcefcf33701`
- **License:** Microsoft proprietary — download from official Microsoft CDN for interoperability/testing
- **PVD label:** `SFOD_X64FRE_SDL_DV9`
- **Notes:** Windows Server 2019 Features on Demand package disc mastered by Microsoft's own toolchain. VD chain: PVD (LBA 16) → Terminator (LBA 17); extended area: BEA01 (LBA 18) → NSR02 (LBA 19) → TEA01 (LBA 20). Authoritative real-world positive case for `has_udf()` — smallest freely downloadable Microsoft ISO carrying genuine UDF NSR02.

### debian-13.5.0-amd64-netinst.iso

- **Origin:** Official Debian CD image server
- **Source URL:** <https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso>
- **Checksum source:** <https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS>
- **File size:** 755 MB (791,674,880 bytes)
- **SHA-256:** `95838884f5ea6c82421dfe6baaa5a639dbbe6756c1e380f9fe7a7cb0c1949d2a`
- **License:** DFSG-free (Debian Free Software Guidelines)
- **PVD label:** `Debian 13.5.0 amd64 n` (build system truncates to 32 bytes)
- **Joliet label:** `Debian 13.5.0 am` (16 UCS-2 code units = 32 bytes)
- **Notes:** VD chain: PVD → Boot Record (El Torito, catalog at LBA 1027) → Joliet SVD (`%/E`) → Terminator. SP + PX + TF + NM entries throughout root directory. No NSR02/NSR03 at any LBA in 16–36 — confirms `has_udf()=false` on a real modern Linux installer. Volume label truncation at 32 bytes vs. 16 UCS-2 code units validated.

---

## Re-downloading

Run the fetch script from the repo root:

```bash
bash corpus/fetch.sh
```

Then verify checksums:

```bash
shasum -a 256 iso/tests/data/*.iso
```

For the Windows XP VL image, search [archive.org](https://archive.org/search?query=x14-74070) for product ID `x14-74070` and verify the SHA-256 before use.

---

## Regenerating committed fixtures

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
