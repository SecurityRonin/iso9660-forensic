# tests/data — ISO Test Corpus

All test data lives here. Small images (≤ 2 MB) are committed; large real-world images are listed in `.gitignore` and must be downloaded separately.

See [docs/validation.md](../../docs/validation.md) for SHA-256 hashes, source URLs, test results, coverage matrix, and reproduction steps.

## Committed fixtures

| File | Size | Format | Tool / Source |
|------|------|--------|---------------|
| `dfvfs_plain.iso` | 358 KB | ISO 9660 only | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) (Apache-2.0) |
| `rock_ridge.iso` | 376 KB | ISO 9660 + Rock Ridge | xorriso 1.5.8 |
| `joliet.iso` | 376 KB | ISO 9660 + Rock Ridge + Joliet | xorriso 1.5.8 |
| `multisession.iso` | 512 KB | ISO 9660 + Rock Ridge, 2 sessions | xorriso 1.5.8 |
| `eltorito.iso` | 380 KB | ISO 9660 + Rock Ridge + Joliet + El Torito | xorriso 1.5.8 |
| `udf_bridge.iso` | 1.1 MB | ISO 9660 + Rock Ridge + Joliet + UDF | macOS `hdiutil` |
| `truncated.iso` | 40 KB | ISO 9660 + Joliet + El Torito — truncated | [ExifTool test suite](https://github.com/exiftool/exiftool) (Artistic 2.0) |
| `multi_extent_8k.iso` | 120 KB | ISO 9660 + Rock Ridge, multi-extent file | [libcdio test corpus](https://github.com/libcdio/libcdio/tree/master/test/data) (GPL-3.0) |

### `multi_extent_8k.iso` — REAL-ext, `isoinfo` independent-oracle (`✓` confirmed)

Backs `iso/tests/isoinfo_oracle.rs`, which reconciles the parsed PVD + root
listing against cdrtools `isoinfo` (the independent oracle) rather than only
self-checking structural booleans.

- **Classification:** REAL-ext (real published test image, external corpus).
- **Source:** libcdio project regression-test corpus
  (xorriso/libisofs 1.5.5). Download URL (hotlinked):
  <https://raw.githubusercontent.com/libcdio/libcdio/master/test/data/multi_extent_8k.iso>
- **MD5:** `ab4592264b549fbbd393671db251e3fb` (122880 bytes).
- **SHA-256:** `c929aa5932527932fcca905cddea466d3ff768bac992dbafca94af6c4fbdbc85`
- **Genuine ISO 9660:** `CD001` magic at byte offset `0x8001` (sector 16) — verified.
- **Independent oracle:** cdrtools `isoinfo` (`brew install cdrtools`):
  ```sh
  isoinfo -d -i multi_extent_8k.iso   # PVD
  isoinfo -l -i multi_extent_8k.iso   # directory listing
  ```
  Reconciled values (`isoinfo` line → asserted value):
  - `Volume id: ISOIMAGE` → `volume_label()` == `"ISOIMAGE"`
  - `System id:` (empty) → `system_id()` == `""`
  - `Volume size is: 60` → `volume_space_size()` == `60`
  - `Logical block size is: 2048` → `logical_block_size()` == `2048`
  - `NO Joliet present` → `has_joliet()` == `false`
  - `Rock Ridge signatures version 1 found` (`RRIP_1991A`) → `has_rock_ridge()` == `true`
  - `isoinfo -l` root entry `MULTI_EXTENT_FILE.;1` → root listing == `["MULTI_EXTENT_FILE."]`
    (the parser strips the `;version` suffix)
- **Result:** `IsoReader` reproduces every reconciled `isoinfo` value exactly —
  no divergence found between the parser and `isoinfo`.

## Large real-world images (gitignored)

Tests in `real_world_large.rs` skip silently when absent — CI always passes on a fresh checkout. Run `bash corpus/fetch.sh` to download.

| File | Size | Key features |
|------|------|-------------|
| `zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso` | 601 MB | El Torito · no Joliet · no Rock Ridge · no UDF |
| `TinyCore-14.0.iso` | 23 MB | Rock Ridge · Joliet · El Torito |
| `17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso` | 334 MB | **UDF NSR02** · no Joliet · no Rock Ridge |
| `debian-13.5.0-amd64-netinst.iso` | 755 MB | Rock Ridge · Joliet · El Torito |
| `Fedora-Workstation-Live-44-1.7.x86_64.first-1MiB.iso` | 1 MiB prefix | Hybrid ISO false-positive session regression; first `bytes=0-1048575` from the official Fedora image |

### Fedora Workstation Live 44 prefix

- Source: <https://download.fedoraproject.org/pub/fedora/linux/releases/44/Workstation/x86_64/iso/Fedora-Workstation-Live-44-1.7.x86_64.iso>
- Download only bytes `0-1048575` (1,048,576 bytes); the full image is 2,851,612,672 bytes.
- SHA-256 of the prefix: `0cbadeafbc17f837d82629583845926c5e8d99f38c51fd6e89a5f117e8b28b7f`
- The prefix contains valid descriptors at LBAs 16 and 32; LBA 32 points at file data rather than a directory.
