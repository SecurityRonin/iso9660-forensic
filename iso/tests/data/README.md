# tests/data — ISO Test Corpus

All test data lives here. Small images (≤ 2 MB) are committed; large real-world images are listed in `.gitignore` and must be downloaded separately.

- **Validation report** (test results, checker methodology, coverage matrix): [`docs/validation.md`](../../../docs/validation.md)
- **Full provenance** (SHA-256, source URLs, download commands): [`SOURCES.md`](SOURCES.md)

## Committed fixtures

| File | Size | Format | Tool / Source |
|------|------|--------|---------------|
| `dfvfs_plain.iso` | 358 KB | ISO 9660 only | log2timeline/dfvfs (Apache-2.0) |
| `rock_ridge.iso` | 376 KB | ISO 9660 + Rock Ridge | xorriso 1.5.8 |
| `joliet.iso` | 376 KB | ISO 9660 + Rock Ridge + Joliet | xorriso 1.5.8 |
| `multisession.iso` | 512 KB | ISO 9660 + Rock Ridge, 2 sessions | xorriso 1.5.8 |
| `eltorito.iso` | 380 KB | ISO 9660 + Rock Ridge + Joliet + El Torito | xorriso 1.5.8 |
| `udf_bridge.iso` | 1.1 MB | ISO 9660 + Rock Ridge + Joliet + UDF | macOS `hdiutil` |
| `truncated.iso` | 40 KB | ISO 9660 + Joliet + El Torito — truncated | ExifTool test suite (Artistic 2.0) |

## Large real-world images (gitignored)

Tests in `real_world_large.rs` skip silently when absent — CI always passes on a fresh checkout. Run `corpus/fetch.sh` to download.

| File | Size | Key features |
|------|------|-------------|
| `zh-hans_windows_xp_professional_with_service_pack_3_x86_cd_vl_x14-74070.iso` | 601 MB | El Torito · no Joliet · no Rock Ridge · no UDF |
| `TinyCore-14.0.iso` | 23 MB | Rock Ridge · Joliet · El Torito |
| `17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso` | 334 MB | **UDF NSR02** · no Joliet · no Rock Ridge |
| `debian-13.5.0-amd64-netinst.iso` | 755 MB | Rock Ridge · Joliet · El Torito |
