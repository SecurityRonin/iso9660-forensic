# tests/data — ISO Corpus

Real ISO images from independent sources, covering all format variants the
parser claims to support. Using files produced by different tools satisfies the
doer-checker principle: the parser cannot share blind spots with the fixture
generator.

## Files

| File | Size | Format | Tool / Source | License |
|------|------|--------|---------------|---------|
| `dfvfs_plain.iso` | 358 KB | ISO 9660 only — no extensions | dfvfs reference corpus | Apache-2.0 |
| `rock_ridge.iso` | 376 KB | ISO 9660 + Rock Ridge (RRIP) | xorriso 1.5.8 (`-r`) | Generated |
| `joliet.iso` | 376 KB | ISO 9660 + Rock Ridge + Joliet | xorriso 1.5.8 (`-J`) | Generated |
| `multisession.iso` | 512 KB | ISO 9660 + Rock Ridge, 2 sessions | xorriso 1.5.8 (append) | Generated |
| `eltorito.iso` | 380 KB | ISO 9660 + Rock Ridge + Joliet + El Torito | xorriso 1.5.8 (`-b`) | Generated |
| `udf_bridge.iso` | 1.1 MB | ISO 9660 + Rock Ridge + Joliet + UDF | hdiutil makehybrid `-udf` | Generated |
| `truncated.iso` | 40 KB | ISO 9660 + Joliet + El Torito — truncated | ExifTool test suite | Artistic 2.0 |

## Provenance

### `dfvfs_plain.iso`
- **Origin**: log2timeline/dfvfs reference test corpus  
- **Source URL**: `https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw`
- **SHA-256**: `<run: shasum -a 256 dfvfs_plain.iso>`
- **Notes**: Pure ISO 9660 Level 1 with no Rock Ridge, Joliet, El Torito, or UDF.
  The only file in the corpus that exercises the plain-ISO code path without extensions.

### `rock_ridge.iso`
- **Origin**: Generated locally with xorriso 1.5.8 (Homebrew, macOS)
- **Command**: `xorriso -as mkisofs -o rock_ridge.iso -V "ROCK_RIDGE" -r <src>`
- **Notes**: Rock Ridge RRIP extensions (PX, TF, NM entries). No Joliet SVD.

### `joliet.iso`
- **Origin**: Generated locally with xorriso 1.5.8
- **Command**: `xorriso -as mkisofs -o joliet.iso -V "JOLIET" -J <src>`
- **Notes**: xorriso adds Rock Ridge by default even with `-J` only. Exercises
  the case where both Joliet SVD and Rock Ridge SUSP entries are present.

### `multisession.iso`
- **Origin**: Generated locally with xorriso 1.5.8 (two successive `-commit` runs)
- **Notes**: Two sessions: session 1 contains `hello.txt`; session 2 appends
  `nested.txt`. The active (last) session PVD determines `read_root_dir()`.

### `eltorito.iso`
- **Origin**: Generated locally with xorriso 1.5.8
- **Command**: `xorriso -as mkisofs -o eltorito.iso -V "EL_TORITO" -b boot.img -c boot.catalog -no-emul-boot -r -J -graft-points boot.img=<boot.img> <src>`
- **Notes**: Dummy zero-filled 2048-byte boot image — no real bootloader. Tests
  that boot catalog parsing does not depend on bootloader content.

### `udf_bridge.iso`
- **Origin**: Generated locally with macOS `hdiutil makehybrid -iso -joliet -udf`
- **Notes**: Contains ISO 9660 PVD + Joliet SVD + UDF recognition sequence (BEA01,
  NSR02, TEA01 at sectors 19–21). Tests the UDF detection code path.

### `truncated.iso`
- **Origin**: ExifTool test suite (`t/images/ISO.iso`)
- **License**: Artistic License 2.0 (ExifTool is Artistic/GPL dual-licensed)
- **Notes**: 40 KB file where the PVD declares a volume of ~381 MB. The metadata
  sectors (0–20) are intact and contain a valid ISO 9660 PVD, El Torito boot
  record, and Joliet SVD. File content sectors are absent. Used to verify the
  parser handles truncated images without panicking.

## Regenerating

```bash
# dfvfs plain ISO
curl -L https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw \
  -o dfvfs_plain.iso

# xorriso-generated variants
SRC=/tmp/iso_src && mkdir -p "$SRC/subdir"
printf 'hello\n' > "$SRC/hello.txt"
printf 'world\n' > "$SRC/world.txt"
printf 'nested\n' > "$SRC/subdir/nested.txt"

xorriso -as mkisofs -o rock_ridge.iso    -V ROCK_RIDGE  -r    "$SRC"
xorriso -as mkisofs -o joliet.iso        -V JOLIET      -J    "$SRC"

xorriso -outdev multisession.iso -volid SESSION1 -add "$SRC"/hello.txt  -- -commit -end
xorriso -dev    multisession.iso -volid SESSION2 -add "$SRC"/subdir/nested.txt -- -commit -end

dd if=/dev/zero of=/tmp/boot.img bs=512 count=4
xorriso -as mkisofs -o eltorito.iso -V EL_TORITO \
  -b boot.img -c boot.catalog -no-emul-boot -r -J \
  -graft-points boot.img=/tmp/boot.img "$SRC"

# UDF bridge (macOS only)
hdiutil makehybrid -o udf_bridge.iso -iso -joliet -udf "$SRC"
```
