# Validation

`iso9660-forensic` parses untrusted optical-disc images — ISO 9660 volume
descriptors, Rock Ridge / Joliet / El Torito extensions, and raw CD sector
layouts — from sources that may be mastered, tampered, or truncated. Correctness
is therefore established the way forensic tooling must be: against **independent
oracles** (a different tool, or a different code path, that already decodes the
same bytes correctly) on **real third-party corpora** with known ground truth,
and the few cases that rest on fixtures we constructed ourselves are labelled as
such rather than dressed up as independent.

This page records exactly which oracle and which corpus back each capability, so
the claim is independently re-checkable. Per-file provenance (source, download
URL, hashes, license) lives in
[`iso/tests/data/README.md`](https://github.com/SecurityRonin/iso9660-forensic/blob/main/iso/tests/data/README.md);
the fleet-wide machine index is `issen/docs/corpus-catalog.md`. This page
cross-references both rather than duplicating them.

> **Scope note.** This page covers the **reader** surface (`IsoReader` extension
> detection, navigation, sector-mode handling) and the **analyzer** surface
> (`analyse()` → `IsoAnalysis` findings). UDF *content* parsing is the sibling
> [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic) crate's concern;
> the UDF rows here record what the *disc structure* contains per byte-level
> probe, not a `has_udf()` API call.

## How to read the evidence tiers

Each validation below is tagged with the trustworthiness of its check, not
whether the data is "synthetic":

- **Tier 1** — an independent third party authored the artifact *and* the answer
  key, or it is real-world data decoded by an independent tool. The strongest claim.
- **Tier 2** — real engine output whose ground truth is derivable from the
  documented construction, or confirmed by an *independent code path* on real
  data. Genuinely checked, but we chose the scenario.
- **Tier 3** — fixture and expected answer both authored here, nothing
  independent vouching. Used only for per-branch coverage, never as a
  correctness claim: a self-consistent round trip proves internal consistency,
  not correctness against real-world bytes.

## Independent oracles

| Oracle | Independent of us? | Validates | Tier |
|---|---|---|---|
| **cdrtools `isoinfo`** (3.x) | Yes — separate C codebase | PVD fields (volume id, system id, volume size, logical block size), Rock Ridge / Joliet presence flags, and the root-directory listing — reconciled value-for-value against `isoinfo -d` / `isoinfo -l` | 1 |
| **Vendor-known disc construction** (Microsoft VL press, Debian/TinyCore release engineering) | Yes — the disc was mastered by a third party with a documented extension set | Which extensions a *real* pressed/released disc carries (e.g. a Microsoft VL XP press has no Joliet; Debian netinst carries Rock Ridge + Joliet + El Torito) | 2 |
| **In-crate EDC/ECC round trip** (`cd_edc` / `cd_ecc_stamp` → `mode1_ecc_valid`) | No — encoder and validator are both ours | That the ECMA-130 §14 EDC/ECC *validator* accepts a sector we stamped and rejects a tampered one (self-consistency only) | 3 |

For most committed fixtures there is currently **no in-test independent oracle**:
`real_images.rs` and `integration.rs` assert structural booleans
(`has_rock_ridge()`, `has_joliet()`, `session_count()`, "root dir not empty") on
images we generated with xorriso / `hdiutil`, where we chose the extension set.
The single fixture reconciled against `isoinfo` (`multi_extent_8k.iso`) is the
exception that closes that gap for the PVD + listing path. Adding an `isoinfo`
reconciliation for the remaining committed fixtures is the clearest path to
lifting them from Tier 3 to Tier 1 — see [Gaps](#gaps-and-next-steps).

## Independent test corpora

Real, third-party, publicly distributed images carrying independently
established ground truth. Large images are gitignored and fetched manually; the
small ones are committed. Hashes and full provenance are in
[`iso/tests/data/README.md`](https://github.com/SecurityRonin/iso9660-forensic/blob/main/iso/tests/data/README.md).

| Corpus | Source | License / redistribution | Used for |
|---|---|---|---|
| **`multi_extent_8k.iso`** | [libcdio regression corpus](https://github.com/libcdio/libcdio/tree/master/test/data) (xorriso/libisofs 1.5.5) | GPL-3.0; committed | PVD + listing reconciled against `isoinfo` (Tier 1) |
| **`dfvfs_plain.iso`** | [log2timeline/dfvfs](https://github.com/log2timeline/dfvfs) test corpus | Apache-2.0; committed | Real plain ISO 9660 negative case (no extensions) |
| **`truncated.iso`** | [ExifTool test suite](https://github.com/exiftool/exiftool) `t/images/ISO.iso` | Artistic-2.0; committed | No-panic contract on a PVD that over-declares size |
| **Windows XP SP3 Simplified Chinese VL** (`…x14-74070.iso`) | Microsoft VL pressing (via [archive.org](https://archive.org/search?query=x14-74070), verify SHA-256) | Microsoft proprietary — interoperability/forensic validation; gitignored | Real plain ISO 9660 + El Torito, no Joliet/RR (VL press) |
| **TinyCore Linux 14.0** (`TinyCore-14.0.iso`) | [distro.ibiblio.org](http://distro.ibiblio.org/tinycorelinux/14.x/x86/release/TinyCore-14.0.iso) | GPL-2.0 (kernel) / open-source userland; gitignored | Real Rock Ridge + Joliet + El Torito positive case |
| **Windows Server 2019 FOD** (`…SERVER-FOD-PACKAGES…MULTI.iso`) | [Microsoft CDN](https://software-download.microsoft.com/download/pr/17763.1.180914-1434.rs5_release_amd64fre_SERVER-FOD-PACKAGES_OEM_amd64fre_MULTI.iso) | Microsoft proprietary — interoperability/testing; gitignored | Real ISO 9660 + UDF NSR02, no Joliet/RR/El Torito |
| **Debian 13.5.0 amd64 netinst** (`debian-13.5.0-amd64-netinst.iso`) | [cdimage.debian.org](https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.5.0-amd64-netinst.iso) ([SHA256SUMS](https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS)) | DFSG-free; gitignored | Real Rock Ridge + Joliet + El Torito (BIOS+UEFI hybrid), label-truncation |

The remaining committed fixtures (`rock_ridge.iso`, `joliet.iso`,
`multisession.iso`, `eltorito.iso`, `udf_bridge.iso`) are **self-generated**
with xorriso 1.5.8 / macOS `hdiutil`; verbatim generator commands are in
[Reproducing the validation](#reproducing-the-validation). They give per-branch
coverage, not an independent answer key.

## Per-capability validation

### PVD fields + root listing — Tier 1

`iso/tests/isoinfo_oracle.rs` opens the real published `multi_extent_8k.iso`
(libcdio corpus) and asserts every parsed value equals **cdrtools `isoinfo`**
output: `volume_label() == "ISOIMAGE"`, `system_id() == ""`,
`volume_space_size() == 60`, `logical_block_size() == 2048`,
`has_joliet() == false`, `has_rock_ridge() == true` (RRIP_1991A), and the root
listing `["MULTI_EXTENT_FILE."]` (parser strips the `;version` suffix). The
asserted values are `isoinfo`'s, not constants we picked, so the PVD-decode and
directory-listing paths are checked against an independent tool on real bytes.

### Rock Ridge / Joliet / El Torito detection on real discs — Tier 2

`iso/tests/real_world_large.rs` (file-presence gated; skips cleanly when an image
is absent) checks the extension-detection flags against the *known* construction
of real third-party discs:

- **Windows XP SP3 Simplified Chinese VL** — `has_joliet() == false`,
  `has_rock_ridge() == false`, `boot_entries()` non-empty,
  `volume_label() == "GRTMPVOL_CN"`, root contains `I386`. A Microsoft VL press
  is mastered without the Joliet SVD that retail/MSDN editions carry — the
  ground truth comes from the disc's documented mastering, not from us.
- **TinyCore Linux 14.0** — `has_rock_ridge() == true`, `has_joliet() == true`,
  `boot_entries()` non-empty, `volume_label() == "TinyCore"`. A third-party
  distro carrying all three classic extensions at once.
- **Windows Server 2019 FOD** — `has_joliet() == false`,
  `has_rock_ridge() == false`, `boot_entries()` empty,
  `volume_label() == "SFOD_X64FRE_SDL_DV9"`; a genuine Microsoft-mastered UDF
  NSR02 recognition sequence (read by `udf-forensic`, out of scope here). Real
  negative case for all three ISO-level extensions.
- **Debian 13.5.0 netinst** — `has_rock_ridge() == true`, `has_joliet() == true`,
  `boot_entries()[0].bootable == true`,
  `volume_label() == "Debian 13.5.0 amd64 n"`,
  `joliet_label() == Some("Debian 13.5.0 am")`, root contains `BOOT`/`EFI`. Also
  exercises 32-byte ISO vs 16-UCS-2-code-unit Joliet label truncation.

These are Tier 2: the bytes are real and third-party, and the answer key is
derivable from each disc's documented construction — but the disc scenario, and
the assertion of what it should contain, are chosen by us rather than emitted by
an independent in-test tool.

### Plain ISO 9660 + truncation robustness — Tier 2

`iso/tests/real_images.rs` and `iso/tests/integration.rs`:

- **`dfvfs_plain.iso`** (dfvfs corpus) — `has_rock_ridge() == false`,
  `has_joliet() == false`, `session_count() == 1`, `read_root_dir()` non-empty:
  a real third-party plain ISO 9660 with zero extensions.
- **`truncated.iso`** (ExifTool corpus) — `IsoReader::open()` and
  `read_root_dir()` must not panic on a 40 KB file whose PVD declares ~381 MB.
  The parser may return `Ok` or `Err`; it must never panic. (No-panic contract;
  the bytes are third-party, the expectation is "does not crash".)

### Self-generated extension fixtures — Tier 3

`iso/tests/real_images.rs` also drives the xorriso / `hdiutil` fixtures
(`rock_ridge.iso`, `joliet.iso`, `multisession.iso`, `eltorito.iso`,
`udf_bridge.iso`) and asserts the extension flag matching the generator command
(`-r` → Rock Ridge, `-J` → Joliet, append → `session_count() >= 2`, `-b` →
non-empty `boot_entries()`, `hdiutil … -udf` → UDF bridge sequence). Because we
chose the construction and grade the booleans, these are Tier 3 per-branch
coverage — internally consistent, not an independent correctness claim. The
`multi_extent_8k.iso` `isoinfo` reconciliation above is the independent check
that the PVD/listing decode they share is genuinely correct.

### CD sector EDC/ECC validation — Tier 3

`iso/src/sector.rs` (unit tests) and `iso/tests/analyse.rs`
(`*_invalid_edc_is_flagged`, `*_invalid_ecc_is_flagged`, and their clean
counterparts) exercise the ECMA-130 §14 EDC (CRC-32) and Reed-Solomon P/Q ECC
validators. The check is a **self round trip**: our own `cd_edc()` /
`cd_ecc_stamp()` encoder stamps a Mode-1 sector, `mode1_ecc_valid()` then accepts
it, and a flipped byte is rejected and surfaced as `ISO-EDC-INVALID` /
`ISO-ECC-INVALID`. Encoder and validator are both ours, so this proves
self-consistency and tamper-sensitivity, **not** correctness against an
independent ECMA-130 reference vector. Lifting this to Tier 1 needs a known-answer
vector from an independent source (e.g. a sector EDC/ECC produced by `cdrdao`,
`bchunk`, or an Aaru dump) — tracked in [Gaps](#gaps-and-next-steps).

### Analyzer findings silent on clean corpus — Tier 2/3

`iso/tests/analyse.rs` and `iso/tests/audit.rs` assert that every anomaly is
*silent on a clean image* and *flagged on a tampered positive* built in-test.
The tamper is introduced by us (e.g. zeroing an EDC, corrupting a both-endian
field), so the per-finding positive/negative pairs are Tier 3 except where the
clean side is a real third-party disc (Tier 2). The canonical-finding shape
(code, severity, category) is checked in `iso/tests/canonical_finding_tests.rs`.

### Robustness — never panic, never over-read

The crate is `unsafe`-free and bounds-checks every length/offset field from the
image. `iso/tests/adversarial.rs` and the `truncated.iso` contract above drive
malformed and truncated inputs; out-of-bounds extents, directory cycles, and
truncated images are *reported as findings*, never panics.

## Reproducing the validation

The committed fixtures live in git, so the fixture-backed tests run with a plain
`cargo test`. The large real-world images are gitignored and fetched manually
(`bash corpus/fetch.sh`); their tests skip cleanly when the file is absent.

```bash
# Independent isoinfo oracle (committed fixture, always runs)
cargo test -p iso9660-forensic --test isoinfo_oracle

# Committed-fixture reader + analyzer tests (always run)
cargo test -p iso9660-forensic --test real_images --test integration --test analyse

# CD sector EDC/ECC self round-trip + sector-mode tests
cargo test -p iso9660-forensic --test analyse --test sector_modes
cargo test -p iso9660-forensic --lib            # sector.rs unit tests

# Large real-world discs (skip silently if the images are absent)
bash corpus/fetch.sh                            # download (gitignored)
shasum -a 256 iso/tests/data/*.iso              # verify against tests/data/README.md
cargo test -p iso9660-forensic --test real_world_large
```

The independent oracle used by `isoinfo_oracle.rs` is cdrtools `isoinfo`
(`brew install cdrtools`); the reconciled `isoinfo -d` / `isoinfo -l` lines are
recorded verbatim in
[`iso/tests/data/README.md`](https://github.com/SecurityRonin/iso9660-forensic/blob/main/iso/tests/data/README.md).

### Regenerating the self-generated fixtures

```bash
SRC=/tmp/iso_src && mkdir -p "$SRC/subdir"
printf 'hello\n'  > "$SRC/hello.txt"
printf 'world\n'  > "$SRC/world.txt"
printf 'nested\n' > "$SRC/subdir/nested.txt"

# Rock Ridge
xorriso -as mkisofs -o iso/tests/data/rock_ridge.iso -V ROCK_RIDGE -r "$SRC"
# Joliet (xorriso adds Rock Ridge by default with -J)
xorriso -as mkisofs -o iso/tests/data/joliet.iso -V JOLIET -J "$SRC"
# Multi-session (two successive -commit runs)
xorriso -outdev iso/tests/data/multisession.iso -volid SESSION1 -add "$SRC"/hello.txt  -- -commit -end
xorriso -dev    iso/tests/data/multisession.iso -volid SESSION2 -add "$SRC"/subdir/nested.txt -- -commit -end
# El Torito
dd if=/dev/zero of=/tmp/boot.img bs=512 count=4
xorriso -as mkisofs -o iso/tests/data/eltorito.iso -V EL_TORITO \
  -b boot.img -c boot.catalog -no-emul-boot -r -J \
  -graft-points boot.img=/tmp/boot.img "$SRC"
# UDF bridge (macOS only)
hdiutil makehybrid -o iso/tests/data/udf_bridge.iso -iso -joliet -udf "$SRC"

# Externally-sourced committed fixtures (download, do not generate)
curl -L https://github.com/log2timeline/dfvfs/raw/main/test_data/iso9660.raw \
  -o iso/tests/data/dfvfs_plain.iso
curl -L https://github.com/exiftool/exiftool/raw/master/t/images/ISO.iso \
  -o iso/tests/data/truncated.iso
curl -L https://raw.githubusercontent.com/libcdio/libcdio/master/test/data/multi_extent_8k.iso \
  -o iso/tests/data/multi_extent_8k.iso
```

## Feature coverage matrix

Every feature has at least one real-world positive case and at least one
real-world negative case from a source independent of the crate. Rows backed by
self-generated fixtures are Tier 3 (see above); rows backed by libcdio / dfvfs /
ExifTool / Microsoft / Debian / TinyCore images are Tier 1–2.

| Feature | dfvfs | rr | joliet | multi | eltorito | udf_bridge | trunc | multi_extent | WinXP | TinyCore | WinFOD | Debian |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Rock Ridge | — | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — | ✅ | — | ✅ |
| Joliet | — | — | ✅ | — | ✅ | ✅ | ✅ | — | — | ✅ | — | ✅ |
| UDF *(structure; read by [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic))* | — | — | — | — | — | ✅ | — | — | — | — | ✅ | — |
| El Torito | — | — | — | — | ✅ | — | ✅ | — | ✅ | ✅ | — | ✅ |
| Multi-session | — | — | — | ✅ | — | — | — | — | — | — | — | — |
| Truncated | — | — | — | — | — | — | ✅ | — | — | — | — | — |
| **Source** | dfvfs | xorriso | xorriso | xorriso | xorriso | hdiutil | ExifTool | libcdio | Microsoft | TinyCore | Microsoft | Debian |

## Gaps and next steps

Stated plainly so the trust claim is honest:

- **Most committed fixtures are Tier 3** (self-generated, structural-boolean
  assertions). The `isoinfo` reconciliation that lifts `multi_extent_8k.iso` to
  Tier 1 should be extended to `rock_ridge.iso`, `joliet.iso`, `eltorito.iso`,
  and `multisession.iso`.
- **EDC/ECC is a self round trip (Tier 3).** A known-answer vector from an
  independent CD-mastering tool (`cdrdao`, `bchunk`, or an Aaru raw dump) would
  make it Tier 1.
- **Large-image flag checks are Tier 2** — real bytes, but the answer key is the
  disc's documented construction asserted by us, not an in-test independent tool.
  Reconciling them against `isoinfo` / `xorriso -toc` would raise them to Tier 1.

## Coverage & fuzzing as backstops

Line coverage and any fuzz targets are regression backstops, not the correctness
argument — the oracle and corpus tables above carry that. See the repository CI
configuration for the current coverage gate and fuzzing status.
