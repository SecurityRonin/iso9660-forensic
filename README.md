[![Crates.io](https://img.shields.io/crates/v/iso9660-forensic.svg)](https://crates.io/crates/iso9660-forensic)
[![docs.rs](https://img.shields.io/docsrs/iso9660-forensic)](https://docs.rs/iso9660-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/iso9660-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/iso9660-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Hand an optical disc image to `analyse()` and get back a ranked list of tamper, corruption, and concealment findings — plus the provenance breadcrumbs that say who, what, and when built it.**

A pure-Rust ISO 9660 reader *and* forensic analyzer. The reader handles the extensions that trip up basic parsers (multi-session, Rock Ridge, Joliet, El Torito, raw 2352-byte CD sectors). The analyzer turns that parsing into **23 anomaly findings** — the redundant copies ISO 9660 keeps everywhere are diffed, and every non-file byte is carved.

## 30 seconds to a finding

```toml
[dependencies]
iso9660-forensic = "0.4"
```

```rust
use iso9660_forensic::analyse;
use std::fs::File;

let mut img = File::open("evidence.iso")?;
let report = analyse(&mut img)?;

// Provenance — what a report leads with (observed facts, never conclusions)
let v = &report.volume;
println!("label={:?}  mastered-by={:?}  created={:?}",
         v.volume_label, v.data_preparer_id, v.creation_time);

// Anomalies — ranked by severity, each with a stable code and a plain-language note
for a in &report.anomalies {
    println!("[{}] {} — {}", a.severity, a.code, a.note);
}
```

```text
label="INSTALL_CD"  mastered-by="MKISOFS 2.01"  created=Some("2026-01-14 09:02:11")
[High]   ISO-PATHTABLE-ENDIAN  — path-table entry 3: LBA mismatch L=412 M=88231 …
[High]   ISO-DISGUISED-EXEC    — `docs/readme.txt` content begins with a PE executable …
[Medium] ISO-TRAILING-DATA     — 1.2 MB of non-zero data past the declared volume end …
[Medium] ISO-SUPERSEDED-FILE   — `setup.ini` exists in session 0 but not the active tree …
```

Every finding derives its `severity`, `code`, and `note` from a single classified `kind`, so they can't drift — the same shape the sibling `gpt-forensic` / `mbr-forensic` crates use, ready to fold into one uniform report.

## What it detects

The engine is **redundancy + slack**: ISO 9660 stores most things twice (both-endian fields, two path tables, primary + Joliet trees, per-session descriptors) — diff every copy; then carve every byte no file claims. Each finding distinguishes an *observed fact* from a *"consistent with"* inference and leaves conclusions to the examiner.

| Category | Findings |
|----------|----------|
| **Cross-redundancy** (tamper) | both-endian field mismatch · L↔M path table · path-table↔tree (phantom/ghost dirs) · primary↔Joliet tree |
| **Slack & appended data** | non-zero file slack · trailing payload past volume end · pre-system-area payload · non-zero PVD reserved fields |
| **Structural** | out-of-bounds extent · overlapping extents · directory cycle · orphaned (unlinked) file |
| **Temporal** | file recorded after volume · mixed timezones · implausible volume date (pre-1985 / future) · ISO ↔ Rock Ridge time mismatch |
| **History** | superseded / recoverable content across sessions |
| **Identity & escape** | symlink path-traversal & absolute-target leak |
| **Concealment & authenticity** | Rock Ridge ↔ Joliet filename divergence · executable disguised by document extension · invalid/zero EDC · invalid Reed-Solomon P/Q ECC |

…and the provenance summary surfaces mastering-tool fingerprint, volume timestamps, the authoring time-window, Rock Ridge owner UIDs/GIDs/inodes, El Torito boot platforms + boot-image SHA-256, and the Rock Ridge / Joliet / ISO 9660:1999 extension flags.

It also **degrades gracefully on damaged evidence**: out-of-bounds extents, directory cycles, and truncated images are *reported as findings* rather than crashing the analysis.

## Feed it any optical container

`open()` resolves the common image containers to a `Read + Seek` over the ISO 9660 data track, so the same `analyse()` works on all of them:

```rust
use iso9660_forensic::{analyse, open};

let mut src = open("image.cue")?;   // .iso .cue .ccd .nrg .mds .toc
let report = analyse(&mut src)?;
```

## Browsing the volume

Beyond analysis, `IsoReader` is a full navigator:

```rust
use iso9660_forensic::IsoReader;
use std::fs::File;

let mut reader = IsoReader::open(File::open("image.iso")?)?;
println!("sessions={}  rock_ridge={}  joliet={}",
         reader.session_count(), reader.has_rock_ridge(), reader.has_joliet());

for entry in reader.walk()? {
    println!("  {}  ({} bytes, LBA {})", entry.path, entry.record.size, entry.record.lba);
}

let entry = reader.find_entry("docs/readme.txt")?;
let bytes = reader.read_file_entry(&entry)?;
```

| Extension | Basic reader | `iso9660-forensic` |
|-----------|:-----------:|:------:|
| Multi-session / multi-track | last session only | all sessions (+ per-session walk) |
| Rock Ridge (RRIP) NM / PX / TF / SL | no | yes |
| Joliet UCS-2 filenames | no | yes |
| El Torito boot catalog | no | yes (BIOS + UEFI, multi-section) |
| ISO 9660:1999 Enhanced Volume Descriptor | no | yes |
| Raw 2352-byte Mode-1 sectors | no | yes (auto-detected) |
| Path-traversal / cycle / OOB guards | rarely | always |

`serde` is behind the `serde` feature — every output type derives `Serialize` for JSON / DFXML reporting.

## Validation

- Validated against **independent real-world images** from distinct sources, so the parser can't share a blind spot with any single fixture generator — Microsoft VL pressing (plain ISO 9660), TinyCore Linux (Rock Ridge + Joliet + El Torito), Debian netinst (BIOS+UEFI hybrid boot), and real CloneCD / Alcohol / CDRDAO containers.
- Every anomaly was proven *silent on the clean corpus* before shipping, and the EDC/ECC algorithms are round-trip + known-answer tested against the ECMA-130 reference.
- Large images skip automatically when absent; run `bash corpus/fetch.sh` to enable them locally.

See [docs/formats.md](docs/formats.md) for the supported-format matrix and [docs/validation.md](docs/validation.md) for sources and reproduction steps.

## Where it fits

This crate reads **ISO 9660 + its optical layers only**. Other filesystems, partition schemes, and acquisition containers that may co-reside on or wrap a disc are separate single-responsibility crates — compose them at your orchestrator (e.g. `disk-forensic`) rather than expecting this one to know about them.

| Crate | Layer |
|-------|-------|
| [`udf-forensic`](https://github.com/SecurityRonin/udf-forensic) · [`hfsplus-forensic`](https://github.com/SecurityRonin/hfsplus-forensic) | Co-resident optical filesystems (UDF, Apple HFS+) |
| [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic) · [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) · [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) | Partition schemes (same `analyse()` contract) |
| [`ewf`](https://github.com/SecurityRonin/ewf) · [`aff4`](https://github.com/SecurityRonin/aff4) · [`vmdk`](https://github.com/SecurityRonin/vmdk) · [`vhdx`](https://github.com/SecurityRonin/vhdx) · [`dmg`](https://github.com/SecurityRonin/dmg) | Acquisition / virtual-disk containers |

---

[Privacy Policy](https://securityronin.github.io/iso9660-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/iso9660-forensic/terms/) · © 2026 Security Ronin Ltd
