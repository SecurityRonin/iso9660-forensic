# iso9660-forensic — Design, Purpose & Scope

This is a **library** design/scope doc, not a PRD. `iso9660-forensic` ships no
binary an examiner runs; it is a crate that other tools (`disk-forensic`, issen,
a future GUI) *link*. Per the fleet PRD & ADR standard, a linked library records
its "why does this exist" as a concise Purpose & Scope, and its load-bearing
decisions as ADRs under [`docs/decisions/`](decisions/). This document is the
former; it does not invent a product story the crate never had.

## Purpose

Turn an optical-disc image into two things a forensic examiner can act on:

1. **Provenance** — who/what/when built the disc: mastering-tool fingerprint and
   version, volume timestamps and the authoring time-window, Rock Ridge owner
   UIDs/GIDs/inodes, El Torito boot platforms and boot-image SHA-256, and the
   Rock Ridge / Joliet / ISO 9660:1999 extension flags.
2. **Anomaly findings** — a ranked list of tamper, corruption, concealment, and
   recovery observations, each a stable machine code plus a plain-language note,
   graded on the fleet's canonical 5-level severity.

The forensic engine is **redundancy + slack**: ISO 9660 stores most things
redundantly (both-endian numeric fields, the L and M path tables, primary vs
Joliet trees, per-session descriptors), so every copy is diffed for disagreement;
then every byte no file claims (slack, trailing payload, pre-system-area data) is
carved. Findings separate an *observed fact* from a *"consistent with"* inference
and leave conclusions to the examiner.

## Users

- **A disk-forensic orchestrator** that calls `analyse(reader)` on an ISO 9660
  volume uniformly alongside the partition analyzers (`gpt-forensic`,
  `mbr-forensic`, `apm-forensic`) and folds the results into one report
  (see ADR-0002, ADR-0003).
- **A Rust developer** who needs a pure-Rust ISO 9660 *reader* that handles the
  extensions basic parsers trip on: multi-session, Rock Ridge (RRIP), Joliet
  UCS-2, El Torito, ISO 9660:1999, and raw 2352-byte Mode-1 CD sectors.
- **A VFS/mount consumer** (with `--features vfs`) that composes the volume as
  `Arc<dyn FileSystem>` in the `forensic-vfs-engine` (ADR-0006).

## What it does

- **Read** — `IsoReader::open` navigates sessions, walks the directory tree
  (`walk`), resolves paths (`find_entry`), and streams file bytes
  (`read_file_entry`), with path-traversal / cycle / out-of-bounds guards always
  on.
- **Open any optical container** — `open(path)` resolves `.iso .cue .ccd .nrg
  .mds .toc` to a `Read + Seek` over the ISO 9660 data track, auto-detecting the
  sector mode (ADR-0005).
- **Analyse** — `analyse(reader)` returns an `IsoVolumeInfo` provenance summary
  plus the ranked anomaly list. The 23 findings span cross-redundancy (tamper),
  slack/appended data, structural defects, temporal inconsistencies, cross-
  session history (superseded/recoverable content), identity/escape (symlink
  traversal), and concealment/authenticity (Rock Ridge↔Joliet name divergence,
  document-extension-disguised executables, EDC/ECC validation per ECMA-130 §14).
- **Degrade gracefully** — out-of-bounds extents, directory cycles, and
  truncated images are *reported as findings*, never crashes (ADR-0004).

## Scope boundaries (non-goals)

- **This crate reads ISO 9660 and its optical layers only.** Co-resident optical
  filesystems (UDF, Apple HFS+), partition schemes, and acquisition/virtual-disk
  containers (E01/VMDK/VHDX/DMG/AFF4) are separate single-responsibility crates,
  composed at an orchestrator — not folded in here.
- **No raw-disk container detection.** `open()` handles optical sheet/track
  shapes; raw-disk and acquisition containers stay in
  `disk-forensic::container::open`, whose resulting `Read + Seek` this crate
  consumes (ADR-0005).
- **No verdicts.** Findings are observations and "consistent with" inferences;
  legal/intent conclusions are the examiner's, never the crate's.
- **No writing to evidence.** The crate is read-only over the image; derived
  artifacts (carved boot images, hashes) are values it returns, not edits.

## Robustness & memory-safety posture

Every input is an untrusted, attacker-controllable image. The crate carries zero
`unsafe`, denies `unwrap`/`expect` in production, routes fixed-width reads
through the audited `safe-read` helper, caps allocations and walk depth
(`MAX_DIR_SIZE` = 64 MB, `MAX_WALK_DEPTH` = 256), and is fuzzed over the
`open`/`analyse` pipeline. See ADR-0004.

## Validation approach

Correctness is proven against **independent oracles and real third-party discs**,
not only self-authored fixtures (see [`docs/validation.md`](validation.md)):

- PVD fields and root listing reconciled value-for-value against cdrtools
  `isoinfo` on the published libcdio `multi_extent_8k.iso` (Tier 1, real bytes).
- Extension detection exercised on independent real-world discs from distinct
  sources — Microsoft VL pressing (plain ISO 9660), TinyCore Linux (Rock Ridge +
  Joliet + El Torito), Windows Server 2019 FOD (UDF NSR02 negative case), Debian
  netinst (BIOS+UEFI hybrid boot) — so the parser cannot share a blind spot with
  any single fixture generator.
- Every anomaly proven silent on the clean corpus before shipping; the EDC/ECC
  validators are round-trip and tamper-detection tested.

## Key design decisions

See [`docs/decisions/`](decisions/):

- **0001** — one crate combines the reader and the analyzer (deviation from the
  two-crate core/forensic Pattern A).
- **0002** — `analyse(reader) -> Analysis` contract matching the partition
  analyzers.
- **0003** — findings normalized onto `forensicnomicon::report`.
- **0004** — memory-safety and panic-free posture (`unsafe = deny`, no unsafe
  sites; `unwrap`/`expect` denied; `safe-read`; fuzzed).
- **0005** — in-crate multi-container optical `open()`.
- **0006** — optional forensic-vfs `FileSystem` adapter behind the `vfs` feature.
- **0007** — low published MSRV floor (1.85) distinct from the 1.96.0 dev pin.
- **0008** — Apache-2.0 relicense.
