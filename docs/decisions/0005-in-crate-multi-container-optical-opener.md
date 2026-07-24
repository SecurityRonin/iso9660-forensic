# 5. Resolve optical container shapes in-crate via `open()`

Date: 2026-07-24
Status: Accepted

## Context

An ISO 9660 volume arrives inside several *optical* container shapes, not just a
raw `.iso`: a `.cue` sheet pointing at a `.bin`, a CloneCD `.ccd` pointing at an
`.img`, or a Nero `.nrg` / Alcohol `.mds` / CDRDAO `.toc` whose data track sits
at a byte offset inside a larger file, sometimes in 2352-byte raw CD sectors
rather than 2048-byte logical sectors.

The fleet's universal container abstraction (`disk-forensic::container::open`,
`ronin-issen/CLAUDE.md` "VFS & Universal Container Abstraction") decodes
**raw-disk acquisition containers** — Raw/dd, E01, VMDK, QCOW2, VHD/VHDX, DMG,
ISO, AFF4. It does not resolve the optical-specific `.cue`/`.ccd`/`.nrg`/`.mds`/
`.toc` sheet-and-track layouts, which are meaningful only to an optical reader.

## Decision

Provide an **in-crate `open(path) -> Box<dyn ReadSeek>`** (`opener.rs`, exported
from `lib.rs`) that resolves the optical container to a `Read + Seek` positioned
over the ISO 9660 data track:

- `.cue` → sibling `.bin`, `.ccd` → sibling `.img` (same-basename data file).
- `.nrg` / `.mds` / `.toc` → window the data track at its byte offset
  (`OffsetReader`), auto-detecting 2048 vs 2352-byte sector mode (`SectorMode`).
- Any other extension → opened as a raw image.
- `ReadSeek` is a type-erased `Read + Seek` blanket trait so the plain-file and
  offset-windowed resolutions unify behind one return type.

`opener.rs`'s module doc draws the boundary explicitly: "A higher-level tool
composes this with its own evidence-container layer (E01/VMDK/…) for non-optical
inputs." So the optical layer lives here; the raw-disk/acquisition layer stays in
`disk-forensic`.

## Consequences

- The same `analyse()` / `IsoReader` works across `.iso .cue .ccd .nrg .mds
  .toc` with no caller branching on format.
- This crate owns **optical** container knowledge only; it does not duplicate the
  raw-disk container detection that `disk-forensic::container::open` owns. An
  orchestrator that has already unwrapped an E01/VMDK feeds the resulting
  `Read + Seek` straight to `analyse()`.
- Adding another optical sheet format is a single new arm in `opener.rs`,
  benefiting every consumer at once.
