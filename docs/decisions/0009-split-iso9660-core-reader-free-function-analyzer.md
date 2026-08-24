# 9. Split the reader into `iso9660-core`; audit methods become free functions

Date: 2026-08-24

Status: Accepted

Supersedes [ADR-0001](0001-single-crate-reader-and-analyzer.md).

## Context

[ADR-0001](0001-single-crate-reader-and-analyzer.md) kept the reader and the
analyzer in one crate. It recorded that the repo was "born combined" with "no
commit [recording] a deliberation of one crate versus two" — the single crate
was organic growth, not a decision. A reader-only consumer now exists
(`forensic-vfs-engine`, and an external archiver), which is the condition the
fleet standard names for revisiting a combined crate.

The other two filesystem repos split this month (`udf-forensic` ADR-0010,
`hfsplus-forensic` ADR-0009) were **source-compatible** splits: their analyzer
was already a separate module of free functions, so relocating it changed
nothing at any call site. iso9660 differs. Its `analyse() -> IsoAnalysis`
aggregate was a free function, but the *fine-grained* audit operations
(`audit_both_endian`, `fingerprint_tool`, `timeline`, `hashlist`,
`recover_lost_files`, …) had accreted as **inherent methods on `IsoReader`**.
Rust forbids defining a type's inherent methods outside its own crate, so those
methods cannot move to `iso9660-forensic` while `IsoReader` lives in
`iso9660-core`.

Two ways to resolve that were considered: an **extension trait** (keeps
`reader.audit_x()`, adds a `use` at each call site), and **free functions**
(`audit_x(&mut reader)`, matching udf/hfsplus). Both yield the same lean core;
the free-function form was chosen for **consistency** — so all three filesystem
analyzers present the same shape.

## Decision

Split the workspace into two published members:

- **`iso9660-core`** — the reader: volume descriptors, path tables, directory /
  Rock Ridge / Joliet / El Torito traversal, file extraction, multi-session, and
  the CD image formats (bw5/ccd/cdi/cue/mds/nrg), plus the optional `vfs`
  adapter. It carries **no `forensicnomicon` dependency**.
- **`iso9660-forensic`** — the analyzer: `analysis`, `audit`, `findings`, and the
  audit operations **as free functions over the reader**.

`iso9660-forensic` re-exports the entire reader surface (`pub use
iso9660_core::*`), so reader access is **unchanged**: `iso9660_forensic::{IsoReader,
open, walk}` and the `vfs` feature keep working, and the `analyse()` aggregate is
untouched. External reader consumers (`forensic-vfs-engine`, the archiver) need
no change.

## Consequences

- **The audit methods are now free functions** — the one breaking change. A
  caller of `reader.audit_both_endian()` writes
  `iso9660_forensic::audit_both_endian(&mut reader)`. In practice **no fleet
  consumer called the fine-grained audit methods**: `issen` uses the reader
  (`IsoReader::open`) and `disk-forensic` uses the `analyse()` aggregate (a free
  function, unchanged) and `IsoAnalysis`. The only callers were this repo's own
  tests, converted here. So despite the public-API change, no companion change to
  a consumer was needed — verified by a fleet-wide grep for every audit-method
  name across `components/orchestration/`.
- A reader-only consumer links `iso9660-core` with no `forensicnomicon` and a
  reader-only dependency set.
- The reader internals the analyzer grades over (`pvd()`, `svd()`,
  `boot_catalog_lba()`, `read_path_table_bytes`) become part of `iso9660-core`'s
  public API — the seam the free functions need.
- **The reader publishes as `iso9660-forensic-core`, not `iso9660-core`** — the
  latter is squatted on crates.io by an unrelated third party. Per the fleet
  naming grammar, the collided `-core` name takes the full repo-prefixed form
  with a `[lib] name = "iso9660_core"` override, so the import path is
  unchanged: all `use iso9660_core::` code and the facade keep working.
- All three filesystem analyzers now present the same shape: a lean `-core`
  reader and a `-forensic` analyzer whose operations are free functions.
