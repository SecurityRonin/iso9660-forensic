# 2. Expose an `analyse(reader) -> Analysis` contract matching the partition analyzers

Date: 2026-07-24
Status: Accepted

## Context

An ISO 9660 volume sits alongside partition schemes and other filesystem layers
that a disk-forensic orchestrator reports on together. Those sibling analyzers —
`gpt-forensic`, `mbr-forensic`, `apm-forensic` — already expose a uniform batch
entry point: `analyse(reader) -> Analysis`, returning a provenance summary plus a
list of graded anomalies. The fleet's own `report` model (`forensicnomicon`)
otherwise uses the verb `audit()` in the two-crate core/forensic convention.

This crate had to pick one surface for an orchestrator to call uniformly across
optical, partition, and filesystem layers.

## Decision

Mirror the sibling partition crates' contract rather than the `audit()`
convention:

- The public entry point is **`analyse(reader: &mut R) -> Result<IsoAnalysis,
  IsoError>`** plus `analyse_with_options` (`analysis.rs:104`), returning an
  `IsoVolumeInfo` provenance summary (tool fingerprints, timestamps, extension
  flags, El Torito boot records, Rock Ridge UIDs/GIDs/inodes) and a `Vec<Anomaly>`.
- Every `Anomaly`'s `severity`, machine-readable `code`, and human `note` are
  **derived from a single classified `AnomalyKind`** (`findings.rs` module doc),
  so the three can never drift out of sync.
- The module docs state the intent explicitly: `analysis.rs` and `findings.rs`
  both open with "Mirrors the sibling partition crates' `analyse(reader) ->
  Analysis` contract (`gpt-forensic`, `mbr-forensic`, `apm-forensic`)".

## Consequences

- A `disk-forensic` orchestrator calls the same `analyse()` shape on an ISO 9660
  volume as on a GPT/MBR/APM layer and aggregates the findings uniformly.
- The crate uses `analyse` where the two-crate core/forensic standard would use
  `audit`; this is intentional alignment with the partition-analyzer family, one
  concept / one name *within that family*.
- Derive-from-`AnomalyKind` keeps the 23 findings' code/severity/note
  self-consistent and makes adding a finding a single-site change.
