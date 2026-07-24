# 3. Normalize findings onto the canonical `forensicnomicon::report` model

Date: 2026-07-24
Status: Accepted

## Context

Early versions of this crate carried a bespoke `IsoAnalysis`/severity type. The
fleet later adopted a single normalized reporting vocabulary,
`forensicnomicon::report` (`Severity`, `Category`, `Finding`, `Observation`), so
that ORCHESTRATION (issen, disk-forensic) and a future GUI render every
analyzer's output uniformly instead of N bespoke `XxxAnalysis` types
(`ronin-issen/CLAUDE.md`, "The Reporting Model"). `forensicnomicon` is the
KNOWLEDGE leaf every analyzer depends **down** onto.

This crate had to join that model without discarding its ISO-specific domain
knowledge (23 distinct anomaly kinds, each carrying the evidence to reproduce
the observation).

## Decision

Normalize onto `forensicnomicon::report` while keeping the typed domain enum
(the producer pattern the constitution prescribes):

- **Keep** the ISO-specific `AnomalyKind` enum (`findings.rs`) — each variant
  holds its own reproduction evidence (byte offsets, field names, LBAs).
- **Re-export** the canonical scale: `pub use forensicnomicon::report::Severity`
  (`findings.rs`), so this crate grades on the shared 5-level
  `Info < Low < Medium < High < Critical` axis with identity mapping (the
  constitution's severity-normalization table lists iso9660 as 5-level identity).
- **Implement** `forensicnomicon::report::Observation for Anomaly` (`findings.rs`)
  so an `Anomaly` converts to a canonical `Finding` in one place, letting an
  orchestrator fold ISO findings into one `Report`.
- Gate `forensicnomicon/serde` behind this crate's `serde` feature
  (`iso/Cargo.toml`) so JSON/DFXML reporting stays optional.

The migration is recorded in history: `d4b75a4` (RED — Anomaly → canonical
report::Finding), `772cfd6` ("normalize onto forensicnomicon::report", a `!`
breaking change), and `f044056` (release 0.5.0 on the new model).

## Consequences

- ISO findings aggregate uniformly with every other fleet analyzer's findings.
- `forensicnomicon` version bumps ripple here (the log shows tracked bumps
  0.3 → 0.5 → 0.11 → 1.0); the dependency is declared as `forensicnomicon = "1"`
  at the workspace root for one-edit control.
- The typed `AnomalyKind` retains the full ISO domain detail; the canonical
  `Finding` is the interchange form — no information is flattened away at the
  domain layer.
