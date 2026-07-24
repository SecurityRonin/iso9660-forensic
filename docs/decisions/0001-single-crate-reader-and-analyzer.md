# 1. One crate combines the ISO 9660 reader and the forensic analyzer

Date: 2026-07-24
Status: Accepted

## Context

The fleet's default crate-structure standard (`ronin-issen/CLAUDE.md`,
"Crate-structure standard" / "Crate naming grammar", Pattern A) splits a
single-format repo into **two** crates: `<x>-core` (the raw reader) and
`<x>-forensic` (the anomaly analyzer). This repo does not follow that split. It
is a single-member Cargo workspace (`Cargo.toml` → `members = ["iso"]`) that
ships **one** crate, `iso9660-forensic` (`iso/Cargo.toml`), exposing both the
navigator (`IsoReader`, `open`, `walk`) and the analyzer (`analyse`,
`IsoAnalysis`) from the same `lib.rs`.

The forensic engine is "redundancy + slack" (README §"What it detects"): it
diffs the copies ISO 9660 keeps of everything (both-endian numeric fields, the L
and M path tables, primary vs Joliet trees, per-session descriptors) and carves
every byte no file claims. That work reaches directly into the parser's internal
structures — `analysis.rs` imports and drives `pvd`, `path_table`, `dir`,
`session`, `rock_ridge`, `el_torito`, and `sector` in-situ, exactly the raw,
possibly-broken structure the constitution says a `-forensic` layer must SEE
rather than consume through a normalized happy-path reader API. The same fleet
principle explicitly permits a `-forensic` analyzer to parse the format itself
at a lower level instead of going through `-core`.

The repo was born combined; the git history (333 commits, root `c0d7345`,
2026-05-25, "feat(iso): implement IsoReader with session, extension, and boot
detection") shows continuous development on the combined crate with no
split-vs-merge commit. The founding commit adds the reader alone, so the
combined crate grew a reader first and the analyzer on top of it — but no commit
records a deliberation of one crate versus two.

## Decision

1. Ship **one crate, `iso9660-forensic`**, holding both the reader and the
   analyzer. The crate name equals the repo name; the import path is
   `iso9660_forensic` (no `[lib] name` override), so consumers write
   `use iso9660_forensic::{analyse, IsoReader, open}`.
2. Keep the reader and analyzer as **separate modules** over one shared parser:
   `analysis.rs` (batch analysis surface) is distinct from the
   navigation/mount surface (`IsoReader`), and both "share the same parser
   underneath" (`analysis.rs` module doc). This preserves the
   reader/analyzer *conceptual* separation without a crate boundary.
3. Do **not** publish a separate `iso9660-core`; the parser modules stay
   `pub` inside this crate for lower-level consumers.

## Consequences

- The analyzer sees the raw structure it needs (deleted/superseded records,
  slack, both-endian mismatches) with no intermediate normalization — the
  motivating requirement.
- This is a deliberate deviation from Pattern A's two-crate split. A downstream
  developer who only wants the parser must pull the analyzer code too (it is one
  crate); the cost is small because the analyzer adds no heavy dependencies.
- Should a third party ever need a low-MSRV, analyzer-free `iso9660-core`, this
  decision would have to be revisited and the crate split — an additive,
  non-breaking move (new `-core` crate, re-export from here).
- **Rationale reconstructed from structure; original intent not recovered in
  available history.** The evidence supports *why the combined shape works*
  (the redundancy engine needs parser internals), but the record does not show a
  deliberation of one crate vs two at inception.
