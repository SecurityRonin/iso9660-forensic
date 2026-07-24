# 8. Relicense from MIT to Apache-2.0

Date: 2026-07-24
Status: Accepted

## Context

The crate was originally published under MIT. The fleet standardized on
**Apache-2.0** for its explicit patent grant, and directs any residual
MIT repo to migrate (`ronin-issen/CLAUDE.md`, README standard: "the fleet
standardized on Apache-2.0 for its explicit patent grant — migrate any residual
MIT repos").

## Decision

Relicense the crate to **Apache-2.0**:

- `license = "Apache-2.0"` at the workspace root (`Cargo.toml
  [workspace.package]`), inherited by the member via `license.workspace = true`.
- `LICENSE` carries the verbatim Apache-2.0 text.
- The README badge links to `LICENSE` as the single source of truth; there is no
  `## License` prose section.

Recorded in `b6b525a` (relicense MIT → Apache-2.0) and `3701627` (use verbatim
Apache-2.0 license text).

## Consequences

- Consumers get an explicit patent grant; the crate is license-consistent with
  the rest of the fleet, which matters for aggregation into `disk-forensic` /
  issen.
- `deny.toml` allows Apache-2.0 (and the permissive set MIT/BSD/ISC/Unicode-3.0/
  Zlib) so the dependency graph stays license-clean under `cargo deny`.
- Apache-2.0 is one-way relative to MIT-only downstreams that cannot accept its
  terms; this is accepted as the fleet norm.
