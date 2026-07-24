# 7. Declare a low published MSRV floor distinct from the pinned dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`ronin-issen/CLAUDE.md` + `CLAUDE.core.md`, "Rust MSRV &
Toolchain Policy") separates two numbers that must not be conflated:

- the **dev toolchain** — one pinned current stable everyone builds/fmt/clippy
  with, to end version drift; and
- the **declared MSRV** (`rust-version`) — a downstream-facing compatibility
  promise, kept **low and CI-verified** for a *published library* because a low
  MSRV widens the crates.io audience and is a trust signal.

`iso9660-forensic` is a published library (developers link it), so both numbers
apply and must differ deliberately.

## Decision

- **Dev toolchain pinned to the fleet current stable:** `rust-toolchain.toml`
  → `channel = "1.96.0"`, with `clippy` + `rustfmt` components declared in the
  toml (single source of truth for CI and local), set in `a2ddc26`.
- **Declared MSRV floor `rust-version = "1.85"`** at the workspace root
  (`Cargo.toml [workspace.package]`), inherited by the member via
  `rust-version.workspace = true`. This is a deliberate low floor, distinct from
  the 1.96.0 dev pin, verified in CI.

## Consequences

- Downstream consumers on Rust as old as 1.85 can build the crate; contributors
  and CI all use 1.96.0, so fmt/clippy stay consistent.
- Bumping the dev pin (a fleet-wide, one-pass action) does **not** silently raise
  the promise; the MSRV floor moves only deliberately, as a near-breaking change.
- **The exact 1.85 floor** (versus the 1.75/1.80 the constitution cites as
  typical) is **reconstructed from structure; original intent not recovered in
  available history** — it is most likely the highest MSRV among the dependency
  graph (`forensicnomicon`, `safe-read`, `forensic-vfs`, `thiserror 2`), i.e. the
  lowest this crate can honestly verify, but the driving dependency is not
  recorded in the commit history.
