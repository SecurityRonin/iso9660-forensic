# 4. Memory-safety and panic-free posture for untrusted optical images

Date: 2026-07-24
Status: Accepted

## Context

Every input to this crate is an **untrusted, attacker-controllable disk image**:
a malformed PVD, a lying length field, an out-of-bounds extent, a directory
cycle, or a truncated track must never panic, read out of bounds, or produce
silently wrong output. This is the fleet's Paranoid Gatekeeper standard for
`*-forensic` parsers (`ronin-issen/CLAUDE.md`, "Security & Robustness Standard").

Two questions had to be settled: the `unsafe` posture, and how fixed-width
integer fields are read out of raw image bytes without panicking.

## Decision

1. **`unsafe_code = "deny"`** at the workspace root (`Cargo.toml`
   `[workspace.lints.rust]`). The crate in fact contains **zero** `unsafe`
   blocks and **zero** `#[allow(unsafe_code)]` sites (verified: no `unsafe`
   tokens in `iso/src`), so no memory-corruption surface exists. There is no
   `mmap` or FFI here — reads go through `std::io::{Read, Seek}`.
2. **Deny panics in production:** `unwrap_used` and `expect_used` are `deny` in
   the workspace clippy lints. Test modules opt out narrowly — `lib.rs` carries
   `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]` and each
   integration test file its own top-level allow.
3. **Route every fixed-width integer read through `safe-read`** (the fleet's
   single audited, `no_std`, `forbid(unsafe)`, fuzzed bounds-checked helper;
   `safe-read = "0.1"` at the workspace root). This removed the infallible
   `try_into().unwrap()` conversions from the parsers — including the
   macro-generated `both_endian` PVD reads that clippy could not see
   (`c75b849`), and the broader read routing in `ecf3719`.
4. **Fuzz the parse pipeline:** `fuzz/fuzz_targets/fuzz_open.rs` drives the
   `open`/`analyse` path over arbitrary bytes; `fuzz.yml` builds and smoke-runs
   it (`3bb9662`). Malformed structure (OOB extents, cycles, truncation) is
   *reported as a finding*, not a crash (README §"degrades gracefully").

## Consequences

- No input can corrupt memory (deny + zero unsafe) or panic the analyzer through
  a checked read; malformed images degrade to findings and typed `IsoError`s
  (`error.rs`: `NotAnIso`, `BadDescriptor`, `ResourceLimit`, `PathTraversal`, …).
- Resource limits guard against alloc bombs and runaway walks (`MAX_DIR_SIZE`
  = 64 MB, `MAX_WALK_DEPTH` = 256 in `lib.rs`).
- **`deny` rather than `forbid`:** the constitution names `forbid(unsafe)` as
  the default and goal for a zero-unsafe crate, and this crate could carry
  `forbid` today. It ships `deny`. The reason for choosing `deny` over `forbid`
  here is **reconstructed from structure; original intent not recovered in
  available history** — `deny` is the fleet template default and leaves a
  bounded per-site escape hatch, but no `#[allow(unsafe_code)]` uses it. A future
  hardening pass could tighten this to `forbid` at no functional cost.
- A single fuzz target covers the whole `open`→`analyse` funnel rather than one
  per parsed structure; expanding to per-structure targets is a future
  robustness improvement, not a correctness gap.
