# 6. Ship the forensic-vfs FileSystem adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

`forensic-vfs` is the fleet's KNOWLEDGE-leaf contract crate for uniform,
read-only filesystem navigation: a reader that implements its `FileSystem` trait
composes as `Arc<dyn FileSystem>` in the `forensic-vfs-engine`, so a whole stack
(container → volume system → crypto → filesystem) reads as one `ImageSource` that
N workers share (`ronin-issen/CLAUDE.md`, "VFS & Universal Container
Abstraction"). Wiring an ISO 9660 volume into that engine lets it be mounted and
walked alongside NTFS/ext4/APFS through one contract.

But not every consumer of this crate wants the engine. A bare parser or the
`analyse()` path should stay dependency-light and not pull `forensic-vfs`.

## Decision

Provide an `IsoVfs` adapter (`vfs.rs`) that implements `FileSystem` for a wrapped
`IsoReader`, **gated behind a non-default `vfs` Cargo feature**
(`iso/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, with `forensic-vfs = { version
= "0.7", optional = true }`). Design points documented in `vfs.rs`:

- The reader is wrapped in a `Mutex`, so every read is `&self` over interior
  mutability and one mounted handle serves N workers (matching the ext4/NTFS
  adapters).
- Nodes are addressed by `FileId::IsoExtent` — the directory record's data
  extent LBA — the ISO identity primitive (there is no inode table), backed by a
  per-extent record cache seeded from the PVD root at open.
- Time mapping is honest: the single ISO recording time maps to `born`
  (matching TSK `istat` *Created*); `modified/accessed/changed` are `None`, not
  epoch-0; unknown GMT offset ⇒ `TimeZonePolicy::LocalUnknown`.

Implemented TDD in `c3086ee` (RED) / `ab65495` (GREEN); the dependency was
tracked forward 0.1 → 0.7 (`0f5042c`, `04227b1`, `41007ce`, `3059115`,
`501da65`).

## Consequences

- With `--features vfs`, an ISO volume mounts and walks through the same
  `FileSystem` contract as every other fleet filesystem; without it, the crate
  carries no `forensic-vfs` dependency.
- The adapter's limits are stated as facts, not hidden: an untraversed *file*
  extent cannot be stat'd (a loud `VfsError::Decode`, never a guessed value),
  because ISO stores a node's metadata in its parent's directory record.
- The `forensic-vfs` version pin travels with the feature; bumps are isolated to
  consumers that opt in.
