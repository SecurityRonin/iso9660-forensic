# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Reject hybrid-image PVD candidates whose declared root extent is not a valid ISO 9660 directory.

## [0.1.0](https://github.com/SecurityRonin/iso9660-forensic/releases/tag/iso9660-core-v0.1.0) - 2026-08-24

### Added

- *(iso)* corpus validation, README, CI, and docs overhaul

### Documentation

- *(iso9660-forensic)* align validation.md — oracles, corpora, evidence tiers
- lowercase docs/formats.md; add Pages permalinks for privacy/terms
- v0.4.0 — analyzer-first README, privacy/terms, drop stale UDF dep
- reflect de-scoping to a pure ISO9660 reader
- cross-link all 11 container repos in Related section

### Fixed

- *(ci)* clippy, fmt, MSRV, fuzz, and doc cleanup

### Other

- split the reader into iso9660-core; audit methods become free functions ([#11](https://github.com/SecurityRonin/iso9660-forensic/pull/11))
