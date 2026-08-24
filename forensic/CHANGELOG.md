# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/SecurityRonin/iso9660-forensic/compare/iso9660-forensic-v0.7.6...iso9660-forensic-v0.8.0) - 2026-08-24

### Other

- split the reader into iso9660-core; audit methods become free functions ([#11](https://github.com/SecurityRonin/iso9660-forensic/pull/11))

## [0.7.6](https://github.com/SecurityRonin/iso9660-forensic/compare/iso9660-forensic-v0.7.5...iso9660-forensic-v0.7.6) - 2026-07-24

### Fixed

- *(panic-free)* route reads through safe-read + enforce unwrap/expect deny

### Other

- *(panic-free)* route both_endian PVD reads through safe-read

## [0.7.4](https://github.com/SecurityRonin/iso9660-forensic/compare/v0.7.3...v0.7.4) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5
# Changelog

All notable changes to `iso9660-forensic` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
