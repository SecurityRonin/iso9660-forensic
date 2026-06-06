---
title: Privacy Policy
permalink: /privacy/
---

# Privacy Policy

**Effective date:** 2026-06-06  
**Product:** iso9660-forensic (Rust library)  
**Operator:** Security Ronin Ltd

---

## What iso9660-forensic collects

Nothing. `iso9660-forensic` is a local Rust library that parses and analyzes ISO 9660 / optical disc images entirely in-process. It has no server, no backend, and makes no network connections of any kind.

---

## File data

The library reads the disc image bytes you hand it (a file path or any `Read + Seek` source) solely to parse and analyze them in memory. It does not upload, transmit, or persist your data anywhere. Any analysis results (the `IsoAnalysis` structure, extracted files, hashes) are returned to your own code and remain entirely under your control.

---

## Telemetry

There is none. No telemetry, no crash reporting, no analytics, and no update checks. The library never phones home — it cannot, as it opens no network sockets.

---

## Open source

iso9660-forensic is fully open source under the MIT licence. You can audit every line — including the complete absence of any network code — at [github.com/SecurityRonin/iso9660-forensic](https://github.com/SecurityRonin/iso9660-forensic).

---

## Changes

If this policy changes materially, the effective date above will be updated and a note will appear in the release changelog.

---

## Contact

Security Ronin Ltd — [github.com/SecurityRonin](https://github.com/SecurityRonin)
