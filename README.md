[![Crates.io](https://img.shields.io/crates/v/iso9660-forensic.svg)](https://crates.io/crates/iso9660-forensic)
[![docs.rs](https://img.shields.io/docsrs/iso9660-forensic)](https://docs.rs/iso9660-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/iso9660/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/iso9660/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Pure Rust forensic ISO 9660 reader — multi-session, UDF, Rock Ridge, Joliet, El Torito, 2352-byte raw sectors.**

## Install

```toml
[dependencies]
iso9660-forensic = "0.1"
```

## Quick start

```rust
use iso9660-forensic::IsoReader;
use std::fs::File;
use std::io::BufReader;

let f = BufReader::new(File::open("image.iso")?);
let mut reader = IsoReader::open(f)?;

println!("Label:       {}", reader.volume_label());
println!("Sessions:    {}", reader.session_count());
println!("Rock Ridge:  {}", reader.has_rock_ridge());
println!("Joliet:      {}", reader.has_joliet());
println!("UDF:         {}", reader.has_udf());

for entry in reader.read_root_dir()? {
    println!("  {}  {} bytes  LBA {}", entry.iso_name(), entry.size, entry.lba);
}
```

## Features

`IsoReader` handles the extensions that trip up basic readers:

| Feature | Basic reader | `iso` |
|---------|:-----------:|:------:|
| Multi-session / multi-track | last session only | all sessions, active = last |
| UDF bridge disc detection | no | yes (NSR02/NSR03 scan) |
| Rock Ridge (RRIP) NM/PX entries | no | yes |
| Joliet UCS-2 filenames | no | yes (`%/@` / `%/C` / `%/E`) |
| El Torito boot catalog | no | yes |
| 2352-byte raw Mode-1 sectors | no | yes (auto-detected) |
| Path traversal guard (`..`) | rarely | always |

## API examples

### Find and read a file

```rust
let entry = reader.find_entry("docs/readme.txt")?;
let bytes  = reader.read_file_entry(&entry)?;
```

### Detect extensions

```rust
if reader.has_udf()        { println!("UDF bridge disc"); }
if reader.has_joliet()     { println!("Joliet SVD present"); }
if reader.has_rock_ridge() { println!("Rock Ridge RRIP present"); }
```

### Enumerate boot entries

```rust
for boot in reader.boot_entries() {
    println!("boot entry: bootable={} lba={}", boot.bootable, boot.lba);
}
```

### Walk all sessions

```rust
for i in 0..reader.session_count() {
    println!("session {}: PVD at LBA {}", i, reader.session_pvd_lba(i));
}
```

## Testing

- **84 tests** (42 unit + fixture · 42 real-world images) across 6 suites
- Validated against **11 independent ISO images** from 7 distinct sources — chosen so the parser cannot share blind spots with any single fixture generator
- Every parser extension has a real-world positive case and a real-world negative case from a source independent of the `iso` crate
- Real-world images include Microsoft VL pressing (plain ISO 9660), Windows Server 2019 FOD (genuine UDF NSR02), TinyCore Linux (Rock Ridge + Joliet + El Torito), and Debian netinst
- Large image tests skip automatically in CI when files are absent; run `bash corpus/fetch.sh` to enable locally

See [docs/validation.md](docs/validation.md) for detailed results, image sources, and reproduction steps.

## Related

### Container readers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf`](https://github.com/SecurityRonin/ewf) | E01 / EWF / Ex01 | Dominant professional forensic acquisition format |
| [`aff4`](https://github.com/SecurityRonin/aff4) | AFF4 v1 | Evimetry / aff4-imager forensic disk images with Map streams |
| [`vmdk`](https://github.com/SecurityRonin/vmdk) | VMware VMDK | Monolithic sparse disk images from VMware Workstation / ESXi |
| [`vhdx`](https://github.com/SecurityRonin/vhdx) | Microsoft VHDX | Hyper-V, Windows 8+, WSL2, Azure disk container |
| [`vhd`](https://github.com/SecurityRonin/vhd) | Legacy VHD | Virtual PC / Hyper-V Generation-1 fixed and dynamic disk images |
| [`qcow2`](https://github.com/SecurityRonin/qcow2) | QCOW2 v2/v3 | QEMU / KVM / libvirt disk images |
| [`ufed`](https://github.com/SecurityRonin/ufed) | Cellebrite UFED | Physical mobile device dumps with UFD XML segment mapping |
| [`dd`](https://github.com/SecurityRonin/dd) | Raw / flat / gz | dd, dcfldd, and gzip-wrapped raw images |
| [`dmg`](https://github.com/SecurityRonin/dmg) | Apple DMG / UDIF | macOS disk images with koly trailer, mish block tables, zlib decompression |
| [`dar`](https://github.com/SecurityRonin/dar) | DAR archive | Disk ARchiver archives with catalog index and CRC32 validation |

### Forensic analysers

| Crate | Format | Notes |
|-------|--------|-------|
| [`ewf-forensic`](https://github.com/SecurityRonin/ewf-forensic) | E01 | Structural integrity audit, Adler-32 / MD5 hash verification, and in-memory repair |
| [`vhdx-forensic`](https://github.com/SecurityRonin/vhdx-forensic) | VHDX | Forensic integrity analyser and in-memory repair tool for VHDX containers |

---

[Privacy Policy](https://securityronin.github.io/iso9660/privacy/) · [Terms of Service](https://securityronin.github.io/iso9660/terms/) · © 2026 Security Ronin Ltd
