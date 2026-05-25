[![Crates.io](https://img.shields.io/crates/v/iso)](https://crates.io/crates/iso)
[![Docs.rs](https://img.shields.io/docsrs/iso)](https://docs.rs/iso)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/SecurityRonin/iso/ci.yml?branch=main)](https://github.com/SecurityRonin/iso/actions)

**Pure-Rust forensic ISO reader — multi-session, UDF, Rock Ridge, Joliet, El Torito, 2352-byte raw sectors.**

```rust
use iso::IsoReader;
use std::fs::File;
use std::io::BufReader;

let f = BufReader::new(File::open("image.iso")?);
let mut reader = IsoReader::open(f)?;

println!("Label:        {}", reader.volume_label());
println!("Sessions:     {}", reader.session_count());
println!("Rock Ridge:   {}", reader.has_rock_ridge());
println!("Joliet:       {}", reader.has_joliet());
println!("UDF bridge:   {}", reader.has_udf());

for entry in reader.read_root_dir()? {
    println!("  {:?}  {} bytes  LBA {}", entry.iso_name(), entry.size, entry.lba);
}

// Read a file by path
let entry = reader.find_entry("docs/readme.txt")?;
let bytes  = reader.read_file_entry(&entry)?;
```

## What This Handles That Basic Readers Miss

| Feature | Basic reader | `iso` |
|---------|:-----------:|:------:|
| Multi-session / multi-track | last session only | all sessions, active = last |
| UDF bridge disc detection | no | yes (NSR02/NSR03 scan) |
| Rock Ridge (RRIP) NM/PX entries | no | yes |
| Joliet UCS-2 filenames | no | yes (`%/@` / `%/C` / `%/E`) |
| El Torito boot catalog | no | yes |
| 2352-byte raw Mode-1 sectors | no | yes (auto-detected) |
| Path traversal guard (`..`) | rarely | always |

## Related crates

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

[Privacy Policy](https://securityronin.github.io/iso/privacy/) · [Terms of Service](https://securityronin.github.io/iso/terms/) · © 2026 Security Ronin Ltd
