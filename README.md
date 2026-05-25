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

## Related

### Container readers
- [ewf](https://github.com/SecurityRonin/ewf) — E01/EWF/Ex01 forensic images
- [vmdk](https://github.com/SecurityRonin/vmdk) — VMware VMDK (monolithic sparse)
- [vhdx](https://github.com/SecurityRonin/vhdx) — Hyper-V VHDX dynamic images
- [vhd](https://github.com/SecurityRonin/vhd) — Microsoft VHD (fixed + dynamic)
- [qcow2](https://github.com/SecurityRonin/qcow2) — QEMU QCOW2 (with snapshots)
- [aff4](https://github.com/SecurityRonin/aff4) — AFF4 logical + physical images
- [dd](https://github.com/SecurityRonin/dd) — Raw/dd/img flat images
- [iso](https://github.com/SecurityRonin/iso) — ISO 9660 optical disc images ← **you are here**

### Forensic analysers
- [winevt-forensic](https://github.com/SecurityRonin/winevt-forensic) — Windows Event Log (EVTX) parser
- [srum-forensic](https://github.com/SecurityRonin/srum-forensic) — System Resource Usage Monitor (ESE)
- [memory-forensic](https://github.com/SecurityRonin/memory-forensic) — Memory dump analysis

---

[Privacy Policy](https://securityronin.github.io/iso/privacy/) · [Terms of Service](https://securityronin.github.io/iso/terms/) · © 2026 Security Ronin Ltd
