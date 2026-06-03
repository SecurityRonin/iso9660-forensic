use std::fs::File;
use std::path::Path;
use std::process;

use iso9660_forensic::{IsoReader, SectorMode};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        print_help();
        process::exit(0);
    }

    match args[1].as_str() {
        "inspect" => {
            if args.len() < 3 {
                eprintln!("error: 'inspect' requires an image path");
                eprintln!("Usage: iso9660-forensic inspect <image.iso>");
                process::exit(1);
            }
            if let Err(e) = inspect(&args[2]) {
                eprintln!("error: {e}");
                process::exit(1);
            }
        }
        other => {
            eprintln!("error: unknown command '{other}'");
            print_help();
            process::exit(1);
        }
    }
}

fn print_help() {
    println!("iso9660-forensic — forensic ISO 9660 / UDF inspector");
    println!();
    println!("USAGE:");
    println!("    iso9660-forensic inspect <image.iso>");
    println!();
    println!("COMMANDS:");
    println!("    inspect    Parse and display metadata for an ISO image");
    println!();
    println!("FLAGS:");
    println!("    --help, -h    Print this help message");
}

fn inspect(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let abs = std::fs::canonicalize(Path::new(path))
        .map_err(|e| format!("{path}: {e}"))?;
    let f = File::open(&abs).map_err(|e| format!("{}: {e}", abs.display()))?;

    let mut reader = IsoReader::open(f)?;

    // ── Header ──────────────────────────────────────────────────────────────
    println!("File:         {}", abs.display());
    let mode_str = match reader.sector_mode() {
        SectorMode::Iso2048      => "2048-byte (ISO)",
        SectorMode::Raw2352      => "2352-byte raw (CD-ROM Mode 1)",
        SectorMode::Raw2352Mode2 => "2352-byte raw (CD-ROM Mode 2 Form 1)",
        SectorMode::Raw2448      => "2448-byte raw (Mode 1 + subchannel)",
        SectorMode::Raw2448Mode2 => "2448-byte raw (Mode 2 Form 1 + subchannel)",
        SectorMode::Mode2_2336   => "2336-byte raw (Mode 2)",
    };
    println!("Sector mode:  {mode_str}");
    println!("Sessions:     {}", reader.session_count());

    // Print each session PVD LBA
    for (i, lba) in reader.session_pvd_lbas.iter().enumerate() {
        println!("  Session {}: PVD LBA {lba}", i + 1);
    }

    // ── Volume ───────────────────────────────────────────────────────────────
    let vol = reader.volume_label().trim_matches(|c: char| c == '\0' || c == ' ');
    println!("Volume:       {vol}");
    if let Some(jlabel) = reader.joliet_label() {
        let jvol = jlabel.trim_matches(|c: char| c == '\0' || c == ' ');
        println!("Joliet label: {jvol}");
    }

    // ── Extensions ───────────────────────────────────────────────────────────
    println!("Rock Ridge:   {}", yesno(reader.has_rock_ridge()));
    println!("Joliet:       {}", yesno(reader.has_joliet()));
    println!("UDF:          {}", yesno(reader.has_udf()));

    // ── El Torito ────────────────────────────────────────────────────────────
    let boot = reader.boot_entries()?;
    if !boot.is_empty() {
        println!("El Torito:    yes ({} boot entries)", boot.len());
        for (i, entry) in boot.iter().enumerate() {
            println!("  Boot entry {}: LBA {}, {} bytes, bootable={}",
                i + 1, entry.lba, entry.sector_count * 512, entry.bootable);
        }
    } else {
        println!("El Torito:    no");
    }

    // ── ISO 9660 root directory ───────────────────────────────────────────────
    println!();
    println!("Root directory (ISO 9660):");
    let root = reader.read_root_dir()?;
    if root.is_empty() {
        println!("  (empty)");
    } else {
        for entry in &root {
            let kind = if entry.is_dir() { "DIR " } else { "FILE" };
            let rr_name = iso9660_forensic::rock_ridge::alternate_name(&entry.system_use);
            let iso_name = entry.iso_name();
            let display_name = rr_name.as_deref().unwrap_or(&iso_name);
            println!("  [{kind}] {:<40} {:>12} bytes  LBA {}",
                display_name, entry.size, entry.lba);
        }
    }

    // ── UDF root directory ────────────────────────────────────────────────────
    if reader.has_udf() {
        println!();
        println!("Root directory (UDF):");
        match reader.read_udf_root_dir() {
            Ok(entries) if entries.is_empty() => println!("  (empty)"),
            Ok(entries) => {
                for entry in &entries {
                    let kind = if entry.is_dir { "DIR " } else { "FILE" };
                    println!("  [{kind}] {:<40} {:>12} bytes  LBA {}",
                        entry.name, entry.size, entry.fe_lba);
                }
            }
            Err(e) => println!("  (unreadable: {e})"),
        }
    }

    Ok(())
}

fn yesno(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}
