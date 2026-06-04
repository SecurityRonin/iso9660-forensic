#![no_main]

use iso9660_forensic as iso;
use iso::IsoReader;
use libfuzzer_sys::fuzz_target;
use std::io::{BufReader, Cursor};

fuzz_target!(|data: &[u8]| {
    let cursor = BufReader::new(Cursor::new(data));
    if let Ok(mut reader) = IsoReader::open(cursor) {
        let _ = reader.session_count();
        let _ = reader.has_rock_ridge();
        let _ = reader.has_joliet();
        let _ = reader.volume_label();
        let _ = reader.system_id();
        let _ = reader.application_id();
        let _ = reader.volume_space_size();
        let _ = reader.volume_creation_time();

        if let Ok(entries) = reader.read_root_dir() {
            for e in &entries {
                // Exercise every SUSP parser on each entry's system_use bytes.
                let su = &e.system_use;
                let _ = iso::rock_ridge::alternate_name(su);
                let _ = iso::rock_ridge::posix_attrs(su);
                let _ = iso::rock_ridge::timestamps(su);
                let _ = iso::rock_ridge::timestamps_any(su);
                let _ = iso::rock_ridge::symlink_target(su);
                let _ = iso::rock_ridge::continuation(su);
                let _ = iso::rock_ridge::child_link(su);
                let _ = iso::rock_ridge::is_relocated(su);
            }

            // Exercise walk (depth-limited).
            let _ = reader.walk();

            // Exercise find_path on adversarial names.
            let _ = reader.find_path("../etc/passwd");
            let _ = reader.find_path("A/B/C/D/E/F/G/H/I/J/K/L/M/N/O/P/Q/R/S/T");
        }

        // Exercise boot entries.
        let _ = reader.boot_entries();
    }
});
