#![no_main]

use iso::IsoReader;
use libfuzzer_sys::fuzz_target;
use std::io::{BufReader, Cursor};

fuzz_target!(|data: &[u8]| {
    // Use an in-memory cursor — no tempfile needed for ISO since IsoReader<R: Read+Seek>
    let cursor = BufReader::new(Cursor::new(data));
    if let Ok(mut reader) = IsoReader::open(cursor) {
        let _ = reader.session_count();
        let _ = reader.has_rock_ridge();
        let _ = reader.has_joliet();
        let _ = reader.has_udf();
        let _ = reader.read_root_dir();
    }
});
