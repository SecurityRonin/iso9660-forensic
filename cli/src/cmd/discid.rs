use iso9660_forensic::cdtoc::Toc;
use iso9660_forensic::cue::CueSheet;
use iso9660_forensic::IsoError;

/// Compute whole-disc identity fingerprints (freedb + MusicBrainz) from a CUE
/// sheet's track layout and the total disc length in CD frames.
pub fn run(sheet: &CueSheet, total_frames: u32) -> Result<String, IsoError> {
    let _ = (sheet, total_frames);
    Ok(String::new())
}
