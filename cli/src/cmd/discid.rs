use iso9660_forensic::cdtoc::Toc;
use iso9660_forensic::cue::CueSheet;
use iso9660_forensic::IsoError;

/// Compute whole-disc identity fingerprints (freedb + MusicBrainz) from a CUE
/// sheet's track layout and the total disc length in CD frames.
pub fn run(sheet: &CueSheet, total_frames: u32) -> Result<String, IsoError> {
    let toc = Toc::from_cue(sheet, total_frames)
        .ok_or_else(|| IsoError::NotFound("no tracks in CUE sheet".into()))?;
    let mut out = String::new();
    out.push_str(&format!("Tracks:           {}\n", toc.track_count()));
    out.push_str(&format!("Total Frames:     {}\n", toc.leadout_frame));
    out.push_str(&format!("freedb Disc ID:   {}\n", toc.freedb_id_hex()));
    out.push_str(&format!("MusicBrainz ID:   {}\n", toc.musicbrainz_id()));
    Ok(out)
}
