use iso9660_forensic::IsoReader;
use std::io::{Read, Seek};

/// Run the full forensic audit suite and produce a fixed-width ASCII report.
///
/// Each check is reported on one line with a `[PASS]`/`[WARN]` status tag.
/// A trailing `Result:` line summarises the warning count.
pub fn run<R: Read + Seek>(reader: &mut IsoReader<R>, image_name: &str) -> String {
    let mut out = String::new();
    let rule = "=".repeat(80);

    out.push_str(&format!("Forensic Audit: {image_name}\n"));
    out.push_str(&rule);
    out.push('\n');

    // ── Tool fingerprint (informational, never a warning) ──
    let fp = reader.fingerprint_tool();
    let ver = fp.version.as_deref().unwrap_or("");
    out.push_str(&format!(
        "Tool:            {} {}  [confidence: {}]\n\n",
        fp.tool, ver, fp.confidence
    ));

    let mut warnings = 0usize;

    // ── Both-endian fields ──
    match reader.audit_both_endian() {
        Ok(m) if m.is_empty() => {
            out.push_str("[PASS] Both-Endian Fields:    0 mismatches\n");
        }
        Ok(m) => {
            warnings += 1;
            out.push_str(&format!(
                "[WARN] Both-Endian Fields:    {} mismatch(es) -- possible tampering\n",
                m.len()
            ));
            for x in m.iter().take(10) {
                out.push_str(&format!(
                    "         {} {} @0x{:08X}: LE={} BE={}\n",
                    x.context, x.field, x.byte_offset, x.le_val, x.be_val
                ));
            }
        }
        Err(e) => {
            warnings += 1;
            out.push_str(&format!("[WARN] Both-Endian Fields:    error: {e}\n"));
        }
    }

    // ── Pre-system area ──
    match reader.audit_pre_system() {
        Ok(h) if h.is_empty() => {
            out.push_str("[PASS] Pre-System Area:       sectors 0-15 are empty\n");
        }
        Ok(h) => {
            warnings += 1;
            out.push_str(&format!(
                "[WARN] Pre-System Area:       {} sector(s) contain data\n",
                h.len()
            ));
            for x in &h {
                out.push_str(&format!("         sector {} ({})\n", x.sector, x.kind));
            }
        }
        Err(e) => {
            warnings += 1;
            out.push_str(&format!("[WARN] Pre-System Area:       error: {e}\n"));
        }
    }

    // ── Path table vs tree ──
    match reader.audit_path_table() {
        Ok(a) if a.phantom_lbas.is_empty() && a.ghost_lbas.is_empty() => {
            out.push_str(&format!(
                "[PASS] Path Table:            {} dirs in table, {} in tree, consistent\n",
                a.path_table_lbas.len(), a.tree_lbas.len()
            ));
        }
        Ok(a) => {
            warnings += 1;
            out.push_str(&format!(
                "[WARN] Path Table:            {} phantom, {} ghost\n",
                a.phantom_lbas.len(), a.ghost_lbas.len()
            ));
        }
        Err(e) => {
            warnings += 1;
            out.push_str(&format!("[WARN] Path Table:            error: {e}\n"));
        }
    }

    // ── Symlinks ──
    match reader.audit_symlinks() {
        Ok(s) if s.is_empty() => {
            out.push_str("[PASS] Symlinks:              no dangerous symlinks\n");
        }
        Ok(s) => {
            warnings += 1;
            out.push_str(&format!("[WARN] Symlinks:              {} flagged\n", s.len()));
            for x in &s {
                out.push_str(&format!(
                    "         {} -> {} ({})\n", x.entry_path, x.target, x.issue
                ));
            }
        }
        Err(e) => {
            warnings += 1;
            out.push_str(&format!("[WARN] Symlinks:              error: {e}\n"));
        }
    }

    // ── File slack ──
    match reader.audit_file_slack() {
        Ok(s) => {
            let nz = s.iter().filter(|h| h.nonzero).count();
            if nz == 0 {
                out.push_str(&format!(
                    "[PASS] File Slack:            {} file(s), no non-zero slack\n", s.len()
                ));
            } else {
                warnings += 1;
                out.push_str(&format!(
                    "[WARN] File Slack:            {} of {} file(s) have non-zero slack\n",
                    nz, s.len()
                ));
            }
        }
        Err(e) => {
            warnings += 1;
            out.push_str(&format!("[WARN] File Slack:            error: {e}\n"));
        }
    }

    // ── Sector gaps ──
    match reader.audit_sector_gaps() {
        Ok(g) => {
            let nz = g.iter().filter(|x| x.nonzero).count();
            if nz == 0 {
                out.push_str(&format!(
                    "[PASS] Sector Gaps:           {} unallocated, no content\n", g.len()
                ));
            } else {
                warnings += 1;
                out.push_str(&format!(
                    "[WARN] Sector Gaps:           {} of {} gap sector(s) contain data\n",
                    nz, g.len()
                ));
            }
        }
        Err(e) => {
            warnings += 1;
            out.push_str(&format!("[WARN] Sector Gaps:           error: {e}\n"));
        }
    }

    out.push_str(&rule);
    out.push('\n');
    out.push_str(&format!("Result:          {warnings} warning(s)\n"));
    out
}
