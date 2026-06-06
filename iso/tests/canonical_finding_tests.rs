//! iso9660-forensic anomalies normalize onto the canonical
//! `forensicnomicon::report` model via the `Observation` producer trait.

use forensicnomicon::report::{Observation, Source};
use iso9660_forensic::findings::{Anomaly, AnomalyKind};

#[test]
fn anomaly_converts_to_a_canonical_finding() {
    let a = Anomaly::new(AnomalyKind::MixedTimezones {
        offsets: vec![0, 4],
    });
    let f = a.to_finding(Source {
        analyzer: "iso9660-forensic".to_string(),
        scope: "ISO".to_string(),
        version: None,
    });
    assert_eq!(f.code, "ISO-MIXED-TZ");
    assert!(f.severity.is_some());
}
