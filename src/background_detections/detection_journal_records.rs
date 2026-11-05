use std::path::PathBuf;

use crate::malware_scan::{
    scanner_command_builder::ScannerBackend, scanner_output_parser::parse_threat_detection_line,
};

pub const ON_ACCESS_SERVICE_UNITS: [&str; 2] = ["clamav-clamonacc.service", "clamonacc.service"];
pub const SCHEDULED_SCAN_SERVICE_UNITS: [&str; 1] = ["clamdscan.service"];
const MICROSECONDS_PER_SECOND: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionSource {
    OnAccessScanner,
    ScheduledScan,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalDetectionRecord {
    pub observed_at_unix: i64,
    pub detection_source: DetectionSource,
    pub file_path: PathBuf,
    pub signature_name: String,
}

pub fn detection_source_of_unit(systemd_unit: &str) -> Option<DetectionSource> {
    if ON_ACCESS_SERVICE_UNITS.contains(&systemd_unit) {
        Some(DetectionSource::OnAccessScanner)
    } else if SCHEDULED_SCAN_SERVICE_UNITS.contains(&systemd_unit) {
        Some(DetectionSource::ScheduledScan)
    } else {
        None
    }
}

pub fn detection_record_from_fields(
    systemd_unit: &str,
    message_bytes: &[u8],
    realtime_microseconds: u64,
) -> Option<JournalDetectionRecord> {
    let detection_source = detection_source_of_unit(systemd_unit)?;
    let detected_threat = parse_threat_detection_line(message_bytes, ScannerBackend::ClamdDaemon)?;
    Some(JournalDetectionRecord {
        observed_at_unix: i64::try_from(realtime_microseconds / MICROSECONDS_PER_SECOND).ok()?,
        detection_source,
        file_path: detected_threat.file_path,
        signature_name: detected_threat.threat_name,
    })
}

#[cfg(test)]
mod detection_journal_records_tests {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    use super::*;

    const OBSERVED_MICROSECONDS: u64 = 1_793_869_222_072_914;

    #[test]
    fn a_real_on_access_line_keeps_its_path_and_signature() {
        assert_eq!(
            detection_record_from_fields(
                "clamav-clamonacc.service",
                b"/home/user/Downloads/invoice.exe: Eicar-Test-Signature FOUND",
                OBSERVED_MICROSECONDS,
            ),
            Some(JournalDetectionRecord {
                observed_at_unix: 1_793_869_222,
                detection_source: DetectionSource::OnAccessScanner,
                file_path: PathBuf::from("/home/user/Downloads/invoice.exe"),
                signature_name: "Eicar-Test-Signature".to_owned(),
            })
        );
    }

    #[test]
    fn scheduled_scans_are_told_apart_from_on_access() {
        assert_eq!(
            detection_record_from_fields(
                "clamdscan.service",
                b"/tmp/dropper: Win.Trojan.Agent-1 FOUND",
                OBSERVED_MICROSECONDS,
            )
            .map(|detection_record| detection_record.detection_source),
            Some(DetectionSource::ScheduledScan)
        );
    }

    #[test]
    fn manual_scans_seen_only_by_the_daemon_are_ignored() {
        assert_eq!(
            detection_record_from_fields(
                "clamav-daemon.service",
                b"/tmp/scratch/eicar.txt: Eicar-Test-Signature FOUND",
                OBSERVED_MICROSECONDS,
            ),
            None
        );
    }

    #[test]
    fn paths_containing_separators_and_invalid_utf8_survive() {
        let detection_record = detection_record_from_fields(
            "clamav-clamonacc.service",
            b"/home/user/Downloads/a: b\xff.exe: Win.Test-1 FOUND",
            OBSERVED_MICROSECONDS,
        )
        .expect("detection");
        assert_eq!(
            detection_record.file_path.as_os_str(),
            OsStr::from_bytes(b"/home/user/Downloads/a: b\xff.exe")
        );
        assert_eq!(detection_record.signature_name, "Win.Test-1");
    }

    #[test]
    fn other_scanner_output_is_not_a_detection() {
        [
            b"ClamInotif: watching '/home/user/Downloads'".as_slice(),
            b"----------- SCAN SUMMARY -----------",
            b"Infected files: 1",
            b"",
        ]
        .into_iter()
        .for_each(|message_bytes| {
            assert_eq!(
                detection_record_from_fields(
                    "clamav-clamonacc.service",
                    message_bytes,
                    OBSERVED_MICROSECONDS,
                ),
                None
            );
        });
    }
}
