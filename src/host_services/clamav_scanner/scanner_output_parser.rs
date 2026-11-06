use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf};

use crate::host_services::clamav_scanner::scanner_command_builder::ScannerBackend;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThreatIdentity {
    Signature { signature_name: String },
    BlockedByOnAccess,
}

impl ThreatIdentity {
    pub fn threat_category(&self) -> &'static str {
        match self {
            Self::Signature { signature_name } => categorize_threat_name(signature_name),
            Self::BlockedByOnAccess => ON_ACCESS_BLOCK_CATEGORY,
        }
    }

    pub fn threat_severity(&self) -> ThreatSeverity {
        match self {
            Self::Signature { signature_name } => classify_threat_severity(signature_name),
            Self::BlockedByOnAccess => ThreatSeverity::Medium,
        }
    }

    pub fn matched_signature_name(&self) -> Option<&str> {
        match self {
            Self::Signature { signature_name } => Some(signature_name),
            Self::BlockedByOnAccess => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DetectedThreat {
    pub file_path: PathBuf,
    pub threat_identity: ThreatIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportedSignatureMatch {
    pub file_path: PathBuf,
    pub signature_name: String,
}

impl From<ReportedSignatureMatch> for DetectedThreat {
    fn from(signature_match: ReportedSignatureMatch) -> Self {
        Self {
            file_path: signature_match.file_path,
            threat_identity: ThreatIdentity::Signature {
                signature_name: signature_match.signature_name,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanFailureReason {
    NoFilesScanned,
    ScannerReported { scanner_message: String },
    UnexplainedScannerFailure { exit_code: i32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanVerdict {
    NoThreatsFound,
    ThreatsFound,
    ScanFailed(ScanFailureReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanNotice {
    NoNotice,
    FilesInaccessible { file_count: u64 },
    FilesUnreadable { file_count: u64 },
    NonfatalWarnings { warning_count: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterpretedScan {
    pub scan_verdict: ScanVerdict,
    pub scan_notice: ScanNotice,
    pub skipped_paths: Vec<String>,
    pub nonfatal_warnings: Vec<String>,
    pub reported_directory_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
    Low,
}

pub struct ScannerTranscript<'transcript> {
    pub report_text: &'transcript str,
    pub diagnostic_text: &'transcript str,
    pub exit_code: i32,
    pub detected_threats: &'transcript [DetectedThreat],
}

#[derive(Default)]
struct ScannerWarningEvidence {
    skipped_paths: Vec<String>,
    nonfatal_warnings: Vec<String>,
    hard_errors: Vec<String>,
}

const ON_ACCESS_BLOCK_CATEGORY: &str = "On-access";
const ACCESS_FAILURE_PREFIXES: &[&[u8]] =
    &[b"ERROR: Can't access file ", b"WARNING: Can't open file "];
const ACCESS_FAILURE_MARKERS: &[&[u8]] = &[
    b": Failed to open file",
    b": Can't access file",
    b": Access denied",
    b": Operation not permitted",
];

const SKIP_MARKERS: &[&str] = &[
    ": Failed to open file",
    ": File path check failure:",
    ": Not supported file type",
    ": Can't access file",
    ": Access denied",
];
const NONFATAL_WARNING_MARKERS: &[&str] = &[
    "exceeds limits",
    "file truncated",
    "size limit reached",
    "recursion limit",
    "max recursion level reached",
    "cannot dlopen libclamunrar",
    "bytecode run timed out",
];
const SEVERITY_TIERS: &[ThreatSeverityTier] = &[
    ThreatSeverityTier {
        threat_severity: ThreatSeverity::Critical,
        signature_markers: &["ransom", "rootkit", "bootkit", "cryptolocker", "wannacry"],
    },
    ThreatSeverityTier {
        threat_severity: ThreatSeverity::High,
        signature_markers: &[
            "trojan",
            "worm",
            "backdoor",
            "exploit",
            "downloader",
            "dropper",
            "keylogger",
        ],
    },
    ThreatSeverityTier {
        threat_severity: ThreatSeverity::Medium,
        signature_markers: &["adware", "pua", "pup", "spyware", "miner"],
    },
    ThreatSeverityTier {
        threat_severity: ThreatSeverity::Low,
        signature_markers: &[
            "eicar",
            "test-signature",
            "test.file",
            "heuristic",
            "generic",
        ],
    },
];
const SPECIFIC_CATEGORY_MARKERS: &[ThreatCategoryMarker] = &[
    ThreatCategoryMarker::new("ransomware", "Ransomware"),
    ThreatCategoryMarker::new("ransom", "Ransomware"),
    ThreatCategoryMarker::new("rootkit", "Rootkit"),
    ThreatCategoryMarker::new("bootkit", "Rootkit"),
    ThreatCategoryMarker::new("trojan", "Trojan"),
    ThreatCategoryMarker::new("worm", "Worm"),
    ThreatCategoryMarker::new("backdoor", "Backdoor"),
    ThreatCategoryMarker::new("exploit", "Exploit"),
    ThreatCategoryMarker::new("adware", "Adware"),
    ThreatCategoryMarker::new("spyware", "Spyware"),
    ThreatCategoryMarker::new("keylogger", "Spyware"),
    ThreatCategoryMarker::new("eicar", "Test"),
    ThreatCategoryMarker::new("test-signature", "Test"),
    ThreatCategoryMarker::new("test.file", "Test"),
    ThreatCategoryMarker::new("macro", "Macro"),
    ThreatCategoryMarker::new("phish", "Phishing"),
    ThreatCategoryMarker::new("heuristic", "Heuristic"),
];
const GENERIC_CATEGORY_MARKERS: &[ThreatCategoryMarker] = &[
    ThreatCategoryMarker::new("pua", "PUA"),
    ThreatCategoryMarker::new("pup", "PUA"),
    ThreatCategoryMarker::new("virus", "Virus"),
];

struct ThreatSeverityTier {
    threat_severity: ThreatSeverity,
    signature_markers: &'static [&'static str],
}

struct ThreatCategoryMarker {
    signature_marker: &'static str,
    category_label: &'static str,
}

impl ThreatCategoryMarker {
    const fn new(signature_marker: &'static str, category_label: &'static str) -> Self {
        Self {
            signature_marker,
            category_label,
        }
    }
}

fn earliest_category_label(
    lowercase_name: &str,
    category_markers: &[ThreatCategoryMarker],
) -> Option<&'static str> {
    category_markers
        .iter()
        .filter_map(|category_marker| {
            lowercase_name
                .find(category_marker.signature_marker)
                .map(|marker_position| CategoryPosition {
                    marker_position,
                    category_label: category_marker.category_label,
                })
        })
        .min_by_key(|category_position| category_position.marker_position)
        .map(|category_position| category_position.category_label)
}

struct CategoryPosition {
    marker_position: usize,
    category_label: &'static str,
}

fn categorize_threat_name(signature_name: &str) -> &'static str {
    if signature_name.is_empty() {
        return "Unknown";
    }
    let lowercase_name = signature_name.to_ascii_lowercase();
    earliest_category_label(&lowercase_name, SPECIFIC_CATEGORY_MARKERS)
        .or_else(|| earliest_category_label(&lowercase_name, GENERIC_CATEGORY_MARKERS))
        .unwrap_or("Virus")
}

fn classify_threat_severity(signature_name: &str) -> ThreatSeverity {
    let lowercase_name = signature_name.to_ascii_lowercase();
    SEVERITY_TIERS
        .iter()
        .find(|severity_tier| {
            severity_tier
                .signature_markers
                .iter()
                .any(|signature_marker| lowercase_name.contains(signature_marker))
        })
        .map_or(ThreatSeverity::Medium, |severity_tier| {
            severity_tier.threat_severity
        })
}

fn trim_ascii_whitespace(mut line_bytes: &[u8]) -> &[u8] {
    while line_bytes.first().is_some_and(u8::is_ascii_whitespace) {
        line_bytes = &line_bytes[1..];
    }
    while line_bytes.last().is_some_and(u8::is_ascii_whitespace) {
        line_bytes = &line_bytes[..line_bytes.len() - 1];
    }
    line_bytes
}

pub fn parse_threat_detection_line(
    report_line: &[u8],
    scanner_backend: ScannerBackend,
) -> Option<ReportedSignatureMatch> {
    let trimmed_line = trim_ascii_whitespace(report_line);
    if !trimmed_line.ends_with(b"FOUND")
        || (scanner_backend == ScannerBackend::StandaloneClamscan
            && trimmed_line.starts_with(b"Scanning "))
    {
        return None;
    }
    let separator_position = trimmed_line.iter().rposition(|byte| *byte == b':')?;
    let reported_path = trim_ascii_whitespace(&trimmed_line[..separator_position]);
    let signature_text = String::from_utf8_lossy(&trimmed_line[separator_position + 1..]);
    let trimmed_signature = signature_text.trim();
    let signature_name = trimmed_signature
        .strip_suffix(" FOUND")
        .unwrap_or(trimmed_signature)
        .trim();
    if reported_path.is_empty() || signature_name.is_empty() {
        return None;
    }
    Some(ReportedSignatureMatch {
        file_path: PathBuf::from(OsStr::from_bytes(reported_path)),
        signature_name: signature_name.to_owned(),
    })
}

pub fn parse_inspected_file_line(
    report_line: &[u8],
    scanner_backend: ScannerBackend,
) -> Option<PathBuf> {
    let trimmed_line = trim_ascii_whitespace(report_line);
    let reported_path = match scanner_backend {
        ScannerBackend::ClamdDaemon => trimmed_line.strip_suffix(b": OK")?,
        ScannerBackend::StandaloneClamscan => trimmed_line.strip_prefix(b"Scanning ")?,
    };
    Some(PathBuf::from(OsStr::from_bytes(trim_ascii_whitespace(
        reported_path,
    ))))
}

fn byte_pattern_position(line_bytes: &[u8], byte_pattern: &[u8]) -> Option<usize> {
    line_bytes
        .windows(byte_pattern.len())
        .position(|line_window| line_window == byte_pattern)
}

pub fn parse_inaccessible_path_line(scanner_line: &[u8]) -> Option<PathBuf> {
    let trimmed_line = trim_ascii_whitespace(scanner_line);
    let prefixed_path = ACCESS_FAILURE_PREFIXES
        .iter()
        .find_map(|failure_prefix| trimmed_line.strip_prefix(*failure_prefix))
        .map(|text_after_prefix| {
            text_after_prefix
                .iter()
                .rposition(|line_byte| *line_byte == b':')
                .map_or(text_after_prefix, |separator_position| {
                    &text_after_prefix[..separator_position]
                })
        });
    let marked_path = || {
        ACCESS_FAILURE_MARKERS.iter().find_map(|failure_marker| {
            byte_pattern_position(trimmed_line, failure_marker)
                .map(|marker_position| &trimmed_line[..marker_position])
        })
    };
    prefixed_path
        .or_else(marked_path)
        .map(trim_ascii_whitespace)
        .filter(|reported_path| !reported_path.is_empty())
        .map(|reported_path| PathBuf::from(OsStr::from_bytes(reported_path)))
}

pub fn is_blocked_by_on_access(file_path: &std::path::Path) -> bool {
    matches!(
        rustix::fs::open(
            file_path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        ),
        Err(rustix::io::Errno::PERM)
    )
}

pub fn displayed_threat_name(threat_identity: &ThreatIdentity) -> String {
    match threat_identity {
        ThreatIdentity::Signature { signature_name } => sanitize_scanner_line(signature_name),
        ThreatIdentity::BlockedByOnAccess => gettextrs::gettext("Blocked by on-access scanning"),
    }
}

pub const fn on_access_blocked_threat(file_path: PathBuf) -> DetectedThreat {
    DetectedThreat {
        file_path,
        threat_identity: ThreatIdentity::BlockedByOnAccess,
    }
}

pub fn interpret_clamscan_transcript(
    scanner_transcript: &ScannerTranscript<'_>,
    inspected_file_count: u64,
) -> InterpretedScan {
    InterpretedScan {
        reported_directory_count: clamscan_directory_count(scanner_transcript.report_text),
        ..interpret_scanner_transcript(
            ScannerBackend::StandaloneClamscan,
            scanner_transcript,
            clamscan_scanned_file_count(scanner_transcript.report_text, inspected_file_count),
        )
    }
}

pub fn interpret_clamdscan_transcript(
    scanner_transcript: &ScannerTranscript<'_>,
    planned_file_count: u64,
) -> InterpretedScan {
    interpret_scanner_transcript(
        ScannerBackend::ClamdDaemon,
        scanner_transcript,
        planned_file_count,
    )
}

fn clamscan_scanned_file_count(report_text: &str, inspected_file_count: u64) -> u64 {
    report_text
        .lines()
        .map(str::trim)
        .filter_map(|report_line| report_line.strip_prefix("Scanned files:"))
        .next_back()
        .and_then(|summary_text| summary_text.trim().parse().ok())
        .unwrap_or(inspected_file_count)
}

fn clamscan_directory_count(report_text: &str) -> u64 {
    report_text
        .lines()
        .map(str::trim)
        .filter_map(|report_line| report_line.strip_prefix("Scanned directories:"))
        .next_back()
        .and_then(|summary_text| summary_text.trim().parse().ok())
        .unwrap_or(0)
}

const LOST_CLAMD_CONNECTION_MARKERS: &[&str] = &[
    "Can't send to clamd",
    "Connection reset by peer",
    "Broken pipe",
];

pub fn reports_lost_clamd_connection(report_text: &str, diagnostic_text: &str) -> bool {
    report_text
        .lines()
        .chain(diagnostic_text.lines())
        .any(|scanner_line| {
            LOST_CLAMD_CONNECTION_MARKERS
                .iter()
                .any(|connection_marker| scanner_line.contains(connection_marker))
        })
}

pub fn is_noteworthy_scanner_line(scanner_line: &str) -> bool {
    let trimmed_line = scanner_line.trim();
    !trimmed_line.is_empty()
        && !trimmed_line.ends_with(": OK")
        && !trimmed_line.starts_with("Scanning ")
}

fn collect_warning_evidence(report_text: &str, diagnostic_text: &str) -> ScannerWarningEvidence {
    report_text
        .lines()
        .chain(diagnostic_text.lines())
        .map(str::trim)
        .filter(|transcript_line| !transcript_line.is_empty())
        .fold(
            ScannerWarningEvidence::default(),
            |mut warning_evidence, transcript_line| {
                if let Some(skipped_path) = skipped_path_in_line(transcript_line) {
                    if !warning_evidence
                        .skipped_paths
                        .iter()
                        .any(|known_path| known_path == skipped_path)
                    {
                        warning_evidence.skipped_paths.push(skipped_path.to_owned());
                    }
                } else if is_ignored_library_noise(transcript_line) {
                } else if is_nonfatal_warning(transcript_line) {
                    warning_evidence
                        .nonfatal_warnings
                        .push(transcript_line.to_owned());
                } else if is_hard_error(transcript_line) {
                    warning_evidence
                        .hard_errors
                        .push(transcript_line.to_owned());
                }
                warning_evidence
            },
        )
}

fn is_ignored_library_noise(transcript_line: &str) -> bool {
    transcript_line.contains("LibClamAV Warning: cli_realpath: Invalid arguments.")
        || (transcript_line.starts_with("LibClamAV Error:")
            && (transcript_line.contains("index_local_file_headers_within_bounds")
                || transcript_line.contains("Invalid offset arguments")))
}

fn is_nonfatal_warning(transcript_line: &str) -> bool {
    let lowercase_line = transcript_line.to_ascii_lowercase();
    (transcript_line.starts_with("LibClamAV Warning:")
        && NONFATAL_WARNING_MARKERS
            .iter()
            .any(|warning_marker| lowercase_line.contains(warning_marker)))
        || transcript_line.contains(": Time limit reached")
}

fn is_hard_error(transcript_line: &str) -> bool {
    transcript_line.starts_with("WARNING:")
        || transcript_line.starts_with("ERROR:")
        || transcript_line.starts_with("LibClamAV Error:")
        || transcript_line.starts_with("LibClamAV Warning:")
        || transcript_line.ends_with("ERROR")
}

fn skipped_path_in_line(transcript_line: &str) -> Option<&str> {
    if let Some(inaccessible_path) = transcript_line.strip_prefix("ERROR: Can't access file ") {
        return nonempty_trimmed_text(inaccessible_path);
    }
    let marked_path = SKIP_MARKERS.iter().find_map(|skip_marker| {
        let (text_before_marker, _text_after_marker) = transcript_line.split_once(skip_marker)?;
        let candidate_path = text_before_marker
            .trim()
            .trim_start_matches("WARNING:")
            .trim_start_matches("ERROR:")
            .trim();
        if candidate_path == "WARNING" || candidate_path == "ERROR" {
            None
        } else {
            nonempty_trimmed_text(candidate_path)
        }
    });
    if marked_path.is_some() {
        return marked_path;
    }
    transcript_line
        .strip_prefix("WARNING: Can't open file ")
        .and_then(|unopened_path| {
            nonempty_trimmed_text(
                unopened_path
                    .rsplit_once(':')
                    .map_or(unopened_path, |path_and_reason| path_and_reason.0),
            )
        })
}

fn nonempty_trimmed_text(candidate_text: &str) -> Option<&str> {
    let trimmed_text = candidate_text.trim();
    (!trimmed_text.is_empty()).then_some(trimmed_text)
}

fn total_error_count(report_text: &str) -> u64 {
    report_text
        .lines()
        .map(str::trim)
        .find_map(|report_line| {
            report_line
                .strip_prefix("Total errors:")
                .and_then(|error_count_text| error_count_text.trim().parse().ok())
        })
        .unwrap_or(0)
}

fn is_genuine_error(transcript_line: &str) -> bool {
    transcript_line.ends_with(" ERROR")
        || transcript_line.starts_with("ERROR:")
        || transcript_line.starts_with("LibClamAV Error:")
}

fn inaccessible_or_warning_notice(
    warning_evidence: &ScannerWarningEvidence,
    total_errors: u64,
) -> ScanNotice {
    if !warning_evidence.skipped_paths.is_empty() {
        ScanNotice::FilesInaccessible {
            file_count: warning_evidence.skipped_paths.len() as u64,
        }
    } else if total_errors > 0 {
        ScanNotice::FilesUnreadable {
            file_count: total_errors,
        }
    } else {
        ScanNotice::NonfatalWarnings {
            warning_count: warning_evidence.nonfatal_warnings.len() as u64,
        }
    }
}

fn scanner_failure_reason(
    scanner_backend: ScannerBackend,
    scanner_transcript: &ScannerTranscript<'_>,
    warning_evidence: &ScannerWarningEvidence,
) -> ScanFailureReason {
    let daemon_report_line = || {
        (scanner_backend == ScannerBackend::ClamdDaemon)
            .then(|| {
                scanner_transcript
                    .report_text
                    .lines()
                    .map(str::trim)
                    .find(|report_line| {
                        !report_line.is_empty() && !report_line.contains("SCAN SUMMARY")
                    })
            })
            .flatten()
    };
    nonempty_trimmed_text(scanner_transcript.diagnostic_text)
        .or_else(|| warning_evidence.hard_errors.first().map(String::as_str))
        .or_else(daemon_report_line)
        .map_or(
            ScanFailureReason::UnexplainedScannerFailure {
                exit_code: scanner_transcript.exit_code,
            },
            |scanner_message| ScanFailureReason::ScannerReported {
                scanner_message: scanner_message.to_owned(),
            },
        )
}

fn interpret_scanner_transcript(
    scanner_backend: ScannerBackend,
    scanner_transcript: &ScannerTranscript<'_>,
    scanned_file_count: u64,
) -> InterpretedScan {
    let warning_evidence = collect_warning_evidence(
        scanner_transcript.report_text,
        scanner_transcript.diagnostic_text,
    );
    let hard_error_is_genuine = warning_evidence
        .hard_errors
        .iter()
        .any(|hard_error| is_genuine_error(hard_error));
    let total_errors = total_error_count(scanner_transcript.report_text);
    let failed_verdict = ScanVerdict::ScanFailed(scanner_failure_reason(
        scanner_backend,
        scanner_transcript,
        &warning_evidence,
    ));
    let exit_code = scanner_transcript.exit_code;

    let (scan_verdict, scan_notice) = if !scanner_transcript.detected_threats.is_empty() {
        let scan_notice = if exit_code == 2 && !warning_evidence.skipped_paths.is_empty() {
            ScanNotice::FilesInaccessible {
                file_count: warning_evidence.skipped_paths.len() as u64,
            }
        } else {
            ScanNotice::NoNotice
        };
        (ScanVerdict::ThreatsFound, scan_notice)
    } else if exit_code == 0 {
        let daemon_reported_failure =
            scanner_backend == ScannerBackend::ClamdDaemon && hard_error_is_genuine;
        (
            if daemon_reported_failure {
                failed_verdict
            } else {
                ScanVerdict::NoThreatsFound
            },
            ScanNotice::NoNotice,
        )
    } else if exit_code == 1 {
        (ScanVerdict::ThreatsFound, ScanNotice::NoNotice)
    } else if exit_code == 2 {
        let benign_evidence_present = !warning_evidence.skipped_paths.is_empty()
            || !warning_evidence.nonfatal_warnings.is_empty()
            || total_errors > 0;
        let every_file_failed = match scanner_backend {
            ScannerBackend::ClamdDaemon => {
                scanned_file_count > 0
                    && (warning_evidence.skipped_paths.len() as u64 >= scanned_file_count
                        || total_errors >= scanned_file_count)
            }
            ScannerBackend::StandaloneClamscan => scanned_file_count == 0,
        };
        if benign_evidence_present && warning_evidence.hard_errors.is_empty() && !every_file_failed
        {
            (
                ScanVerdict::NoThreatsFound,
                inaccessible_or_warning_notice(&warning_evidence, total_errors),
            )
        } else if every_file_failed {
            (
                ScanVerdict::ScanFailed(ScanFailureReason::NoFilesScanned),
                ScanNotice::NoNotice,
            )
        } else {
            (failed_verdict, ScanNotice::NoNotice)
        }
    } else {
        (failed_verdict, ScanNotice::NoNotice)
    };

    InterpretedScan {
        scan_verdict,
        scan_notice,
        skipped_paths: warning_evidence.skipped_paths,
        nonfatal_warnings: warning_evidence.nonfatal_warnings,
        reported_directory_count: 0,
    }
}

fn strip_terminal_escape_sequences(scanner_text: &str) -> String {
    let mut stripped_text = String::with_capacity(scanner_text.len());
    let mut remaining_characters = scanner_text.chars().peekable();
    while let Some(scanner_character) = remaining_characters.next() {
        if scanner_character == '\u{1b}' {
            if remaining_characters.peek() == Some(&'[') {
                remaining_characters.next();
                let _sequence_terminator = remaining_characters
                    .by_ref()
                    .find(char::is_ascii_alphabetic);
            } else {
                remaining_characters.next();
            }
        } else {
            stripped_text.push(scanner_character);
        }
    }
    stripped_text
}

fn is_bidirectional_override(scanner_character: char) -> bool {
    matches!(
        scanner_character,
        '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

pub fn sanitize_scanner_line(scanner_line: &str) -> String {
    strip_terminal_escape_sequences(scanner_line)
        .chars()
        .filter_map(|scanner_character| {
            let code_point = scanner_character as u32;
            if is_bidirectional_override(scanner_character)
                || code_point == 0x7f
                || (0x80..=0x9f).contains(&code_point)
            {
                None
            } else if matches!(
                scanner_character,
                '\n' | '\r' | '\u{0085}' | '\u{2028}' | '\u{2029}'
            ) {
                Some(' ')
            } else if scanner_character == '\t' || code_point >= 0x20 {
                Some(scanner_character)
            } else {
                None
            }
        })
        .collect()
}

pub fn sanitize_scanner_text(scanner_text: &str) -> String {
    strip_terminal_escape_sequences(scanner_text)
        .chars()
        .filter(|scanner_character| {
            let code_point = *scanner_character as u32;
            !is_bidirectional_override(*scanner_character)
                && code_point != 0x7f
                && !(0x80..=0x9f).contains(&code_point)
                && (matches!(*scanner_character, '\n' | '\r' | '\t') || code_point >= 0x20)
        })
        .collect()
}

#[cfg(test)]
mod scanner_output_parser_tests {
    use super::*;

    #[test]
    fn severity_follows_the_upstream_priority_order() {
        assert_eq!(
            classify_threat_severity("Win.Ransom.WannaCry-1"),
            ThreatSeverity::Critical
        );
        assert_eq!(
            classify_threat_severity("Unix.Trojan.Generic"),
            ThreatSeverity::High
        );
        assert_eq!(
            classify_threat_severity("PUA.Win.Tool"),
            ThreatSeverity::Medium
        );
        assert_eq!(
            classify_threat_severity("Eicar-Test-Signature"),
            ThreatSeverity::Low
        );
        assert_eq!(
            classify_threat_severity("Unclassified.Name"),
            ThreatSeverity::Medium
        );
    }

    #[test]
    fn clamscan_directory_summary_is_reported() {
        let interpreted_scan = interpret_clamscan_transcript(
            &ScannerTranscript {
                report_text: "Scanned directories: 7\nScanned files: 3\n",
                diagnostic_text: "",
                exit_code: 0,
                detected_threats: &[],
            },
            3,
        );
        assert_eq!(interpreted_scan.reported_directory_count, 7);
    }

    #[test]
    fn clean_and_progress_lines_are_not_noteworthy() {
        assert!(!is_noteworthy_scanner_line("/scan/file: OK"));
        assert!(!is_noteworthy_scanner_line("Scanning /scan/file"));
        assert!(is_noteworthy_scanner_line("/scan/file: Bad.Sig FOUND"));
        assert!(is_noteworthy_scanner_line("Scanned files: 1"));
    }

    fn transcript_threats(
        report_text: &str,
        scanner_backend: ScannerBackend,
    ) -> Vec<DetectedThreat> {
        report_text
            .lines()
            .filter_map(|report_line| {
                parse_threat_detection_line(report_line.as_bytes(), scanner_backend)
                    .map(DetectedThreat::from)
            })
            .collect()
    }

    fn interpret_clamscan_text(
        report_text: &str,
        diagnostic_text: &str,
        exit_code: i32,
    ) -> InterpretedScan {
        let detected_threats = transcript_threats(report_text, ScannerBackend::StandaloneClamscan);
        interpret_clamscan_transcript(
            &ScannerTranscript {
                report_text,
                diagnostic_text,
                exit_code,
                detected_threats: &detected_threats,
            },
            0,
        )
    }

    #[test]
    fn infection_wins_over_exit_two_and_preserves_warning_evidence() {
        let report_text = "/scan/eicar: Eicar-Test-Signature FOUND\n/root/locked: Failed to open \
                           file ERROR\nScanned files: 1\n";
        let interpreted_scan = interpret_clamscan_text(report_text, "", 2);
        let detected_threats = transcript_threats(report_text, ScannerBackend::StandaloneClamscan);
        assert_eq!(interpreted_scan.scan_verdict, ScanVerdict::ThreatsFound);
        assert_eq!(
            detected_threats[0].threat_identity.threat_category(),
            "Test"
        );
        assert_eq!(interpreted_scan.skipped_paths, vec!["/root/locked"]);
    }

    #[test]
    fn daemon_zero_precount_is_unknown_but_clamscan_zero_summary_is_all_failed() {
        let report_text = "WARNING: /scan/gone: Can't access file\nScanned files: 0\n";
        let daemon_scan = interpret_clamdscan_transcript(
            &ScannerTranscript {
                report_text,
                diagnostic_text: "",
                exit_code: 2,
                detected_threats: &[],
            },
            0,
        );
        let standalone_scan = interpret_clamscan_text(report_text, "", 2);
        assert_eq!(daemon_scan.scan_verdict, ScanVerdict::NoThreatsFound);
        assert_eq!(
            standalone_scan.scan_verdict,
            ScanVerdict::ScanFailed(ScanFailureReason::NoFilesScanned)
        );
    }

    #[test]
    fn nonfatal_limit_warning_does_not_hide_a_real_error() {
        let diagnostic_text = "LibClamAV Warning: cli_scanxz: file size exceeds limits\nERROR: \
                               unable to initialize engine\n";
        let interpreted_scan = interpret_clamscan_text("Scanned files: 4\n", diagnostic_text, 2);
        assert_eq!(interpreted_scan.nonfatal_warnings.len(), 1);
        assert_eq!(
            interpreted_scan.scan_verdict,
            ScanVerdict::ScanFailed(ScanFailureReason::ScannerReported {
                scanner_message: "LibClamAV Warning: cli_scanxz: file size exceeds limits\nERROR: \
                                  unable to initialize engine"
                    .to_owned(),
            })
        );
    }

    #[test]
    fn classifier_preserves_category_priority() {
        assert_eq!(categorize_threat_name("Trojan.Ransomware.Locky"), "Trojan");
        assert_eq!(
            categorize_threat_name("Ransomware.Trojan.Locky"),
            "Ransomware"
        );
        assert_eq!(categorize_threat_name("PUA.Win.Adware.Generic"), "Adware");
        assert_eq!(categorize_threat_name("Eicar-Test-Signature"), "Test");
        assert_eq!(categorize_threat_name("Unknown.Signature"), "Virus");
    }

    #[test]
    fn hard_warnings_keep_exit_two_scans_in_error() {
        let interpreted_scan = interpret_clamscan_text(
            "WARNING: database metadata could not be read\nTotal errors: 1\nScanned files: 4\n",
            "",
            2,
        );
        assert_eq!(
            interpreted_scan.scan_verdict,
            ScanVerdict::ScanFailed(ScanFailureReason::ScannerReported {
                scanner_message: "WARNING: database metadata could not be read".to_owned(),
            })
        );
    }

    #[test]
    fn benign_exit_two_evidence_downgrades_to_clean() {
        let interpreted_scan = interpret_clamscan_text(
            "WARNING: /scan/gone: Can't access file\nScanned files: 4\n",
            "",
            2,
        );
        assert_eq!(interpreted_scan.scan_verdict, ScanVerdict::NoThreatsFound);
    }

    struct ReportLineCase {
        report_line: &'static [u8],
        scanner_backend: ScannerBackend,
        expected_path: &'static str,
        expected_signature: &'static str,
    }

    #[test]
    fn real_clamd_and_clamonacc_lines_yield_the_reported_signature() {
        [
            ReportLineCase {
                report_line: b"/home/user/Downloads/eicar.com: Win.Test.EICAR_HDB-1 FOUND",
                scanner_backend: ScannerBackend::ClamdDaemon,
                expected_path: "/home/user/Downloads/eicar.com",
                expected_signature: "Win.Test.EICAR_HDB-1",
            },
            ReportLineCase {
                report_line: b"/home/user/Downloads/invoice.exe: Sanesecurity.Foo.UNOFFICIAL FOUND",
                scanner_backend: ScannerBackend::ClamdDaemon,
                expected_path: "/home/user/Downloads/invoice.exe",
                expected_signature: "Sanesecurity.Foo.UNOFFICIAL",
            },
            ReportLineCase {
                report_line: b"/scan/eicar.txt: Eicar-Test-Signature FOUND",
                scanner_backend: ScannerBackend::StandaloneClamscan,
                expected_path: "/scan/eicar.txt",
                expected_signature: "Eicar-Test-Signature",
            },
        ]
        .into_iter()
        .for_each(|line_case| {
            assert_eq!(
                parse_threat_detection_line(line_case.report_line, line_case.scanner_backend)
                    .map(DetectedThreat::from),
                Some(DetectedThreat {
                    file_path: PathBuf::from(line_case.expected_path),
                    threat_identity: ThreatIdentity::Signature {
                        signature_name: line_case.expected_signature.to_owned(),
                    },
                })
            );
        });
    }

    #[test]
    fn non_utf8_threat_paths_stay_byte_exact() {
        let detected_threat = parse_threat_detection_line(
            b"/scan/bad-\xff-name: Eicar-Test-Signature FOUND",
            ScannerBackend::ClamdDaemon,
        )
        .expect("detection");
        assert_eq!(
            detected_threat.file_path.as_os_str().as_bytes(),
            b"/scan/bad-\xff-name"
        );
    }

    #[test]
    fn inaccessible_paths_are_parsed_byte_exactly() {
        assert_eq!(
            parse_inaccessible_path_line(b"/scan/bad-\xff-name: Failed to open file ERROR")
                .expect("clamd path")
                .as_os_str()
                .as_bytes(),
            b"/scan/bad-\xff-name"
        );
        assert_eq!(
            parse_inaccessible_path_line(
                b"WARNING: Can't open file /scan/file: Operation not permitted"
            ),
            Some(PathBuf::from("/scan/file"))
        );
        assert_eq!(
            parse_inaccessible_path_line(b"ERROR: Can't access file /scan/other"),
            Some(PathBuf::from("/scan/other"))
        );
        assert_eq!(parse_inaccessible_path_line(b"/scan/fine: OK"), None);
    }

    #[test]
    fn unreadable_but_unblocked_files_are_not_treated_as_on_access_blocks() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        assert!(!is_blocked_by_on_access(
            &temporary_root.path().join("missing")
        ));
    }

    #[test]
    fn sanitizers_remove_control_sequences_without_collapsing_text() {
        assert_eq!(
            sanitize_scanner_line("a\u{1b}[31mred\u{1b}[0m\nnext\u{202e}"),
            "ared next"
        );
        assert_eq!(sanitize_scanner_text("one\ntwo\u{7f}\u{85}"), "one\ntwo");
    }

    #[test]
    fn a_broken_pipe_to_clamd_counts_as_a_lost_connection() {
        assert!(reports_lost_clamd_connection(
            "Infected files: 0\n",
            "ERROR: Can't send to clamd: Broken pipe\n"
        ));
        assert!(!reports_lost_clamd_connection(
            "/scan/first: OK\n",
            "/scan/locked: Failed to open file\n"
        ));
    }
}
