use gettextrs::gettext;
use jiff::{Timestamp, tz::TimeZone};

use crate::{
    host_services::{
        clamav_scanner::{
            clamd_log_lines::ClamdLogLine,
            scanner_command_builder::ScannerBackend,
            scanner_output_parser::{parse_threat_detection_line, sanitize_scanner_line},
        },
        systemd_journal::{
            journal_log_entries::{JournalLogEntry, LogSeverityLevel},
            service_log_contents::ServiceLogContents,
        },
    },
    shared_widgets::{
        host_read_failure_text::unit_journal_failure_text,
        loading_indicators::{LOADED_PAGE_NAME, LOADING_PAGE_NAME},
    },
};

pub const MISSING_LOG_PAGE_NAME: &str = "missing-log";
pub const NO_MATCHING_ROWS_PAGE_NAME: &str = "no-matching-rows";
const EXPORTED_TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShownRowLevel {
    ThreatDetected,
    Severity(LogSeverityLevel),
}

impl ShownRowLevel {
    fn of_message(message_text: &str, severity_level: &LogSeverityLevel) -> Self {
        if parse_threat_detection_line(message_text.as_bytes(), ScannerBackend::ClamdDaemon)
            .is_some()
        {
            Self::ThreatDetected
        } else {
            Self::Severity(severity_level.clone())
        }
    }

    pub const fn is_notable(&self) -> bool {
        match self {
            Self::ThreatDetected => true,
            Self::Severity(severity_level) => severity_level.is_warning_or_worse(),
        }
    }

    pub fn level_label_text(&self) -> String {
        match self {
            Self::ThreatDetected => gettext("Detection"),
            Self::Severity(LogSeverityLevel::Emergency) => gettext("Emergency"),
            Self::Severity(LogSeverityLevel::Alert) => gettext("Alert"),
            Self::Severity(LogSeverityLevel::Critical) => gettext("Critical"),
            Self::Severity(LogSeverityLevel::Error) => gettext("Error"),
            Self::Severity(LogSeverityLevel::Warning) => gettext("Warning"),
            Self::Severity(LogSeverityLevel::Notice) => gettext("Notice"),
            Self::Severity(LogSeverityLevel::Informational) => gettext("Info"),
            Self::Severity(LogSeverityLevel::Debug) => gettext("Debug"),
            Self::Severity(LogSeverityLevel::SeverityMissing) => String::new(),
            Self::Severity(LogSeverityLevel::UnrecognizedSeverity { priority_field }) => {
                sanitize_scanner_line(priority_field)
            }
        }
    }

    pub fn exported_level_text(&self) -> String {
        match self {
            Self::ThreatDetected => "found".to_owned(),
            Self::Severity(LogSeverityLevel::Emergency) => "emerg".to_owned(),
            Self::Severity(LogSeverityLevel::Alert) => "alert".to_owned(),
            Self::Severity(LogSeverityLevel::Critical) => "crit".to_owned(),
            Self::Severity(LogSeverityLevel::Error) => "err".to_owned(),
            Self::Severity(LogSeverityLevel::Warning) => "warning".to_owned(),
            Self::Severity(LogSeverityLevel::Notice) => "notice".to_owned(),
            Self::Severity(LogSeverityLevel::Informational) => "info".to_owned(),
            Self::Severity(LogSeverityLevel::Debug) => "debug".to_owned(),
            Self::Severity(LogSeverityLevel::SeverityMissing) => "-".to_owned(),
            Self::Severity(LogSeverityLevel::UnrecognizedSeverity { priority_field }) => {
                sanitize_scanner_line(priority_field)
            }
        }
    }

    pub const fn level_icon_name(&self) -> Option<&'static str> {
        match self {
            Self::ThreatDetected => Some("security-low-symbolic"),
            Self::Severity(severity_level) if severity_level.is_error_or_worse() => {
                Some("dialog-error-symbolic")
            }
            Self::Severity(LogSeverityLevel::Warning) => Some("dialog-warning-symbolic"),
            Self::Severity(_) => None,
        }
    }

    pub const fn level_style_class(&self) -> Option<&'static str> {
        match self {
            Self::ThreatDetected => Some("error"),
            Self::Severity(severity_level) if severity_level.is_error_or_worse() => Some("error"),
            Self::Severity(LogSeverityLevel::Warning) => Some("warning"),
            Self::Severity(_) => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShownLogRow {
    pub logged_at: Option<Timestamp>,
    pub row_level: ShownRowLevel,
    pub sender_text: String,
    pub message_text: String,
    pub source_position: usize,
}

fn sender_text_of(journal_entry: &JournalLogEntry) -> String {
    match (&journal_entry.sender_name, journal_entry.sender_process) {
        (Some(sender_name), Some(sender_process)) => format!("{sender_name}[{sender_process}]"),
        (Some(sender_name), None) => sender_name.clone(),
        (None, Some(sender_process)) => format!("[{sender_process}]"),
        (None, None) => String::new(),
    }
}

fn journal_row(source_position: usize, journal_entry: &JournalLogEntry) -> ShownLogRow {
    ShownLogRow {
        logged_at: Some(journal_entry.recorded_at),
        row_level: ShownRowLevel::of_message(
            &journal_entry.message_text,
            &journal_entry.severity_level,
        ),
        sender_text: sender_text_of(journal_entry),
        message_text: journal_entry.message_text.clone(),
        source_position,
    }
}

fn clamd_line_row(source_position: usize, clamd_line: &ClamdLogLine) -> ShownLogRow {
    let (logged_at, severity_level, message_text) = match clamd_line {
        ClamdLogLine::Stamped {
            logged_at,
            severity_level,
            message_text,
        } => (Some(*logged_at), severity_level, message_text),
        ClamdLogLine::Unstamped {
            severity_level,
            message_text,
        } => (None, severity_level, message_text),
    };
    ShownLogRow {
        logged_at,
        row_level: ShownRowLevel::of_message(message_text, severity_level),
        sender_text: String::new(),
        message_text: message_text.clone(),
        source_position,
    }
}

pub fn all_log_rows(log_contents: &ServiceLogContents) -> Vec<ShownLogRow> {
    match log_contents {
        ServiceLogContents::FromSystemJournal { log_entries } => log_entries
            .iter()
            .enumerate()
            .map(|(source_position, journal_entry)| journal_row(source_position, journal_entry))
            .collect(),
        ServiceLogContents::FromLogFile { log_lines, .. } => log_lines
            .iter()
            .enumerate()
            .map(|(source_position, clamd_line)| clamd_line_row(source_position, clamd_line))
            .collect(),
        ServiceLogContents::NoReadableLog | ServiceLogContents::JournalUnreadable(_) => Vec::new(),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LogRowFilter {
    pub search_query: String,
    pub notable_only: bool,
}

impl LogRowFilter {
    pub fn admits_row(&self, log_row: &ShownLogRow) -> bool {
        let lowered_query = self.search_query.trim().to_lowercase();
        (!self.notable_only || log_row.row_level.is_notable())
            && (lowered_query.is_empty()
                || log_row.message_text.to_lowercase().contains(&lowered_query)
                || log_row.sender_text.to_lowercase().contains(&lowered_query))
    }
}

pub fn filtered_log_rows(
    log_contents: &ServiceLogContents,
    row_filter: &LogRowFilter,
) -> Vec<ShownLogRow> {
    all_log_rows(log_contents)
        .into_iter()
        .filter(|log_row| row_filter.admits_row(log_row))
        .collect()
}

fn exported_row_line(log_row: &ShownLogRow, export_time_zone: &TimeZone) -> String {
    let time_prefix = log_row.logged_at.map_or_else(String::new, |logged_at| {
        format!(
            "{} ",
            logged_at
                .to_zoned(export_time_zone.clone())
                .strftime(EXPORTED_TIME_FORMAT)
        )
    });
    let sender_prefix = if log_row.sender_text.is_empty() {
        String::new()
    } else {
        format!("{} ", log_row.sender_text)
    };
    format!(
        "{time_prefix}{sender_prefix}<{}> {}\n",
        log_row.row_level.exported_level_text(),
        log_row.message_text
    )
}

pub fn exported_log_text(
    log_contents: &ServiceLogContents,
    export_time_zone: &TimeZone,
) -> Option<String> {
    let log_rows = all_log_rows(log_contents);
    (!log_rows.is_empty()).then(|| {
        log_rows
            .iter()
            .map(|log_row| exported_row_line(log_row, export_time_zone))
            .collect()
    })
}

#[derive(Debug)]
pub enum ServiceLogView {
    LogReading,
    LogRead(ServiceLogContents),
}

impl ServiceLogView {
    pub const fn has_log_rows(&self) -> bool {
        matches!(
            self,
            Self::LogRead(
                ServiceLogContents::FromLogFile { .. }
                    | ServiceLogContents::FromSystemJournal { .. }
            )
        )
    }

    pub const fn shown_page_name(&self, shown_row_count: usize) -> &'static str {
        match self {
            Self::LogReading => LOADING_PAGE_NAME,
            Self::LogRead(
                ServiceLogContents::FromLogFile { .. }
                | ServiceLogContents::FromSystemJournal { .. },
            ) if shown_row_count == 0 => NO_MATCHING_ROWS_PAGE_NAME,
            Self::LogRead(
                ServiceLogContents::FromLogFile { .. }
                | ServiceLogContents::FromSystemJournal { .. },
            ) => LOADED_PAGE_NAME,
            Self::LogRead(
                ServiceLogContents::NoReadableLog | ServiceLogContents::JournalUnreadable(_),
            ) => MISSING_LOG_PAGE_NAME,
        }
    }

    pub fn source_text(&self) -> String {
        match self {
            Self::LogReading => gettext("Checking…"),
            Self::LogRead(ServiceLogContents::FromLogFile { log_path, .. }) => {
                sanitize_scanner_line(&log_path.to_string_lossy())
            }
            Self::LogRead(ServiceLogContents::FromSystemJournal { .. }) => {
                gettext("System journal")
            }
            Self::LogRead(ServiceLogContents::NoReadableLog) => {
                gettext("Neither a log file nor journal lines were found.")
            }
            Self::LogRead(ServiceLogContents::JournalUnreadable(read_failure)) => {
                gettext("No log file was found. {reason}")
                    .replace("{reason}", &unit_journal_failure_text(*read_failure))
            }
        }
    }
}

#[cfg(test)]
mod service_log_state_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::host_services::systemd_journal::unit_journal_reader::UnitJournalReadFailure;

    fn sample_moment() -> Timestamp {
        "2026-11-07T10:15:42Z".parse().expect("timestamp")
    }

    fn sample_journal_log() -> ServiceLogContents {
        ServiceLogContents::FromSystemJournal {
            log_entries: vec![
                JournalLogEntry {
                    recorded_at: sample_moment(),
                    severity_level: LogSeverityLevel::Informational,
                    sender_name: Some("clamonacc".to_owned()),
                    sender_process: Some(1234),
                    message_text: "watching /home".to_owned(),
                },
                JournalLogEntry {
                    recorded_at: sample_moment(),
                    severity_level: LogSeverityLevel::Informational,
                    sender_name: Some("clamonacc".to_owned()),
                    sender_process: Some(1234),
                    message_text: "/home/user/eicar.txt: Eicar-Test-Signature FOUND".to_owned(),
                },
                JournalLogEntry {
                    recorded_at: sample_moment(),
                    severity_level: LogSeverityLevel::Warning,
                    sender_name: None,
                    sender_process: None,
                    message_text: "fanotify queue overflow".to_owned(),
                },
            ],
        }
    }

    fn shown_messages(log_rows: &[ShownLogRow]) -> Vec<&str> {
        log_rows
            .iter()
            .map(|log_row| log_row.message_text.as_str())
            .collect()
    }

    #[test]
    fn journal_rows_name_their_sender_and_flag_detections() {
        let log_rows = all_log_rows(&sample_journal_log());
        assert_eq!(log_rows[0].sender_text, "clamonacc[1234]");
        assert_eq!(log_rows[1].row_level, ShownRowLevel::ThreatDetected);
        assert_eq!(log_rows[2].sender_text, "");
        assert_eq!(
            log_rows[2].row_level,
            ShownRowLevel::Severity(LogSeverityLevel::Warning)
        );
    }

    #[test]
    fn notable_only_keeps_detections_warnings_and_errors() {
        let notable_rows = filtered_log_rows(
            &sample_journal_log(),
            &LogRowFilter {
                search_query: String::new(),
                notable_only: true,
            },
        );
        assert_eq!(
            shown_messages(&notable_rows),
            [
                "/home/user/eicar.txt: Eicar-Test-Signature FOUND",
                "fanotify queue overflow"
            ]
        );
    }

    #[test]
    fn search_matches_message_and_sender_ignoring_case() {
        let eicar_rows = filtered_log_rows(
            &sample_journal_log(),
            &LogRowFilter {
                search_query: "  EICAR ".to_owned(),
                notable_only: false,
            },
        );
        assert_eq!(
            shown_messages(&eicar_rows),
            ["/home/user/eicar.txt: Eicar-Test-Signature FOUND"]
        );
        let sender_rows = filtered_log_rows(
            &sample_journal_log(),
            &LogRowFilter {
                search_query: "clamonacc".to_owned(),
                notable_only: false,
            },
        );
        assert_eq!(sender_rows.len(), 2);
    }

    #[test]
    fn search_and_notable_only_combine() {
        let combined_rows = filtered_log_rows(
            &sample_journal_log(),
            &LogRowFilter {
                search_query: "watching".to_owned(),
                notable_only: true,
            },
        );
        assert!(combined_rows.is_empty());
    }

    #[test]
    fn exported_text_keeps_time_sender_and_level_of_every_row() {
        assert_eq!(
            exported_log_text(&sample_journal_log(), &TimeZone::UTC).as_deref(),
            Some(
                "2026-11-07 10:15:42 clamonacc[1234] <info> watching /home\n2026-11-07 10:15:42 \
                 clamonacc[1234] <found> /home/user/eicar.txt: Eicar-Test-Signature \
                 FOUND\n2026-11-07 10:15:42 <warning> fanotify queue overflow\n"
            )
        );
    }

    #[test]
    fn exported_log_file_lines_omit_missing_times() {
        let file_log = ServiceLogContents::FromLogFile {
            log_path: PathBuf::from("/var/log/clamav/clamd.log"),
            log_lines: vec![
                ClamdLogLine::Unstamped {
                    severity_level: LogSeverityLevel::Informational,
                    message_text: "clamd started".to_owned(),
                },
                ClamdLogLine::Stamped {
                    logged_at: sample_moment(),
                    severity_level: LogSeverityLevel::Error,
                    message_text: "ERROR: socket busy".to_owned(),
                },
            ],
        };
        assert_eq!(
            exported_log_text(&file_log, &TimeZone::UTC).as_deref(),
            Some("<info> clamd started\n2026-11-07 10:15:42 <err> ERROR: socket busy\n")
        );
    }

    #[test]
    fn there_is_no_log_to_copy_while_it_is_read_or_missing() {
        assert_eq!(
            exported_log_text(&ServiceLogContents::NoReadableLog, &TimeZone::UTC),
            None
        );
        assert!(!ServiceLogView::LogReading.has_log_rows());
    }

    #[test]
    fn each_reading_state_shows_its_own_page() {
        assert_eq!(
            ServiceLogView::LogReading.shown_page_name(0),
            LOADING_PAGE_NAME
        );
        assert_eq!(
            ServiceLogView::LogRead(sample_journal_log()).shown_page_name(3),
            LOADED_PAGE_NAME
        );
        assert_eq!(
            ServiceLogView::LogRead(sample_journal_log()).shown_page_name(0),
            NO_MATCHING_ROWS_PAGE_NAME
        );
        assert_eq!(
            ServiceLogView::LogRead(ServiceLogContents::JournalUnreadable(
                UnitJournalReadFailure::ReadingTaskInterrupted
            ))
            .shown_page_name(0),
            MISSING_LOG_PAGE_NAME
        );
    }

    #[test]
    fn an_unreadable_journal_names_its_reason_rather_than_no_log() {
        let source_text = ServiceLogView::LogRead(ServiceLogContents::JournalUnreadable(
            UnitJournalReadFailure::ReadingTaskInterrupted,
        ))
        .source_text();
        assert!(source_text.starts_with("No log file was found. "));
        assert_ne!(
            source_text,
            ServiceLogView::LogRead(ServiceLogContents::NoReadableLog).source_text()
        );
    }
}
