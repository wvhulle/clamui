use std::io;

use jiff::Timestamp;
use systemd::journal::Journal;

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    systemd_journal::unit_journal_reader::{
        add_unit_matches, journal_field_value, open_system_journal,
    },
};

const MESSAGE_FIELD: &str = "MESSAGE";
const PRIORITY_FIELD: &str = "PRIORITY";
const SYSLOG_IDENTIFIER_FIELD: &str = "SYSLOG_IDENTIFIER";
const COMMAND_NAME_FIELD: &str = "_COMM";
const SENDER_PROCESS_FIELD: &str = "_PID";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogSeverityLevel {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Informational,
    Debug,
    SeverityMissing,
    UnrecognizedSeverity { priority_field: String },
}

impl LogSeverityLevel {
    pub const fn is_warning_or_worse(&self) -> bool {
        matches!(
            self,
            Self::Emergency | Self::Alert | Self::Critical | Self::Error | Self::Warning
        )
    }

    pub const fn is_error_or_worse(&self) -> bool {
        matches!(
            self,
            Self::Emergency | Self::Alert | Self::Critical | Self::Error
        )
    }
}

pub fn classify_journal_priority(priority_field: &str) -> LogSeverityLevel {
    match priority_field.trim() {
        "0" => LogSeverityLevel::Emergency,
        "1" => LogSeverityLevel::Alert,
        "2" => LogSeverityLevel::Critical,
        "3" => LogSeverityLevel::Error,
        "4" => LogSeverityLevel::Warning,
        "5" => LogSeverityLevel::Notice,
        "6" => LogSeverityLevel::Informational,
        "7" => LogSeverityLevel::Debug,
        unrecognized_priority => LogSeverityLevel::UnrecognizedSeverity {
            priority_field: unrecognized_priority.to_owned(),
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalLogEntry {
    pub recorded_at: Timestamp,
    pub severity_level: LogSeverityLevel,
    pub sender_name: Option<String>,
    pub sender_process: Option<u32>,
    pub message_text: String,
}

fn journal_entry_at_position(journal: &mut Journal) -> systemd::Result<Option<JournalLogEntry>> {
    let Some(message_field) = journal_field_value(journal, MESSAGE_FIELD)? else {
        return Ok(None);
    };
    let sender_name = match journal_field_value(journal, SYSLOG_IDENTIFIER_FIELD)? {
        Some(syslog_identifier) => Some(syslog_identifier),
        None => journal_field_value(journal, COMMAND_NAME_FIELD)?,
    };
    Ok(Some(JournalLogEntry {
        recorded_at: Timestamp::try_from(journal.timestamp()?).map_err(io::Error::other)?,
        severity_level: journal_field_value(journal, PRIORITY_FIELD)?
            .map_or(LogSeverityLevel::SeverityMissing, |priority_field| {
                classify_journal_priority(&priority_field)
            }),
        sender_name: sender_name.map(|sender_text| sanitize_scanner_line(&sender_text)),
        sender_process: journal_field_value(journal, SENDER_PROCESS_FIELD)?
            .and_then(|process_field| process_field.parse().ok()),
        message_text: sanitize_scanner_line(&message_field),
    }))
}

pub fn newest_unit_entries(
    service_units: &[&str],
    entry_limit: usize,
) -> systemd::Result<Vec<JournalLogEntry>> {
    let mut journal = open_system_journal()?;
    add_unit_matches(&mut journal, service_units)?;
    journal.seek_tail()?;
    let mut newest_first = Vec::new();
    while newest_first.len() < entry_limit && journal.previous()? > 0 {
        newest_first.extend(journal_entry_at_position(&mut journal)?);
    }
    newest_first.reverse();
    Ok(newest_first)
}

#[cfg(test)]
mod journal_log_entries_tests {
    use super::*;

    #[test]
    fn syslog_priorities_become_severity_levels() {
        assert_eq!(classify_journal_priority("3"), LogSeverityLevel::Error);
        assert_eq!(classify_journal_priority("4"), LogSeverityLevel::Warning);
        assert_eq!(
            classify_journal_priority("6"),
            LogSeverityLevel::Informational
        );
        assert_eq!(classify_journal_priority("7"), LogSeverityLevel::Debug);
    }

    #[test]
    fn unrecognized_priorities_keep_their_raw_text() {
        assert_eq!(
            classify_journal_priority("loud"),
            LogSeverityLevel::UnrecognizedSeverity {
                priority_field: "loud".to_owned()
            }
        );
    }

    #[test]
    fn warnings_and_errors_are_ranked_above_notices() {
        assert!(LogSeverityLevel::Critical.is_warning_or_worse());
        assert!(LogSeverityLevel::Warning.is_warning_or_worse());
        assert!(!LogSeverityLevel::Warning.is_error_or_worse());
        assert!(!LogSeverityLevel::Notice.is_warning_or_worse());
        assert!(!LogSeverityLevel::SeverityMissing.is_warning_or_worse());
    }

    #[test]
    #[ignore = "reads the real host journal"]
    fn host_journal_returns_entries_in_chronological_order() {
        let daemon_entries =
            newest_unit_entries(&["clamav-daemon.service"], 5).expect("readable journal");
        assert!(daemon_entries.len() <= 5);
        assert!(
            daemon_entries
                .windows(2)
                .all(|entry_pair| entry_pair[0].recorded_at <= entry_pair[1].recorded_at)
        );
        println!("{daemon_entries:#?}");
    }
}
