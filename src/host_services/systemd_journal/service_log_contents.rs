use std::path::PathBuf;

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_text,
    systemd_journal::unit_journal_reader::{
        UnitJournalReadFailure, newest_unit_messages, read_journal_off_thread,
    },
};

pub const SHOWN_LOG_LINE_COUNT: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceLogContents {
    FromLogFile { log_path: PathBuf, log_text: String },
    FromSystemJournal { log_text: String },
    NoReadableLog,
    JournalUnreadable(UnitJournalReadFailure),
}

pub fn journal_log_contents(
    journal_reading: Result<Vec<String>, UnitJournalReadFailure>,
) -> ServiceLogContents {
    match journal_reading {
        Ok(unit_messages) if unit_messages.is_empty() => ServiceLogContents::NoReadableLog,
        Ok(unit_messages) => ServiceLogContents::FromSystemJournal {
            log_text: sanitize_scanner_text(&unit_messages.join("\n")),
        },
        Err(read_failure) => ServiceLogContents::JournalUnreadable(read_failure),
    }
}

pub async fn read_unit_journal_log(service_units: &'static [&'static str]) -> ServiceLogContents {
    journal_log_contents(
        read_journal_off_thread(move || newest_unit_messages(service_units, SHOWN_LOG_LINE_COUNT))
            .await,
    )
}

#[cfg(test)]
mod service_log_contents_tests {
    use super::*;

    #[test]
    fn an_unreadable_journal_is_not_reported_as_no_log() {
        assert_eq!(
            journal_log_contents(Err(UnitJournalReadFailure::ReadingTaskInterrupted)),
            ServiceLogContents::JournalUnreadable(UnitJournalReadFailure::ReadingTaskInterrupted)
        );
        assert_eq!(
            journal_log_contents(Ok(Vec::new())),
            ServiceLogContents::NoReadableLog
        );
    }

    #[test]
    fn journal_lines_are_joined_and_sanitized() {
        assert_eq!(
            journal_log_contents(Ok(vec![
                "clamonacc started".to_owned(),
                "watching /home".to_owned()
            ])),
            ServiceLogContents::FromSystemJournal {
                log_text: "clamonacc started\nwatching /home".to_owned()
            }
        );
    }
}
