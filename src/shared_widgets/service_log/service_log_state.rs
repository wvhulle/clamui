use gettextrs::gettext;

use crate::{
    host_services::{
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        systemd_journal::service_log_contents::ServiceLogContents,
    },
    shared_widgets::{
        host_read_failure_text::unit_journal_failure_text,
        loading_indicators::{LOADED_PAGE_NAME, LOADING_PAGE_NAME},
    },
};

pub const MISSING_LOG_PAGE_NAME: &str = "missing-log";

#[derive(Debug)]
pub enum ServiceLogView {
    LogReading,
    LogRead(ServiceLogContents),
}

impl ServiceLogView {
    pub fn shown_log_text(&self) -> Option<&str> {
        match self {
            Self::LogRead(
                ServiceLogContents::FromLogFile { log_text, .. }
                | ServiceLogContents::FromSystemJournal { log_text },
            ) => Some(log_text),
            Self::LogRead(
                ServiceLogContents::NoReadableLog | ServiceLogContents::JournalUnreadable(_),
            )
            | Self::LogReading => None,
        }
    }

    pub const fn shown_page_name(&self) -> &'static str {
        match self {
            Self::LogReading => LOADING_PAGE_NAME,
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

    #[test]
    fn there_is_no_log_to_copy_while_it_is_read_or_missing() {
        assert_eq!(ServiceLogView::LogReading.shown_log_text(), None);
        assert_eq!(
            ServiceLogView::LogRead(ServiceLogContents::NoReadableLog).shown_log_text(),
            None
        );
        assert_eq!(
            ServiceLogView::LogRead(ServiceLogContents::FromLogFile {
                log_path: PathBuf::from("/var/log/clamav/clamd.log"),
                log_text: "clamd started\n".to_owned(),
            })
            .shown_log_text(),
            Some("clamd started\n")
        );
    }

    #[test]
    fn each_reading_state_shows_its_own_page() {
        assert_eq!(
            ServiceLogView::LogReading.shown_page_name(),
            LOADING_PAGE_NAME
        );
        assert_eq!(
            ServiceLogView::LogRead(ServiceLogContents::FromSystemJournal {
                log_text: "started".to_owned()
            })
            .shown_page_name(),
            LOADED_PAGE_NAME
        );
        assert_eq!(
            ServiceLogView::LogRead(ServiceLogContents::JournalUnreadable(
                UnitJournalReadFailure::ReadingTaskInterrupted
            ))
            .shown_page_name(),
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
