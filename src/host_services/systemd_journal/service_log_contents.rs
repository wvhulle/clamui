use std::path::PathBuf;

use futures::{Stream, StreamExt, stream};

use crate::host_services::{
    blocking_iterator_stream::blocking_iterator_stream,
    clamav_scanner::scanner_output_parser::sanitize_scanner_text,
    systemd_journal::unit_journal_reader::{
        UnitJournalReadFailure, appended_unit_entries, newest_unit_messages,
        read_journal_off_thread,
    },
};

pub const SHOWN_LOG_LINE_COUNT: usize = 100;
const UNIT_LOG_WATCH_THREAD: &str = "unit-log-watch";
const CHANGE_BURST_SIZE: usize = 64;

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

pub fn unit_journal_log_updates(
    service_units: &'static [&'static str],
) -> impl Stream<Item = ServiceLogContents> + Send + 'static {
    stream::once(read_unit_journal_log(service_units)).chain(
        blocking_iterator_stream(
            UNIT_LOG_WATCH_THREAD,
            move || appended_unit_entries(service_units),
            |_spawn_failure| (),
        )
        .ready_chunks(CHANGE_BURST_SIZE)
        .then(move |_change_burst| read_unit_journal_log(service_units)),
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
