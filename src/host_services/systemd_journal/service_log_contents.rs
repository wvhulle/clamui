use std::path::PathBuf;

use futures::{Stream, StreamExt, stream};

use crate::host_services::{
    blocking_iterator_stream::blocking_iterator_stream,
    clamav_scanner::clamd_log_lines::ClamdLogLine,
    systemd_journal::{
        journal_log_entries::{JournalLogEntry, newest_unit_entries},
        unit_journal_reader::{
            UnitJournalReadFailure, appended_unit_entries, read_journal_off_thread,
        },
    },
};

pub const SHOWN_LOG_LINE_COUNT: usize = 500;
const UNIT_LOG_WATCH_THREAD: &str = "unit-log-watch";
const CHANGE_BURST_SIZE: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceLogContents {
    FromLogFile {
        log_path: PathBuf,
        log_lines: Vec<ClamdLogLine>,
    },
    FromSystemJournal {
        log_entries: Vec<JournalLogEntry>,
    },
    NoReadableLog,
    JournalUnreadable(UnitJournalReadFailure),
}

pub fn journal_log_contents(
    journal_reading: Result<Vec<JournalLogEntry>, UnitJournalReadFailure>,
) -> ServiceLogContents {
    match journal_reading {
        Ok(log_entries) if log_entries.is_empty() => ServiceLogContents::NoReadableLog,
        Ok(log_entries) => ServiceLogContents::FromSystemJournal { log_entries },
        Err(read_failure) => ServiceLogContents::JournalUnreadable(read_failure),
    }
}

pub async fn read_unit_journal_log(service_units: &'static [&'static str]) -> ServiceLogContents {
    journal_log_contents(
        read_journal_off_thread(move || newest_unit_entries(service_units, SHOWN_LOG_LINE_COUNT))
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
}
