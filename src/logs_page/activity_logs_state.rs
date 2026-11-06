use crate::{
    host_services::activity_history::activity_history_database::{
        ActivityEntryRecord, ActivityHistoryFailure,
    },
    logs_page::daemon_log_reader::DaemonLogContents,
    shared_widgets::loading_indicators::{
        LOAD_FAILED_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
    },
};

#[derive(Debug)]
pub enum HistoryActionOutcome {
    NoActionTaken,
    ClearingFailed(ActivityHistoryFailure),
}

#[derive(Debug)]
pub enum HistoryView {
    HistoryLoading,
    HistoryLoaded {
        listed_entries: Vec<ActivityEntryRecord>,
        last_action: HistoryActionOutcome,
    },
    HistoryLoadFailed(ActivityHistoryFailure),
}

impl HistoryView {
    pub fn listed_entries(&self) -> &[ActivityEntryRecord] {
        match self {
            Self::HistoryLoaded { listed_entries, .. } => listed_entries,
            Self::HistoryLoading | Self::HistoryLoadFailed(_) => &[],
        }
    }

    pub const fn placeholder_page_name(&self) -> &'static str {
        match self {
            Self::HistoryLoading => LOADING_PAGE_NAME,
            Self::HistoryLoaded { .. } => LOADED_PAGE_NAME,
            Self::HistoryLoadFailed(_) => LOAD_FAILED_PAGE_NAME,
        }
    }

    pub fn with_loaded_entries(
        self,
        load_outcome: Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>,
    ) -> Self {
        match load_outcome {
            Ok(listed_entries) => Self::HistoryLoaded {
                listed_entries,
                last_action: match self {
                    Self::HistoryLoaded { last_action, .. } => last_action,
                    Self::HistoryLoading | Self::HistoryLoadFailed(_) => {
                        HistoryActionOutcome::NoActionTaken
                    }
                },
            },
            Err(load_failure) => Self::HistoryLoadFailed(load_failure),
        }
    }

    pub fn with_clearing_started(self) -> Self {
        match self {
            Self::HistoryLoaded { listed_entries, .. } => Self::HistoryLoaded {
                listed_entries,
                last_action: HistoryActionOutcome::NoActionTaken,
            },
            Self::HistoryLoading | Self::HistoryLoadFailed(_) => self,
        }
    }

    pub fn with_clearing_failure(self, clearing_failure: ActivityHistoryFailure) -> Self {
        match self {
            Self::HistoryLoaded { listed_entries, .. } => Self::HistoryLoaded {
                listed_entries,
                last_action: HistoryActionOutcome::ClearingFailed(clearing_failure),
            },
            Self::HistoryLoading | Self::HistoryLoadFailed(_) => self,
        }
    }
}

#[derive(Debug)]
pub enum DaemonLogView {
    DaemonLogReading,
    DaemonLogRead(DaemonLogContents),
}

impl DaemonLogView {
    pub fn shown_log_text(&self) -> Option<&str> {
        match self {
            Self::DaemonLogRead(
                DaemonLogContents::FromLogFile { log_text, .. }
                | DaemonLogContents::FromSystemJournal { log_text },
            ) => Some(log_text),
            Self::DaemonLogRead(DaemonLogContents::NoReadableLog) | Self::DaemonLogReading => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SystemChangesReadFailure {
    #[error("the system journal can't be read: {0}")]
    JournalUnreadable(#[from] systemd::Error),
    #[error("the system journal read stopped unexpectedly: {0}")]
    JournalReadInterrupted(#[from] tokio::task::JoinError),
}

#[derive(Debug)]
pub enum SystemChangesView {
    SystemChangesLoading,
    SystemChangesLoaded,
    SystemChangesFailed(SystemChangesReadFailure),
}

impl SystemChangesView {
    pub const fn placeholder_page_name(&self) -> &'static str {
        match self {
            Self::SystemChangesLoading => LOADING_PAGE_NAME,
            Self::SystemChangesLoaded => LOADED_PAGE_NAME,
            Self::SystemChangesFailed(_) => LOAD_FAILED_PAGE_NAME,
        }
    }
}

#[cfg(test)]
mod activity_logs_state_tests {
    use std::path::PathBuf;

    use super::*;

    fn loaded_history() -> HistoryView {
        HistoryView::HistoryLoading.with_loaded_entries(Ok(Vec::new()))
    }

    #[test]
    fn a_first_load_failure_never_shows_the_empty_state() {
        let history_view = HistoryView::HistoryLoading
            .with_loaded_entries(Err(ActivityHistoryFailure::DatabasePathNotUtf8));
        assert_eq!(history_view.placeholder_page_name(), LOAD_FAILED_PAGE_NAME);
    }

    #[test]
    fn a_failed_clear_survives_the_reload() {
        let history_view = loaded_history()
            .with_clearing_failure(ActivityHistoryFailure::StoredStatusUnknown)
            .with_loaded_entries(Ok(Vec::new()));
        assert!(matches!(
            history_view,
            HistoryView::HistoryLoaded {
                last_action: HistoryActionOutcome::ClearingFailed(
                    ActivityHistoryFailure::StoredStatusUnknown
                ),
                ..
            }
        ));
    }

    #[test]
    fn a_new_clear_attempt_forgets_the_earlier_failure() {
        let history_view = loaded_history()
            .with_clearing_failure(ActivityHistoryFailure::StoredStatusUnknown)
            .with_clearing_started();
        assert!(matches!(
            history_view,
            HistoryView::HistoryLoaded {
                last_action: HistoryActionOutcome::NoActionTaken,
                ..
            }
        ));
    }

    #[test]
    fn a_successful_reload_replaces_a_load_failure() {
        let history_view = HistoryView::HistoryLoading
            .with_loaded_entries(Err(ActivityHistoryFailure::DatabasePathNotUtf8))
            .with_loaded_entries(Ok(Vec::new()));
        assert_eq!(history_view.placeholder_page_name(), LOADED_PAGE_NAME);
    }

    #[test]
    fn there_is_no_daemon_log_to_copy_while_it_is_read() {
        assert_eq!(DaemonLogView::DaemonLogReading.shown_log_text(), None);
        assert_eq!(
            DaemonLogView::DaemonLogRead(DaemonLogContents::NoReadableLog).shown_log_text(),
            None
        );
        assert_eq!(
            DaemonLogView::DaemonLogRead(DaemonLogContents::FromLogFile {
                log_path: PathBuf::from("/var/log/clamav/clamd.log"),
                log_text: "clamd started\n".to_owned(),
            })
            .shown_log_text(),
            Some("clamd started\n")
        );
    }
}
