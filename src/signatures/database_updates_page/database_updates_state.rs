use crate::{
    host_services::activity_history::activity_history_database::{
        ActivityEntryRecord, ActivityHistoryFailure, ActivityRecord, NewActivityEntry,
    },
    shared_widgets::{
        component_streams::RunningStream,
        loading_indicators::{LOAD_FAILED_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME},
    },
    signatures::database_updates_page::signature_update_run::{
        database_update_events::{DatabaseUpdateEvent, DatabaseUpdatePlan},
        signature_update_session::{
            DatabaseHostStatus, SignatureUpdateSession, SignatureUpdateView, UpdateStreamEnding,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseUpdatesPageOutput {
    EvidenceRefreshRequested,
    SignaturesUpdated,
    ActivityRecorded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueuedUpdateRequest {
    NothingQueued,
    QueuedUntilHostStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateStartDecision {
    StartUpdateNow(DatabaseUpdatePlan),
    UpdateQueued,
    NothingToStart,
}

#[derive(Debug)]
pub struct FinishedUpdateEffects {
    pub summary_line: String,
    pub activity_entry: NewActivityEntry,
    pub page_outputs: Vec<DatabaseUpdatesPageOutput>,
}

#[derive(Debug)]
pub enum UpdateFinishEffects {
    StaleStreamEnding,
    UpdateFinished(FinishedUpdateEffects),
}

pub fn finished_update_outputs(definitions_changed: bool) -> Vec<DatabaseUpdatesPageOutput> {
    definitions_changed
        .then_some(DatabaseUpdatesPageOutput::SignaturesUpdated)
        .into_iter()
        .chain([DatabaseUpdatesPageOutput::EvidenceRefreshRequested])
        .collect()
}

pub struct SignatureUpdateControl {
    signature_update_session: SignatureUpdateSession,
    queued_request: QueuedUpdateRequest,
}

impl SignatureUpdateControl {
    pub const fn new() -> Self {
        Self {
            signature_update_session: SignatureUpdateSession::new(),
            queued_request: QueuedUpdateRequest::NothingQueued,
        }
    }

    pub fn update_view(&self) -> SignatureUpdateView {
        self.signature_update_session.update_view()
    }

    fn requested_start(&self) -> UpdateStartDecision {
        self.signature_update_session
            .requested_update_plan()
            .map_or(
                UpdateStartDecision::NothingToStart,
                UpdateStartDecision::StartUpdateNow,
            )
    }

    pub fn update_requested(&mut self) -> UpdateStartDecision {
        if self.signature_update_session.host_status_known() {
            self.requested_start()
        } else {
            self.queued_request = QueuedUpdateRequest::QueuedUntilHostStatus;
            UpdateStartDecision::UpdateQueued
        }
    }

    pub fn host_status_loaded(&mut self, host_status: DatabaseHostStatus) -> UpdateStartDecision {
        self.signature_update_session
            .host_status_loaded(host_status);
        match std::mem::replace(&mut self.queued_request, QueuedUpdateRequest::NothingQueued) {
            QueuedUpdateRequest::QueuedUntilHostStatus => self.requested_start(),
            QueuedUpdateRequest::NothingQueued => UpdateStartDecision::NothingToStart,
        }
    }

    pub fn update_started(
        &mut self,
        update_plan: DatabaseUpdatePlan,
        update_stream: RunningStream,
    ) {
        self.signature_update_session
            .update_started(update_plan, update_stream);
    }

    pub fn cancel_requested(&mut self) {
        self.signature_update_session.cancel_requested();
    }

    pub fn absorb_update_batch(&mut self, update_batch: Vec<DatabaseUpdateEvent>) {
        self.signature_update_session
            .absorb_update_batch(update_batch);
    }

    pub fn update_stream_ended(&mut self) -> UpdateFinishEffects {
        match self.signature_update_session.update_stream_ended() {
            UpdateStreamEnding::NoUpdateWasRunning => UpdateFinishEffects::StaleStreamEnding,
            UpdateStreamEnding::UpdateEnded(finished_report) => {
                UpdateFinishEffects::UpdateFinished(FinishedUpdateEffects {
                    summary_line: finished_report
                        .summary_text
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                    page_outputs: finished_update_outputs(finished_report.definitions_changed),
                    activity_entry: finished_report.activity_entry,
                })
            }
        }
    }
}

const fn is_update_activity(activity_record: &ActivityRecord) -> bool {
    match activity_record {
        ActivityRecord::UpdateActivity { .. } => true,
        ActivityRecord::ScanActivity { .. } | ActivityRecord::SkippedScan { .. } => false,
    }
}

pub fn update_history_entries(
    activity_entries: Vec<ActivityEntryRecord>,
) -> Vec<ActivityEntryRecord> {
    let mut update_entries = activity_entries
        .into_iter()
        .filter(|activity_entry| is_update_activity(&activity_entry.activity_record))
        .collect::<Vec<_>>();
    update_entries.sort_by(|earlier_entry, later_entry| {
        (later_entry.started_at, later_entry.entry_id)
            .cmp(&(earlier_entry.started_at, earlier_entry.entry_id))
    });
    update_entries
}

#[derive(Debug)]
pub enum UpdateHistoryView {
    HistoryLoading,
    HistoryLoaded(Vec<ActivityEntryRecord>),
    HistoryLoadFailed(ActivityHistoryFailure),
}

impl UpdateHistoryView {
    pub fn from_load_outcome(
        load_outcome: Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>,
    ) -> Self {
        match load_outcome {
            Ok(activity_entries) => Self::HistoryLoaded(update_history_entries(activity_entries)),
            Err(load_failure) => Self::HistoryLoadFailed(load_failure),
        }
    }

    pub fn listed_entries(&self) -> &[ActivityEntryRecord] {
        match self {
            Self::HistoryLoaded(listed_entries) => listed_entries,
            Self::HistoryLoading | Self::HistoryLoadFailed(_) => &[],
        }
    }

    pub const fn placeholder_page_name(&self) -> &'static str {
        match self {
            Self::HistoryLoading => LOADING_PAGE_NAME,
            Self::HistoryLoaded(_) => LOADED_PAGE_NAME,
            Self::HistoryLoadFailed(_) => LOAD_FAILED_PAGE_NAME,
        }
    }
}

#[cfg(test)]
mod database_updates_state_tests {
    use std::path::PathBuf;

    use jiff::Timestamp;

    use super::*;
    use crate::host_services::{
        activity_history::activity_history_database::{ScanActivityStatus, UpdateActivityStatus},
        clamav_programs::database_directory_status::FreshclamServiceState,
    };

    fn history_entry(
        entry_id: i64,
        started_seconds: i64,
        activity_record: ActivityRecord,
    ) -> ActivityEntryRecord {
        ActivityEntryRecord {
            entry_id,
            started_at: Timestamp::constant(started_seconds, 0),
            activity_record,
            duration_millis: 1000,
            activity_output: String::new(),
        }
    }

    const fn applied_update() -> ActivityRecord {
        ActivityRecord::UpdateActivity {
            update_status: UpdateActivityStatus::UpdateApplied,
        }
    }

    fn listed_ids(activity_entries: &[ActivityEntryRecord]) -> Vec<i64> {
        activity_entries
            .iter()
            .map(|activity_entry| activity_entry.entry_id)
            .collect()
    }

    #[test]
    fn the_update_history_lists_only_updates_newest_first() {
        let activity_entries = vec![
            history_entry(1, 100, applied_update()),
            history_entry(
                2,
                300,
                ActivityRecord::ScanActivity {
                    scan_targets: vec![PathBuf::from("/tmp")],
                    inspected_file_count: 4,
                    scan_status: ScanActivityStatus::ScanClean,
                },
            ),
            history_entry(
                3,
                200,
                ActivityRecord::UpdateActivity {
                    update_status: UpdateActivityStatus::UpdateFailed,
                },
            ),
            history_entry(
                4,
                400,
                ActivityRecord::SkippedScan {
                    scan_targets: vec![PathBuf::from("/home")],
                },
            ),
            history_entry(5, 200, applied_update()),
        ];
        assert_eq!(
            listed_ids(&update_history_entries(activity_entries)),
            vec![5, 3, 1]
        );
    }

    #[test]
    fn a_failed_history_load_lists_nothing_and_shows_the_failure() {
        let history_view =
            UpdateHistoryView::from_load_outcome(Err(ActivityHistoryFailure::DatabasePathNotUtf8));
        assert!(history_view.listed_entries().is_empty());
        assert_eq!(history_view.placeholder_page_name(), LOAD_FAILED_PAGE_NAME);
    }

    #[test]
    fn an_update_requested_before_the_host_is_known_starts_once_it_is() {
        let mut update_control = SignatureUpdateControl::new();
        assert_eq!(
            update_control.update_requested(),
            UpdateStartDecision::UpdateQueued
        );
        assert_eq!(
            update_control.host_status_loaded(DatabaseHostStatus::installed_with_service(
                FreshclamServiceState::ServiceNotFound
            )),
            UpdateStartDecision::StartUpdateNow(DatabaseUpdatePlan::RunFreshclamDirectly)
        );
        assert_eq!(
            update_control.host_status_loaded(DatabaseHostStatus::installed_with_service(
                FreshclamServiceState::ServiceNotFound
            )),
            UpdateStartDecision::NothingToStart
        );
    }

    #[test]
    fn an_update_requested_while_one_runs_starts_nothing() {
        let mut update_control = SignatureUpdateControl::new();
        update_control.host_status_loaded(DatabaseHostStatus::installed_with_service(
            FreshclamServiceState::ServiceNotFound,
        ));
        update_control.update_started(
            DatabaseUpdatePlan::RunFreshclamDirectly,
            RunningStream::already_stopped(),
        );
        assert_eq!(
            update_control.update_requested(),
            UpdateStartDecision::NothingToStart
        );
    }

    #[test]
    fn a_stale_stream_end_has_no_effects() {
        let mut update_control = SignatureUpdateControl::new();
        assert!(matches!(
            update_control.update_stream_ended(),
            UpdateFinishEffects::StaleStreamEnding
        ));
    }

    #[test]
    fn a_finished_update_requests_an_evidence_refresh_and_is_recorded() {
        let mut update_control = SignatureUpdateControl::new();
        update_control.update_started(
            DatabaseUpdatePlan::RunFreshclamDirectly,
            RunningStream::already_stopped(),
        );
        let UpdateFinishEffects::UpdateFinished(finished_effects) =
            update_control.update_stream_ended()
        else {
            panic!("expected the running update to finish");
        };
        assert_eq!(
            finished_effects.page_outputs,
            vec![DatabaseUpdatesPageOutput::EvidenceRefreshRequested]
        );
        assert!(matches!(
            finished_effects.activity_entry.activity_record,
            ActivityRecord::UpdateActivity { .. }
        ));
        assert!(!finished_effects.summary_line.is_empty());
        assert!(matches!(
            update_control.update_stream_ended(),
            UpdateFinishEffects::StaleStreamEnding
        ));
    }

    #[test]
    fn changed_definitions_also_trigger_the_quarantine_recheck() {
        assert_eq!(
            finished_update_outputs(true),
            vec![
                DatabaseUpdatesPageOutput::SignaturesUpdated,
                DatabaseUpdatesPageOutput::EvidenceRefreshRequested,
            ]
        );
    }
}
