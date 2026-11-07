use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{
    findings::quarantine_page::quarantine_entries_page::entry_matches_search,
    host_services::{
        clamav_scanner::content_verdict::ContentVerdict,
        quarantine_vault::{
            quarantine_entry_database::QuarantineEntryRecord,
            quarantine_file_moves::QuarantineMoveFailure,
        },
        threat_intel::file_reputation_check::ReputationAnswers,
    },
    shared_widgets::{
        component_streams::RunningStream,
        loading_indicators::{LOAD_FAILED_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME},
    },
};

#[derive(Debug)]
pub enum QuarantineListing {
    ListingLoading,
    ListingLoaded(Vec<QuarantineEntryRecord>),
    ListingFailed(QuarantineMoveFailure),
}

impl QuarantineListing {
    pub fn listed_entries(&self) -> &[QuarantineEntryRecord] {
        match self {
            Self::ListingLoaded(listed_entries) => listed_entries,
            Self::ListingLoading | Self::ListingFailed(_) => &[],
        }
    }

    pub const fn placeholder_page_name(&self) -> &'static str {
        match self {
            Self::ListingLoading => LOADING_PAGE_NAME,
            Self::ListingLoaded(_) => LOADED_PAGE_NAME,
            Self::ListingFailed(_) => LOAD_FAILED_PAGE_NAME,
        }
    }

    fn lists_entry(&self, entry_id: i64) -> bool {
        self.listed_entries()
            .iter()
            .any(|listed_entry| listed_entry.entry_id == entry_id)
    }
}

#[derive(Clone, Debug)]
pub enum RowRecheckState {
    NotRechecked,
    Rechecking,
    Rechecked(ContentVerdict),
}

#[derive(Clone, Debug)]
pub enum RowReputation {
    NotChecked,
    CheckingReputation,
    ReputationChecked(ReputationAnswers),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowActivity {
    ActionsAvailable,
    OperationInProgress,
}

#[derive(Clone, Debug)]
pub struct EntryRowState {
    pub recheck_state: RowRecheckState,
    pub row_reputation: RowReputation,
    pub row_activity: RowActivity,
}

#[derive(Clone, Debug)]
pub struct QuarantineRowInit {
    pub entry_record: QuarantineEntryRecord,
    pub row_state: EntryRowState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryOperationKind {
    VerifyingBeforeRestore,
    RestoringEntry,
    DeletingEntry,
}

#[derive(Debug)]
pub enum EntryOperationState {
    OperationRunning(EntryOperationKind),
    OperationFailed(QuarantineMoveFailure),
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum EntryActionRefusal {
    #[error("an operation on quarantine entry {entry_id} is still running")]
    EntryBusy { entry_id: i64 },
    #[error("quarantine entry {entry_id} is not in the current list")]
    EntryNotListed { entry_id: i64 },
    #[error("quarantine entry {entry_id} was not checked before restoring it")]
    RestoreNotVerified { entry_id: i64 },
    #[error("the reputation of quarantine entry {entry_id} is already being checked")]
    ReputationCheckRunning { entry_id: i64 },
    #[error("a re-check of the quarantine is already running")]
    RecheckAlreadyRunning,
    #[error("there are no quarantined files to check")]
    NothingToRecheck,
}

#[derive(Debug)]
pub enum RecheckRun {
    RecheckIdle,
    RecheckRunning {
        rechecked_ids: BTreeSet<i64>,
        _recheck_stream: RunningStream,
    },
}

#[derive(Debug)]
pub struct QuarantinePageState {
    listing: QuarantineListing,
    recheck_states: HashMap<i64, RowRecheckState>,
    row_reputations: HashMap<i64, RowReputation>,
    entry_operations: BTreeMap<i64, EntryOperationState>,
    recheck_run: RecheckRun,
}

impl QuarantinePageState {
    pub fn new() -> Self {
        Self {
            listing: QuarantineListing::ListingLoading,
            recheck_states: HashMap::new(),
            row_reputations: HashMap::new(),
            entry_operations: BTreeMap::new(),
            recheck_run: RecheckRun::RecheckIdle,
        }
    }

    pub const fn listing(&self) -> &QuarantineListing {
        &self.listing
    }

    pub fn listed_entries(&self) -> &[QuarantineEntryRecord] {
        self.listing.listed_entries()
    }

    pub const fn recheck_running(&self) -> bool {
        matches!(self.recheck_run, RecheckRun::RecheckRunning { .. })
    }

    pub fn record_loaded_entries(
        &mut self,
        load_outcome: Result<Vec<QuarantineEntryRecord>, QuarantineMoveFailure>,
    ) {
        self.listing = match load_outcome {
            Ok(listed_entries) => {
                let listed_ids = listed_entries
                    .iter()
                    .map(|listed_entry| listed_entry.entry_id)
                    .collect::<BTreeSet<_>>();
                self.recheck_states
                    .retain(|entry_id, _recheck_state| listed_ids.contains(entry_id));
                self.row_reputations
                    .retain(|entry_id, _row_reputation| listed_ids.contains(entry_id));
                QuarantineListing::ListingLoaded(listed_entries)
            }
            Err(load_failure) => QuarantineListing::ListingFailed(load_failure),
        };
    }

    fn running_operation(&self, entry_id: i64) -> Option<EntryOperationKind> {
        match self.entry_operations.get(&entry_id) {
            Some(EntryOperationState::OperationRunning(running_kind)) => Some(*running_kind),
            Some(EntryOperationState::OperationFailed(_)) | None => None,
        }
    }

    pub fn begin_entry_operation(
        &mut self,
        entry_id: i64,
        operation_kind: EntryOperationKind,
    ) -> Result<(), EntryActionRefusal> {
        if self.running_operation(entry_id).is_some() {
            return Err(EntryActionRefusal::EntryBusy { entry_id });
        }
        if !self.listing.lists_entry(entry_id) {
            return Err(EntryActionRefusal::EntryNotListed { entry_id });
        }
        self.entry_operations.insert(
            entry_id,
            EntryOperationState::OperationRunning(operation_kind),
        );
        if operation_kind == EntryOperationKind::VerifyingBeforeRestore {
            self.recheck_states
                .insert(entry_id, RowRecheckState::Rechecking);
        }
        Ok(())
    }

    pub fn confirm_verified_restore(&mut self, entry_id: i64) -> Result<(), EntryActionRefusal> {
        match self.running_operation(entry_id) {
            Some(EntryOperationKind::VerifyingBeforeRestore) => {
                self.entry_operations.insert(
                    entry_id,
                    EntryOperationState::OperationRunning(EntryOperationKind::RestoringEntry),
                );
                Ok(())
            }
            Some(EntryOperationKind::RestoringEntry | EntryOperationKind::DeletingEntry) => {
                Err(EntryActionRefusal::EntryBusy { entry_id })
            }
            None => Err(EntryActionRefusal::RestoreNotVerified { entry_id }),
        }
    }

    pub fn cancel_verified_restore(&mut self, entry_id: i64) {
        if self.running_operation(entry_id) == Some(EntryOperationKind::VerifyingBeforeRestore) {
            self.entry_operations.remove(&entry_id);
        }
    }

    pub fn finish_entry_operation(
        &mut self,
        entry_id: i64,
        operation_outcome: Result<QuarantineEntryRecord, QuarantineMoveFailure>,
    ) {
        match operation_outcome {
            Ok(_finished_entry) => {
                self.entry_operations.remove(&entry_id);
            }
            Err(operation_failure) => {
                self.entry_operations.insert(
                    entry_id,
                    EntryOperationState::OperationFailed(operation_failure),
                );
            }
        }
    }

    pub fn operations_running(&self) -> bool {
        self.entry_operations.values().any(|operation_state| {
            matches!(operation_state, EntryOperationState::OperationRunning(_))
        })
    }

    pub fn operation_failures(&self) -> impl Iterator<Item = &QuarantineMoveFailure> {
        self.entry_operations
            .values()
            .filter_map(|operation_state| match operation_state {
                EntryOperationState::OperationFailed(operation_failure) => Some(operation_failure),
                EntryOperationState::OperationRunning(_) => None,
            })
    }

    pub fn dismiss_operation_failures(&mut self) {
        self.entry_operations.retain(|_entry_id, operation_state| {
            matches!(operation_state, EntryOperationState::OperationRunning(_))
        });
    }

    pub fn record_recheck_verdict(&mut self, entry_id: i64, content_verdict: ContentVerdict) {
        if self.listing.lists_entry(entry_id) {
            self.recheck_states
                .insert(entry_id, RowRecheckState::Rechecked(content_verdict));
        }
    }

    pub fn start_recheck_run(
        &mut self,
        start_recheck_stream: impl FnOnce(Vec<i64>) -> RunningStream,
    ) -> Result<(), EntryActionRefusal> {
        if self.recheck_running() {
            return Err(EntryActionRefusal::RecheckAlreadyRunning);
        }
        let rechecked_ids = self
            .listed_entries()
            .iter()
            .map(|listed_entry| listed_entry.entry_id)
            .collect::<BTreeSet<_>>();
        if rechecked_ids.is_empty() {
            return Err(EntryActionRefusal::NothingToRecheck);
        }
        rechecked_ids.iter().for_each(|entry_id| {
            self.recheck_states
                .insert(*entry_id, RowRecheckState::Rechecking);
        });
        let recheck_stream = start_recheck_stream(rechecked_ids.iter().copied().collect());
        self.recheck_run = RecheckRun::RecheckRunning {
            rechecked_ids,
            _recheck_stream: recheck_stream,
        };
        Ok(())
    }

    pub fn finish_recheck_run(&mut self) -> usize {
        let finished_run = std::mem::replace(&mut self.recheck_run, RecheckRun::RecheckIdle);
        match finished_run {
            RecheckRun::RecheckIdle => 0,
            RecheckRun::RecheckRunning { rechecked_ids, .. } => rechecked_ids
                .iter()
                .filter(|entry_id| self.listing.lists_entry(**entry_id))
                .filter(|entry_id| {
                    matches!(
                        self.recheck_states.get(entry_id),
                        Some(RowRecheckState::Rechecked(ContentVerdict::NoLongerDetected))
                    )
                })
                .count(),
        }
    }

    pub fn begin_reputation_check(&mut self, entry_id: i64) -> Result<(), EntryActionRefusal> {
        if !self.listing.lists_entry(entry_id) {
            return Err(EntryActionRefusal::EntryNotListed { entry_id });
        }
        if matches!(
            self.row_reputations.get(&entry_id),
            Some(RowReputation::CheckingReputation)
        ) {
            return Err(EntryActionRefusal::ReputationCheckRunning { entry_id });
        }
        self.row_reputations
            .insert(entry_id, RowReputation::CheckingReputation);
        Ok(())
    }

    pub fn record_reputation_answers(
        &mut self,
        entry_id: i64,
        reputation_answers: ReputationAnswers,
    ) {
        if self.listing.lists_entry(entry_id) {
            self.row_reputations.insert(
                entry_id,
                RowReputation::ReputationChecked(reputation_answers),
            );
        }
    }

    pub fn row_state(&self, entry_id: i64) -> EntryRowState {
        EntryRowState {
            recheck_state: self
                .recheck_states
                .get(&entry_id)
                .cloned()
                .unwrap_or(RowRecheckState::NotRechecked),
            row_reputation: self
                .row_reputations
                .get(&entry_id)
                .cloned()
                .unwrap_or(RowReputation::NotChecked),
            row_activity: match self.running_operation(entry_id) {
                Some(_running_kind) => RowActivity::OperationInProgress,
                None => RowActivity::ActionsAvailable,
            },
        }
    }

    pub fn matching_rows(&self, search_text: &str) -> Vec<QuarantineRowInit> {
        self.listed_entries()
            .iter()
            .filter(|entry_record| entry_matches_search(entry_record, search_text))
            .map(|entry_record| QuarantineRowInit {
                entry_record: entry_record.clone(),
                row_state: self.row_state(entry_record.entry_id),
            })
            .collect()
    }
}

#[cfg(test)]
mod quarantine_page_state_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::host_services::{
        clamav_scanner::scanner_output_parser::ThreatIdentity,
        quarantine_vault::{
            quarantine_entry_database::StoredDetectionDate,
            quarantine_file_moves::RecordedPayloadHash,
        },
        threat_intel::file_reputation_check::SourceAnswer,
    };

    fn quarantined_entry(entry_id: i64) -> QuarantineEntryRecord {
        QuarantineEntryRecord {
            entry_id,
            original_path: PathBuf::from(format!("/home/user/Downloads/sample-{entry_id}.exe")),
            quarantine_path: PathBuf::from("/vault/payload"),
            threat_identity: ThreatIdentity::Signature {
                signature_name: "Win.Trojan.Agent".to_owned(),
            },
            detection_date: StoredDetectionDate::from("2026-11-01T00:00:00Z".to_owned()),
            file_size: bytesize::ByteSize::b(1),
            payload_hash: RecordedPayloadHash::IntegrityUnknown,
            original_permissions: 0o644,
        }
    }

    fn state_listing(entry_ids: &[i64]) -> QuarantinePageState {
        let mut page_state = QuarantinePageState::new();
        page_state.record_loaded_entries(Ok(entry_ids
            .iter()
            .copied()
            .map(quarantined_entry)
            .collect()));
        page_state
    }

    fn checked_answers() -> ReputationAnswers {
        ReputationAnswers {
            circl_answer: SourceAnswer::NeedsKey,
            bazaar_answer: SourceAnswer::NeedsKey,
            virustotal_answer: SourceAnswer::Answered {
                verdict_text: "Unknown to VirusTotal".to_owned(),
            },
        }
    }

    fn no_longer_detected_count_after_run(
        page_state: &mut QuarantinePageState,
        verdict_ids: &[i64],
    ) -> usize {
        page_state
            .start_recheck_run(|_rechecked_ids| RunningStream::already_stopped())
            .expect("recheck run starts");
        verdict_ids.iter().for_each(|entry_id| {
            page_state.record_recheck_verdict(*entry_id, ContentVerdict::NoLongerDetected);
        });
        page_state.finish_recheck_run()
    }

    #[test]
    fn a_load_failure_never_shows_the_empty_state() {
        let mut page_state = state_listing(&[1, 2]);
        page_state.record_loaded_entries(Err(QuarantineMoveFailure::DatabaseNotRegularFile));
        assert_eq!(
            page_state.listing().placeholder_page_name(),
            LOAD_FAILED_PAGE_NAME
        );
        assert!(page_state.matching_rows("").is_empty());
    }

    #[test]
    fn a_successful_refresh_clears_a_load_error_but_keeps_an_operation_failure() {
        let mut page_state = state_listing(&[1]);
        page_state
            .begin_entry_operation(1, EntryOperationKind::DeletingEntry)
            .expect("deletion starts");
        page_state.finish_entry_operation(1, Err(QuarantineMoveFailure::EntryRecordNotRemoved));
        page_state.record_loaded_entries(Err(QuarantineMoveFailure::DatabaseNotRegularFile));
        page_state.record_loaded_entries(Ok(vec![quarantined_entry(1)]));
        assert_eq!(
            page_state.listing().placeholder_page_name(),
            LOADED_PAGE_NAME
        );
        assert_eq!(page_state.operation_failures().count(), 1);
    }

    #[test]
    fn a_later_success_on_another_entry_keeps_the_earlier_failure() {
        let mut page_state = state_listing(&[1, 2]);
        page_state
            .begin_entry_operation(1, EntryOperationKind::DeletingEntry)
            .expect("first deletion starts");
        page_state.finish_entry_operation(1, Err(QuarantineMoveFailure::FileHashMismatch));
        page_state
            .begin_entry_operation(2, EntryOperationKind::DeletingEntry)
            .expect("second deletion starts");
        page_state.finish_entry_operation(2, Ok(quarantined_entry(2)));
        assert_eq!(page_state.operation_failures().count(), 1);
        page_state.dismiss_operation_failures();
        assert_eq!(page_state.operation_failures().count(), 0);
    }

    #[test]
    fn a_new_operation_on_the_entry_replaces_its_recorded_failure() {
        let mut page_state = state_listing(&[1]);
        page_state
            .begin_entry_operation(1, EntryOperationKind::DeletingEntry)
            .expect("first deletion starts");
        page_state.finish_entry_operation(1, Err(QuarantineMoveFailure::FileHashMismatch));
        page_state
            .begin_entry_operation(1, EntryOperationKind::DeletingEntry)
            .expect("retry starts");
        assert_eq!(page_state.operation_failures().count(), 0);
    }

    #[test]
    fn a_second_operation_on_a_busy_entry_is_refused() {
        let mut page_state = state_listing(&[1]);
        page_state
            .begin_entry_operation(1, EntryOperationKind::VerifyingBeforeRestore)
            .expect("restore check starts");
        assert_eq!(
            page_state.begin_entry_operation(1, EntryOperationKind::DeletingEntry),
            Err(EntryActionRefusal::EntryBusy { entry_id: 1 })
        );
        page_state
            .confirm_verified_restore(1)
            .expect("restore confirmed");
        assert_eq!(
            page_state.begin_entry_operation(1, EntryOperationKind::VerifyingBeforeRestore),
            Err(EntryActionRefusal::EntryBusy { entry_id: 1 })
        );
        assert_eq!(
            page_state.row_state(1).row_activity,
            RowActivity::OperationInProgress
        );
    }

    #[test]
    fn a_restore_needs_a_finished_check_first() {
        let mut page_state = state_listing(&[1]);
        assert_eq!(
            page_state.confirm_verified_restore(1),
            Err(EntryActionRefusal::RestoreNotVerified { entry_id: 1 })
        );
        page_state
            .begin_entry_operation(1, EntryOperationKind::VerifyingBeforeRestore)
            .expect("restore check starts");
        page_state.cancel_verified_restore(1);
        assert_eq!(
            page_state.row_state(1).row_activity,
            RowActivity::ActionsAvailable
        );
    }

    #[test]
    fn recheck_counting_ignores_entries_that_are_gone_or_from_earlier_runs() {
        let mut page_state = state_listing(&[1, 2, 3]);
        assert_eq!(
            no_longer_detected_count_after_run(&mut page_state, &[1, 2, 3]),
            3
        );
        page_state.record_loaded_entries(Ok(vec![quarantined_entry(1), quarantined_entry(4)]));
        page_state
            .begin_entry_operation(4, EntryOperationKind::VerifyingBeforeRestore)
            .expect("restore check starts");
        page_state.record_recheck_verdict(4, ContentVerdict::NoLongerDetected);
        page_state.record_recheck_verdict(2, ContentVerdict::NoLongerDetected);
        page_state
            .start_recheck_run(|_rechecked_ids| RunningStream::already_stopped())
            .expect("second run starts");
        page_state.record_recheck_verdict(
            1,
            ContentVerdict::StillDetected {
                detection_name: "Win.Trojan.Agent".to_owned(),
            },
        );
        page_state.record_loaded_entries(Ok(vec![quarantined_entry(1)]));
        assert_eq!(page_state.finish_recheck_run(), 0);
    }

    #[test]
    fn row_reputation_survives_a_search_refresh() {
        let mut page_state = state_listing(&[1, 2]);
        page_state
            .begin_reputation_check(1)
            .expect("reputation check starts");
        assert_eq!(
            page_state.begin_reputation_check(1),
            Err(EntryActionRefusal::ReputationCheckRunning { entry_id: 1 })
        );
        page_state.record_reputation_answers(1, checked_answers());
        assert!(page_state.matching_rows("sample-2").len() == 1);
        page_state.record_loaded_entries(Ok(vec![quarantined_entry(1), quarantined_entry(2)]));
        let shown_rows = page_state.matching_rows("sample-1");
        assert!(matches!(
            shown_rows.as_slice(),
            [QuarantineRowInit {
                row_state: EntryRowState {
                    row_reputation: RowReputation::ReputationChecked(reputation_answers),
                    ..
                },
                ..
            }] if reputation_answers.virustotal_answer.displayed_text() == "Unknown to VirusTotal"
                && reputation_answers.circl_answer.needs_key()
        ));
    }

    #[test]
    fn reputation_of_removed_entries_is_pruned_on_load() {
        let mut page_state = state_listing(&[1]);
        page_state.record_reputation_answers(1, checked_answers());
        page_state.record_loaded_entries(Ok(Vec::new()));
        page_state.record_loaded_entries(Ok(vec![quarantined_entry(1)]));
        assert!(matches!(
            page_state.row_state(1).row_reputation,
            RowReputation::NotChecked
        ));
    }
}
