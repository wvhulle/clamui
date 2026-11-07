use std::time::Instant;

use crate::{
    host_services::clamav_scanner::{
        scan_progress_events::ScanProgressEvent, scanner_output_parser::DetectedThreat,
    },
    shared_widgets::scan_runs::{
        scan_progress_view::ScanProgressView,
        scan_run_progress::{
            FinishedScan, PREPARING_SCAN_VIEW, RunningScan, ScanRunNumber, ScanStreamEnding,
        },
    },
};

pub struct ScanStartPermit(());

pub enum ScanStartPermission {
    ScanMayStart(ScanStartPermit),
    ScanAlreadyActive,
}

pub enum ScanPageState {
    WaitingForTargets,
    WritingEicarFile,
    ScanRunning(RunningScan),
    ScanFinished(FinishedScan),
}

impl ScanPageState {
    pub fn new_scan_permission(&self) -> ScanStartPermission {
        match self {
            Self::WaitingForTargets | Self::ScanFinished(_) => {
                ScanStartPermission::ScanMayStart(ScanStartPermit(()))
            }
            Self::WritingEicarFile | Self::ScanRunning(_) => ScanStartPermission::ScanAlreadyActive,
        }
    }

    pub fn written_eicar_file_permission(&self) -> ScanStartPermission {
        match self {
            Self::WritingEicarFile => ScanStartPermission::ScanMayStart(ScanStartPermit(())),
            Self::WaitingForTargets | Self::ScanRunning(_) | Self::ScanFinished(_) => {
                ScanStartPermission::ScanAlreadyActive
            }
        }
    }

    pub fn begin_writing_eicar_file(&mut self, _start_permit: ScanStartPermit) {
        *self = Self::WritingEicarFile;
    }

    pub fn abandon_scan_start(&mut self, _start_permit: ScanStartPermit) {
        *self = Self::WaitingForTargets;
    }

    pub fn begin_scan_run(&mut self, _start_permit: ScanStartPermit, running_scan: RunningScan) {
        *self = Self::ScanRunning(running_scan);
    }

    pub fn return_to_targets(&mut self) {
        if let Self::ScanFinished(_) = self {
            *self = Self::WaitingForTargets;
        }
    }

    pub fn request_cancel(&mut self) {
        if let Self::ScanRunning(running_scan) = self {
            running_scan.request_cancel();
        }
    }

    pub fn absorb_progress_batch(
        &mut self,
        scan_run_number: ScanRunNumber,
        progress_batch: Vec<ScanProgressEvent>,
        refreshed_at: Instant,
    ) -> Vec<DetectedThreat> {
        match self {
            Self::ScanRunning(running_scan) if running_scan.belongs_to_run(scan_run_number) => {
                running_scan.absorb_progress_batch(progress_batch, refreshed_at)
            }
            _stale_or_idle_state => Vec::new(),
        }
    }

    pub fn finish_scan_stream(
        &mut self,
        scan_run_number: ScanRunNumber,
        finished_instant: Instant,
    ) -> ScanStreamEnding<'_> {
        let running_scan = match std::mem::replace(self, Self::WaitingForTargets) {
            Self::ScanRunning(running_scan) if running_scan.belongs_to_run(scan_run_number) => {
                running_scan
            }
            unchanged_state => {
                *self = unchanged_state;
                return ScanStreamEnding::StaleStreamIgnored;
            }
        };
        *self = Self::ScanFinished(running_scan.finished_at(finished_instant));
        match self {
            Self::ScanFinished(finished_scan) => ScanStreamEnding::ScanRunFinished(finished_scan),
            Self::WaitingForTargets | Self::WritingEicarFile | Self::ScanRunning(_) => {
                ScanStreamEnding::StaleStreamIgnored
            }
        }
    }

    pub fn scan_is_active(&self) -> bool {
        matches!(self, Self::WritingEicarFile | Self::ScanRunning(_))
    }

    pub fn shows_results(&self) -> bool {
        matches!(self, Self::ScanFinished(_))
    }

    pub fn shows_scan_settings(&self) -> bool {
        matches!(self, Self::WaitingForTargets)
    }

    pub fn accepts_cancel(&self) -> bool {
        matches!(self, Self::ScanRunning(running_scan) if running_scan.accepts_cancel())
    }

    pub fn scan_progress_view(&self) -> &ScanProgressView {
        match self {
            Self::ScanRunning(running_scan) => running_scan.scan_progress_view(),
            Self::WaitingForTargets | Self::WritingEicarFile | Self::ScanFinished(_) => {
                &PREPARING_SCAN_VIEW
            }
        }
    }
}

#[cfg(test)]
mod scan_page_state_tests {
    use std::{path::PathBuf, time::Duration};

    use super::*;
    use crate::{
        host_services::clamav_scanner::scan_progress_events::{
            CompletedScanOutcome, ThreatFindings,
        },
        shared_widgets::scan_runs::scan_run_progress::{
            ScanEnding, ScanRun,
            scan_run_fixtures::{running_scan_of, threat_batch_in},
        },
    };

    fn running_state(scan_run_number: ScanRunNumber, started_instant: Instant) -> ScanPageState {
        ScanPageState::ScanRunning(running_scan_of(
            scan_run_number,
            PathBuf::from("/home/someone/Downloads"),
            started_instant,
        ))
    }

    fn threat_batch() -> Vec<ScanProgressEvent> {
        threat_batch_in("/home/someone/Downloads")
    }

    fn running_outcome(scan_page_state: &ScanPageState) -> &CompletedScanOutcome {
        match scan_page_state {
            ScanPageState::ScanRunning(running_scan) => &running_scan.scan_run.scan_outcome,
            ScanPageState::WaitingForTargets
            | ScanPageState::WritingEicarFile
            | ScanPageState::ScanFinished(_) => panic!("the scan should still be running"),
        }
    }

    #[test]
    fn a_stale_progress_batch_changes_nothing() {
        let started_instant = Instant::now();
        let first_run = ScanRunNumber::FIRST_RUN;
        let second_run = first_run.following_run();
        let mut scan_page_state = running_state(second_run, started_instant);
        let found_threats =
            scan_page_state.absorb_progress_batch(first_run, threat_batch(), started_instant);
        assert!(found_threats.is_empty());
        let unchanged_outcome = running_outcome(&scan_page_state);
        assert_eq!(unchanged_outcome.inspected_file_count, 0);
        assert_eq!(
            unchanged_outcome.threat_findings,
            ThreatFindings::NoThreatsFound
        );
        assert_eq!(
            scan_page_state.scan_progress_view(),
            &ScanProgressView::PreparingScan
        );
    }

    #[test]
    fn a_current_progress_batch_reaches_the_running_scan() {
        let started_instant = Instant::now();
        let current_run = ScanRunNumber::FIRST_RUN;
        let mut scan_page_state = running_state(current_run, started_instant);
        let found_threats =
            scan_page_state.absorb_progress_batch(current_run, threat_batch(), started_instant);
        assert_eq!(found_threats.len(), 1);
        assert_eq!(running_outcome(&scan_page_state).planned_file_count, 4);
        assert!(matches!(
            scan_page_state.scan_progress_view(),
            ScanProgressView::ScanningFiles {
                planned_file_count: 4,
                ..
            }
        ));
    }

    #[test]
    fn a_stale_finish_leaves_the_running_scan_alone() {
        let started_instant = Instant::now();
        let first_run = ScanRunNumber::FIRST_RUN;
        let second_run = first_run.following_run();
        let mut scan_page_state = running_state(second_run, started_instant);
        assert!(matches!(
            scan_page_state.finish_scan_stream(first_run, started_instant),
            ScanStreamEnding::StaleStreamIgnored
        ));
        assert!(matches!(
            scan_page_state,
            ScanPageState::ScanRunning(RunningScan {
                scan_run: ScanRun {
                    scan_run_number,
                    ..
                },
                ..
            }) if scan_run_number == second_run
        ));
    }

    #[test]
    fn a_finish_without_a_running_scan_changes_nothing() {
        let mut scan_page_state = ScanPageState::WaitingForTargets;
        assert!(matches!(
            scan_page_state.finish_scan_stream(ScanRunNumber::FIRST_RUN, Instant::now()),
            ScanStreamEnding::StaleStreamIgnored
        ));
        assert!(scan_page_state.shows_scan_settings());
    }

    #[test]
    fn a_finished_scan_records_exactly_once() {
        let started_instant = Instant::now();
        let current_run = ScanRunNumber::FIRST_RUN;
        let mut scan_page_state = running_state(current_run, started_instant);
        let finished_instant = started_instant + Duration::from_secs(3);
        assert!(matches!(
            scan_page_state.finish_scan_stream(current_run, finished_instant),
            ScanStreamEnding::ScanRunFinished(FinishedScan {
                scan_ending: ScanEnding::ScanCompleted,
                elapsed_time,
                ..
            }) if *elapsed_time == Duration::from_secs(3)
        ));
        assert!(matches!(
            scan_page_state.finish_scan_stream(current_run, finished_instant),
            ScanStreamEnding::StaleStreamIgnored
        ));
        assert!(scan_page_state.shows_results());
    }

    #[test]
    fn a_cancelled_scan_finishes_as_cancelled() {
        let started_instant = Instant::now();
        let current_run = ScanRunNumber::FIRST_RUN;
        let mut scan_page_state = running_state(current_run, started_instant);
        scan_page_state.request_cancel();
        assert!(!scan_page_state.accepts_cancel());
        assert!(matches!(
            scan_page_state.finish_scan_stream(current_run, started_instant),
            ScanStreamEnding::ScanRunFinished(FinishedScan {
                scan_ending: ScanEnding::ScanCancelled,
                ..
            })
        ));
    }

    #[test]
    fn an_eicar_file_written_during_another_scan_starts_nothing() {
        let current_run = ScanRunNumber::FIRST_RUN;
        let scan_page_state = running_state(current_run, Instant::now());
        assert!(matches!(
            scan_page_state.written_eicar_file_permission(),
            ScanStartPermission::ScanAlreadyActive
        ));
        assert!(matches!(
            scan_page_state.new_scan_permission(),
            ScanStartPermission::ScanAlreadyActive
        ));
    }

    #[test]
    fn no_other_scan_starts_while_the_eicar_file_is_written() {
        let mut scan_page_state = ScanPageState::WaitingForTargets;
        let ScanStartPermission::ScanMayStart(start_permit) = scan_page_state.new_scan_permission()
        else {
            panic!("an idle page should allow a scan");
        };
        scan_page_state.begin_writing_eicar_file(start_permit);
        assert!(matches!(
            scan_page_state.new_scan_permission(),
            ScanStartPermission::ScanAlreadyActive
        ));
        assert!(matches!(
            scan_page_state.written_eicar_file_permission(),
            ScanStartPermission::ScanMayStart(_)
        ));
    }

    #[test]
    fn an_eicar_file_nobody_waits_for_starts_nothing() {
        assert!(matches!(
            ScanPageState::WaitingForTargets.written_eicar_file_permission(),
            ScanStartPermission::ScanAlreadyActive
        ));
    }

    #[test]
    fn only_finished_scans_return_to_targets() {
        let current_run = ScanRunNumber::FIRST_RUN;
        let mut scan_page_state = running_state(current_run, Instant::now());
        scan_page_state.return_to_targets();
        assert!(scan_page_state.scan_is_active());
    }
}
