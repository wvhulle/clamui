use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use jiff::Timestamp;
use tempfile::NamedTempFile;

use crate::{
    host_services::clamav_scanner::{
        scan_progress_estimates::RefreshThrottle,
        scan_progress_events::{CompletedScanOutcome, ScanProgressEvent},
        scan_target_enumeration::EnumerationProgress,
        scanner_output_parser::{DetectedThreat, sanitize_scanner_line},
    },
    scans::manual_scan_page::scan_progress_view::ScanProgressView,
    shared_widgets::component_streams::RunningStream,
};

const DISPLAY_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

static PREPARING_SCAN_VIEW: ScanProgressView = ScanProgressView::PreparingScan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanRunNumber(u64);

impl ScanRunNumber {
    pub const FIRST_RUN: Self = Self(0);

    pub fn following_run(self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanEnding {
    ScanCompleted,
    ScanCancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelRequest {
    CancelNotRequested,
    CancelRequested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentFileDisplay {
    ShowCurrentFile,
    HideCurrentFile,
}

pub enum TemporaryScanTarget {
    NoTemporaryTarget,
    EicarTestFile { _eicar_file_kept: NamedTempFile },
}

pub struct ScanRun {
    pub scan_run_number: ScanRunNumber,
    pub started_at: Timestamp,
    pub started_instant: Instant,
    pub scan_targets: Vec<PathBuf>,
    pub scan_outcome: CompletedScanOutcome,
}

impl ScanRun {
    pub fn starting(
        scan_run_number: ScanRunNumber,
        scan_targets: Vec<PathBuf>,
        started_at: Timestamp,
        started_instant: Instant,
    ) -> Self {
        Self {
            scan_run_number,
            started_at,
            started_instant,
            scan_targets,
            scan_outcome: CompletedScanOutcome::default(),
        }
    }
}

pub struct LiveProgress {
    current_file_display: CurrentFileDisplay,
    current_file_label: String,
    scan_progress_view: ScanProgressView,
    display_throttle: RefreshThrottle,
}

impl LiveProgress {
    pub fn starting(current_file_display: CurrentFileDisplay, started_instant: Instant) -> Self {
        Self {
            current_file_display,
            current_file_label: String::new(),
            scan_progress_view: ScanProgressView::PreparingScan,
            display_throttle: RefreshThrottle::starting_at(
                DISPLAY_REFRESH_INTERVAL,
                started_instant,
            ),
        }
    }

    fn show_scanning_progress(&mut self, scan_run: &ScanRun, refreshed_at: Instant) {
        self.scan_progress_view = ScanProgressView::ScanningFiles {
            inspected_file_count: scan_run.scan_outcome.inspected_file_count,
            planned_file_count: scan_run.scan_outcome.planned_file_count,
            elapsed_time: refreshed_at.saturating_duration_since(scan_run.started_instant),
            current_file_text: match self.current_file_display {
                CurrentFileDisplay::ShowCurrentFile => self.current_file_label.clone(),
                CurrentFileDisplay::HideCurrentFile => String::new(),
            },
        };
    }
}

pub struct RunningScan {
    pub scan_run: ScanRun,
    pub live_progress: LiveProgress,
    pub cancel_request: CancelRequest,
    scan_stream: RunningStream,
    _temporary_scan_target: TemporaryScanTarget,
}

impl RunningScan {
    pub fn started(
        scan_run: ScanRun,
        scan_stream: RunningStream,
        live_progress: LiveProgress,
        temporary_scan_target: TemporaryScanTarget,
    ) -> Self {
        Self {
            scan_run,
            live_progress,
            cancel_request: CancelRequest::CancelNotRequested,
            scan_stream,
            _temporary_scan_target: temporary_scan_target,
        }
    }

    fn absorb_progress_batch(
        &mut self,
        progress_batch: Vec<ScanProgressEvent>,
        refreshed_at: Instant,
    ) -> Vec<DetectedThreat> {
        let mut batch_phase_change = BatchPhaseChange::PhaseUnchanged;
        let mut newly_found_threats = Vec::new();
        progress_batch.into_iter().for_each(|progress_event| {
            match &progress_event {
                ScanProgressEvent::EnumerationProgressed(enumeration_progress) => {
                    batch_phase_change =
                        BatchPhaseChange::EnumerationReported(enumeration_progress.clone());
                }
                ScanProgressEvent::TargetEnumerated { .. } => {
                    batch_phase_change = BatchPhaseChange::TargetEnumerated;
                }
                ScanProgressEvent::ThreatDetected(detected_threat) => {
                    newly_found_threats.push(detected_threat.clone());
                }
                ScanProgressEvent::FileInspected { file_path } => {
                    self.live_progress.current_file_label =
                        sanitize_scanner_line(&file_path.to_string_lossy());
                }
                _other_event => {}
            }
            self.scan_run
                .scan_outcome
                .absorb_progress_event(progress_event);
        });
        match batch_phase_change {
            BatchPhaseChange::EnumerationReported(enumeration_progress) => {
                self.live_progress.scan_progress_view =
                    ScanProgressView::finding_files(&enumeration_progress);
            }
            BatchPhaseChange::TargetEnumerated => {
                self.live_progress
                    .show_scanning_progress(&self.scan_run, refreshed_at);
            }
            BatchPhaseChange::PhaseUnchanged => {
                if matches!(
                    self.live_progress.scan_progress_view,
                    ScanProgressView::ScanningFiles { .. }
                ) && self
                    .live_progress
                    .display_throttle
                    .allows_refresh(refreshed_at)
                {
                    self.live_progress
                        .show_scanning_progress(&self.scan_run, refreshed_at);
                }
            }
        }
        newly_found_threats
    }
}

enum BatchPhaseChange {
    PhaseUnchanged,
    EnumerationReported(EnumerationProgress),
    TargetEnumerated,
}

pub struct FinishedScan {
    pub scan_run: ScanRun,
    pub scan_ending: ScanEnding,
    pub elapsed_time: Duration,
}

pub struct ScanStartPermit(());

pub enum ScanStartPermission {
    ScanMayStart(ScanStartPermit),
    ScanAlreadyActive,
}

pub enum ScanStreamEnding<'finished> {
    StaleStreamIgnored,
    ScanRunFinished(&'finished FinishedScan),
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
        if let Self::ScanRunning(running_scan) = self
            && running_scan.cancel_request == CancelRequest::CancelNotRequested
        {
            running_scan.scan_stream.stop();
            running_scan.cancel_request = CancelRequest::CancelRequested;
        }
    }

    pub fn absorb_progress_batch(
        &mut self,
        scan_run_number: ScanRunNumber,
        progress_batch: Vec<ScanProgressEvent>,
        refreshed_at: Instant,
    ) -> Vec<DetectedThreat> {
        match self {
            Self::ScanRunning(running_scan)
                if running_scan.scan_run.scan_run_number == scan_run_number =>
            {
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
            Self::ScanRunning(running_scan)
                if running_scan.scan_run.scan_run_number == scan_run_number =>
            {
                running_scan
            }
            unchanged_state => {
                *self = unchanged_state;
                return ScanStreamEnding::StaleStreamIgnored;
            }
        };
        let elapsed_time =
            finished_instant.saturating_duration_since(running_scan.scan_run.started_instant);
        let scan_ending = match running_scan.cancel_request {
            CancelRequest::CancelNotRequested => ScanEnding::ScanCompleted,
            CancelRequest::CancelRequested => ScanEnding::ScanCancelled,
        };
        *self = Self::ScanFinished(FinishedScan {
            scan_run: running_scan.scan_run,
            scan_ending,
            elapsed_time,
        });
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
        matches!(
            self,
            Self::ScanRunning(RunningScan {
                cancel_request: CancelRequest::CancelNotRequested,
                ..
            })
        )
    }

    pub fn scan_progress_view(&self) -> &ScanProgressView {
        match self {
            Self::ScanRunning(running_scan) => &running_scan.live_progress.scan_progress_view,
            Self::WaitingForTargets | Self::WritingEicarFile | Self::ScanFinished(_) => {
                &PREPARING_SCAN_VIEW
            }
        }
    }
}

#[cfg(test)]
mod scan_page_state_tests {
    use super::*;
    use crate::host_services::clamav_scanner::{
        scan_progress_events::ThreatFindings, scanner_output_parser::ThreatIdentity,
    };

    fn running_state(scan_run_number: ScanRunNumber, started_instant: Instant) -> ScanPageState {
        ScanPageState::ScanRunning(RunningScan::started(
            ScanRun::starting(
                scan_run_number,
                vec![PathBuf::from("/home/someone/Downloads")],
                Timestamp::UNIX_EPOCH,
                started_instant,
            ),
            RunningStream::already_stopped(),
            LiveProgress::starting(CurrentFileDisplay::ShowCurrentFile, started_instant),
            TemporaryScanTarget::NoTemporaryTarget,
        ))
    }

    fn threat_batch() -> Vec<ScanProgressEvent> {
        vec![
            ScanProgressEvent::TargetEnumerated {
                planned_file_count: 4,
                planned_directory_count: 1,
                excluded_entry_count: 0,
            },
            ScanProgressEvent::FileInspected {
                file_path: PathBuf::from("/home/someone/Downloads/eicar.txt"),
            },
            ScanProgressEvent::ThreatDetected(DetectedThreat {
                file_path: PathBuf::from("/home/someone/Downloads/eicar.txt"),
                threat_identity: ThreatIdentity::Signature {
                    signature_name: String::from("Eicar-Signature"),
                },
            }),
        ]
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
