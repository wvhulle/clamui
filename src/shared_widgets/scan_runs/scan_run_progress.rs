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
    shared_widgets::{
        component_streams::RunningStream, scan_runs::scan_progress_view::ScanProgressView,
    },
};

const DISPLAY_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

pub static PREPARING_SCAN_VIEW: ScanProgressView = ScanProgressView::PreparingScan;

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

    pub fn belongs_to_run(&self, scan_run_number: ScanRunNumber) -> bool {
        self.scan_run.scan_run_number == scan_run_number
    }

    pub const fn scan_progress_view(&self) -> &ScanProgressView {
        &self.live_progress.scan_progress_view
    }

    pub fn accepts_cancel(&self) -> bool {
        self.cancel_request == CancelRequest::CancelNotRequested
    }

    pub fn request_cancel(&mut self) {
        if self.accepts_cancel() {
            self.scan_stream.stop();
            self.cancel_request = CancelRequest::CancelRequested;
        }
    }

    pub fn finished_at(self, finished_instant: Instant) -> FinishedScan {
        let elapsed_time =
            finished_instant.saturating_duration_since(self.scan_run.started_instant);
        let scan_ending = match self.cancel_request {
            CancelRequest::CancelNotRequested => ScanEnding::ScanCompleted,
            CancelRequest::CancelRequested => ScanEnding::ScanCancelled,
        };
        FinishedScan {
            scan_run: self.scan_run,
            scan_ending,
            elapsed_time,
        }
    }

    pub fn absorb_progress_batch(
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

pub enum ScanStreamEnding<'finished> {
    StaleStreamIgnored,
    ScanRunFinished(&'finished FinishedScan),
}

#[cfg(test)]
pub mod scan_run_fixtures {
    use super::*;
    use crate::host_services::clamav_scanner::scanner_output_parser::ThreatIdentity;

    pub fn running_scan_of(
        scan_run_number: ScanRunNumber,
        scan_target: PathBuf,
        started_instant: Instant,
    ) -> RunningScan {
        RunningScan::started(
            ScanRun::starting(
                scan_run_number,
                vec![scan_target],
                Timestamp::UNIX_EPOCH,
                started_instant,
            ),
            RunningStream::already_stopped(),
            LiveProgress::starting(CurrentFileDisplay::ShowCurrentFile, started_instant),
            TemporaryScanTarget::NoTemporaryTarget,
        )
    }

    pub fn threat_batch_in(scanned_folder: &str) -> Vec<ScanProgressEvent> {
        let threat_path = PathBuf::from(scanned_folder).join("eicar.txt");
        vec![
            ScanProgressEvent::TargetEnumerated {
                planned_file_count: 4,
                planned_directory_count: 1,
                excluded_entry_count: 0,
            },
            ScanProgressEvent::FileInspected {
                file_path: threat_path.clone(),
            },
            ScanProgressEvent::ThreatDetected(DetectedThreat {
                file_path: threat_path,
                threat_identity: ThreatIdentity::Signature {
                    signature_name: String::from("Eicar-Signature"),
                },
            }),
        ]
    }
}
