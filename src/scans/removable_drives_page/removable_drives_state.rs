use std::{path::PathBuf, time::Instant};

use jiff::Timestamp;

use crate::{
    host_services::clamav_scanner::{
        scan_progress_events::ScanProgressEvent, scanner_output_parser::DetectedThreat,
    },
    scans::removable_drives_page::drive_mount_checks::{
        DeviceAutoScanSettings, DriveScanDecision, DriveSkipReason,
    },
    shared_widgets::scan_runs::{
        scan_progress_view::ScanProgressView,
        scan_results_section::scan_results_state::ScanResultsStatus,
        scan_run_progress::{FinishedScan, PREPARING_SCAN_VIEW, RunningScan, ScanRunNumber},
        scan_run_start::finished_results_status,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriveEventNumber(u64);

impl DriveEventNumber {
    pub const FIRST_EVENT: Self = Self(0);

    const fn following_event(self) -> Self {
        Self(self.0 + 1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriveEvent {
    pub drive_event_number: DriveEventNumber,
    pub drive_name: String,
    pub mount_path: PathBuf,
    pub seen_at: Timestamp,
    pub drive_decision: DriveScanDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriveEventLog {
    newest_first_events: Vec<DriveEvent>,
    next_event_number: DriveEventNumber,
}

impl DriveEventLog {
    pub const fn empty_session() -> Self {
        Self {
            newest_first_events: Vec::new(),
            next_event_number: DriveEventNumber::FIRST_EVENT,
        }
    }

    pub fn record_seen_drive(
        &mut self,
        drive_name: String,
        mount_path: PathBuf,
        seen_at: Timestamp,
        drive_decision: DriveScanDecision,
    ) -> DriveEventNumber {
        let drive_event_number = self.next_event_number;
        self.next_event_number = drive_event_number.following_event();
        self.newest_first_events.insert(
            0,
            DriveEvent {
                drive_event_number,
                drive_name,
                mount_path,
                seen_at,
                drive_decision,
            },
        );
        drive_event_number
    }

    pub fn decide_drive(
        &mut self,
        drive_event_number: DriveEventNumber,
        drive_decision: DriveScanDecision,
    ) {
        self.newest_first_events
            .iter_mut()
            .filter(|drive_event| drive_event.drive_event_number == drive_event_number)
            .for_each(|drive_event| drive_event.drive_decision = drive_decision);
    }

    pub fn newest_first_events(&self) -> &[DriveEvent] {
        &self.newest_first_events
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriveScanTarget {
    pub drive_event_number: DriveEventNumber,
    pub drive_name: String,
    pub mount_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanSlotRequest {
    NoSlotRequested,
    SlotRequested(DriveScanTarget),
}

pub enum DeviceScanState {
    NoDeviceScan,
    DeviceScanRunning {
        scan_target: DriveScanTarget,
        running_scan: RunningScan,
    },
    DeviceScanFinished {
        scan_target: DriveScanTarget,
        finished_scan: FinishedScan,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadyDriveOutcome {
    ScanSlotNeeded { drive_name: String },
    SkippedWhileBusy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantedSlotUse {
    ScanGrantedDrive(DriveScanTarget),
    ReleaseUnusedSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WithdrawnDrive {
    NoDriveWithdrawn,
    DriveWithdrawn(DriveEventNumber),
}

pub struct FinishedDeviceScan<'finished> {
    pub scan_target: &'finished DriveScanTarget,
    pub finished_scan: &'finished FinishedScan,
}

pub enum DeviceScanEnding<'finished> {
    StaleDeviceStreamIgnored,
    DeviceScanFinished(FinishedDeviceScan<'finished>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceScanStatus {
    NoDeviceScanYet,
    DeviceScanRunning {
        drive_name: String,
    },
    DeviceScanEnded {
        drive_name: String,
        scan_result: ScanResultsStatus,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemovableDrivesStatus {
    pub auto_scan_settings: DeviceAutoScanSettings,
    pub device_scan_status: DeviceScanStatus,
}

#[derive(Debug)]
pub enum RemovableDrivesPageOutput {
    ScanSlotRequested { drive_name: String },
    DeviceScanEnded,
    StatusChanged(RemovableDrivesStatus),
    QuarantineEntriesChanged,
    ActivityRecorded,
}

pub struct DeviceScanFlow {
    slot_request: ScanSlotRequest,
    device_scan_state: DeviceScanState,
}

impl DeviceScanFlow {
    pub const fn idle_flow() -> Self {
        Self {
            slot_request: ScanSlotRequest::NoSlotRequested,
            device_scan_state: DeviceScanState::NoDeviceScan,
        }
    }

    const fn holds_or_awaits_scan_slot(&self) -> bool {
        matches!(self.slot_request, ScanSlotRequest::SlotRequested(_))
            || matches!(
                self.device_scan_state,
                DeviceScanState::DeviceScanRunning { .. }
            )
    }

    pub fn drive_ready_to_scan(&mut self, scan_target: DriveScanTarget) -> ReadyDriveOutcome {
        if self.holds_or_awaits_scan_slot() {
            return ReadyDriveOutcome::SkippedWhileBusy;
        }
        let drive_name = scan_target.drive_name.clone();
        self.slot_request = ScanSlotRequest::SlotRequested(scan_target);
        ReadyDriveOutcome::ScanSlotNeeded { drive_name }
    }

    pub fn scan_slot_granted(&mut self) -> GrantedSlotUse {
        match std::mem::replace(&mut self.slot_request, ScanSlotRequest::NoSlotRequested) {
            ScanSlotRequest::SlotRequested(scan_target) => {
                GrantedSlotUse::ScanGrantedDrive(scan_target)
            }
            ScanSlotRequest::NoSlotRequested => GrantedSlotUse::ReleaseUnusedSlot,
        }
    }

    pub fn begin_device_scan(&mut self, scan_target: DriveScanTarget, running_scan: RunningScan) {
        self.device_scan_state = DeviceScanState::DeviceScanRunning {
            scan_target,
            running_scan,
        };
    }

    pub fn scan_slot_refused(&mut self) -> WithdrawnDrive {
        match std::mem::replace(&mut self.slot_request, ScanSlotRequest::NoSlotRequested) {
            ScanSlotRequest::SlotRequested(scan_target) => {
                WithdrawnDrive::DriveWithdrawn(scan_target.drive_event_number)
            }
            ScanSlotRequest::NoSlotRequested => WithdrawnDrive::NoDriveWithdrawn,
        }
    }

    pub fn scan_slot_revoked(&mut self) -> WithdrawnDrive {
        match std::mem::replace(&mut self.device_scan_state, DeviceScanState::NoDeviceScan) {
            DeviceScanState::DeviceScanRunning { scan_target, .. } => {
                WithdrawnDrive::DriveWithdrawn(scan_target.drive_event_number)
            }
            unchanged_state @ (DeviceScanState::NoDeviceScan
            | DeviceScanState::DeviceScanFinished { .. }) => {
                self.device_scan_state = unchanged_state;
                WithdrawnDrive::NoDriveWithdrawn
            }
        }
    }

    pub fn request_cancel(&mut self) {
        if let DeviceScanState::DeviceScanRunning { running_scan, .. } = &mut self.device_scan_state
        {
            running_scan.request_cancel();
        }
    }

    pub fn dismiss_results(&mut self) {
        if let DeviceScanState::DeviceScanFinished { .. } = self.device_scan_state {
            self.device_scan_state = DeviceScanState::NoDeviceScan;
        }
    }

    pub fn absorb_progress_batch(
        &mut self,
        scan_run_number: ScanRunNumber,
        progress_batch: Vec<ScanProgressEvent>,
        refreshed_at: Instant,
    ) -> Vec<DetectedThreat> {
        match &mut self.device_scan_state {
            DeviceScanState::DeviceScanRunning { running_scan, .. }
                if running_scan.belongs_to_run(scan_run_number) =>
            {
                running_scan.absorb_progress_batch(progress_batch, refreshed_at)
            }
            DeviceScanState::NoDeviceScan
            | DeviceScanState::DeviceScanRunning { .. }
            | DeviceScanState::DeviceScanFinished { .. } => Vec::new(),
        }
    }

    pub fn finish_scan_stream(
        &mut self,
        scan_run_number: ScanRunNumber,
        finished_instant: Instant,
    ) -> DeviceScanEnding<'_> {
        match std::mem::replace(&mut self.device_scan_state, DeviceScanState::NoDeviceScan) {
            DeviceScanState::DeviceScanRunning {
                scan_target,
                running_scan,
            } if running_scan.belongs_to_run(scan_run_number) => {
                self.device_scan_state = DeviceScanState::DeviceScanFinished {
                    scan_target,
                    finished_scan: running_scan.finished_at(finished_instant),
                };
            }
            unchanged_state => {
                self.device_scan_state = unchanged_state;
                return DeviceScanEnding::StaleDeviceStreamIgnored;
            }
        }
        match &self.device_scan_state {
            DeviceScanState::DeviceScanFinished {
                scan_target,
                finished_scan,
            } => DeviceScanEnding::DeviceScanFinished(FinishedDeviceScan {
                scan_target,
                finished_scan,
            }),
            DeviceScanState::NoDeviceScan | DeviceScanState::DeviceScanRunning { .. } => {
                DeviceScanEnding::StaleDeviceStreamIgnored
            }
        }
    }

    pub const fn scan_is_running(&self) -> bool {
        matches!(
            self.device_scan_state,
            DeviceScanState::DeviceScanRunning { .. }
        )
    }

    pub const fn shows_results(&self) -> bool {
        matches!(
            self.device_scan_state,
            DeviceScanState::DeviceScanFinished { .. }
        )
    }

    pub fn accepts_cancel(&self) -> bool {
        match &self.device_scan_state {
            DeviceScanState::DeviceScanRunning { running_scan, .. } => {
                running_scan.accepts_cancel()
            }
            DeviceScanState::NoDeviceScan | DeviceScanState::DeviceScanFinished { .. } => false,
        }
    }

    pub const fn scan_progress_view(&self) -> &ScanProgressView {
        match &self.device_scan_state {
            DeviceScanState::DeviceScanRunning { running_scan, .. } => {
                running_scan.scan_progress_view()
            }
            DeviceScanState::NoDeviceScan | DeviceScanState::DeviceScanFinished { .. } => {
                &PREPARING_SCAN_VIEW
            }
        }
    }

    pub fn device_scan_status(&self) -> DeviceScanStatus {
        match &self.device_scan_state {
            DeviceScanState::NoDeviceScan => DeviceScanStatus::NoDeviceScanYet,
            DeviceScanState::DeviceScanRunning { scan_target, .. } => {
                DeviceScanStatus::DeviceScanRunning {
                    drive_name: scan_target.drive_name.clone(),
                }
            }
            DeviceScanState::DeviceScanFinished {
                scan_target,
                finished_scan,
            } => DeviceScanStatus::DeviceScanEnded {
                drive_name: scan_target.drive_name.clone(),
                scan_result: finished_results_status(finished_scan),
            },
        }
    }
}

pub const fn skipped_while_scanning() -> DriveScanDecision {
    DriveScanDecision::DriveSkipped(DriveSkipReason::SkippedWhileScanning)
}

#[cfg(test)]
mod removable_drives_state_tests {
    use super::*;
    use crate::shared_widgets::scan_runs::scan_run_progress::scan_run_fixtures::{
        running_scan_of, threat_batch_in,
    };

    fn drive_target(drive_event_number: DriveEventNumber, drive_name: &str) -> DriveScanTarget {
        DriveScanTarget {
            drive_event_number,
            drive_name: drive_name.to_owned(),
            mount_path: PathBuf::from("/run/media/user").join(drive_name),
        }
    }

    fn started_flow(
        scan_target: DriveScanTarget,
        scan_run_number: ScanRunNumber,
    ) -> DeviceScanFlow {
        let mut device_scan_flow = DeviceScanFlow::idle_flow();
        let mount_path = scan_target.mount_path.clone();
        assert_eq!(
            device_scan_flow.drive_ready_to_scan(scan_target),
            ReadyDriveOutcome::ScanSlotNeeded {
                drive_name: "USB STICK".to_owned()
            }
        );
        let GrantedSlotUse::ScanGrantedDrive(granted_target) = device_scan_flow.scan_slot_granted()
        else {
            panic!("the requested drive should be scanned");
        };
        device_scan_flow.begin_device_scan(
            granted_target,
            running_scan_of(scan_run_number, mount_path, Instant::now()),
        );
        device_scan_flow
    }

    #[test]
    fn the_log_lists_drives_newest_first_and_updates_each_by_number() {
        let mut drive_event_log = DriveEventLog::empty_session();
        let first_drive = drive_event_log.record_seen_drive(
            "CAMERA".to_owned(),
            PathBuf::from("/run/media/user/CAMERA"),
            Timestamp::constant(100, 0),
            DriveScanDecision::DriveSettling,
        );
        let second_drive = drive_event_log.record_seen_drive(
            "BACKUP".to_owned(),
            PathBuf::from("/run/media/user/BACKUP"),
            Timestamp::constant(200, 0),
            DriveScanDecision::DriveSkipped(DriveSkipReason::SkippedAutoScanOff),
        );
        drive_event_log.decide_drive(first_drive, skipped_while_scanning());
        let listed_events = drive_event_log.newest_first_events();
        assert_eq!(listed_events[0].drive_event_number, second_drive);
        assert_eq!(listed_events[1].drive_name, "CAMERA");
        assert_eq!(listed_events[1].drive_decision, skipped_while_scanning());
    }

    #[test]
    fn a_second_drive_during_a_device_scan_is_skipped_while_scanning() {
        let mut device_scan_flow = started_flow(
            drive_target(DriveEventNumber::FIRST_EVENT, "USB STICK"),
            ScanRunNumber::FIRST_RUN,
        );
        assert_eq!(
            device_scan_flow.drive_ready_to_scan(drive_target(
                DriveEventNumber::FIRST_EVENT.following_event(),
                "CAMERA"
            )),
            ReadyDriveOutcome::SkippedWhileBusy
        );
        assert_eq!(
            device_scan_flow.device_scan_status(),
            DeviceScanStatus::DeviceScanRunning {
                drive_name: "USB STICK".to_owned()
            }
        );
    }

    #[test]
    fn a_second_drive_while_waiting_for_the_slot_is_skipped_too() {
        let mut device_scan_flow = DeviceScanFlow::idle_flow();
        let _first_request = device_scan_flow
            .drive_ready_to_scan(drive_target(DriveEventNumber::FIRST_EVENT, "USB STICK"));
        assert_eq!(
            device_scan_flow.drive_ready_to_scan(drive_target(
                DriveEventNumber::FIRST_EVENT.following_event(),
                "CAMERA"
            )),
            ReadyDriveOutcome::SkippedWhileBusy
        );
    }

    #[test]
    fn a_refused_slot_withdraws_the_waiting_drive() {
        let mut device_scan_flow = DeviceScanFlow::idle_flow();
        let _slot_request = device_scan_flow
            .drive_ready_to_scan(drive_target(DriveEventNumber::FIRST_EVENT, "USB STICK"));
        assert_eq!(
            device_scan_flow.scan_slot_refused(),
            WithdrawnDrive::DriveWithdrawn(DriveEventNumber::FIRST_EVENT)
        );
        assert_eq!(
            device_scan_flow.scan_slot_granted(),
            GrantedSlotUse::ReleaseUnusedSlot
        );
    }

    #[test]
    fn a_revoked_slot_stops_the_device_scan_and_ignores_its_late_stream() {
        let mut device_scan_flow = started_flow(
            drive_target(DriveEventNumber::FIRST_EVENT, "USB STICK"),
            ScanRunNumber::FIRST_RUN,
        );
        assert_eq!(
            device_scan_flow.scan_slot_revoked(),
            WithdrawnDrive::DriveWithdrawn(DriveEventNumber::FIRST_EVENT)
        );
        assert!(!device_scan_flow.scan_is_running());
        assert!(matches!(
            device_scan_flow.finish_scan_stream(ScanRunNumber::FIRST_RUN, Instant::now()),
            DeviceScanEnding::StaleDeviceStreamIgnored
        ));
        assert_eq!(
            device_scan_flow.scan_slot_revoked(),
            WithdrawnDrive::NoDriveWithdrawn
        );
    }

    #[test]
    fn a_finished_device_scan_reports_its_drive_and_result() {
        let mut device_scan_flow = started_flow(
            drive_target(DriveEventNumber::FIRST_EVENT, "USB STICK"),
            ScanRunNumber::FIRST_RUN,
        );
        let found_threats = device_scan_flow.absorb_progress_batch(
            ScanRunNumber::FIRST_RUN,
            threat_batch_in("/run/media/user/USB STICK"),
            Instant::now(),
        );
        assert_eq!(found_threats.len(), 1);
        let DeviceScanEnding::DeviceScanFinished(finished_device_scan) =
            device_scan_flow.finish_scan_stream(ScanRunNumber::FIRST_RUN, Instant::now())
        else {
            panic!("the current run should finish");
        };
        assert_eq!(
            finished_device_scan.scan_target.drive_event_number,
            DriveEventNumber::FIRST_EVENT
        );
        assert_eq!(
            device_scan_flow.device_scan_status(),
            DeviceScanStatus::DeviceScanEnded {
                drive_name: "USB STICK".to_owned(),
                scan_result: ScanResultsStatus::ThreatsDetected,
            }
        );
        device_scan_flow.dismiss_results();
        assert_eq!(
            device_scan_flow.device_scan_status(),
            DeviceScanStatus::NoDeviceScanYet
        );
    }
}
