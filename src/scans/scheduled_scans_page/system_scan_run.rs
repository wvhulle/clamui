use gettextrs::gettext;

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    protection_evidence::host_protection_evidence::{
        DaemonEvidence, ProtectionEvidence, ScanServiceEvidence, ScanUnitResult,
        ScheduledScanEvidence,
    },
    systemd_bus::host_systemd_units::{SystemdBusFailure, UnitStartOutcome},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SystemScanAvailability {
    NoSystemScanService,
    SystemScanService {
        service_unit: &'static str,
        scanned_folders: Vec<String>,
        daemon_answering: bool,
    },
}

pub fn system_scan_availability(
    protection_evidence: &ProtectionEvidence,
) -> SystemScanAvailability {
    match &protection_evidence.scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            service_unit,
            scan_service: ScanServiceEvidence::ServiceConfigured { scan_targets, .. },
            ..
        } => SystemScanAvailability::SystemScanService {
            service_unit,
            scanned_folders: scan_targets.clone(),
            daemon_answering: matches!(
                protection_evidence.daemon_evidence,
                DaemonEvidence::ClamdAnswering { .. }
            ),
        },
        ScheduledScanEvidence::SystemTimer { .. }
        | ScheduledScanEvidence::LazaretSchedule
        | ScheduledScanEvidence::NoSchedule => SystemScanAvailability::NoSystemScanService,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemScanRun {
    RunIdle,
    RunStarting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemScanStart {
    StartServiceUnit { service_unit: &'static str },
    NothingToStart,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemScanControl {
    scan_availability: SystemScanAvailability,
    scan_run: SystemScanRun,
}

impl SystemScanControl {
    pub const fn new() -> Self {
        Self {
            scan_availability: SystemScanAvailability::NoSystemScanService,
            scan_run: SystemScanRun::RunIdle,
        }
    }

    pub fn evidence_gathered(&mut self, protection_evidence: &ProtectionEvidence) {
        self.scan_availability = system_scan_availability(protection_evidence);
    }

    pub const fn run_requested(&mut self) -> SystemScanStart {
        match (&self.scan_run, &self.scan_availability) {
            (
                SystemScanRun::RunIdle,
                SystemScanAvailability::SystemScanService {
                    service_unit,
                    daemon_answering: true,
                    ..
                },
            ) => {
                self.scan_run = SystemScanRun::RunStarting;
                SystemScanStart::StartServiceUnit { service_unit }
            }
            (SystemScanRun::RunStarting, _)
            | (
                SystemScanRun::RunIdle,
                SystemScanAvailability::NoSystemScanService
                | SystemScanAvailability::SystemScanService {
                    daemon_answering: false,
                    ..
                },
            ) => SystemScanStart::NothingToStart,
        }
    }

    pub const fn run_finished(&mut self) {
        self.scan_run = SystemScanRun::RunIdle;
    }

    pub const fn shows_system_scan(&self) -> bool {
        matches!(
            self.scan_availability,
            SystemScanAvailability::SystemScanService { .. }
        )
    }

    pub const fn run_is_starting(&self) -> bool {
        matches!(self.scan_run, SystemScanRun::RunStarting)
    }

    pub const fn accepts_run(&self) -> bool {
        matches!(
            (&self.scan_run, &self.scan_availability),
            (
                SystemScanRun::RunIdle,
                SystemScanAvailability::SystemScanService {
                    daemon_answering: true,
                    ..
                }
            )
        )
    }

    pub fn scanned_folders_text(&self) -> String {
        match &self.scan_availability {
            SystemScanAvailability::SystemScanService {
                scanned_folders, ..
            } if !scanned_folders.is_empty() => scanned_folders.join(", "),
            SystemScanAvailability::SystemScanService { .. } => {
                gettext("The scan unit names no folders")
            }
            SystemScanAvailability::NoSystemScanService => String::new(),
        }
    }

    pub fn group_description(&self) -> String {
        match &self.scan_availability {
            SystemScanAvailability::SystemScanService {
                service_unit,
                daemon_answering: true,
                ..
            } => gettext(
                "Your system's scan service {unit} scans these folders with the system's own \
                 settings. Running it needs administrator authorization.",
            )
            .replace("{unit}", service_unit),
            SystemScanAvailability::SystemScanService {
                daemon_answering: false,
                ..
            } => gettext("Needs the daemon, see Scan Engine"),
            SystemScanAvailability::NoSystemScanService => String::new(),
        }
    }
}

pub fn scan_found_threats(
    start_outcome: &UnitStartOutcome,
    scan_service: &ScanServiceEvidence,
) -> bool {
    matches!(start_outcome, UnitStartOutcome::JobEnded { .. })
        && matches!(
            scan_service,
            ScanServiceEvidence::ServiceConfigured {
                last_result: ScanUnitResult::ThreatsFound,
                ..
            }
        )
}

fn systemd_failure_text(bus_failure: &SystemdBusFailure) -> String {
    match bus_failure {
        SystemdBusFailure::BusCallFailed(bus_error) => gettext("systemd did not answer: {error}")
            .replace("{error}", &sanitize_scanner_line(&bus_error.to_string())),
        SystemdBusFailure::UnrecognizedLoadState => {
            gettext("systemd reported a unit state Lazaret does not recognize")
        }
    }
}

pub fn unit_run_toast_text(
    start_outcome: &UnitStartOutcome,
    scan_service: &ScanServiceEvidence,
) -> String {
    if scan_found_threats(start_outcome, scan_service) {
        return gettext("The scan found malware");
    }
    match start_outcome {
        UnitStartOutcome::UnitFinished => gettext("The scan finished"),
        UnitStartOutcome::JobEnded { job_result } => {
            gettext("The scan did not finish cleanly: {result}")
                .replace("{result}", &sanitize_scanner_line(job_result))
        }
        UnitStartOutcome::AuthorizationRefused => {
            gettext("Starting the scan needs administrator authorization")
        }
        UnitStartOutcome::BusFailure(bus_failure) => {
            gettext("The scan could not be started: {error}")
                .replace("{error}", &systemd_failure_text(bus_failure))
        }
    }
}

#[cfg(test)]
mod system_scan_run_tests {
    use super::*;
    use crate::host_services::{
        protection_evidence::{
            host_protection_evidence::scan_service_evidence,
            protection_evidence_fixtures::healthy_evidence,
        },
        systemd_bus::host_systemd_units::{ServiceLastResult, ServiceUnitSnapshot, UnitActivity},
    };

    fn control_with(protection_evidence: &ProtectionEvidence) -> SystemScanControl {
        let mut system_scan_control = SystemScanControl::new();
        system_scan_control.evidence_gathered(protection_evidence);
        system_scan_control
    }

    #[test]
    fn a_system_scan_service_can_be_run_once_until_it_finishes() {
        let mut system_scan_control = control_with(&healthy_evidence());
        assert!(system_scan_control.shows_system_scan());
        assert!(system_scan_control.accepts_run());
        assert!(matches!(
            system_scan_control.run_requested(),
            SystemScanStart::StartServiceUnit { .. }
        ));
        assert!(system_scan_control.run_is_starting());
        assert!(!system_scan_control.accepts_run());
        assert_eq!(
            system_scan_control.run_requested(),
            SystemScanStart::NothingToStart
        );
        system_scan_control.run_finished();
        assert!(system_scan_control.accepts_run());
    }

    #[test]
    fn lazarets_own_schedule_and_no_schedule_offer_no_system_scan() {
        [
            ScheduledScanEvidence::LazaretSchedule,
            ScheduledScanEvidence::NoSchedule,
        ]
        .into_iter()
        .for_each(|scheduled_scan_evidence| {
            let mut system_scan_control = control_with(&ProtectionEvidence {
                scheduled_scan_evidence,
                ..healthy_evidence()
            });
            assert!(!system_scan_control.shows_system_scan());
            assert_eq!(
                system_scan_control.run_requested(),
                SystemScanStart::NothingToStart
            );
        });
    }

    #[test]
    fn a_stopped_daemon_shows_the_service_but_does_not_run_it() {
        let mut system_scan_control = control_with(&ProtectionEvidence {
            daemon_evidence: DaemonEvidence::UnitStopped {
                service_unit: "clamav-daemon.service",
            },
            ..healthy_evidence()
        });
        assert!(system_scan_control.shows_system_scan());
        assert!(!system_scan_control.accepts_run());
        assert_eq!(
            system_scan_control.run_requested(),
            SystemScanStart::NothingToStart
        );
        assert_eq!(
            system_scan_control.group_description(),
            "Needs the daemon, see Scan Engine"
        );
    }

    #[test]
    fn the_scanned_folders_come_from_the_scan_unit() {
        assert_eq!(
            control_with(&healthy_evidence()).scanned_folders_text(),
            "/tmp, /var/tmp"
        );
    }

    fn loaded_scan_service(exit_status: i32) -> ScanServiceEvidence {
        scan_service_evidence(ServiceUnitSnapshot::LoadedService {
            unit_activity: UnitActivity::UnitInactive,
            last_result: ServiceLastResult::ExitedWithStatus { exit_status },
            program_arguments: Vec::new(),
        })
    }

    #[test]
    fn finding_malware_is_not_reported_as_a_failed_scan() {
        let failed_job = UnitStartOutcome::JobEnded {
            job_result: "failed".to_owned(),
        };
        assert_eq!(
            unit_run_toast_text(&failed_job, &loaded_scan_service(1)),
            "The scan found malware"
        );
        assert!(
            unit_run_toast_text(&failed_job, &loaded_scan_service(2))
                .contains("did not finish cleanly")
        );
    }

    #[test]
    fn an_unreadable_scan_service_never_claims_malware_was_found() {
        let failed_job = UnitStartOutcome::JobEnded {
            job_result: "failed".to_owned(),
        };
        assert!(
            unit_run_toast_text(
                &failed_job,
                &scan_service_evidence(ServiceUnitSnapshot::SystemdUnreachable(
                    SystemdBusFailure::UnrecognizedLoadState
                ))
            )
            .contains("did not finish cleanly")
        );
        assert_eq!(
            unit_run_toast_text(
                &UnitStartOutcome::BusFailure(SystemdBusFailure::UnrecognizedLoadState),
                &ScanServiceEvidence::ServiceMissing
            ),
            "The scan could not be started: systemd reported a unit state Lazaret does not \
             recognize"
        );
    }
}
