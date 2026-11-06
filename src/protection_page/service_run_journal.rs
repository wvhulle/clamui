use jiff::Timestamp;
use tokio::task::spawn_blocking;

use crate::host_services::systemd_journal::unit_journal_reader::{
    JournalProcessExit, ManagerUnitRecord, UnitJournalEvent, newest_manager_records_for_unit,
};

const JOURNAL_RECORD_LIMIT: usize = 500;
const SCANNER_FOUND_THREATS_STATUS: i32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanRunFindings {
    NothingFound,
    ThreatsFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanRunHistory {
    NoCompletedScan,
    CompletedScan {
        finished_at: Timestamp,
        scan_findings: ScanRunFindings,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdaterRunHistory {
    NoCompletedUpdate,
    CompletedUpdate { finished_at: Timestamp },
}

fn scan_run_findings(unit_journal_event: &UnitJournalEvent) -> Option<ScanRunFindings> {
    match unit_journal_event {
        UnitJournalEvent::UnitDeactivated => Some(ScanRunFindings::NothingFound),
        UnitJournalEvent::MainProcessExited(JournalProcessExit::ExitedWithStatus {
            exit_status: SCANNER_FOUND_THREATS_STATUS,
        }) => Some(ScanRunFindings::ThreatsFound),
        UnitJournalEvent::MainProcessExited(
            JournalProcessExit::ExitedWithStatus { .. }
            | JournalProcessExit::KilledBySignal { .. }
            | JournalProcessExit::DumpedCore { .. }
            | JournalProcessExit::UnrecognizedExit { .. },
        )
        | UnitJournalEvent::UnrecognizedMessage { .. } => None,
    }
}

fn update_completed(unit_journal_event: &UnitJournalEvent) -> bool {
    match unit_journal_event {
        UnitJournalEvent::UnitDeactivated => true,
        UnitJournalEvent::MainProcessExited(_) | UnitJournalEvent::UnrecognizedMessage { .. } => {
            false
        }
    }
}

fn newest_completed_scan(manager_records: &[ManagerUnitRecord]) -> ScanRunHistory {
    manager_records
        .iter()
        .find_map(|manager_record| {
            scan_run_findings(&manager_record.unit_journal_event).map(|scan_findings| {
                ScanRunHistory::CompletedScan {
                    finished_at: manager_record.recorded_at,
                    scan_findings,
                }
            })
        })
        .unwrap_or(ScanRunHistory::NoCompletedScan)
}

fn newest_completed_update(manager_records: &[ManagerUnitRecord]) -> UpdaterRunHistory {
    manager_records
        .iter()
        .find(|manager_record| update_completed(&manager_record.unit_journal_event))
        .map_or(UpdaterRunHistory::NoCompletedUpdate, |manager_record| {
            UpdaterRunHistory::CompletedUpdate {
                finished_at: manager_record.recorded_at,
            }
        })
}

async fn newest_unit_records(service_unit: &'static str) -> Vec<ManagerUnitRecord> {
    spawn_blocking(move || newest_manager_records_for_unit(service_unit, JOURNAL_RECORD_LIMIT))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

pub async fn newest_scan_run(service_unit: &'static str) -> ScanRunHistory {
    newest_completed_scan(&newest_unit_records(service_unit).await)
}

pub async fn newest_update_run(service_unit: &'static str) -> UpdaterRunHistory {
    newest_completed_update(&newest_unit_records(service_unit).await)
}

#[cfg(test)]
mod service_run_journal_tests {
    use super::*;

    const RECORDED_AT: Timestamp = Timestamp::constant(1_793_872_800, 860_146_000);

    fn recorded_event(unit_journal_event: UnitJournalEvent) -> ManagerUnitRecord {
        ManagerUnitRecord {
            recorded_at: RECORDED_AT,
            unit_journal_event,
        }
    }

    fn exited_record(exit_status: i32) -> ManagerUnitRecord {
        recorded_event(UnitJournalEvent::MainProcessExited(
            JournalProcessExit::ExitedWithStatus { exit_status },
        ))
    }

    fn killed_record() -> ManagerUnitRecord {
        recorded_event(UnitJournalEvent::MainProcessExited(
            JournalProcessExit::KilledBySignal {
                signal_name: "KILL".to_owned(),
            },
        ))
    }

    fn unrecognized_record() -> ManagerUnitRecord {
        recorded_event(UnitJournalEvent::UnrecognizedMessage {
            message_id: String::new(),
        })
    }

    #[test]
    fn a_deactivated_unit_is_a_clean_scan() {
        assert_eq!(
            newest_completed_scan(&[recorded_event(UnitJournalEvent::UnitDeactivated)]),
            ScanRunHistory::CompletedScan {
                finished_at: RECORDED_AT,
                scan_findings: ScanRunFindings::NothingFound,
            }
        );
    }

    #[test]
    fn exit_status_one_is_a_completed_scan_with_threats() {
        assert_eq!(
            newest_completed_scan(&[exited_record(1)]),
            ScanRunHistory::CompletedScan {
                finished_at: RECORDED_AT,
                scan_findings: ScanRunFindings::ThreatsFound,
            }
        );
    }

    #[test]
    fn errors_and_kills_do_not_count_as_completed_scans() {
        [exited_record(2), killed_record(), unrecognized_record()]
            .iter()
            .for_each(|manager_record| {
                assert_eq!(
                    newest_completed_scan(std::slice::from_ref(manager_record)),
                    ScanRunHistory::NoCompletedScan,
                    "{manager_record:?}"
                );
            });
    }

    #[test]
    fn a_failed_newest_scan_falls_back_to_the_last_completed_scan() {
        assert!(matches!(
            newest_completed_scan(&[
                exited_record(2),
                recorded_event(UnitJournalEvent::UnitDeactivated)
            ]),
            ScanRunHistory::CompletedScan {
                scan_findings: ScanRunFindings::NothingFound,
                ..
            }
        ));
    }

    #[test]
    fn an_updater_exiting_with_status_one_did_not_complete_an_update() {
        assert_eq!(
            newest_completed_update(&[exited_record(1), killed_record()]),
            UpdaterRunHistory::NoCompletedUpdate
        );
        assert_eq!(
            newest_completed_update(&[
                exited_record(1),
                recorded_event(UnitJournalEvent::UnitDeactivated)
            ]),
            UpdaterRunHistory::CompletedUpdate {
                finished_at: RECORDED_AT
            }
        );
    }

    #[tokio::test]
    #[ignore = "needs a host where clamav-freshclam.service ran from a timer"]
    async fn host_journal_reports_the_real_update_run() {
        assert!(matches!(
            newest_update_run("clamav-freshclam.service").await,
            UpdaterRunHistory::CompletedUpdate { .. }
        ));
    }
}
