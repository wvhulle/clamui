use jiff::Timestamp;

use crate::{
    host_services::systemd_journal::unit_journal_reader::{
        JournalProcessExit, ManagerUnitRecord, UnitJournalEvent, UnitJournalReadFailure,
        newest_manager_records_for_unit, read_journal_off_thread,
    },
    signatures::database_updates_page::signature_update_run::updater_exit_status::{
        SignatureUpdaterProgram, UpdaterExitMeaning, classify_updater_exit_status,
    },
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
    JournalUnreadable(UnitJournalReadFailure),
    CompletedScan {
        finished_at: Timestamp,
        scan_findings: ScanRunFindings,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdaterRunHistory {
    NoCompletedUpdate,
    JournalUnreadable(UnitJournalReadFailure),
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
            | JournalProcessExit::UnrecognizedExit { .. }
            | JournalProcessExit::ExitFieldsMissing,
        )
        | UnitJournalEvent::UnrecognizedMessage { .. }
        | UnitJournalEvent::MessageIdMissing => None,
    }
}

const fn update_completed(
    updater_program: SignatureUpdaterProgram,
    unit_journal_event: &UnitJournalEvent,
) -> bool {
    match unit_journal_event {
        UnitJournalEvent::UnitDeactivated => true,
        UnitJournalEvent::MainProcessExited(JournalProcessExit::ExitedWithStatus {
            exit_status,
        }) => match classify_updater_exit_status(updater_program, *exit_status) {
            UpdaterExitMeaning::UpdateSucceeded | UpdaterExitMeaning::UpdateAlreadyCurrent => true,
            UpdaterExitMeaning::UpdaterError { .. } => false,
        },
        UnitJournalEvent::MainProcessExited(
            JournalProcessExit::KilledBySignal { .. }
            | JournalProcessExit::DumpedCore { .. }
            | JournalProcessExit::UnrecognizedExit { .. }
            | JournalProcessExit::ExitFieldsMissing,
        )
        | UnitJournalEvent::UnrecognizedMessage { .. }
        | UnitJournalEvent::MessageIdMissing => false,
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

fn newest_completed_update(
    updater_program: SignatureUpdaterProgram,
    manager_records: &[ManagerUnitRecord],
) -> UpdaterRunHistory {
    manager_records
        .iter()
        .find(|manager_record| {
            update_completed(updater_program, &manager_record.unit_journal_event)
        })
        .map_or(UpdaterRunHistory::NoCompletedUpdate, |manager_record| {
            UpdaterRunHistory::CompletedUpdate {
                finished_at: manager_record.recorded_at,
            }
        })
}

async fn newest_unit_records(
    service_unit: &'static str,
) -> Result<Vec<ManagerUnitRecord>, UnitJournalReadFailure> {
    read_journal_off_thread(move || {
        newest_manager_records_for_unit(service_unit, JOURNAL_RECORD_LIMIT)
    })
    .await
}

pub fn scan_run_from_journal(
    journal_reading: Result<Vec<ManagerUnitRecord>, UnitJournalReadFailure>,
) -> ScanRunHistory {
    match journal_reading {
        Ok(manager_records) => newest_completed_scan(&manager_records),
        Err(read_failure) => ScanRunHistory::JournalUnreadable(read_failure),
    }
}

pub fn update_run_from_journal(
    updater_program: SignatureUpdaterProgram,
    journal_reading: Result<Vec<ManagerUnitRecord>, UnitJournalReadFailure>,
) -> UpdaterRunHistory {
    match journal_reading {
        Ok(manager_records) => newest_completed_update(updater_program, &manager_records),
        Err(read_failure) => UpdaterRunHistory::JournalUnreadable(read_failure),
    }
}

pub async fn newest_scan_run(service_unit: &'static str) -> ScanRunHistory {
    scan_run_from_journal(newest_unit_records(service_unit).await)
}

pub async fn newest_update_run(
    updater_program: SignatureUpdaterProgram,
    service_unit: &'static str,
) -> UpdaterRunHistory {
    update_run_from_journal(updater_program, newest_unit_records(service_unit).await)
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
    fn an_unreadable_journal_is_not_reported_as_no_completed_run() {
        let read_failure = UnitJournalReadFailure::JournalReadFailed {
            failure_kind: std::io::ErrorKind::PermissionDenied,
        };
        assert_eq!(
            scan_run_from_journal(Err(read_failure)),
            ScanRunHistory::JournalUnreadable(read_failure)
        );
        assert_eq!(
            update_run_from_journal(SignatureUpdaterProgram::Freshclam, Err(read_failure)),
            UpdaterRunHistory::JournalUnreadable(read_failure)
        );
        assert_eq!(
            scan_run_from_journal(Ok(Vec::new())),
            ScanRunHistory::NoCompletedScan
        );
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
    fn freshclam_exit_one_completed_an_update_but_fangfrisch_exit_one_did_not() {
        assert_eq!(
            newest_completed_update(
                SignatureUpdaterProgram::Freshclam,
                &[exited_record(1), killed_record()]
            ),
            UpdaterRunHistory::CompletedUpdate {
                finished_at: RECORDED_AT
            }
        );
        assert_eq!(
            newest_completed_update(
                SignatureUpdaterProgram::Fangfrisch,
                &[exited_record(1), killed_record()]
            ),
            UpdaterRunHistory::NoCompletedUpdate
        );
        assert_eq!(
            newest_completed_update(
                SignatureUpdaterProgram::Freshclam,
                &[exited_record(52), killed_record()]
            ),
            UpdaterRunHistory::NoCompletedUpdate
        );
        assert_eq!(
            newest_completed_update(
                SignatureUpdaterProgram::Fangfrisch,
                &[
                    exited_record(1),
                    recorded_event(UnitJournalEvent::UnitDeactivated)
                ]
            ),
            UpdaterRunHistory::CompletedUpdate {
                finished_at: RECORDED_AT
            }
        );
    }

    #[tokio::test]
    #[ignore = "needs a host where clamav-freshclam.service ran from a timer"]
    async fn host_journal_reports_the_real_update_run() {
        assert!(matches!(
            newest_update_run(
                SignatureUpdaterProgram::Freshclam,
                "clamav-freshclam.service"
            )
            .await,
            UpdaterRunHistory::CompletedUpdate { .. }
        ));
    }
}
