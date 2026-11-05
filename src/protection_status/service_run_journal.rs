use tokio::task::spawn_blocking;

use crate::systemd_journal::unit_journal_reader::{
    ManagerUnitRecord, newest_manager_records_for_unit,
};

const JOURNAL_RECORD_LIMIT: usize = 500;
const UNIT_DEACTIVATED_MESSAGE: &str = "7ad2d189f7e94e70a38c781354912448";
const PROCESS_EXITED_MESSAGE: &str = "98e322203f7a4ed290d09fe03c09fe15";
const NORMAL_EXIT_CODE: &str = "exited";
const THREATS_FOUND_STATUS: &str = "1";
const MICROSECONDS_PER_SECOND: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceRunRecord {
    pub finished_at_unix: i64,
    pub threats_found: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceRunHistory {
    NoCompletedRun,
    CompletedRun(ServiceRunRecord),
}

fn completed_service_run(manager_record: &ManagerUnitRecord) -> Option<ServiceRunRecord> {
    let threats_found = match manager_record.message_id.as_str() {
        UNIT_DEACTIVATED_MESSAGE => false,
        PROCESS_EXITED_MESSAGE
            if manager_record.exit_code == NORMAL_EXIT_CODE
                && manager_record.exit_status == THREATS_FOUND_STATUS =>
        {
            true
        }
        _other_message => return None,
    };
    Some(ServiceRunRecord {
        finished_at_unix: i64::try_from(
            manager_record.realtime_microseconds / MICROSECONDS_PER_SECOND,
        )
        .ok()?,
        threats_found,
    })
}

fn newest_completed_run(manager_records: &[ManagerUnitRecord]) -> ServiceRunHistory {
    manager_records
        .iter()
        .find_map(completed_service_run)
        .map_or(
            ServiceRunHistory::NoCompletedRun,
            ServiceRunHistory::CompletedRun,
        )
}

pub async fn newest_service_run(service_unit: &'static str) -> ServiceRunHistory {
    spawn_blocking(move || newest_manager_records_for_unit(service_unit, JOURNAL_RECORD_LIMIT))
        .await
        .ok()
        .and_then(Result::ok)
        .map_or(ServiceRunHistory::NoCompletedRun, |manager_records| {
            newest_completed_run(&manager_records)
        })
}

#[cfg(test)]
mod service_run_journal_tests {
    use super::*;

    const RECORDED_AT_MICROSECONDS: u64 = 1_793_872_800_860_146;

    fn deactivated_record() -> ManagerUnitRecord {
        ManagerUnitRecord {
            realtime_microseconds: RECORDED_AT_MICROSECONDS,
            message_id: UNIT_DEACTIVATED_MESSAGE.to_owned(),
            ..ManagerUnitRecord::default()
        }
    }

    fn exited_record(exit_code: &str, exit_status: &str) -> ManagerUnitRecord {
        ManagerUnitRecord {
            realtime_microseconds: RECORDED_AT_MICROSECONDS,
            message_id: PROCESS_EXITED_MESSAGE.to_owned(),
            exit_code: exit_code.to_owned(),
            exit_status: exit_status.to_owned(),
        }
    }

    #[test]
    fn a_deactivated_unit_is_a_clean_run() {
        assert_eq!(
            newest_completed_run(&[deactivated_record()]),
            ServiceRunHistory::CompletedRun(ServiceRunRecord {
                finished_at_unix: 1_793_872_800,
                threats_found: false,
            })
        );
    }

    #[test]
    fn exit_status_one_is_a_completed_run_with_threats() {
        assert_eq!(
            newest_completed_run(&[exited_record("exited", "1")]),
            ServiceRunHistory::CompletedRun(ServiceRunRecord {
                finished_at_unix: 1_793_872_800,
                threats_found: true,
            })
        );
    }

    #[test]
    fn errors_and_kills_do_not_count_as_completed_runs() {
        [
            exited_record("exited", "2"),
            exited_record("killed", "1"),
            ManagerUnitRecord::default(),
        ]
        .iter()
        .for_each(|manager_record| {
            assert_eq!(
                newest_completed_run(std::slice::from_ref(manager_record)),
                ServiceRunHistory::NoCompletedRun,
                "{manager_record:?}"
            );
        });
    }

    #[test]
    fn a_failed_newest_run_falls_back_to_the_last_completed_run() {
        assert!(matches!(
            newest_completed_run(&[exited_record("exited", "2"), deactivated_record()]),
            ServiceRunHistory::CompletedRun(ServiceRunRecord {
                threats_found: false,
                ..
            })
        ));
    }

    #[tokio::test]
    #[ignore = "needs a host where clamav-freshclam.service ran from a timer"]
    async fn host_journal_reports_the_real_service_run() {
        assert!(matches!(
            newest_service_run("clamav-freshclam.service").await,
            ServiceRunHistory::CompletedRun(ServiceRunRecord {
                threats_found: false,
                ..
            })
        ));
    }
}
