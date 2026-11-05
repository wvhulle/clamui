use std::{process::Stdio, time::Duration};

use serde::Deserialize;
use tokio::{process::Command, time::timeout};

const SYSTEM_SCAN_UNIT: &str = "clamdscan.service";
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);
const JOURNAL_RECORD_LIMIT: &str = "500";
const UNIT_DEACTIVATED_MESSAGE: &str = "7ad2d189f7e94e70a38c781354912448";
const PROCESS_EXITED_MESSAGE: &str = "98e322203f7a4ed290d09fe03c09fe15";
const NORMAL_EXIT_CODE: &str = "exited";
const VIRUS_FOUND_STATUS: &str = "1";
const MICROSECONDS_PER_SECOND: i64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemScanRun {
    pub finished_at_unix: i64,
    pub threats_found: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemScanHistory {
    NoCompletedRun,
    CompletedRun(SystemScanRun),
}

#[derive(Deserialize)]
struct JournalExitRecord {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_microseconds: String,
    #[serde(rename = "MESSAGE_ID")]
    message_id: Option<String>,
    #[serde(rename = "EXIT_CODE")]
    exit_code: Option<String>,
    #[serde(rename = "EXIT_STATUS")]
    exit_status: Option<String>,
}

fn completed_scan_run(journal_line: &str) -> Option<SystemScanRun> {
    let exit_record: JournalExitRecord = serde_json::from_str(journal_line).ok()?;
    let threats_found = match exit_record.message_id.as_deref()? {
        UNIT_DEACTIVATED_MESSAGE => false,
        PROCESS_EXITED_MESSAGE
            if exit_record.exit_code.as_deref() == Some(NORMAL_EXIT_CODE)
                && exit_record.exit_status.as_deref() == Some(VIRUS_FOUND_STATUS) =>
        {
            true
        }
        _other_message => return None,
    };
    let realtime_microseconds: i64 = exit_record.realtime_microseconds.parse().ok()?;
    Some(SystemScanRun {
        finished_at_unix: realtime_microseconds / MICROSECONDS_PER_SECOND,
        threats_found,
    })
}

fn newest_run_in_journal(journal_text: &str) -> SystemScanHistory {
    journal_text.lines().find_map(completed_scan_run).map_or(
        SystemScanHistory::NoCompletedRun,
        SystemScanHistory::CompletedRun,
    )
}

async fn newest_service_run(service_unit: &str) -> SystemScanHistory {
    let mut journal_command = Command::new("journalctl");
    journal_command
        .arg("--unit")
        .arg(service_unit)
        .arg("_PID=1")
        .args([
            "--output=json",
            "--output-fields=MESSAGE_ID,EXIT_CODE,EXIT_STATUS",
            "--reverse",
            "--no-pager",
            "--quiet",
            "--lines",
            JOURNAL_RECORD_LIMIT,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    match timeout(JOURNAL_TIMEOUT, journal_command.output()).await {
        Ok(Ok(journal_output)) if journal_output.status.success() => {
            newest_run_in_journal(&String::from_utf8_lossy(&journal_output.stdout))
        }
        _unreadable_journal => SystemScanHistory::NoCompletedRun,
    }
}

pub async fn newest_system_scan_run() -> SystemScanHistory {
    newest_service_run(SYSTEM_SCAN_UNIT).await
}

#[cfg(test)]
mod system_scan_journal_tests {
    use super::*;

    const CLEAN_RUN_RECORD: &str = r#"{"__REALTIME_TIMESTAMP":"1793872800860146","_PID":"1","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","UNIT":"clamdscan.service"}"#;
    const VIRUS_FOUND_RECORD: &str = r#"{"EXIT_STATUS":"1","EXIT_CODE":"exited","__REALTIME_TIMESTAMP":"1793653012260843","MESSAGE_ID":"98e322203f7a4ed290d09fe03c09fe15","_PID":"1"}"#;
    const SCANNER_ERROR_RECORD: &str = r#"{"EXIT_STATUS":"2","EXIT_CODE":"exited","__REALTIME_TIMESTAMP":"1793900000000000","MESSAGE_ID":"98e322203f7a4ed290d09fe03c09fe15","_PID":"1"}"#;
    const SCANNER_KILLED_RECORD: &str = r#"{"EXIT_STATUS":"1","EXIT_CODE":"killed","__REALTIME_TIMESTAMP":"1793900000000000","MESSAGE_ID":"98e322203f7a4ed290d09fe03c09fe15","_PID":"1"}"#;
    const UNIT_FINISHED_RECORD: &str = r#"{"__REALTIME_TIMESTAMP":"1793900000000000","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","_PID":"1"}"#;
    const BINARY_FIELD_RECORD: &str =
        r#"{"__REALTIME_TIMESTAMP":"1793900000000000","MESSAGE_ID":[55,97]}"#;

    #[test]
    fn a_deactivated_unit_is_a_clean_run() {
        assert_eq!(
            newest_run_in_journal(CLEAN_RUN_RECORD),
            SystemScanHistory::CompletedRun(SystemScanRun {
                finished_at_unix: 1_793_872_800,
                threats_found: false,
            })
        );
    }

    #[test]
    fn exit_status_one_is_a_completed_run_with_threats() {
        assert_eq!(
            newest_run_in_journal(VIRUS_FOUND_RECORD),
            SystemScanHistory::CompletedRun(SystemScanRun {
                finished_at_unix: 1_793_653_012,
                threats_found: true,
            })
        );
    }

    #[test]
    fn errors_and_kills_do_not_count_as_completed_runs() {
        [
            SCANNER_ERROR_RECORD,
            SCANNER_KILLED_RECORD,
            UNIT_FINISHED_RECORD,
            BINARY_FIELD_RECORD,
            "",
            "not json",
        ]
        .into_iter()
        .for_each(|journal_line| {
            assert_eq!(
                newest_run_in_journal(journal_line),
                SystemScanHistory::NoCompletedRun,
                "{journal_line}"
            );
        });
    }

    #[test]
    fn a_failed_newest_run_falls_back_to_the_last_completed_run() {
        assert_eq!(
            newest_run_in_journal(&format!("{SCANNER_ERROR_RECORD}\n{CLEAN_RUN_RECORD}\n")),
            SystemScanHistory::CompletedRun(SystemScanRun {
                finished_at_unix: 1_793_872_800,
                threats_found: false,
            })
        );
    }

    #[tokio::test]
    #[ignore = "needs a host where clamav-freshclam.service ran from a timer"]
    async fn host_journal_reports_the_real_service_run() {
        assert!(matches!(
            newest_service_run("clamav-freshclam.service").await,
            SystemScanHistory::CompletedRun(SystemScanRun {
                threats_found: false,
                ..
            })
        ));
    }
}
