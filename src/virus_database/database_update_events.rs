use std::{
    os::unix::process::CommandExt,
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::{
    Stream, StreamExt,
    future::{Either, ready},
    stream,
};
use tokio::{process::Command, task::spawn_blocking};

use crate::{
    malware_scan::scanner_process_events::{
        RetainedScannerFiles, ScanStartFailure, ScannerProcessEvent, scanner_process_events,
    },
    systemd_journal::unit_journal_reader::unit_messages_since,
    virus_database::database_directory_status::FreshclamServiceState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseUpdatePlan {
    SignalRunningDaemon { service_unit: &'static str },
    StartServiceUnit { service_unit: &'static str },
    RunFreshclamDirectly,
}

#[derive(Debug)]
pub enum DatabaseUpdateEvent {
    UpdateOutputLine(String),
    UpdaterExited { exit_code: i32 },
    UpdaterUnstartable(ScanStartFailure),
}

pub fn plan_database_update(service_state: FreshclamServiceState) -> DatabaseUpdatePlan {
    match service_state {
        FreshclamServiceState::DaemonRunning { service_unit } => {
            DatabaseUpdatePlan::SignalRunningDaemon { service_unit }
        }
        FreshclamServiceState::TimerScheduled { service_unit }
        | FreshclamServiceState::ServiceStopped { service_unit } => {
            DatabaseUpdatePlan::StartServiceUnit { service_unit }
        }
        FreshclamServiceState::ServiceNotFound => DatabaseUpdatePlan::RunFreshclamDirectly,
    }
}

fn update_command_arguments(update_plan: DatabaseUpdatePlan) -> Vec<String> {
    match update_plan {
        DatabaseUpdatePlan::SignalRunningDaemon { service_unit } => vec![
            "systemctl".to_owned(),
            "kill".to_owned(),
            "--signal=SIGUSR1".to_owned(),
            format!("{service_unit}.service"),
        ],
        DatabaseUpdatePlan::StartServiceUnit { service_unit } => vec![
            "systemctl".to_owned(),
            "start".to_owned(),
            format!("{service_unit}.service"),
        ],
        DatabaseUpdatePlan::RunFreshclamDirectly => {
            vec!["freshclam".to_owned(), "--verbose".to_owned()]
        }
    }
}

fn build_update_command(update_plan: DatabaseUpdatePlan) -> Command {
    let command_arguments = update_command_arguments(update_plan);
    let mut update_command = std::process::Command::new(&command_arguments[0]);
    update_command
        .args(&command_arguments[1..])
        .stdin(Stdio::null())
        .process_group(0);
    Command::from(update_command)
}

fn lossy_output_line(output_line: &[u8]) -> String {
    String::from_utf8_lossy(output_line).into_owned()
}

fn update_event_from_process(process_event: ScannerProcessEvent) -> DatabaseUpdateEvent {
    match process_event {
        ScannerProcessEvent::ReportLine(output_line)
        | ScannerProcessEvent::DiagnosticLine(output_line) => {
            DatabaseUpdateEvent::UpdateOutputLine(lossy_output_line(&output_line))
        }
        ScannerProcessEvent::Exited(exit_status) => DatabaseUpdateEvent::UpdaterExited {
            exit_code: exit_status
                .ok()
                .and_then(|exit_status| exit_status.code())
                .unwrap_or(-1),
        },
    }
}

async fn service_journal_lines(service_unit: &'static str, started_after: u64) -> Vec<String> {
    spawn_blocking(move || unit_messages_since(&format!("{service_unit}.service"), started_after))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn database_update_events(
    update_plan: DatabaseUpdatePlan,
) -> impl Stream<Item = DatabaseUpdateEvent> + Send + 'static {
    let started_after = current_unix_seconds();
    let journal_lines = stream::once(async move {
        match update_plan {
            DatabaseUpdatePlan::StartServiceUnit { service_unit } => {
                service_journal_lines(service_unit, started_after).await
            }
            DatabaseUpdatePlan::SignalRunningDaemon { .. }
            | DatabaseUpdatePlan::RunFreshclamDirectly => Vec::new(),
        }
    })
    .flat_map(stream::iter)
    .map(DatabaseUpdateEvent::UpdateOutputLine);
    match scanner_process_events(
        build_update_command(update_plan),
        RetainedScannerFiles::NoRetainedFiles,
    ) {
        Ok(process_events) => Either::Left(
            process_events
                .map(update_event_from_process)
                .chain(journal_lines),
        ),
        Err(start_failure) => Either::Right(stream::once(ready(
            DatabaseUpdateEvent::UpdaterUnstartable(start_failure),
        ))),
    }
}

#[cfg(test)]
mod database_update_events_tests {
    use super::*;

    #[test]
    fn running_daemons_are_signalled_and_idle_units_are_started() {
        assert_eq!(
            plan_database_update(FreshclamServiceState::DaemonRunning {
                service_unit: "clamav-freshclam"
            }),
            DatabaseUpdatePlan::SignalRunningDaemon {
                service_unit: "clamav-freshclam"
            }
        );
        assert_eq!(
            plan_database_update(FreshclamServiceState::TimerScheduled {
                service_unit: "clamav-freshclam"
            }),
            DatabaseUpdatePlan::StartServiceUnit {
                service_unit: "clamav-freshclam"
            }
        );
        assert_eq!(
            plan_database_update(FreshclamServiceState::ServiceNotFound),
            DatabaseUpdatePlan::RunFreshclamDirectly
        );
    }

    #[test]
    fn no_plan_elevates_freshclam_itself() {
        [
            DatabaseUpdatePlan::SignalRunningDaemon {
                service_unit: "clamav-freshclam",
            },
            DatabaseUpdatePlan::StartServiceUnit {
                service_unit: "clamav-freshclam",
            },
            DatabaseUpdatePlan::RunFreshclamDirectly,
        ]
        .into_iter()
        .for_each(|update_plan| {
            let command_arguments = update_command_arguments(update_plan);
            assert_ne!(command_arguments[0], "pkexec");
            assert_ne!(command_arguments[0], "sudo");
            assert!(
                !command_arguments
                    .iter()
                    .any(|command_argument| command_argument.starts_with("--config-file"))
            );
        });
    }
}
