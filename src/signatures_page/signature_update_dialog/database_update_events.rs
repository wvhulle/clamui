use std::{
    os::unix::process::CommandExt,
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::{Stream, StreamExt, future::ready, stream};
use tokio::{process::Command, task::spawn_blocking};

use crate::{
    host_services::{
        clamav_programs::{
            database_directory_status::FreshclamServiceState,
            trusted_program_lookup::{ClamavProgram, ProgramRefusal, locate_trusted_program},
        },
        clamav_scanner::scanner_process_events::{
            RetainedScannerFiles, ScanStartFailure, ScannerProcessEvent, scanner_process_events,
        },
        desktop::flatpak_sandbox::host_program_command,
        systemd_bus::host_systemd_units::{
            UnitStartOutcome, UnitState, probe_unit_state, signal_system_unit, start_system_unit,
        },
        systemd_journal::unit_journal_reader::unit_messages_since,
    },
    signatures_page::signature_provider_catalogue::hide_addresses_in_text,
};

const UPDATE_NOW_SIGNAL: i32 = 10;
const FANGFRISCH_UNIT_NAME: &str = "clamav-fangfrisch";
const FANGFRISCH_SERVICE_UNIT: &str = "clamav-fangfrisch.service";

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

fn build_freshclam_command() -> Result<Command, ProgramRefusal> {
    let mut update_command = host_program_command(
        locate_trusted_program(ClamavProgram::SignatureUpdater).runnable_path()?,
        &[],
    );
    update_command
        .arg("--verbose")
        .stdin(Stdio::null())
        .process_group(0);
    Ok(Command::from(update_command))
}

fn events_from_unit_outcome(start_outcome: UnitStartOutcome) -> Vec<DatabaseUpdateEvent> {
    let exited_cleanly = DatabaseUpdateEvent::UpdaterExited { exit_code: 0 };
    let exited_with_failure = DatabaseUpdateEvent::UpdaterExited { exit_code: 1 };
    match start_outcome {
        UnitStartOutcome::UnitFinished => vec![exited_cleanly],
        UnitStartOutcome::JobEnded { job_result } => vec![
            DatabaseUpdateEvent::UpdateOutputLine(format!("service job ended: {job_result}")),
            exited_with_failure,
        ],
        UnitStartOutcome::AuthorizationRefused => vec![
            DatabaseUpdateEvent::UpdateOutputLine("access denied".to_owned()),
            exited_with_failure,
        ],
        UnitStartOutcome::BusFailure { failure_text } => vec![
            DatabaseUpdateEvent::UpdateOutputLine(failure_text),
            exited_with_failure,
        ],
    }
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

async fn third_party_update_lines(started_after: u64) -> Vec<String> {
    if !matches!(
        probe_unit_state(FANGFRISCH_SERVICE_UNIT).await,
        UnitState::UnitActive | UnitState::UnitInactive
    ) {
        return Vec::new();
    }
    let outcome_line = match start_system_unit(FANGFRISCH_SERVICE_UNIT).await {
        UnitStartOutcome::UnitFinished => "fangfrisch finished".to_owned(),
        UnitStartOutcome::JobEnded { job_result } => format!("fangfrisch ended: {job_result}"),
        UnitStartOutcome::AuthorizationRefused => "fangfrisch: access denied".to_owned(),
        UnitStartOutcome::BusFailure { failure_text } => format!("fangfrisch: {failure_text}"),
    };
    service_journal_lines(FANGFRISCH_UNIT_NAME, started_after)
        .await
        .into_iter()
        .chain(std::iter::once(outcome_line))
        .collect()
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
    match update_plan {
        DatabaseUpdatePlan::SignalRunningDaemon { service_unit } => stream::once(async move {
            events_from_unit_outcome(
                signal_system_unit(&format!("{service_unit}.service"), UPDATE_NOW_SIGNAL).await,
            )
        })
        .flat_map(stream::iter)
        .boxed(),
        DatabaseUpdatePlan::StartServiceUnit { service_unit } => stream::once(async move {
            let unit_events = events_from_unit_outcome(
                start_system_unit(&format!("{service_unit}.service")).await,
            );
            service_journal_lines(service_unit, started_after)
                .await
                .into_iter()
                .chain(third_party_update_lines(started_after).await)
                .map(|output_line| {
                    DatabaseUpdateEvent::UpdateOutputLine(hide_addresses_in_text(&output_line))
                })
                .chain(unit_events)
                .collect::<Vec<_>>()
        })
        .flat_map(stream::iter)
        .boxed(),
        DatabaseUpdatePlan::RunFreshclamDirectly => match build_freshclam_command()
            .map_err(ScanStartFailure::from)
            .and_then(|freshclam_command| {
                scanner_process_events(freshclam_command, RetainedScannerFiles::NoRetainedFiles)
            }) {
            Ok(process_events) => process_events.map(update_event_from_process).boxed(),
            Err(start_failure) => stream::once(ready(DatabaseUpdateEvent::UpdaterUnstartable(
                start_failure,
            )))
            .boxed(),
        },
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
    fn a_refused_authorization_is_reported_as_a_failed_update() {
        let refused_events = events_from_unit_outcome(UnitStartOutcome::AuthorizationRefused);
        assert!(matches!(
            refused_events.as_slice(),
            [
                DatabaseUpdateEvent::UpdateOutputLine(_),
                DatabaseUpdateEvent::UpdaterExited { exit_code: 1 }
            ]
        ));
    }

    #[test]
    fn a_finished_unit_is_a_clean_exit() {
        assert!(matches!(
            events_from_unit_outcome(UnitStartOutcome::UnitFinished).as_slice(),
            [DatabaseUpdateEvent::UpdaterExited { exit_code: 0 }]
        ));
    }
}
