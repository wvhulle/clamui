use std::{os::unix::process::CommandExt, process::Stdio};

use futures::{Stream, StreamExt, future::ready, stream};
use jiff::Timestamp;
use tokio::process::Command;

use crate::{
    host_services::{
        clamav_programs::{
            database_directory_status::FreshclamServiceState,
            signature_provider_catalogue::hide_addresses_in_text,
            trusted_program_lookup::{ClamavProgram, ProgramRefusal, locate_trusted_program},
        },
        clamav_scanner::scanner_process_events::{
            RetainedScannerFiles, ScanStartFailure, ScannerProcessEvent, scanner_process_events,
        },
        desktop::flatpak_sandbox::host_program_command,
        systemd_bus::host_systemd_units::{
            UnitStartOutcome, UnitState, probe_unit_state, signal_system_unit, start_system_unit,
        },
        systemd_journal::unit_journal_reader::{
            UnitJournalReadFailure, read_journal_off_thread, unit_messages_since,
        },
    },
    signatures::database_updates_page::signature_update_run::updater_exit_status::{
        FreshclamExit, classify_freshclam_wait,
    },
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
pub enum UpdaterFinish {
    FreshclamExited(FreshclamExit),
    ServiceUnitRan(UnitStartOutcome),
    RunningDaemonSignalled(UnitStartOutcome),
    UpdaterNeverStarted(ScanStartFailure),
}

#[derive(Debug)]
pub enum DatabaseUpdateEvent {
    UpdateOutputLine(String),
    UpdateOutputUnreadable(UnitJournalReadFailure),
    UpdaterFinished(UpdaterFinish),
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
        FreshclamServiceState::ServiceNotFound | FreshclamServiceState::SystemdUnreachable => {
            DatabaseUpdatePlan::RunFreshclamDirectly
        }
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

fn lossy_output_line(output_line: &[u8]) -> String {
    String::from_utf8_lossy(output_line).into_owned()
}

fn update_event_from_process(process_event: ScannerProcessEvent) -> DatabaseUpdateEvent {
    match process_event {
        ScannerProcessEvent::ReportLine(output_line)
        | ScannerProcessEvent::DiagnosticLine(output_line) => {
            DatabaseUpdateEvent::UpdateOutputLine(lossy_output_line(&output_line))
        }
        ScannerProcessEvent::Exited(wait_outcome) => DatabaseUpdateEvent::UpdaterFinished(
            UpdaterFinish::FreshclamExited(classify_freshclam_wait(wait_outcome)),
        ),
    }
}

pub fn output_events_from_journal(
    journal_reading: Result<Vec<String>, UnitJournalReadFailure>,
) -> Vec<DatabaseUpdateEvent> {
    match journal_reading {
        Ok(output_lines) => output_lines
            .iter()
            .map(|output_line| {
                DatabaseUpdateEvent::UpdateOutputLine(hide_addresses_in_text(output_line))
            })
            .collect(),
        Err(read_failure) => vec![DatabaseUpdateEvent::UpdateOutputUnreadable(read_failure)],
    }
}

async fn service_output_events(
    service_unit: &'static str,
    started_after: Timestamp,
) -> Vec<DatabaseUpdateEvent> {
    output_events_from_journal(
        read_journal_off_thread(move || {
            unit_messages_since(&format!("{service_unit}.service"), started_after)
        })
        .await,
    )
}

async fn third_party_output_events(started_after: Timestamp) -> Vec<DatabaseUpdateEvent> {
    if !matches!(
        probe_unit_state(FANGFRISCH_SERVICE_UNIT).await,
        UnitState::UnitLoaded(_)
    ) {
        return Vec::new();
    }
    let _fangfrisch_outcome = start_system_unit(FANGFRISCH_SERVICE_UNIT).await;
    service_output_events(FANGFRISCH_UNIT_NAME, started_after).await
}

pub fn database_update_events(
    update_plan: DatabaseUpdatePlan,
) -> impl Stream<Item = DatabaseUpdateEvent> + Send + 'static {
    let started_after = Timestamp::now();
    match update_plan {
        DatabaseUpdatePlan::SignalRunningDaemon { service_unit } => stream::once(async move {
            DatabaseUpdateEvent::UpdaterFinished(UpdaterFinish::RunningDaemonSignalled(
                signal_system_unit(&format!("{service_unit}.service"), UPDATE_NOW_SIGNAL).await,
            ))
        })
        .boxed(),
        DatabaseUpdatePlan::StartServiceUnit { service_unit } => stream::once(async move {
            let unit_outcome = start_system_unit(&format!("{service_unit}.service")).await;
            service_output_events(service_unit, started_after)
                .await
                .into_iter()
                .chain(third_party_output_events(started_after).await)
                .chain(std::iter::once(DatabaseUpdateEvent::UpdaterFinished(
                    UpdaterFinish::ServiceUnitRan(unit_outcome),
                )))
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
            Err(start_failure) => stream::once(ready(DatabaseUpdateEvent::UpdaterFinished(
                UpdaterFinish::UpdaterNeverStarted(start_failure),
            )))
            .boxed(),
        },
    }
}

#[cfg(test)]
mod database_update_events_tests {
    use super::*;

    #[test]
    fn an_unreadable_service_journal_is_reported_instead_of_no_output() {
        let read_failure = UnitJournalReadFailure::ReadingTaskInterrupted;
        assert!(matches!(
            output_events_from_journal(Err(read_failure)).as_slice(),
            [DatabaseUpdateEvent::UpdateOutputUnreadable(
                UnitJournalReadFailure::ReadingTaskInterrupted
            )]
        ));
        assert!(output_events_from_journal(Ok(Vec::new())).is_empty());
    }

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
        assert_eq!(
            plan_database_update(FreshclamServiceState::SystemdUnreachable),
            DatabaseUpdatePlan::RunFreshclamDirectly
        );
    }
}
