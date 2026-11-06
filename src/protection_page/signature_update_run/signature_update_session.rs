use std::time::{Instant, SystemTime};

use gettextrs::{gettext, ngettext};
use jiff::Timestamp;

use crate::{
    host_services::{
        activity_history::activity_history_database::{ActivityStatus, NewActivityEntry},
        clamav_programs::{
            component_availability::{ProgramProbe, probe_located_program_version},
            database_directory_status::{
                DatabaseDirectoryStatus, FreshclamServiceState, configured_database_directory,
                detect_freshclam_service, inspect_database_directory,
            },
            trusted_program_lookup::{ClamavProgram, ProgramLocation, locate_trusted_program},
        },
        clamav_scanner::{
            scanner_output_parser::{sanitize_scanner_line, sanitize_scanner_text},
            scanner_process_events::ScanStartFailure,
        },
    },
    protection_page::signature_update_run::{
        database_update_events::{DatabaseUpdateEvent, DatabaseUpdatePlan, plan_database_update},
        freshclam_output_parser::{
            DatabaseUpdateOutcome, FreshclamReportSummary, RateLimitCooldown, UpdateFailureReason,
            interpret_update_exit,
        },
    },
    shared_widgets::component_streams::RunningStream,
};

const TRANSCRIPT_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct DatabaseHostStatus {
    freshclam_probe: ProgramProbe,
    service_state: FreshclamServiceState,
    directory_status: DatabaseDirectoryStatus,
}

enum ObservedUpdateExit {
    ExitNotObserved,
    ExitObserved { exit_code: i32 },
    NeverStarted(ScanStartFailure),
}

#[derive(Clone, Copy)]
struct UpdateTiming {
    started_at: Timestamp,
    started_instant: Instant,
}

impl UpdateTiming {
    fn starting_now() -> Self {
        Self {
            started_at: Timestamp::now(),
            started_instant: Instant::now(),
        }
    }
}

enum DatabaseUpdateState {
    NoActiveUpdate,
    UpdateRunning {
        update_plan: DatabaseUpdatePlan,
        update_timing: UpdateTiming,
        _update_stream: RunningStream,
    },
    CancellingUpdate {
        update_timing: UpdateTiming,
    },
}

enum HostStatusView {
    StatusLoading,
    StatusLoaded(DatabaseHostStatus),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureUpdateProgress {
    UpdateUnavailable,
    ReadyToUpdate,
    UpdateRunning {
        latest_output_line: String,
        cancellable: bool,
    },
    UpdateCancelling,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LastManualUpdate {
    NotRunThisSession,
    FinishedAt {
        summary_line: String,
        finished_at: Timestamp,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownUpdateHost {
    pub update_progress: SignatureUpdateProgress,
    pub last_manual_update: LastManualUpdate,
    pub update_service_text: String,
    pub database_folder_text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureUpdateView {
    HostStatusLoading,
    HostStatusKnown(KnownUpdateHost),
}

pub struct FinishedUpdateReport {
    pub summary_text: String,
    pub definitions_changed: bool,
    pub activity_entry: NewActivityEntry,
}

fn service_description(service_state: FreshclamServiceState) -> String {
    match service_state {
        FreshclamServiceState::DaemonRunning { .. } => gettext("Active"),
        FreshclamServiceState::TimerScheduled { .. } => gettext("Scheduled by a systemd timer"),
        FreshclamServiceState::ServiceStopped { .. } => gettext("Installed but stopped"),
        FreshclamServiceState::ServiceNotFound => {
            gettext("No freshclam service detected; updates run manually")
        }
    }
}

fn directory_description(directory_status: &DatabaseDirectoryStatus) -> String {
    match directory_status {
        DatabaseDirectoryStatus::DefinitionsAvailable {
            newest_definition_age_days,
            ..
        } => ngettext(
            "{count} day old",
            "{count} days old",
            u32::try_from(*newest_definition_age_days).unwrap_or(u32::MAX),
        )
        .replace("{count}", &newest_definition_age_days.to_string()),
        DatabaseDirectoryStatus::DefinitionsMissing { .. } => {
            gettext("No readable virus database was found")
        }
    }
}

fn directory_path_text(directory_status: &DatabaseDirectoryStatus) -> String {
    match directory_status {
        DatabaseDirectoryStatus::DefinitionsAvailable {
            database_directory, ..
        }
        | DatabaseDirectoryStatus::DefinitionsMissing { database_directory } => {
            sanitize_scanner_line(&database_directory.to_string_lossy())
        }
    }
}

fn describe_failure_reason(failure_reason: &UpdateFailureReason) -> String {
    match failure_reason {
        UpdateFailureReason::AuthenticationCancelled => {
            gettext("Authentication cancelled. Database update requires administrator privileges.")
        }
        UpdateFailureReason::NotAuthorized => {
            gettext("Authorization failed. Please try again and enter your password.")
        }
        UpdateFailureReason::RateLimitedDatabases | UpdateFailureReason::RateLimitedByMirror => {
            gettext("Update rate limited by mirror. Please wait a few minutes and try again.")
        }
        UpdateFailureReason::BlockedByCdn => gettext(
            "Update blocked by CDN. This may be due to rate limiting. Please wait and try again \
             later.",
        ),
        UpdateFailureReason::MirrorUnavailable => {
            gettext("ClamAV mirror is currently unavailable. Please try again later.")
        }
        UpdateFailureReason::CertificateRejected => {
            gettext("SSL/TLS certificate error. The mirror may have configuration issues.")
        }
        UpdateFailureReason::ConnectionTimedOut => {
            gettext("Connection timed out. Please check your network connection.")
        }
        UpdateFailureReason::DatabaseLocked => {
            gettext("Database is locked. Another freshclam instance may be running.")
        }
        UpdateFailureReason::PermissionDenied => {
            gettext("Permission denied. You may need elevated privileges to update the database.")
        }
        UpdateFailureReason::ConnectionFailed => {
            gettext("Connection error. Please check your network connection.")
        }
        UpdateFailureReason::NameResolutionFailed => {
            gettext("DNS resolution failed. Please check your network settings.")
        }
        UpdateFailureReason::ReportedByUpdater { diagnostic_text } => {
            sanitize_scanner_text(diagnostic_text)
        }
        UpdateFailureReason::UnexplainedFailure => {
            gettext("Update failed with an unknown error. Check the logs for details.")
        }
    }
}

fn describe_report_summary(report_summary: &FreshclamReportSummary) -> Vec<String> {
    let updated_line = (!report_summary.updated_databases.is_empty()).then(|| {
        gettext("Updated: {databases}")
            .replace("{databases}", &report_summary.updated_databases.join(", "))
    });
    let current_line = (!report_summary.current_databases.is_empty()).then(|| {
        gettext("Already current: {databases}")
            .replace("{databases}", &report_summary.current_databases.join(", "))
    });
    let rate_limited_lines =
        report_summary
            .rate_limited_databases
            .iter()
            .map(
                |rate_limited_database| match &rate_limited_database.rate_limit_cooldown {
                    RateLimitCooldown::CooldownUnknown => gettext("Rate limited: {database}")
                        .replace("{database}", &rate_limited_database.database_name),
                    RateLimitCooldown::CooldownUntil { cooldown_text } => {
                        gettext("Rate limited: {database} until {cooldown}")
                            .replace("{database}", &rate_limited_database.database_name)
                            .replace("{cooldown}", &sanitize_scanner_line(cooldown_text))
                    }
                },
            );
    updated_line
        .into_iter()
        .chain(current_line)
        .chain(rate_limited_lines)
        .map(|summary_line| sanitize_scanner_line(&summary_line))
        .collect()
}

fn describe_update_outcome(update_outcome: &DatabaseUpdateOutcome) -> String {
    let (headline, report_summary) = match update_outcome {
        DatabaseUpdateOutcome::DefinitionsUpdated(report_summary) => {
            (gettext("Database update completed"), report_summary)
        }
        DatabaseUpdateOutcome::AlreadyCurrent(report_summary) => {
            (gettext("Database is already up to date"), report_summary)
        }
        DatabaseUpdateOutcome::UpdateFailed {
            failure_reason,
            report_summary,
        } => (describe_failure_reason(failure_reason), report_summary),
    };
    [headline]
        .into_iter()
        .chain(describe_report_summary(report_summary))
        .collect::<Vec<_>>()
        .join("\n")
}

fn describe_start_failure(start_failure: &ScanStartFailure) -> String {
    match start_failure {
        ScanStartFailure::ScannerProgramMissing => {
            gettext("Install freshclam before requesting database updates.")
        }
        other_failure => other_failure.to_string(),
    }
}

pub async fn load_host_status() -> DatabaseHostStatus {
    let freshclam_location =
        tokio::task::spawn_blocking(|| locate_trusted_program(ClamavProgram::SignatureUpdater))
            .await
            .unwrap_or(ProgramLocation::ProgramNotFound);
    let freshclam_probe = probe_located_program_version(&freshclam_location).await;
    let service_state = detect_freshclam_service().await;
    let directory_status = tokio::task::spawn_blocking(|| {
        inspect_database_directory(&configured_database_directory(), SystemTime::now())
    })
    .await
    .unwrap_or_else(
        |_interrupted_inspection| DatabaseDirectoryStatus::DefinitionsMissing {
            database_directory: configured_database_directory(),
        },
    );
    DatabaseHostStatus {
        freshclam_probe,
        service_state,
        directory_status,
    }
}

pub struct SignatureUpdateSession {
    host_status: HostStatusView,
    update_state: DatabaseUpdateState,
    observed_exit: ObservedUpdateExit,
    update_transcript: String,
    latest_output_line: String,
    last_manual_update: LastManualUpdate,
}

impl SignatureUpdateSession {
    pub fn new() -> Self {
        Self {
            host_status: HostStatusView::StatusLoading,
            update_state: DatabaseUpdateState::NoActiveUpdate,
            observed_exit: ObservedUpdateExit::ExitNotObserved,
            update_transcript: String::new(),
            latest_output_line: String::new(),
            last_manual_update: LastManualUpdate::NotRunThisSession,
        }
    }

    const fn loaded_status(&self) -> Option<&DatabaseHostStatus> {
        match &self.host_status {
            HostStatusView::StatusLoaded(host_status) => Some(host_status),
            HostStatusView::StatusLoading => None,
        }
    }

    pub const fn host_status_known(&self) -> bool {
        self.loaded_status().is_some()
    }

    pub fn host_status_loaded(&mut self, host_status: DatabaseHostStatus) {
        self.host_status = HostStatusView::StatusLoaded(host_status);
    }

    const fn update_is_active(&self) -> bool {
        !matches!(self.update_state, DatabaseUpdateState::NoActiveUpdate)
    }

    fn can_request_update(&self) -> bool {
        !self.update_is_active()
            && self.loaded_status().is_some_and(|host_status| {
                !matches!(
                    host_status.service_state,
                    FreshclamServiceState::ServiceNotFound
                ) || matches!(
                    host_status.freshclam_probe,
                    ProgramProbe::VersionReported { .. }
                )
            })
    }

    pub fn requested_update_plan(&self) -> Option<DatabaseUpdatePlan> {
        if !self.can_request_update() {
            return None;
        }
        self.loaded_status()
            .map(|host_status| plan_database_update(host_status.service_state))
    }

    pub fn update_started(
        &mut self,
        update_plan: DatabaseUpdatePlan,
        update_stream: RunningStream,
    ) {
        self.update_transcript.clear();
        self.latest_output_line = gettext("Starting the update…");
        self.observed_exit = ObservedUpdateExit::ExitNotObserved;
        self.update_state = DatabaseUpdateState::UpdateRunning {
            update_plan,
            update_timing: UpdateTiming::starting_now(),
            _update_stream: update_stream,
        };
    }

    pub fn cancel_requested(&mut self) {
        if let DatabaseUpdateState::UpdateRunning {
            update_plan: DatabaseUpdatePlan::RunFreshclamDirectly,
            update_timing,
            ..
        } = self.update_state
        {
            self.update_state = DatabaseUpdateState::CancellingUpdate { update_timing };
        }
    }

    const fn update_is_cancelling(&self) -> bool {
        matches!(
            self.update_state,
            DatabaseUpdateState::CancellingUpdate { .. }
        )
    }

    fn running_update_timing(&self) -> UpdateTiming {
        match self.update_state {
            DatabaseUpdateState::UpdateRunning { update_timing, .. }
            | DatabaseUpdateState::CancellingUpdate { update_timing } => update_timing,
            DatabaseUpdateState::NoActiveUpdate => UpdateTiming::starting_now(),
        }
    }

    fn append_transcript_line(&mut self, output_line: &str) {
        let displayed_line = sanitize_scanner_line(output_line);
        if !displayed_line.trim().is_empty() {
            self.latest_output_line = displayed_line.trim().to_owned();
        }
        if self.update_transcript.len() + displayed_line.len() < TRANSCRIPT_LIMIT {
            self.update_transcript.push_str(&displayed_line);
            self.update_transcript.push('\n');
        }
    }

    pub fn absorb_update_batch(&mut self, update_batch: Vec<DatabaseUpdateEvent>) {
        update_batch
            .into_iter()
            .for_each(|update_event| match update_event {
                DatabaseUpdateEvent::UpdateOutputLine(output_line) => {
                    self.append_transcript_line(&output_line);
                }
                DatabaseUpdateEvent::UpdaterExited { exit_code } => {
                    self.observed_exit = ObservedUpdateExit::ExitObserved { exit_code };
                }
                DatabaseUpdateEvent::UpdaterUnstartable(start_failure) => {
                    self.observed_exit = ObservedUpdateExit::NeverStarted(start_failure);
                }
            });
    }

    fn finished_update_status(&self) -> ActivityStatus {
        match (&self.update_state, &self.observed_exit) {
            (DatabaseUpdateState::CancellingUpdate { .. }, _any_exit) => {
                ActivityStatus::UpdateCancelled
            }
            (
                _any_state,
                ObservedUpdateExit::NeverStarted(_) | ObservedUpdateExit::ExitNotObserved,
            ) => ActivityStatus::UpdateFailed,
            (
                DatabaseUpdateState::UpdateRunning {
                    update_plan: DatabaseUpdatePlan::SignalRunningDaemon { .. },
                    ..
                },
                ObservedUpdateExit::ExitObserved { exit_code: 0 },
            ) => ActivityStatus::UpdateRequested,
            (_any_state, ObservedUpdateExit::ExitObserved { exit_code }) => {
                match interpret_update_exit(&self.update_transcript, *exit_code) {
                    DatabaseUpdateOutcome::DefinitionsUpdated(_) => ActivityStatus::UpdateApplied,
                    DatabaseUpdateOutcome::AlreadyCurrent(_) => {
                        ActivityStatus::UpdateAlreadyCurrent
                    }
                    DatabaseUpdateOutcome::UpdateFailed { .. } => ActivityStatus::UpdateFailed,
                }
            }
        }
    }

    fn finished_update_summary(&self) -> String {
        match (&self.update_state, &self.observed_exit) {
            (DatabaseUpdateState::CancellingUpdate { .. }, _any_exit) => {
                gettext("Database update cancelled")
            }
            (_any_state, ObservedUpdateExit::NeverStarted(start_failure)) => {
                describe_start_failure(start_failure)
            }
            (
                DatabaseUpdateState::UpdateRunning {
                    update_plan: DatabaseUpdatePlan::SignalRunningDaemon { .. },
                    ..
                },
                ObservedUpdateExit::ExitObserved { exit_code: 0 },
            ) => gettext(
                "The service accepted the signal; it performs the update asynchronously. Check \
                 its logs for completion.",
            ),
            (_any_state, ObservedUpdateExit::ExitObserved { exit_code }) => {
                describe_update_outcome(&interpret_update_exit(&self.update_transcript, *exit_code))
            }
            (_any_state, ObservedUpdateExit::ExitNotObserved) => {
                gettext("Update failed with an unknown error. Check the logs for details.")
            }
        }
    }

    pub fn update_finished(&mut self) -> FinishedUpdateReport {
        let summary_text = self.finished_update_summary();
        let definitions_changed = matches!(
            self.observed_exit,
            ObservedUpdateExit::ExitObserved { exit_code: 0 }
        ) && !self.update_is_cancelling();
        let update_timing = self.running_update_timing();
        let activity_entry = NewActivityEntry {
            started_at: update_timing.started_at,
            activity_status: self.finished_update_status(),
            activity_targets: String::new(),
            inspected_file_count: 0,
            threat_count: 0,
            duration_millis: u64::try_from(update_timing.started_instant.elapsed().as_millis())
                .unwrap_or(u64::MAX),
            activity_output: std::mem::take(&mut self.update_transcript),
        };
        self.last_manual_update = LastManualUpdate::FinishedAt {
            summary_line: summary_text.lines().next().unwrap_or_default().to_owned(),
            finished_at: Timestamp::now(),
        };
        self.update_state = DatabaseUpdateState::NoActiveUpdate;
        FinishedUpdateReport {
            summary_text,
            definitions_changed,
            activity_entry,
        }
    }

    fn update_progress(&self) -> SignatureUpdateProgress {
        match &self.update_state {
            DatabaseUpdateState::UpdateRunning { update_plan, .. } => {
                SignatureUpdateProgress::UpdateRunning {
                    latest_output_line: self.latest_output_line.clone(),
                    cancellable: *update_plan == DatabaseUpdatePlan::RunFreshclamDirectly,
                }
            }
            DatabaseUpdateState::CancellingUpdate { .. } => {
                SignatureUpdateProgress::UpdateCancelling
            }
            DatabaseUpdateState::NoActiveUpdate if self.can_request_update() => {
                SignatureUpdateProgress::ReadyToUpdate
            }
            DatabaseUpdateState::NoActiveUpdate => SignatureUpdateProgress::UpdateUnavailable,
        }
    }

    pub fn update_view(&self) -> SignatureUpdateView {
        let Some(host_status) = self.loaded_status() else {
            return SignatureUpdateView::HostStatusLoading;
        };
        SignatureUpdateView::HostStatusKnown(KnownUpdateHost {
            update_progress: self.update_progress(),
            last_manual_update: self.last_manual_update.clone(),
            update_service_text: service_description(host_status.service_state),
            database_folder_text: format!(
                "{}\n{}",
                directory_path_text(&host_status.directory_status),
                directory_description(&host_status.directory_status)
            ),
        })
    }
}
