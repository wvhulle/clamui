use std::time::{Instant, SystemTime};

use gettextrs::{gettext, ngettext};
use jiff::Timestamp;

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityRecord, NewActivityEntry, UpdateActivityStatus,
        },
        clamav_programs::{
            component_availability::{ProgramProbe, probe_located_program_version},
            database_directory_status::{
                DatabaseDirectoryStatus, FreshclamServiceState, configured_database_directory,
                detect_freshclam_service, inspect_database_directory,
            },
            trusted_program_lookup::{ClamavProgram, ProgramLocation, locate_trusted_program},
        },
        clamav_scanner::{
            scanner_exit_classification::AbnormalScannerExit,
            scanner_output_parser::{sanitize_scanner_line, sanitize_scanner_text},
            scanner_process_events::ScanStartFailure,
        },
    },
    shared_widgets::{
        component_streams::RunningStream,
        host_read_failure_text::{database_folder_failure_text, unit_journal_failure_text},
        scanner_start_failure_text::describe_start_failure as describe_scan_start_failure,
    },
    signatures::database_updates_page::signature_update_run::{
        database_update_events::{
            DatabaseUpdateEvent, DatabaseUpdatePlan, UpdaterFinish, plan_database_update,
        },
        freshclam_output_parser::{
            DatabaseUpdateOutcome, FreshclamReportSummary, RateLimitCooldown, UpdateFailureReason,
            interpret_unfinished_update, interpret_updater_finish,
        },
    },
};

const TRANSCRIPT_LIMIT: usize = 4 * 1024 * 1024;

#[derive(Debug)]
pub struct DatabaseHostStatus {
    freshclam_probe: ProgramProbe,
    service_state: FreshclamServiceState,
    directory_status: DatabaseDirectoryStatus,
}

#[cfg(test)]
impl DatabaseHostStatus {
    pub fn installed_with_service(service_state: FreshclamServiceState) -> Self {
        Self {
            freshclam_probe: ProgramProbe::VersionReported {
                version_text: "ClamAV 1.4.3".to_owned(),
            },
            service_state,
            directory_status: DatabaseDirectoryStatus::DefinitionsMissing {
                database_directory: std::path::PathBuf::from("/var/lib/clamav"),
            },
        }
    }
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

enum LatestUpdaterLine {
    NothingPrinted,
    LinePrinted(String),
}

struct UpdateRunOutput {
    update_transcript: String,
    latest_updater_line: LatestUpdaterLine,
}

impl UpdateRunOutput {
    const fn nothing_printed() -> Self {
        Self {
            update_transcript: String::new(),
            latest_updater_line: LatestUpdaterLine::NothingPrinted,
        }
    }

    fn append_output_line(&mut self, output_line: &str) {
        let displayed_line = sanitize_scanner_line(output_line);
        if !displayed_line.trim().is_empty() {
            self.latest_updater_line =
                LatestUpdaterLine::LinePrinted(displayed_line.trim().to_owned());
        }
        if self.update_transcript.len() + displayed_line.len() < TRANSCRIPT_LIMIT {
            self.update_transcript.push_str(&displayed_line);
            self.update_transcript.push('\n');
        }
    }

    fn latest_line_text(&self) -> String {
        match &self.latest_updater_line {
            LatestUpdaterLine::NothingPrinted => gettext("Starting the update…"),
            LatestUpdaterLine::LinePrinted(output_line) => output_line.clone(),
        }
    }
}

enum ActiveUpdateRun {
    UpdateRunning {
        update_plan: DatabaseUpdatePlan,
        update_timing: UpdateTiming,
        run_output: UpdateRunOutput,
        _update_stream: RunningStream,
    },
    UpdaterFinished {
        update_timing: UpdateTiming,
        run_output: UpdateRunOutput,
        updater_finish: UpdaterFinish,
        _update_stream: RunningStream,
    },
    CancellingUpdate {
        update_timing: UpdateTiming,
        run_output: UpdateRunOutput,
    },
}

struct EndedUpdateRun {
    update_timing: UpdateTiming,
    run_output: UpdateRunOutput,
    update_outcome: DatabaseUpdateOutcome,
}

impl ActiveUpdateRun {
    const fn run_output_mut(&mut self) -> &mut UpdateRunOutput {
        match self {
            Self::UpdateRunning { run_output, .. }
            | Self::UpdaterFinished { run_output, .. }
            | Self::CancellingUpdate { run_output, .. } => run_output,
        }
    }

    fn cancel_requested(self) -> Self {
        match self {
            Self::UpdateRunning {
                update_plan: DatabaseUpdatePlan::RunFreshclamDirectly,
                update_timing,
                run_output,
                ..
            } => Self::CancellingUpdate {
                update_timing,
                run_output,
            },
            uncancellable_run @ (Self::UpdateRunning {
                update_plan:
                    DatabaseUpdatePlan::SignalRunningDaemon { .. }
                    | DatabaseUpdatePlan::StartServiceUnit { .. },
                ..
            }
            | Self::UpdaterFinished { .. }
            | Self::CancellingUpdate { .. }) => uncancellable_run,
        }
    }

    fn updater_finished(self, updater_finish: UpdaterFinish) -> Self {
        match self {
            Self::UpdateRunning {
                update_timing,
                run_output,
                _update_stream,
                ..
            } => Self::UpdaterFinished {
                update_timing,
                run_output,
                updater_finish,
                _update_stream,
            },
            settled_run @ (Self::UpdaterFinished { .. } | Self::CancellingUpdate { .. }) => {
                settled_run
            }
        }
    }

    fn absorb_update_event(mut self, update_event: DatabaseUpdateEvent) -> Self {
        match update_event {
            DatabaseUpdateEvent::UpdateOutputLine(output_line) => {
                self.run_output_mut().append_output_line(&output_line);
                self
            }
            DatabaseUpdateEvent::UpdateOutputUnreadable(read_failure) => {
                self.run_output_mut()
                    .append_output_line(&unit_journal_failure_text(read_failure));
                self
            }
            DatabaseUpdateEvent::UpdaterFinished(updater_finish) => {
                self.updater_finished(updater_finish)
            }
        }
    }

    fn into_ended_run(self) -> EndedUpdateRun {
        match self {
            Self::UpdateRunning {
                update_timing,
                run_output,
                ..
            } => EndedUpdateRun {
                update_outcome: interpret_unfinished_update(&run_output.update_transcript),
                update_timing,
                run_output,
            },
            Self::UpdaterFinished {
                update_timing,
                run_output,
                updater_finish,
                ..
            } => EndedUpdateRun {
                update_outcome: interpret_updater_finish(
                    &run_output.update_transcript,
                    updater_finish,
                ),
                update_timing,
                run_output,
            },
            Self::CancellingUpdate {
                update_timing,
                run_output,
            } => EndedUpdateRun {
                update_outcome: DatabaseUpdateOutcome::UpdateCancelled,
                update_timing,
                run_output,
            },
        }
    }

    fn into_finished_report(self) -> FinishedUpdateReport {
        let ended_run = self.into_ended_run();
        FinishedUpdateReport {
            summary_text: describe_update_outcome(&ended_run.update_outcome),
            definitions_changed: definitions_changed(&ended_run.update_outcome),
            activity_entry: NewActivityEntry {
                started_at: ended_run.update_timing.started_at,
                activity_record: ActivityRecord::UpdateActivity {
                    update_status: update_status_of(&ended_run.update_outcome),
                },
                duration_millis: u64::try_from(
                    ended_run
                        .update_timing
                        .started_instant
                        .elapsed()
                        .as_millis(),
                )
                .unwrap_or(u64::MAX),
                activity_output: ended_run.run_output.update_transcript,
            },
        }
    }

    fn update_progress(&self) -> SignatureUpdateProgress {
        match self {
            Self::UpdateRunning {
                update_plan: DatabaseUpdatePlan::RunFreshclamDirectly,
                run_output,
                ..
            } => SignatureUpdateProgress::CancellableUpdateRunning {
                latest_output_line: run_output.latest_line_text(),
            },
            Self::UpdateRunning {
                update_plan:
                    DatabaseUpdatePlan::SignalRunningDaemon { .. }
                    | DatabaseUpdatePlan::StartServiceUnit { .. },
                run_output,
                ..
            }
            | Self::UpdaterFinished { run_output, .. } => {
                SignatureUpdateProgress::UncancellableUpdateRunning {
                    latest_output_line: run_output.latest_line_text(),
                }
            }
            Self::CancellingUpdate { .. } => SignatureUpdateProgress::UpdateCancelling,
        }
    }
}

enum DatabaseUpdateState {
    NoActiveUpdate,
    ActiveUpdate(Box<ActiveUpdateRun>),
}

enum HostStatusView {
    StatusLoading,
    StatusLoaded(DatabaseHostStatus),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignatureUpdateProgress {
    UpdateUnavailable,
    ReadyToUpdate,
    CancellableUpdateRunning { latest_output_line: String },
    UncancellableUpdateRunning { latest_output_line: String },
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

#[derive(Debug)]
pub struct FinishedUpdateReport {
    pub summary_text: String,
    pub definitions_changed: bool,
    pub activity_entry: NewActivityEntry,
}

#[derive(Debug)]
pub enum UpdateStreamEnding {
    UpdateEnded(FinishedUpdateReport),
    NoUpdateWasRunning,
}

fn service_description(service_state: FreshclamServiceState) -> String {
    match service_state {
        FreshclamServiceState::DaemonRunning { .. } => gettext("Active"),
        FreshclamServiceState::TimerScheduled { .. } => gettext("Scheduled by a systemd timer"),
        FreshclamServiceState::ServiceStopped { .. } => gettext("Installed but stopped"),
        FreshclamServiceState::ServiceNotFound => {
            gettext("No freshclam service detected; updates run manually")
        }
        FreshclamServiceState::SystemdUnreachable => {
            gettext("systemd could not be asked about a freshclam service; updates run manually")
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
        DatabaseDirectoryStatus::DirectoryUnreadable { read_failure, .. } => {
            gettext("Unknown. {reason}")
                .replace("{reason}", &database_folder_failure_text(*read_failure))
        }
    }
}

fn directory_path_text(directory_status: &DatabaseDirectoryStatus) -> String {
    match directory_status {
        DatabaseDirectoryStatus::DefinitionsAvailable {
            database_directory, ..
        }
        | DatabaseDirectoryStatus::DefinitionsMissing { database_directory }
        | DatabaseDirectoryStatus::DirectoryUnreadable {
            database_directory, ..
        } => sanitize_scanner_line(&database_directory.to_string_lossy()),
    }
}

fn describe_abnormal_freshclam_exit(abnormal_exit: AbnormalScannerExit) -> String {
    match abnormal_exit {
        AbnormalScannerExit::ScannerError { exit_code } => {
            gettext("freshclam failed with exit code {code}.")
                .replace("{code}", &exit_code.to_string())
        }
        AbnormalScannerExit::KilledBySignal { signal_number } => {
            gettext("freshclam was stopped by signal {signal}.")
                .replace("{signal}", &signal_number.to_string())
        }
        AbnormalScannerExit::UnrecognizedWaitStatus { .. } => {
            gettext("freshclam ended in a way Lazaret does not recognize.")
        }
        AbnormalScannerExit::WaitFailed { .. } => {
            gettext("Lazaret lost track of freshclam before it finished.")
        }
    }
}

fn describe_failure_reason(failure_reason: &UpdateFailureReason) -> String {
    match failure_reason {
        UpdateFailureReason::AuthorizationRefused => {
            gettext("Authorization failed. Please try again and enter your password.")
        }
        UpdateFailureReason::SystemdUnreachable(_bus_failure) => {
            gettext("Systemd could not be reached to run the update.")
        }
        UpdateFailureReason::ServiceJobEnded { job_result } => {
            gettext("The update service did not finish; systemd reported: {result}")
                .replace("{result}", &sanitize_scanner_line(job_result))
        }
        UpdateFailureReason::FreshclamEndedAbnormally(abnormal_exit) => {
            describe_abnormal_freshclam_exit(*abnormal_exit)
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
        UpdateFailureReason::UpdaterResultMissing => {
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
        DatabaseUpdateOutcome::ServiceRanWithoutVerdict(report_summary) => (
            gettext(
                "The update service ran, but its log does not say whether definitions changed.",
            ),
            report_summary,
        ),
        DatabaseUpdateOutcome::UpdateFailed {
            failure_reason,
            report_summary,
        } => (describe_failure_reason(failure_reason), report_summary),
        DatabaseUpdateOutcome::UpdateRequestedFromDaemon => {
            return gettext(
                "The service accepted the signal; it performs the update asynchronously. Check \
                 its logs for completion.",
            );
        }
        DatabaseUpdateOutcome::UpdateCancelled => return gettext("Database update cancelled"),
        DatabaseUpdateOutcome::UpdaterNeverStarted(start_failure) => {
            return describe_start_failure(start_failure);
        }
    };
    [headline]
        .into_iter()
        .chain(describe_report_summary(report_summary))
        .collect::<Vec<_>>()
        .join("\n")
}

const fn update_status_of(update_outcome: &DatabaseUpdateOutcome) -> UpdateActivityStatus {
    match update_outcome {
        DatabaseUpdateOutcome::DefinitionsUpdated(_) => UpdateActivityStatus::UpdateApplied,
        DatabaseUpdateOutcome::AlreadyCurrent(_) => UpdateActivityStatus::UpdateAlreadyCurrent,
        DatabaseUpdateOutcome::ServiceRanWithoutVerdict(_) => {
            UpdateActivityStatus::UpdateResultUnknown
        }
        DatabaseUpdateOutcome::UpdateRequestedFromDaemon => UpdateActivityStatus::UpdateRequested,
        DatabaseUpdateOutcome::UpdateCancelled => UpdateActivityStatus::UpdateCancelled,
        DatabaseUpdateOutcome::UpdateFailed { .. }
        | DatabaseUpdateOutcome::UpdaterNeverStarted(_) => UpdateActivityStatus::UpdateFailed,
    }
}

const fn definitions_changed(update_outcome: &DatabaseUpdateOutcome) -> bool {
    match update_outcome {
        DatabaseUpdateOutcome::DefinitionsUpdated(_) => true,
        DatabaseUpdateOutcome::AlreadyCurrent(_)
        | DatabaseUpdateOutcome::ServiceRanWithoutVerdict(_)
        | DatabaseUpdateOutcome::UpdateRequestedFromDaemon
        | DatabaseUpdateOutcome::UpdateCancelled
        | DatabaseUpdateOutcome::UpdateFailed { .. }
        | DatabaseUpdateOutcome::UpdaterNeverStarted(_) => false,
    }
}

fn describe_start_failure(start_failure: &ScanStartFailure) -> String {
    match start_failure {
        ScanStartFailure::ScannerProgramMissing => {
            gettext("Install freshclam before requesting database updates.")
        }
        ScanStartFailure::ScannerProgramReplaceable { .. }
        | ScanStartFailure::ScannerSpawnFailed(_)
        | ScanStartFailure::ScannerOutputUncaptured
        | ScanStartFailure::ScannerWorkDirectoryUnavailable(_)
        | ScanStartFailure::DetectionSettingsUnreadable(_)
        | ScanStartFailure::ProgramLookupFailed(_)
        | ScanStartFailure::ScanInputUnavailable { .. } => {
            describe_scan_start_failure(start_failure)
        }
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
        |interrupted_inspection| DatabaseDirectoryStatus::DirectoryUnreadable {
            database_directory: configured_database_directory(),
            read_failure: interrupted_inspection.into(),
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
    last_manual_update: LastManualUpdate,
}

impl SignatureUpdateSession {
    pub const fn new() -> Self {
        Self {
            host_status: HostStatusView::StatusLoading,
            update_state: DatabaseUpdateState::NoActiveUpdate,
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
        match self.update_state {
            DatabaseUpdateState::NoActiveUpdate => false,
            DatabaseUpdateState::ActiveUpdate(_) => true,
        }
    }

    fn can_request_update(&self) -> bool {
        !self.update_is_active()
            && self.loaded_status().is_some_and(|host_status| {
                !matches!(
                    host_status.service_state,
                    FreshclamServiceState::ServiceNotFound
                        | FreshclamServiceState::SystemdUnreachable
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
        self.update_state =
            DatabaseUpdateState::ActiveUpdate(Box::new(ActiveUpdateRun::UpdateRunning {
                update_plan,
                update_timing: UpdateTiming::starting_now(),
                run_output: UpdateRunOutput::nothing_printed(),
                _update_stream: update_stream,
            }));
    }

    fn advance_active_run(
        &mut self,
        run_transition: impl FnOnce(ActiveUpdateRun) -> ActiveUpdateRun,
    ) {
        self.update_state =
            match std::mem::replace(&mut self.update_state, DatabaseUpdateState::NoActiveUpdate) {
                DatabaseUpdateState::NoActiveUpdate => DatabaseUpdateState::NoActiveUpdate,
                DatabaseUpdateState::ActiveUpdate(active_run) => {
                    DatabaseUpdateState::ActiveUpdate(Box::new(run_transition(*active_run)))
                }
            };
    }

    pub fn cancel_requested(&mut self) {
        self.advance_active_run(ActiveUpdateRun::cancel_requested);
    }

    pub fn absorb_update_batch(&mut self, update_batch: Vec<DatabaseUpdateEvent>) {
        self.advance_active_run(|active_run| {
            update_batch
                .into_iter()
                .fold(active_run, ActiveUpdateRun::absorb_update_event)
        });
    }

    pub fn update_stream_ended(&mut self) -> UpdateStreamEnding {
        match std::mem::replace(&mut self.update_state, DatabaseUpdateState::NoActiveUpdate) {
            DatabaseUpdateState::NoActiveUpdate => UpdateStreamEnding::NoUpdateWasRunning,
            DatabaseUpdateState::ActiveUpdate(active_run) => {
                let finished_report = active_run.into_finished_report();
                self.last_manual_update = LastManualUpdate::FinishedAt {
                    summary_line: finished_report
                        .summary_text
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                    finished_at: Timestamp::now(),
                };
                UpdateStreamEnding::UpdateEnded(finished_report)
            }
        }
    }

    fn update_progress(&self) -> SignatureUpdateProgress {
        match &self.update_state {
            DatabaseUpdateState::ActiveUpdate(active_run) => active_run.update_progress(),
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

#[cfg(test)]
mod signature_update_session_tests {
    use super::*;
    use crate::{
        host_services::{
            clamav_programs::database_directory_status::DatabaseFolderReadFailure,
            systemd_bus::host_systemd_units::UnitStartOutcome,
            systemd_journal::unit_journal_reader::UnitJournalReadFailure,
        },
        signatures::database_updates_page::signature_update_run::updater_exit_status::FreshclamExit,
    };

    const FRESHCLAM_UNIT: &str = "clamav-freshclam";

    fn session_running(update_plan: DatabaseUpdatePlan) -> SignatureUpdateSession {
        let mut update_session = SignatureUpdateSession::new();
        update_session.update_started(update_plan, RunningStream::already_stopped());
        update_session
    }

    fn ended_report(update_session: &mut SignatureUpdateSession) -> FinishedUpdateReport {
        match update_session.update_stream_ended() {
            UpdateStreamEnding::UpdateEnded(finished_report) => finished_report,
            UpdateStreamEnding::NoUpdateWasRunning => panic!("expected an update to end"),
        }
    }

    #[test]
    fn a_stream_end_without_an_active_update_produces_no_report() {
        let mut update_session = SignatureUpdateSession::new();
        assert!(matches!(
            update_session.update_stream_ended(),
            UpdateStreamEnding::NoUpdateWasRunning
        ));
        assert_eq!(
            update_session.last_manual_update,
            LastManualUpdate::NotRunThisSession
        );
    }

    #[test]
    fn a_stream_end_is_reported_once_per_run() {
        let mut update_session = session_running(DatabaseUpdatePlan::RunFreshclamDirectly);
        let _first_report = ended_report(&mut update_session);
        assert!(matches!(
            update_session.update_stream_ended(),
            UpdateStreamEnding::NoUpdateWasRunning
        ));
    }

    #[test]
    fn a_signalled_daemon_does_not_count_as_updated_definitions() {
        let mut update_session = session_running(DatabaseUpdatePlan::SignalRunningDaemon {
            service_unit: FRESHCLAM_UNIT,
        });
        update_session.absorb_update_batch(vec![DatabaseUpdateEvent::UpdaterFinished(
            UpdaterFinish::RunningDaemonSignalled(UnitStartOutcome::UnitFinished),
        )]);
        let finished_report = ended_report(&mut update_session);
        assert!(!finished_report.definitions_changed);
        assert_eq!(
            finished_report.activity_entry.activity_record,
            ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateRequested
            }
        );
    }

    #[test]
    fn an_unreadable_service_journal_is_written_into_the_update_output() {
        let mut update_session = session_running(DatabaseUpdatePlan::StartServiceUnit {
            service_unit: FRESHCLAM_UNIT,
        });
        update_session.absorb_update_batch(vec![
            DatabaseUpdateEvent::UpdateOutputUnreadable(
                UnitJournalReadFailure::ReadingTaskInterrupted,
            ),
            DatabaseUpdateEvent::UpdaterFinished(UpdaterFinish::ServiceUnitRan(
                UnitStartOutcome::UnitFinished,
            )),
        ]);
        let finished_report = ended_report(&mut update_session);
        assert!(
            finished_report
                .activity_entry
                .activity_output
                .contains("Reading the system journal stopped before it finished")
        );
        assert_eq!(
            finished_report.activity_entry.activity_record,
            ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateResultUnknown
            }
        );
    }

    #[test]
    fn an_unreadable_database_folder_is_not_reported_as_missing() {
        let unreadable_status = DatabaseDirectoryStatus::DirectoryUnreadable {
            database_directory: std::path::PathBuf::from("/var/lib/clamav"),
            read_failure: DatabaseFolderReadFailure::ReadingTaskInterrupted,
        };
        assert_eq!(
            directory_description(&unreadable_status),
            "Unknown. Reading the signature folder stopped before it finished"
        );
        assert_eq!(directory_path_text(&unreadable_status), "/var/lib/clamav");
    }

    #[test]
    fn a_unit_run_without_a_version_line_has_an_unknown_result() {
        let mut update_session = session_running(DatabaseUpdatePlan::StartServiceUnit {
            service_unit: FRESHCLAM_UNIT,
        });
        update_session.absorb_update_batch(vec![
            DatabaseUpdateEvent::UpdateOutputLine("Starting clamav-freshclam".to_owned()),
            DatabaseUpdateEvent::UpdaterFinished(UpdaterFinish::ServiceUnitRan(
                UnitStartOutcome::UnitFinished,
            )),
        ]);
        let finished_report = ended_report(&mut update_session);
        assert!(!finished_report.definitions_changed);
        assert_eq!(
            finished_report.activity_entry.activity_record,
            ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateResultUnknown
            }
        );
    }

    #[test]
    fn a_refused_authorization_fails_without_writing_to_the_transcript() {
        let mut update_session = session_running(DatabaseUpdatePlan::StartServiceUnit {
            service_unit: FRESHCLAM_UNIT,
        });
        update_session.absorb_update_batch(vec![DatabaseUpdateEvent::UpdaterFinished(
            UpdaterFinish::ServiceUnitRan(UnitStartOutcome::AuthorizationRefused),
        )]);
        let finished_report = ended_report(&mut update_session);
        assert_eq!(
            finished_report.activity_entry.activity_record,
            ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateFailed
            }
        );
        assert_eq!(finished_report.activity_entry.activity_output, "");
        assert_eq!(
            finished_report.summary_text,
            "Authorization failed. Please try again and enter your password."
        );
    }

    #[test]
    fn an_exit_from_a_previous_run_does_not_survive_into_the_next_run() {
        let mut update_session = session_running(DatabaseUpdatePlan::RunFreshclamDirectly);
        update_session.absorb_update_batch(vec![
            DatabaseUpdateEvent::UpdateOutputLine(
                "daily.cld updated (version: 1, sigs: 2)".to_owned(),
            ),
            DatabaseUpdateEvent::UpdaterFinished(UpdaterFinish::FreshclamExited(
                FreshclamExit::UpdateSucceeded,
            )),
        ]);
        assert!(ended_report(&mut update_session).definitions_changed);
        update_session.update_started(
            DatabaseUpdatePlan::RunFreshclamDirectly,
            RunningStream::already_stopped(),
        );
        let next_report = ended_report(&mut update_session);
        assert!(!next_report.definitions_changed);
        assert_eq!(
            next_report.activity_entry.activity_record,
            ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateFailed
            }
        );
        assert_eq!(next_report.activity_entry.activity_output, "");
    }

    #[test]
    fn a_cancelled_run_ignores_a_late_exit() {
        let mut update_session = session_running(DatabaseUpdatePlan::RunFreshclamDirectly);
        update_session.cancel_requested();
        update_session.absorb_update_batch(vec![DatabaseUpdateEvent::UpdaterFinished(
            UpdaterFinish::FreshclamExited(FreshclamExit::UpdateSucceeded),
        )]);
        let finished_report = ended_report(&mut update_session);
        assert!(!finished_report.definitions_changed);
        assert_eq!(
            finished_report.activity_entry.activity_record,
            ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateCancelled
            }
        );
    }

    #[test]
    fn only_a_direct_freshclam_run_can_be_cancelled() {
        let mut update_session = session_running(DatabaseUpdatePlan::StartServiceUnit {
            service_unit: FRESHCLAM_UNIT,
        });
        update_session.cancel_requested();
        assert_eq!(
            update_session.update_progress(),
            SignatureUpdateProgress::UncancellableUpdateRunning {
                latest_output_line: "Starting the update…".to_owned()
            }
        );
    }
}
