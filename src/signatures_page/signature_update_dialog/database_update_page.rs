use std::time::{Instant, SystemTime, UNIX_EPOCH};

use futures::{
    StreamExt,
    future::{AbortHandle, ready},
    stream,
};
use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
};

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityHistory, ActivityHistoryFailure, ActivityStatus, NewActivityEntry,
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
            scanner_output_parser::{sanitize_scanner_line, sanitize_scanner_text},
            scanner_process_events::ScanStartFailure,
        },
        desktop::desktop_notifications::notify_outside_the_window,
    },
    signatures_page::signature_update_dialog::{
        database_update_events::{
            DatabaseUpdateEvent, DatabaseUpdatePlan, database_update_events, plan_database_update,
        },
        freshclam_output_parser::{
            DatabaseUpdateOutcome, FreshclamReportSummary, RateLimitCooldown, UpdateFailureReason,
            interpret_update_exit,
        },
    },
};

const UPDATE_BATCH_SIZE: usize = 64;
const TRANSCRIPT_LIMIT: usize = 4 * 1024 * 1024;
const DISPLAYED_TRANSCRIPT_LIMIT: usize = 256 * 1024;

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

enum DatabaseUpdateState {
    NoActiveUpdate,
    UpdateRunning {
        update_plan: DatabaseUpdatePlan,
        update_abort_handle: AbortHandle,
    },
    CancellingUpdate,
}

pub struct DatabaseUpdatePage {
    toaster: Toaster,
    activity_history: ActivityHistory,
    update_started_at: SystemTime,
    update_started_instant: Instant,
    host_status: HostStatusView,
    update_state: DatabaseUpdateState,
    observed_exit: ObservedUpdateExit,
    update_transcript: String,
    transcript_changed: bool,
    update_summary: String,
}

enum HostStatusView {
    StatusLoading,
    StatusLoaded(DatabaseHostStatus),
}

#[derive(Debug)]
pub enum DatabaseUpdatePageInput {
    StatusRefreshRequested,
    UpdateRequested,
    UpdateCancelRequested,
}

#[derive(Debug)]
pub enum DatabaseUpdatePageCommand {
    HostStatusLoaded(DatabaseHostStatus),
    UpdateBatchArrived(Vec<DatabaseUpdateEvent>),
    UpdateStreamFinished,
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
}

#[derive(Debug)]
pub enum DatabaseUpdatePageOutput {
    ActivityRecorded,
    SignaturesUpdated,
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

async fn load_host_status() -> DatabaseHostStatus {
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

impl DatabaseUpdatePage {
    fn loaded_status(&self) -> Option<&DatabaseHostStatus> {
        match &self.host_status {
            HostStatusView::StatusLoaded(host_status) => Some(host_status),
            HostStatusView::StatusLoading => None,
        }
    }

    fn freshclam_subtitle(&self) -> String {
        match self
            .loaded_status()
            .map(|host_status| &host_status.freshclam_probe)
        {
            None => gettext("Checking freshclam…"),
            Some(ProgramProbe::VersionReported { version_text }) => {
                sanitize_scanner_line(version_text)
            }
            Some(ProgramProbe::NotFoundOnPath) => gettext("Not installed"),
            Some(ProgramProbe::ProgramRefused { candidate_path }) => {
                gettext("Refused {path}, because your account can replace it").replace(
                    "{path}",
                    &sanitize_scanner_line(&candidate_path.to_string_lossy()),
                )
            }
            Some(ProgramProbe::ProbeFailed { failure_text }) => sanitize_scanner_line(failure_text),
        }
    }

    fn service_subtitle(&self) -> String {
        self.loaded_status().map_or_else(
            || gettext("Checking…"),
            |host_status| service_description(host_status.service_state),
        )
    }

    fn freshness_title_text(&self) -> String {
        self.loaded_status().map_or_else(
            || gettext("Checking…"),
            |host_status| directory_description(&host_status.directory_status),
        )
    }

    fn freshness_subtitle(&self) -> String {
        self.loaded_status()
            .map_or_else(String::new, |host_status| {
                directory_path_text(&host_status.directory_status)
            })
    }

    fn update_is_active(&self) -> bool {
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

    fn can_cancel_update(&self) -> bool {
        matches!(
            self.update_state,
            DatabaseUpdateState::UpdateRunning {
                update_plan: DatabaseUpdatePlan::RunFreshclamDirectly,
                ..
            }
        )
    }

    fn displayed_transcript(&self) -> &str {
        let shown_start = self
            .update_transcript
            .len()
            .saturating_sub(DISPLAYED_TRANSCRIPT_LIMIT);
        let boundary_start = (shown_start..=self.update_transcript.len())
            .find(|byte_position| self.update_transcript.is_char_boundary(*byte_position))
            .unwrap_or(self.update_transcript.len());
        &self.update_transcript[boundary_start..]
    }

    fn append_transcript_line(&mut self, output_line: &str) {
        let displayed_line = sanitize_scanner_line(output_line);
        if self.update_transcript.len() + displayed_line.len() < TRANSCRIPT_LIMIT {
            self.update_transcript.push_str(&displayed_line);
            self.update_transcript.push('\n');
            self.transcript_changed = true;
        }
    }

    fn refresh_host_status(&mut self, sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            DatabaseUpdatePageCommand::HostStatusLoaded(load_host_status().await)
        });
    }

    fn start_update(&mut self, sender: &ComponentSender<Self>) {
        let Some(host_status) = self.loaded_status() else {
            return;
        };
        let update_plan = plan_database_update(host_status.service_state);
        self.update_started_at = SystemTime::now();
        self.update_started_instant = Instant::now();
        self.update_transcript.clear();
        self.transcript_changed = true;
        self.update_summary.clear();
        self.observed_exit = ObservedUpdateExit::ExitNotObserved;
        let (abortable_events, update_abort_handle) =
            stream::abortable(database_update_events(update_plan));
        self.update_state = DatabaseUpdateState::UpdateRunning {
            update_plan,
            update_abort_handle,
        };
        sender.command(move |command_output, shutdown| {
            shutdown
                .register(async move {
                    abortable_events
                        .ready_chunks(UPDATE_BATCH_SIZE)
                        .for_each(|update_batch| {
                            command_output
                                .emit(DatabaseUpdatePageCommand::UpdateBatchArrived(update_batch));
                            ready(())
                        })
                        .await;
                    command_output.emit(DatabaseUpdatePageCommand::UpdateStreamFinished);
                })
                .drop_on_shutdown()
        });
    }

    fn finished_update_status(&self) -> ActivityStatus {
        match (&self.update_state, &self.observed_exit) {
            (DatabaseUpdateState::CancellingUpdate, _any_exit) => ActivityStatus::UpdateCancelled,
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

    fn record_finished_update(&self, sender: &ComponentSender<Self>) {
        let new_entry = NewActivityEntry {
            started_at_unix: self
                .update_started_at
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed_time| elapsed_time.as_secs() as i64),
            activity_status: self.finished_update_status(),
            activity_targets: String::new(),
            inspected_file_count: 0,
            threat_count: 0,
            duration_millis: self.update_started_instant.elapsed().as_millis() as u64,
            activity_output: self.update_transcript.clone(),
        };
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            DatabaseUpdatePageCommand::ActivityRecordingFinished(
                activity_history.record_activity(new_entry).await,
            )
        });
    }

    fn finished_update_summary(&self) -> String {
        match (&self.update_state, &self.observed_exit) {
            (DatabaseUpdateState::CancellingUpdate, _any_exit) => {
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
}

#[relm4::component(pub)]
impl Component for DatabaseUpdatePage {
    type Init = ActivityHistory;
    type Input = DatabaseUpdatePageInput;
    type Output = DatabaseUpdatePageOutput;
    type CommandOutput = DatabaseUpdatePageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::PreferencesPage {
                set_title: &gettext("Database"),

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Virus definitions"),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Refresh status")),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        connect_clicked => DatabaseUpdatePageInput::StatusRefreshRequested,
                    },

                    adw::ActionRow {
                        set_use_markup: false,
                        set_title: "freshclam",
                        #[watch]
                        set_subtitle: &model.freshclam_subtitle(),
                        set_subtitle_selectable: true,
                        add_css_class: "property",
                    },

                    adw::ActionRow {
                        set_use_markup: false,
                        set_title: &gettext("Update service"),
                        #[watch]
                        set_subtitle: &model.service_subtitle(),
                        add_css_class: "property",
                    },

                    adw::ActionRow {
                        set_use_markup: false,
                        set_title: &gettext("Database freshness"),
                        #[watch]
                        set_subtitle: &format!("{}\n{}", model.freshness_title_text(), model.freshness_subtitle()),
                        set_subtitle_selectable: true,
                        set_subtitle_lines: 0,
                        add_css_class: "property",
                    },
                },

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Update database"),
                    set_description: Some(&gettext("Updates run through the system's updater services, such as freshclam and fangfrisch, so your system may ask for authorization.")),

                    gtk::Box {
                        set_spacing: 6,

                        gtk::Button {
                            add_css_class: "suggested-action",
                            #[watch]
                            set_label: &if model.update_is_active() { gettext("Updating…") } else { gettext("Update database") },
                            #[watch]
                            set_sensitive: model.can_request_update(),
                            connect_clicked => DatabaseUpdatePageInput::UpdateRequested,
                        },

                        gtk::Button {
                            set_label: &gettext("Cancel"),
                            add_css_class: "destructive-action",
                            #[watch]
                            set_visible: model.can_cancel_update(),
                            connect_clicked => DatabaseUpdatePageInput::UpdateCancelRequested,
                        },
                    },

                    gtk::Label {
                        set_xalign: 0.0,
                        set_wrap: true,
                        set_selectable: true,
                        set_margin_top: 12,
                        #[watch]
                        set_visible: !model.update_summary.is_empty(),
                        #[watch]
                        set_label: &model.update_summary,
                    },
                },

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Update log"),

                    gtk::ScrolledWindow {
                        set_min_content_height: 220,
                        add_css_class: "card",

                        gtk::TextView {
                            #[wrap(Some)]
                            set_buffer = &gtk::TextBuffer {
                                #[track(model.transcript_changed)]
                                set_text: model.displayed_transcript(),
                            },
                            set_editable: false,
                            set_cursor_visible: false,
                            set_monospace: true,
                            set_wrap_mode: gtk::WrapMode::WordChar,
                            set_top_margin: 12,
                            set_bottom_margin: 12,
                            set_left_margin: 12,
                            set_right_margin: 12,
                        },
                    },
                },
            },
        }
    }

    fn init(
        activity_history: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let mut model = Self {
            toaster: Toaster::new(&root),
            host_status: HostStatusView::StatusLoading,
            update_state: DatabaseUpdateState::NoActiveUpdate,
            observed_exit: ObservedUpdateExit::ExitNotObserved,
            update_transcript: String::new(),
            transcript_changed: false,
            update_summary: String::new(),
            activity_history,
            update_started_at: SystemTime::now(),
            update_started_instant: Instant::now(),
        };
        model.refresh_host_status(&sender);
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: DatabaseUpdatePageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.transcript_changed = false;
        match page_input {
            DatabaseUpdatePageInput::StatusRefreshRequested => self.refresh_host_status(&sender),
            DatabaseUpdatePageInput::UpdateRequested => {
                if self.can_request_update() {
                    self.start_update(&sender);
                }
            }
            DatabaseUpdatePageInput::UpdateCancelRequested => {
                if let DatabaseUpdateState::UpdateRunning {
                    update_abort_handle,
                    ..
                } = &self.update_state
                {
                    update_abort_handle.abort();
                    self.update_state = DatabaseUpdateState::CancellingUpdate;
                }
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: DatabaseUpdatePageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.transcript_changed = false;
        match page_command {
            DatabaseUpdatePageCommand::HostStatusLoaded(host_status) => {
                self.host_status = HostStatusView::StatusLoaded(host_status);
            }
            DatabaseUpdatePageCommand::UpdateBatchArrived(update_batch) => {
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
            DatabaseUpdatePageCommand::UpdateStreamFinished => {
                if matches!(
                    self.observed_exit,
                    ObservedUpdateExit::ExitObserved { exit_code: 0 }
                ) {
                    let _shell_closed = sender.output(DatabaseUpdatePageOutput::SignaturesUpdated);
                }
                self.update_summary = self.finished_update_summary();
                self.record_finished_update(&sender);
                notify_outside_the_window(
                    "update-finished",
                    &gettext("Database update finished"),
                    self.update_summary.lines().next().unwrap_or_default(),
                );
                self.update_state = DatabaseUpdateState::NoActiveUpdate;
                self.toaster.add_toast(adw::Toast::new(
                    self.update_summary.lines().next().unwrap_or_default(),
                ));
                self.refresh_host_status(&sender);
            }
            DatabaseUpdatePageCommand::ActivityRecordingFinished(Ok(())) => {
                let _shell_closed = sender.output(DatabaseUpdatePageOutput::ActivityRecorded);
            }
            DatabaseUpdatePageCommand::ActivityRecordingFinished(Err(recording_failure)) => {
                self.toaster.add_toast(adw::Toast::new(
                    &gettext("The update could not be added to the history: {error}")
                        .replace("{error}", &recording_failure.to_string()),
                ));
            }
        }
    }
}
