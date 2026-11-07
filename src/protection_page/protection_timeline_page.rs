use futures::StreamExt;
use gettextrs::{gettext, ngettext};
use jiff::Timestamp;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, actions::ActionName, adw,
    adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::{
        application_actions::OpenSettingsAction,
        settings_navigation::{SettingsSubpage, system_settings_group},
    },
    host_services::{
        activity_history::activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::{
            desktop_notifications::notify_outside_the_window,
            locale_formatting::host_moment_formatters,
        },
        detection_journal::detection_journal_follower::JournalAccess,
        protection_evidence::host_protection_evidence::{
            ProtectionEvidence, ScanServiceEvidence, ScanUnitResult, WATCHED_SERVICE_UNITS,
            detection_notifications_are_enabled, gather_protection_evidence,
            lazaret_schedule_is_enabled, scan_service_evidence,
        },
        systemd_bus::host_systemd_units::{
            SystemdBusFailure, UnitStartOutcome, service_unit_snapshot, start_system_unit,
            watched_unit_changes,
        },
    },
    protection_page::protection_timeline_presentation::{
        AlertReadiness, ProtectionActivity, ProtectionStep, ProtectionStepAction,
        protection_timeline,
    },
    shared_widgets::{
        component_streams::{RunningStream, run_stream, run_stream_then},
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        step_timeline::{
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, TimelineStepRowInput},
        },
    },
    signatures::database_updates_page::signature_update_run::{
        database_update_events::{DatabaseUpdateEvent, database_update_events},
        signature_update_session::{
            DatabaseHostStatus, SignatureUpdateSession, UpdateStreamEnding, load_host_status,
        },
    },
};

const FOUND_THREATS_TOAST_SECONDS: u32 = 10;
const UPDATE_BATCH_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceRefresh {
    NothingRunning,
    GatheringOnce,
    GatheringThenAgain,
}

pub struct ProtectionTimelinePage {
    toaster: Toaster,
    protection_rows: FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    engine_rows: FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    review_rows: FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    activity_history: ActivityHistory,
    signature_update_session: SignatureUpdateSession,
    scheduled_scan_starting: bool,
    update_awaits_host_status: bool,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    coverage_summary: String,
    unresolved_detections: usize,
    journal_access: JournalAccess,
    gathered_evidence: GatheredEvidence,
    _unit_watch: RunningStream,
}

enum GatheredEvidence {
    NotGatheredYet,
    Gathered {
        protection_evidence: Box<ProtectionEvidence>,
        gathered_at: Timestamp,
    },
}

#[derive(Debug)]
pub enum ProtectionTimelinePageInput {
    RefreshRequested,
    SignatureUpdateRequested,
    UnresolvedDetectionsChanged(usize),
    JournalAccessChanged(JournalAccess),
    StepRequested(TimelineStepRowOutput<ProtectionStepAction>),
}

#[derive(Debug)]
pub enum ProtectionTimelinePageOutput {
    SignaturesUpdated,
    ActivityRecorded,
}

#[derive(Debug)]
pub enum ProtectionTimelinePageCommand {
    EvidenceGathered {
        protection_evidence: Box<ProtectionEvidence>,
        gathered_at: Timestamp,
    },
    WatchedUnitChanged,
    UnitRunFinished {
        start_outcome: UnitStartOutcome,
        scan_service: ScanServiceEvidence,
    },
    SignatureHostStatusLoaded(DatabaseHostStatus),
    SignatureUpdateBatchArrived(Vec<DatabaseUpdateEvent>),
    SignatureUpdateStreamFinished,
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
}

pub fn decision_headline(unresolved_detections: usize) -> String {
    if unresolved_detections == 0 {
        return gettext("Nothing needs your decision");
    }
    ngettext(
        "{count} detection needs your decision",
        "{count} detections need your decision",
        u32::try_from(unresolved_detections).unwrap_or(u32::MAX),
    )
    .replace("{count}", &unresolved_detections.to_string())
}

pub fn shown_coverage_text(coverage_summary: &str, home_directory: &str) -> String {
    if home_directory.is_empty() || home_directory == "/" {
        return coverage_summary.to_owned();
    }
    coverage_summary
        .replace(&format!("{home_directory}/"), "~/")
        .replace(&format!("{home_directory},"), "~,")
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn scan_found_threats(
    start_outcome: &UnitStartOutcome,
    scan_service: &ScanServiceEvidence,
) -> bool {
    matches!(start_outcome, UnitStartOutcome::JobEnded { .. })
        && matches!(
            scan_service,
            ScanServiceEvidence::ServiceConfigured {
                last_result: ScanUnitResult::ThreatsFound,
                ..
            }
        )
}

fn unit_run_toast(
    start_outcome: &UnitStartOutcome,
    scan_service: &ScanServiceEvidence,
) -> adw::Toast {
    let run_toast = plain_text_toast(&unit_run_toast_text(start_outcome, scan_service));
    if scan_found_threats(start_outcome, scan_service) {
        run_toast.set_button_label(Some(&gettext("Review")));
        run_toast.set_action_name(Some("win.show-page"));
        run_toast.set_action_target_value(Some(&"detections".to_variant()));
        run_toast.set_timeout(FOUND_THREATS_TOAST_SECONDS);
    }
    run_toast
}

fn systemd_failure_text(bus_failure: &SystemdBusFailure) -> String {
    match bus_failure {
        SystemdBusFailure::BusCallFailed(bus_error) => gettext("systemd did not answer: {error}")
            .replace("{error}", &sanitize_scanner_line(&bus_error.to_string())),
        SystemdBusFailure::UnrecognizedLoadState => {
            gettext("systemd reported a unit state Lazaret does not recognize")
        }
    }
}

pub fn unit_run_toast_text(
    start_outcome: &UnitStartOutcome,
    scan_service: &ScanServiceEvidence,
) -> String {
    if scan_found_threats(start_outcome, scan_service) {
        return gettext("The scan found malware");
    }
    match start_outcome {
        UnitStartOutcome::UnitFinished => gettext("The scan finished"),
        UnitStartOutcome::JobEnded { job_result } => {
            gettext("The scan did not finish cleanly: {result}")
                .replace("{result}", &sanitize_scanner_line(job_result))
        }
        UnitStartOutcome::AuthorizationRefused => {
            gettext("Starting the scan needs administrator authorization")
        }
        UnitStartOutcome::BusFailure(bus_failure) => {
            gettext("The scan could not be started: {error}")
                .replace("{error}", &systemd_failure_text(bus_failure))
        }
    }
}

fn show_group_steps(
    group_rows: &mut FactoryVecDeque<TimelineStepRow<ProtectionStepAction>>,
    group_steps: Vec<ProtectionStep>,
) {
    if group_rows.len() == group_steps.len() {
        (0..)
            .zip(group_steps)
            .for_each(|(row_position, timeline_step)| {
                group_rows.send(
                    row_position,
                    TimelineStepRowInput::StepChanged(Box::new(timeline_step)),
                );
            });
    } else {
        let mut row_guard = group_rows.guard();
        row_guard.clear();
        group_steps.into_iter().for_each(|timeline_step| {
            row_guard.push_back(timeline_step);
        });
    }
}

fn launched_step_group(
    step_group: adw::PreferencesGroup,
    sender: &ComponentSender<ProtectionTimelinePage>,
) -> FactoryVecDeque<TimelineStepRow<ProtectionStepAction>> {
    FactoryVecDeque::builder().launch(step_group).forward(
        sender.input_sender(),
        ProtectionTimelinePageInput::StepRequested,
    )
}

fn titled_group(group_title: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder().title(group_title).build()
}

fn described_group(group_title: &str, group_description: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder()
        .title(group_title)
        .description(group_description)
        .build()
}

impl ProtectionTimelinePage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn start_evidence_refresh(&mut self, sender: &ComponentSender<Self>) {
        if self.evidence_refresh != EvidenceRefresh::NothingRunning {
            self.evidence_refresh = EvidenceRefresh::GatheringThenAgain;
            return;
        }
        self.evidence_refresh = EvidenceRefresh::GatheringOnce;
        let lazaret_schedule_enabled = lazaret_schedule_is_enabled();
        sender.oneshot_command(async move {
            let protection_evidence =
                Box::new(gather_protection_evidence(lazaret_schedule_enabled).await);
            ProtectionTimelinePageCommand::EvidenceGathered {
                protection_evidence,
                gathered_at: Timestamp::now(),
            }
        });
    }

    fn show_timeline(&mut self) {
        let GatheredEvidence::Gathered {
            protection_evidence,
            gathered_at,
        } = &self.gathered_evidence
        else {
            return;
        };
        let gathered_timeline = protection_timeline(
            protection_evidence,
            &AlertReadiness {
                journal_access: self.journal_access.clone(),
                notifications_enabled: detection_notifications_are_enabled(),
            },
            &ProtectionActivity {
                signature_update: self.signature_update_session.update_view(),
                scheduled_scan_starting: self.scheduled_scan_starting,
                observed_at: *gathered_at,
                moment_formatters: host_moment_formatters(),
            },
            self.distribution_family,
        );
        self.coverage_summary = gathered_timeline.coverage_summary;
        show_group_steps(
            &mut self.protection_rows,
            gathered_timeline.protection_steps,
        );
        show_group_steps(&mut self.engine_rows, gathered_timeline.engine_steps);
        show_group_steps(&mut self.review_rows, gathered_timeline.review_steps);
    }

    fn refresh_signature_host_status(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            ProtectionTimelinePageCommand::SignatureHostStatusLoaded(load_host_status().await)
        });
    }

    fn start_signature_update(&mut self, sender: &ComponentSender<Self>) {
        let Some(update_plan) = self.signature_update_session.requested_update_plan() else {
            return;
        };
        let update_stream = run_stream_then(
            sender,
            database_update_events(update_plan)
                .ready_chunks(UPDATE_BATCH_SIZE)
                .map(ProtectionTimelinePageCommand::SignatureUpdateBatchArrived),
            ProtectionTimelinePageCommand::SignatureUpdateStreamFinished,
        );
        self.signature_update_session
            .update_started(update_plan, update_stream);
        self.show_timeline();
    }

    fn finish_signature_update(&mut self, sender: &ComponentSender<Self>) {
        let finished_report = match self.signature_update_session.update_stream_ended() {
            UpdateStreamEnding::UpdateEnded(finished_report) => finished_report,
            UpdateStreamEnding::NoUpdateWasRunning => return,
        };
        if finished_report.definitions_changed {
            let _shell_closed = sender.output(ProtectionTimelinePageOutput::SignaturesUpdated);
        }
        let summary_line = finished_report
            .summary_text
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned();
        notify_outside_the_window(
            "update-finished",
            &gettext("Database update finished"),
            &summary_line,
        );
        let finished_toast = plain_text_toast(&summary_line);
        finished_toast.set_button_label(Some(&gettext("Show Log")));
        finished_toast.set_action_name(Some("win.show-page"));
        finished_toast.set_action_target_value(Some(&"logs".to_variant()));
        self.toaster.add_toast(finished_toast);
        let activity_history = self.activity_history.clone();
        let activity_entry = finished_report.activity_entry;
        sender.oneshot_command(async move {
            ProtectionTimelinePageCommand::ActivityRecordingFinished(
                activity_history.record_activity(activity_entry).await,
            )
        });
        Self::refresh_signature_host_status(sender);
        self.show_timeline();
        self.start_evidence_refresh(sender);
    }

    fn run_step_action(
        &mut self,
        chosen_action: ProtectionStepAction,
        sender: &ComponentSender<Self>,
        root: &adw::ToastOverlay,
    ) {
        match chosen_action {
            ProtectionStepAction::UpdateSignatures => self.start_signature_update(sender),
            ProtectionStepAction::CancelSignatureUpdate => {
                self.signature_update_session.cancel_requested();
                self.show_timeline();
            }
            ProtectionStepAction::RunScheduledScan { service_unit } => {
                self.scheduled_scan_starting = true;
                self.show_timeline();
                sender.oneshot_command(async move {
                    let start_outcome = start_system_unit(service_unit).await;
                    ProtectionTimelinePageCommand::UnitRunFinished {
                        start_outcome,
                        scan_service: scan_service_evidence(
                            service_unit_snapshot(service_unit).await,
                        ),
                    }
                });
            }
            ProtectionStepAction::ReviewSettingsSubpage(settings_subpage)
            | ProtectionStepAction::SetUpSettingsSubpage(settings_subpage) => {
                let _action_missing = root.activate_action(
                    &OpenSettingsAction::action_name(),
                    Some(&settings_subpage.action_target().to_variant()),
                );
            }
        }
    }
}

#[relm4::component(pub)]
impl Component for ProtectionTimelinePage {
    type Init = ActivityHistory;
    type Input = ProtectionTimelinePageInput;
    type Output = ProtectionTimelinePageOutput;
    type CommandOutput = ProtectionTimelinePageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
            add_top_bar = &adw::HeaderBar {
                #[wrap(Some)]
                set_title_widget = &adw::WindowTitle {
                    set_title: &gettext("Protection"),
                },

                pack_end = &gtk::Stack {
                    add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Check again")),
                        connect_clicked => ProtectionTimelinePageInput::RefreshRequested,
                    },
                    add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                        set_tooltip_text: Some(&gettext("Checking")),
                    },
                    #[watch]
                    set_visible_child_name: busy_page_name(model.evidence_refresh != EvidenceRefresh::NothingRunning),
                },
            },

            #[wrap(Some)]
            set_content = &gtk::Stack {
            #[local_ref]
            add_named[Some(LOADING_PAGE_NAME)] = protection_loading_page -> adw::StatusPage {},
            add_named[Some(LOADED_PAGE_NAME)] = &adw::PreferencesPage {
                add = &adw::PreferencesGroup {
                    #[watch]
                    set_title: &gtk::glib::markup_escape_text(&decision_headline(model.unresolved_detections)),
                    #[watch]
                    set_description: Some(&gtk::glib::markup_escape_text(&shown_coverage_text(
                        &model.coverage_summary,
                        &gtk::glib::home_dir().to_string_lossy(),
                    ))),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_label: &gettext("Review"),
                        set_valign: gtk::Align::Center,
                        set_action_name: Some("win.show-page"),
                        set_action_target_value: Some(&"detections".to_variant()),
                        add_css_class: "suggested-action",
                        #[watch]
                        set_visible: model.unresolved_detections > 0,
                    },
                },

                add: protection_group,

                add: engine_group,

                #[local_ref]
                add = review_group -> adw::PreferencesGroup {
                    #[watch]
                    set_visible: !model.review_rows.is_empty(),
                },

                add = &system_settings_group(&[
                    SettingsSubpage::OnAccessScanning,
                    SettingsSubpage::TrustedDetections,
                ]),
            },
            #[watch]
            set_visible_child_name: model.first_load().shown_page_name(),
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
            protection_rows: launched_step_group(
                titled_group(&gettext("Checks on your files")),
                &sender,
            ),
            engine_rows: launched_step_group(
                described_group(
                    &gettext("Engine"),
                    &gettext("What the checks above rely on"),
                ),
                &sender,
            ),
            review_rows: launched_step_group(titled_group(&gettext("Needs review")), &sender),
            activity_history,
            signature_update_session: SignatureUpdateSession::new(),
            scheduled_scan_starting: false,
            update_awaits_host_status: false,
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            coverage_summary: gettext("Checking…"),
            unresolved_detections: 0,
            journal_access: JournalAccess::FollowingJournal,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            _unit_watch: run_stream(
                &sender,
                watched_unit_changes(&WATCHED_SERVICE_UNITS)
                    .map(|()| ProtectionTimelinePageCommand::WatchedUnitChanged),
            ),
        };
        let protection_group = &model.protection_rows.widget().clone();
        let engine_group = &model.engine_rows.widget().clone();
        let review_group = &model.review_rows.widget().clone();
        let protection_loading_page = &loading_status_page(&gettext("Checking your protection…"));
        let widgets = view_output!();
        model.start_evidence_refresh(&sender);
        Self::refresh_signature_host_status(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ProtectionTimelinePageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ProtectionTimelinePageInput::UnresolvedDetectionsChanged(unresolved_detections) => {
                self.unresolved_detections = unresolved_detections;
            }
            ProtectionTimelinePageInput::JournalAccessChanged(journal_access) => {
                self.journal_access = journal_access;
                self.show_timeline();
            }
            ProtectionTimelinePageInput::RefreshRequested => {
                self.start_evidence_refresh(&sender);
            }
            ProtectionTimelinePageInput::SignatureUpdateRequested => {
                if self.signature_update_session.host_status_known() {
                    self.start_signature_update(&sender);
                } else {
                    self.update_awaits_host_status = true;
                }
            }
            ProtectionTimelinePageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => self.run_step_action(chosen_action, &sender, root),
            ProtectionTimelinePageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ProtectionTimelinePageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ProtectionTimelinePageCommand::EvidenceGathered {
                protection_evidence,
                gathered_at,
            } => {
                self.gathered_evidence = GatheredEvidence::Gathered {
                    protection_evidence,
                    gathered_at,
                };
                self.show_timeline();
                let refresh_again = self.evidence_refresh == EvidenceRefresh::GatheringThenAgain;
                self.evidence_refresh = EvidenceRefresh::NothingRunning;
                if refresh_again {
                    self.start_evidence_refresh(&sender);
                }
            }
            ProtectionTimelinePageCommand::WatchedUnitChanged => {
                self.start_evidence_refresh(&sender);
            }
            ProtectionTimelinePageCommand::UnitRunFinished {
                start_outcome,
                scan_service,
            } => {
                self.scheduled_scan_starting = false;
                self.toaster
                    .add_toast(unit_run_toast(&start_outcome, &scan_service));
                self.show_timeline();
                self.start_evidence_refresh(&sender);
            }
            ProtectionTimelinePageCommand::SignatureHostStatusLoaded(host_status) => {
                self.signature_update_session
                    .host_status_loaded(host_status);
                if std::mem::take(&mut self.update_awaits_host_status) {
                    self.start_signature_update(&sender);
                }
                self.show_timeline();
            }
            ProtectionTimelinePageCommand::SignatureUpdateBatchArrived(update_batch) => {
                self.signature_update_session
                    .absorb_update_batch(update_batch);
                self.show_timeline();
            }
            ProtectionTimelinePageCommand::SignatureUpdateStreamFinished => {
                self.finish_signature_update(&sender);
            }
            ProtectionTimelinePageCommand::ActivityRecordingFinished(Ok(())) => {
                let _shell_closed = sender.output(ProtectionTimelinePageOutput::ActivityRecorded);
            }
            ProtectionTimelinePageCommand::ActivityRecordingFinished(Err(recording_failure)) => {
                self.toaster.add_toast(plain_text_toast(
                    &gettext("The update could not be added to the history: {error}")
                        .replace("{error}", &recording_failure.to_string()),
                ));
            }
        }
    }
}

#[cfg(test)]
mod protection_timeline_page_tests {
    use super::*;
    use crate::host_services::systemd_bus::host_systemd_units::{
        ServiceLastResult, ServiceUnitSnapshot, UnitActivity,
    };

    fn loaded_scan_service(exit_status: i32) -> ScanServiceEvidence {
        scan_service_evidence(ServiceUnitSnapshot::LoadedService {
            unit_activity: UnitActivity::UnitInactive,
            last_result: ServiceLastResult::ExitedWithStatus { exit_status },
            program_arguments: Vec::new(),
        })
    }

    #[test]
    fn finding_malware_is_not_reported_as_a_failed_scan() {
        let failed_job = UnitStartOutcome::JobEnded {
            job_result: "failed".to_owned(),
        };
        assert_eq!(
            unit_run_toast_text(&failed_job, &loaded_scan_service(1)),
            "The scan found malware"
        );
        assert!(
            unit_run_toast_text(&failed_job, &loaded_scan_service(2))
                .contains("did not finish cleanly")
        );
    }

    #[test]
    fn an_unreadable_scan_service_never_claims_malware_was_found() {
        let failed_job = UnitStartOutcome::JobEnded {
            job_result: "failed".to_owned(),
        };
        assert!(
            unit_run_toast_text(
                &failed_job,
                &scan_service_evidence(ServiceUnitSnapshot::SystemdUnreachable(
                    SystemdBusFailure::UnrecognizedLoadState
                ))
            )
            .contains("did not finish cleanly")
        );
        assert_eq!(
            unit_run_toast_text(
                &UnitStartOutcome::BusFailure(SystemdBusFailure::UnrecognizedLoadState),
                &ScanServiceEvidence::ServiceMissing
            ),
            "The scan could not be started: systemd reported a unit state Lazaret does not \
             recognize"
        );
    }

    #[test]
    fn the_headline_counts_open_decisions() {
        assert_eq!(decision_headline(0), "Nothing needs your decision");
        assert_eq!(decision_headline(2), "2 detections need your decision");
    }

    #[test]
    fn coverage_lines_shorten_the_home_folder() {
        assert_eq!(
            shown_coverage_text("/home/user/Downloads blocked on access", "/home/user"),
            "~/Downloads blocked on access"
        );
        assert_eq!(
            shown_coverage_text("/home/username/Downloads blocked", "/home/user"),
            "/home/username/Downloads blocked"
        );
    }
}
