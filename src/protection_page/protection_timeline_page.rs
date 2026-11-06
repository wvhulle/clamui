use futures::StreamExt;
use gettextrs::{gettext, ngettext};
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
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        detection_journal::detection_journal_follower::JournalAccess,
        systemd_bus::host_systemd_units::{
            ServiceLastResult, UnitStartOutcome, service_unit_snapshot, start_system_unit,
            watched_unit_changes,
        },
    },
    protection_page::{
        protection_evidence::{
            ProtectionEvidence, WATCHED_SERVICE_UNITS, detection_notifications_are_enabled,
            gather_protection_evidence, lazaret_schedule_is_enabled,
        },
        protection_timeline_presentation::{AlertReadiness, protection_timeline},
    },
    shared_widgets::{
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        step_timeline::{
            timeline_step_contents::{TimelineStepAction, TimelineStepRowOutput},
            timeline_step_row::{TimelineStepRow, TimelineStepRowInput},
        },
    },
};

const SCANNER_FOUND_THREATS_STATUS: i32 = 1;
const FOUND_THREATS_TOAST_SECONDS: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceRefresh {
    NothingRunning,
    GatheringOnce,
    GatheringThenAgain,
}

pub struct ProtectionTimelinePage {
    toaster: Toaster,
    timeline_rows: FactoryVecDeque<TimelineStepRow>,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    coverage_summary: String,
    unresolved_detections: usize,
    journal_access: JournalAccess,
    gathered_evidence: GatheredEvidence,
}

enum GatheredEvidence {
    NotGatheredYet,
    Gathered(Box<ProtectionEvidence>),
}

#[derive(Debug)]
pub enum ProtectionTimelinePageInput {
    RefreshRequested,
    UnresolvedDetectionsChanged(usize),
    JournalAccessChanged(JournalAccess),
    StepRequested(TimelineStepRowOutput),
}

#[derive(Debug)]
pub enum ProtectionTimelinePageOutput {
    UpdateSignaturesRequested,
}

#[derive(Debug)]
pub enum ProtectionTimelinePageCommand {
    EvidenceGathered(Box<ProtectionEvidence>),
    WatchedUnitChanged,
    UnitRunFinished {
        start_outcome: UnitStartOutcome,
        last_result: ServiceLastResult,
    },
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

fn scan_found_threats(start_outcome: &UnitStartOutcome, last_result: &ServiceLastResult) -> bool {
    matches!(start_outcome, UnitStartOutcome::JobEnded { .. })
        && *last_result
            == (ServiceLastResult::ExitedWithStatus {
                exit_status: SCANNER_FOUND_THREATS_STATUS,
            })
}

fn unit_run_toast(start_outcome: &UnitStartOutcome, last_result: &ServiceLastResult) -> adw::Toast {
    let run_toast = plain_text_toast(&unit_run_toast_text(start_outcome, last_result));
    if scan_found_threats(start_outcome, last_result) {
        run_toast.set_button_label(Some(&gettext("Review")));
        run_toast.set_action_name(Some("win.show-page"));
        run_toast.set_action_target_value(Some(&"detections".to_variant()));
        run_toast.set_timeout(FOUND_THREATS_TOAST_SECONDS);
    }
    run_toast
}

pub fn unit_run_toast_text(
    start_outcome: &UnitStartOutcome,
    last_result: &ServiceLastResult,
) -> String {
    if scan_found_threats(start_outcome, last_result) {
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
        UnitStartOutcome::BusFailure { failure_text } => {
            gettext("The scan could not be started: {error}")
                .replace("{error}", &sanitize_scanner_line(failure_text))
        }
    }
}

impl ProtectionTimelinePage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered(_) => FirstLoad::LoadFinished,
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
            ProtectionTimelinePageCommand::EvidenceGathered(Box::new(
                gather_protection_evidence(lazaret_schedule_enabled).await,
            ))
        });
    }

    fn show_timeline(&mut self) {
        let GatheredEvidence::Gathered(protection_evidence) = &self.gathered_evidence else {
            return;
        };
        let gathered_timeline = protection_timeline(
            protection_evidence,
            &AlertReadiness {
                journal_access: self.journal_access.clone(),
                notifications_enabled: detection_notifications_are_enabled(),
            },
            self.distribution_family,
        );
        self.coverage_summary = gathered_timeline.coverage_summary;
        if self.timeline_rows.len() == gathered_timeline.timeline_steps.len() {
            gathered_timeline
                .timeline_steps
                .into_iter()
                .enumerate()
                .for_each(|positioned_step| {
                    self.timeline_rows.send(
                        positioned_step.0,
                        TimelineStepRowInput::StepChanged(Box::new(positioned_step.1)),
                    );
                });
        } else {
            let mut row_guard = self.timeline_rows.guard();
            row_guard.clear();
            gathered_timeline
                .timeline_steps
                .into_iter()
                .for_each(|timeline_step| {
                    row_guard.push_back(timeline_step);
                });
        }
    }

    fn run_step_action(
        &self,
        chosen_action: TimelineStepAction,
        sender: &ComponentSender<Self>,
        root: &adw::ToastOverlay,
    ) {
        match chosen_action {
            TimelineStepAction::UpdateSignatures => {
                let _shell_closed =
                    sender.output(ProtectionTimelinePageOutput::UpdateSignaturesRequested);
            }
            TimelineStepAction::RunScheduledScan { service_unit } => {
                self.toaster
                    .add_toast(plain_text_toast(&gettext("Starting the scan…")));
                sender.oneshot_command(async move {
                    let start_outcome = start_system_unit(service_unit).await;
                    ProtectionTimelinePageCommand::UnitRunFinished {
                        start_outcome,
                        last_result: service_unit_snapshot(service_unit).await.last_result,
                    }
                });
            }
            TimelineStepAction::OpenSettingsSubpage(settings_subpage) => {
                let _action_missing = root.activate_action(
                    &OpenSettingsAction::action_name(),
                    Some(&settings_subpage.action_target().to_variant()),
                );
            }
            TimelineStepAction::QuarantineIncident
            | TimelineStepAction::AskIncidentDeletion
            | TimelineStepAction::DeleteIncidentFile
            | TimelineStepAction::CancelIncidentDeletion
            | TimelineStepAction::DismissIncident
            | TimelineStepAction::LookUpIncidentSignature => {}
        }
    }
}

#[relm4::component(pub)]
impl Component for ProtectionTimelinePage {
    type Init = ();
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

                add: timeline_group,

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
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let timeline_rows = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(
                sender.input_sender(),
                ProtectionTimelinePageInput::StepRequested,
            );
        let mut model = Self {
            toaster: Toaster::new(&root),
            timeline_rows,
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            coverage_summary: gettext("Checking…"),
            unresolved_detections: 0,
            journal_access: JournalAccess::FollowingJournal,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
        };
        let timeline_group = model.timeline_rows.widget().clone();
        let timeline_group = &timeline_group;
        let protection_loading_page = &loading_status_page(&gettext("Checking your protection…"));
        let widgets = view_output!();
        sender.command(|command_sender, shutdown_receiver| {
            shutdown_receiver
                .register(async move {
                    let mut unit_changes = Box::pin(watched_unit_changes(&WATCHED_SERVICE_UNITS));
                    while unit_changes.next().await.is_some() {
                        command_sender.emit(ProtectionTimelinePageCommand::WatchedUnitChanged);
                    }
                })
                .drop_on_shutdown()
        });
        model.start_evidence_refresh(&sender);
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
            ProtectionTimelinePageCommand::EvidenceGathered(protection_evidence) => {
                self.gathered_evidence = GatheredEvidence::Gathered(protection_evidence);
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
                last_result,
            } => {
                self.toaster
                    .add_toast(unit_run_toast(&start_outcome, &last_result));
                self.start_evidence_refresh(&sender);
            }
        }
    }
}

#[cfg(test)]
mod protection_timeline_page_tests {
    use super::*;

    #[test]
    fn finding_malware_is_not_reported_as_a_failed_scan() {
        let failed_job = UnitStartOutcome::JobEnded {
            job_result: "failed".to_owned(),
        };
        assert_eq!(
            unit_run_toast_text(
                &failed_job,
                &ServiceLastResult::ExitedWithStatus { exit_status: 1 }
            ),
            "The scan found malware"
        );
        assert!(
            unit_run_toast_text(
                &failed_job,
                &ServiceLastResult::ExitedWithStatus { exit_status: 2 }
            )
            .contains("did not finish cleanly")
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
