use futures::StreamExt;
use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_settings::preferences_dialog::present_preferences_dialog,
    background_detections::detection_journal_follower::JournalAccess,
    clamav_components::distribution_install_guides::{
        DistributionFamily, detect_distribution_family,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    protection_status::{
        protection_evidence::{
            ProtectionEvidence, WATCHED_SERVICE_UNITS, clamui_schedule_is_enabled,
            detection_notifications_are_enabled, gather_protection_evidence,
        },
        protection_timeline_presentation::{AlertReadiness, protection_timeline},
    },
    step_timeline::{
        timeline_step_model::{TimelineStepAction, TimelineStepRequest},
        timeline_step_row::{TimelineStepRow, TimelineStepRowInput},
    },
    systemd_bus::host_systemd_units::{
        ServiceLastResult, UnitStartOutcome, service_unit_snapshot, start_system_unit,
        watched_unit_changes,
    },
};

const SCANNER_FOUND_THREATS_STATUS: i32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceRefresh {
    NothingRunning,
    GatheringOnce,
    GatheringThenAgain,
}

pub struct ProtectionTimelinePage {
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
    StepRequested(TimelineStepRequest),
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

pub fn headline_text(unresolved_detections: usize, coverage_summary: &str) -> String {
    if unresolved_detections == 0 {
        return coverage_summary.to_owned();
    }
    ngettext(
        "{count} detection needs your decision. {coverage}",
        "{count} detections need your decision. {coverage}",
        u32::try_from(unresolved_detections).unwrap_or(u32::MAX),
    )
    .replace("{count}", &unresolved_detections.to_string())
    .replace("{coverage}", coverage_summary)
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

pub fn unit_run_toast_text(
    start_outcome: &UnitStartOutcome,
    last_result: &ServiceLastResult,
) -> String {
    if matches!(start_outcome, UnitStartOutcome::JobEnded { .. })
        && *last_result
            == (ServiceLastResult::ExitedWithStatus {
                exit_status: SCANNER_FOUND_THREATS_STATUS,
            })
    {
        return gettext("The scan found malware. See Detections.");
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
    fn start_evidence_refresh(&mut self, sender: &ComponentSender<Self>) {
        if self.evidence_refresh != EvidenceRefresh::NothingRunning {
            self.evidence_refresh = EvidenceRefresh::GatheringThenAgain;
            return;
        }
        self.evidence_refresh = EvidenceRefresh::GatheringOnce;
        let clamui_schedule_enabled = clamui_schedule_is_enabled();
        sender.oneshot_command(async move {
            ProtectionTimelinePageCommand::EvidenceGathered(Box::new(
                gather_protection_evidence(clamui_schedule_enabled).await,
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
                root.add_toast(plain_text_toast(&gettext("Starting the scan…")));
                sender.oneshot_command(async move {
                    let start_outcome = start_system_unit(service_unit).await;
                    ProtectionTimelinePageCommand::UnitRunFinished {
                        start_outcome,
                        last_result: service_unit_snapshot(service_unit).await.last_result,
                    }
                });
            }
            TimelineStepAction::OpenSchedulePreferences => present_preferences_dialog(),
            TimelineStepAction::QuarantineIncident
            | TimelineStepAction::AskIncidentDeletion
            | TimelineStepAction::DeleteIncidentFile
            | TimelineStepAction::CancelIncidentDeletion
            | TimelineStepAction::DismissIncident
            | TimelineStepAction::LookUpIncidentSignature
            | TimelineStepAction::CheckIncidentOnVirusTotal => {}
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
            set_child = &adw::PreferencesPage {
                add = &adw::PreferencesGroup {
                    #[watch]
                    set_title: &gtk::glib::markup_escape_text(&headline_text(model.unresolved_detections, &model.coverage_summary)),
                    #[wrap(Some)]
                    set_header_suffix = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Check again")),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        connect_clicked => ProtectionTimelinePageInput::RefreshRequested,
                    },
                },

                add: timeline_group,
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
            ProtectionTimelinePageInput::StepRequested(TimelineStepRequest::ActionChosen(
                chosen_action,
            )) => Self::run_step_action(chosen_action, &sender, root),
            ProtectionTimelinePageInput::StepRequested(TimelineStepRequest::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                root.add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ProtectionTimelinePageCommand,
        sender: ComponentSender<Self>,
        root: &Self::Root,
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
                root.add_toast(plain_text_toast(&unit_run_toast_text(
                    &start_outcome,
                    &last_result,
                )));
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
            "The scan found malware. See Detections."
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
    fn unresolved_detections_come_before_coverage() {
        assert_eq!(headline_text(0, "Downloads blocked"), "Downloads blocked");
        assert_eq!(
            headline_text(2, "Downloads blocked"),
            "2 detections need your decision. Downloads blocked"
        );
    }
}
