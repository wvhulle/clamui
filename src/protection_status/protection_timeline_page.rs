use futures::StreamExt;
use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, gtk::gio,
    prelude::FactoryVecDeque,
};

use crate::{
    application_settings::preferences_dialog::present_preferences_dialog,
    clamav_components::distribution_install_guides::{
        DistributionFamily, detect_distribution_family,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    protection_status::{
        protection_evidence::{
            WATCHED_SERVICE_UNITS, clamui_schedule_is_enabled, gather_protection_evidence,
        },
        protection_timeline_presentation::{ProtectionTimeline, protection_timeline},
    },
    step_timeline::{
        timeline_step_model::{TimelineStepAction, TimelineStepRequest},
        timeline_step_row::{TimelineStepRow, TimelineStepRowInput},
    },
    system_audit::{
        audit_report_model::{ALL_AUDIT_CATEGORIES, AuditSection},
        audit_section_group::{AuditGuidanceRequest, AuditSectionGroup, AuditSectionGroupInput},
        security_audit_checks::gather_audit_section,
    },
    systemd_bus::host_systemd_units::{UnitStartOutcome, start_system_unit, watched_unit_changes},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvidenceRefresh {
    NothingRunning,
    GatheringOnce,
    GatheringThenAgain,
}

pub struct ProtectionTimelinePage {
    timeline_rows: FactoryVecDeque<TimelineStepRow>,
    section_groups: FactoryVecDeque<AuditSectionGroup>,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    coverage_summary: String,
}

#[derive(Debug)]
pub enum ProtectionTimelinePageInput {
    RefreshRequested,
    StepRequested(TimelineStepRequest),
    GuidanceRequested(AuditGuidanceRequest),
    DocumentationOpenFailed(String),
}

#[derive(Debug)]
pub enum ProtectionTimelinePageOutput {
    UpdateSignaturesRequested,
}

#[derive(Debug)]
pub enum ProtectionTimelinePageCommand {
    TimelineGathered(ProtectionTimeline),
    SectionFinished(AuditSection),
    WatchedUnitChanged,
    UnitRunFinished(UnitStartOutcome),
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn unit_run_toast_text(start_outcome: &UnitStartOutcome) -> String {
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
        let distribution_family = self.distribution_family;
        let clamui_schedule_enabled = clamui_schedule_is_enabled();
        sender.oneshot_command(async move {
            ProtectionTimelinePageCommand::TimelineGathered(protection_timeline(
                &gather_protection_evidence(clamui_schedule_enabled).await,
                distribution_family,
            ))
        });
    }

    fn start_section_audit(&self, sender: &ComponentSender<Self>) {
        let distribution_family = self.distribution_family;
        ALL_AUDIT_CATEGORIES.into_iter().for_each(|audit_category| {
            self.section_groups.send(
                audit_category.section_position(),
                AuditSectionGroupInput::SectionChanged(AuditSection::awaiting_checks(
                    audit_category,
                )),
            );
            sender.oneshot_command(async move {
                ProtectionTimelinePageCommand::SectionFinished(
                    gather_audit_section(audit_category, distribution_family).await,
                )
            });
        });
    }

    fn show_timeline(&mut self, gathered_timeline: ProtectionTimeline) {
        self.coverage_summary = gathered_timeline.coverage_summary;
        if self.timeline_rows.len() == gathered_timeline.timeline_steps.len() {
            gathered_timeline
                .timeline_steps
                .into_iter()
                .enumerate()
                .for_each(|positioned_step| {
                    self.timeline_rows.send(
                        positioned_step.0,
                        TimelineStepRowInput::StepChanged(positioned_step.1),
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
                    ProtectionTimelinePageCommand::UnitRunFinished(
                        start_system_unit(service_unit).await,
                    )
                });
            }
            TimelineStepAction::OpenSchedulePreferences => present_preferences_dialog(),
        }
    }

    fn open_documentation(
        documentation_url: &str,
        sender: &ComponentSender<Self>,
        root: &adw::ToastOverlay,
    ) {
        let failure_sender = sender.clone();
        let parent_window = root.root().and_downcast::<gtk::Window>();
        gtk::UriLauncher::new(documentation_url).launch(
            parent_window.as_ref(),
            gio::Cancellable::NONE,
            move |launch_outcome| {
                if let Err(launch_failure) = launch_outcome {
                    failure_sender.input(ProtectionTimelinePageInput::DocumentationOpenFailed(
                        launch_failure.message().to_owned(),
                    ));
                }
            },
        );
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
            #[local_ref]
            set_child = protection_preferences_page -> adw::PreferencesPage {
                set_title: &gettext("Protection"),

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Protection"),
                    #[watch]
                    set_description: Some(&gtk::glib::markup_escape_text(&model.coverage_summary)),
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
        let section_groups = FactoryVecDeque::builder()
            .launch(adw::PreferencesPage::default())
            .forward(
                sender.input_sender(),
                ProtectionTimelinePageInput::GuidanceRequested,
            );
        let mut model = Self {
            timeline_rows,
            section_groups,
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            coverage_summary: gettext("Checking…"),
        };
        let protection_preferences_page = &model.section_groups.widget().clone();
        let timeline_group = model.timeline_rows.widget().clone();
        let timeline_group = &timeline_group;
        let widgets = view_output!();
        ALL_AUDIT_CATEGORIES.into_iter().for_each(|audit_category| {
            model.section_groups.guard().push_back(audit_category);
        });
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
        model.start_section_audit(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ProtectionTimelinePageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ProtectionTimelinePageInput::RefreshRequested => {
                self.start_evidence_refresh(&sender);
                self.start_section_audit(&sender);
            }
            ProtectionTimelinePageInput::StepRequested(TimelineStepRequest::ActionChosen(
                chosen_action,
            )) => Self::run_step_action(chosen_action, &sender, root),
            ProtectionTimelinePageInput::StepRequested(TimelineStepRequest::CopyRequested(
                copied_command,
            ))
            | ProtectionTimelinePageInput::GuidanceRequested(
                AuditGuidanceRequest::CopyCommandRequested(copied_command),
            ) => {
                root.clipboard().set_text(&copied_command);
                root.add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            ProtectionTimelinePageInput::GuidanceRequested(
                AuditGuidanceRequest::OpenDocumentationRequested(documentation_url),
            ) => Self::open_documentation(documentation_url, &sender, root),
            ProtectionTimelinePageInput::DocumentationOpenFailed(failure_text) => {
                root.add_toast(plain_text_toast(
                    &gettext("Could not open documentation: {error}")
                        .replace("{error}", &sanitize_scanner_line(&failure_text)),
                ));
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
            ProtectionTimelinePageCommand::TimelineGathered(gathered_timeline) => {
                self.show_timeline(gathered_timeline);
                let refresh_again = self.evidence_refresh == EvidenceRefresh::GatheringThenAgain;
                self.evidence_refresh = EvidenceRefresh::NothingRunning;
                if refresh_again {
                    self.start_evidence_refresh(&sender);
                }
            }
            ProtectionTimelinePageCommand::SectionFinished(audit_section) => {
                self.section_groups.send(
                    audit_section.audit_category.section_position(),
                    AuditSectionGroupInput::SectionChanged(audit_section),
                );
            }
            ProtectionTimelinePageCommand::WatchedUnitChanged => {
                self.start_evidence_refresh(&sender);
            }
            ProtectionTimelinePageCommand::UnitRunFinished(start_outcome) => {
                root.add_toast(plain_text_toast(&unit_run_toast_text(&start_outcome)));
                self.start_evidence_refresh(&sender);
            }
        }
    }
}
