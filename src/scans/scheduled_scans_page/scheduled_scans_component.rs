use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    host_services::{
        activity_history::activity_history_database::ActivityHistory,
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        desktop::locale_formatting::host_moment_formatters,
    },
    scans::scheduled_scans_page::{
        scan_schedule_component::{ScanScheduleSection, ScanScheduleSectionInput},
        scheduled_scans_presentation::{ScheduledScanAction, scheduled_scans_page_steps},
        scheduled_scans_state::ScheduledScansPageOutput,
    },
    shared_widgets::{
        activity_entries::{
            activity_history_filter::ActivityHistoryFilter,
            activity_history_group::{
                ActivityHistoryGroup, ActivityHistoryGroupInit, ActivityHistoryGroupInput,
            },
        },
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        step_timeline::{
            step_evidence_builders::MomentContext,
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, show_timeline_steps},
        },
    },
};

pub struct ScheduledScansPage {
    toaster: Toaster,
    status_rows: FactoryVecDeque<TimelineStepRow<ScheduledScanAction>>,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
    schedule_section: Controller<ScanScheduleSection>,
    history_group: Controller<ActivityHistoryGroup>,
}

#[derive(Debug)]
pub enum ScheduledScansPageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    HistoryReloadRequested,
    SettingsRevealRequested,
    StepRequested(TimelineStepRowOutput<ScheduledScanAction>),
}

impl ScheduledScansPage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn show_status_steps(&mut self) {
        let GatheredEvidence::Gathered {
            protection_evidence,
            gathered_at,
        } = &self.gathered_evidence
        else {
            return;
        };
        show_timeline_steps(
            &mut self.status_rows,
            scheduled_scans_page_steps(
                protection_evidence,
                MomentContext {
                    moment_formatters: host_moment_formatters(),
                    reference_moment: *gathered_at,
                },
                self.distribution_family,
            ),
        );
    }
}

#[relm4::component(pub)]
impl Component for ScheduledScansPage {
    type Init = ActivityHistory;
    type Input = ScheduledScansPageInput;
    type Output = ScheduledScansPageOutput;
    type CommandOutput = ();

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check again")),
                            connect_clicked => ScheduledScansPageInput::RefreshRequested,
                        },
                        add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                            set_tooltip_text: Some(&gettext("Checking")),
                        },
                        #[watch]
                        set_visible_child_name: busy_page_name(model.evidence_refresh.is_running()),
                    },
                },

                #[wrap(Some)]
                set_content = &gtk::Stack {
                    #[local_ref]
                    add_named[Some(LOADING_PAGE_NAME)] = status_loading_page -> adw::StatusPage {},
                    add_named[Some(LOADED_PAGE_NAME)] = &adw::PreferencesPage {
                        add: status_group,
                        add: model.schedule_section.widget(),
                        add: model.history_group.widget(),
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
        let model = Self {
            toaster: Toaster::new(&root),
            status_rows: FactoryVecDeque::builder()
                .launch(
                    adw::PreferencesGroup::builder()
                        .title(gettext("Status"))
                        .build(),
                )
                .forward(
                    sender.input_sender(),
                    ScheduledScansPageInput::StepRequested,
                ),
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            schedule_section: ScanScheduleSection::builder().launch(()).detach(),
            history_group: ActivityHistoryGroup::builder()
                .launch(ActivityHistoryGroupInit {
                    activity_history,
                    history_filter: ActivityHistoryFilter::ScheduledScans,
                    group_title: gettext("Scheduled runs"),
                    group_description: gettext(
                        "Scans Lazaret's schedule ran, newest first. Select one to read its \
                         transcript.",
                    ),
                    empty_title: gettext("Lazaret's schedule has not run a scan yet"),
                    empty_icon_name: "alarm-symbolic",
                })
                .detach(),
        };
        let status_group = &model.status_rows.widget().clone();
        let status_loading_page = &loading_status_page(&gettext("Checking the schedule…"));
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScheduledScansPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ScheduledScansPageInput::RefreshRequested => {
                let _shell_closed =
                    sender.output(ScheduledScansPageOutput::EvidenceRefreshRequested);
            }
            ScheduledScansPageInput::SettingsRevealRequested => {
                self.schedule_section
                    .emit(ScanScheduleSectionInput::RevealRequested);
            }
            ScheduledScansPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            ScheduledScansPageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
                self.show_status_steps();
                self.history_group
                    .emit(ActivityHistoryGroupInput::ReloadRequested);
            }
            ScheduledScansPageInput::HistoryReloadRequested => {
                self.history_group
                    .emit(ActivityHistoryGroupInput::ReloadRequested);
            }
            ScheduledScansPageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => match chosen_action {},
            ScheduledScansPageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
        }
    }
}
