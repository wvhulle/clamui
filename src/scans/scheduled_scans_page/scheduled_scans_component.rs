use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::{
        application_pages::ApplicationPage,
        protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    },
    host_services::{
        activity_history::activity_history_database::ActivityHistory,
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        desktop::locale_formatting::host_moment_formatters,
        protection_evidence::host_protection_evidence::{
            ScanServiceEvidence, scan_service_evidence,
        },
        systemd_bus::host_systemd_units::{
            UnitStartOutcome, service_unit_snapshot, start_system_unit,
        },
    },
    scans::scheduled_scans_page::{
        scan_schedule_component::ScanScheduleSection,
        scheduled_scans_presentation::{ScheduledScanAction, scheduled_scans_page_steps},
        scheduled_scans_state::ScheduledScansPageOutput,
        system_scan_run::{
            SystemScanControl, SystemScanStart, scan_found_threats, unit_run_toast_text,
        },
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
    system_scan_control: SystemScanControl,
}

#[derive(Debug)]
pub enum ScheduledScansPageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    HistoryReloadRequested,
    StepRequested(TimelineStepRowOutput<ScheduledScanAction>),
    SystemScanRequested,
}

#[derive(Debug)]
pub enum ScheduledScansPageCommand {
    SystemScanFinished {
        start_outcome: UnitStartOutcome,
        scan_service: ScanServiceEvidence,
    },
}

const FOUND_THREATS_TOAST_SECONDS: u32 = 10;

fn system_scan_toast(
    start_outcome: &UnitStartOutcome,
    scan_service: &ScanServiceEvidence,
) -> adw::Toast {
    let run_toast = adw::Toast::builder()
        .title(unit_run_toast_text(start_outcome, scan_service))
        .use_markup(false)
        .build();
    if scan_found_threats(start_outcome, scan_service) {
        run_toast.set_button_label(Some(&gettext("Review")));
        run_toast.set_action_name(Some("win.show-page"));
        run_toast
            .set_action_target_value(Some(&ApplicationPage::Detections.page_name().to_variant()));
        run_toast.set_timeout(FOUND_THREATS_TOAST_SECONDS);
    }
    run_toast
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
    type CommandOutput = ScheduledScansPageCommand;

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

                    adw::PreferencesGroup {
                        set_title: &gettext("System scan"),
                        #[watch]
                        set_description: Some(&gtk::glib::markup_escape_text(&model.system_scan_control.group_description())),
                        #[watch]
                        set_visible: model.system_scan_control.shows_system_scan(),

                        adw::ActionRow {
                            set_use_markup: false,
                            set_title: &gettext("Folders scanned"),
                            #[watch]
                            set_subtitle: &model.system_scan_control.scanned_folders_text(),

                            add_suffix = &gtk::Stack {
                                add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                                    set_label: &gettext("Run Now"),
                                    set_valign: gtk::Align::Center,
                                    #[watch]
                                    set_sensitive: model.system_scan_control.accepts_run(),
                                    connect_clicked => ScheduledScansPageInput::SystemScanRequested,
                                },
                                add_named[Some(BUSY_PAGE_NAME)] = &adw::Spinner {
                                    set_tooltip_text: Some(&gettext("Starting the scan…")),
                                },
                                #[watch]
                                set_visible_child_name: busy_page_name(model.system_scan_control.run_is_starting()),
                            },
                        },
                    },

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
                })
                .detach(),
            system_scan_control: SystemScanControl::new(),
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
            ScheduledScansPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            ScheduledScansPageInput::EvidenceGathered(gathered_evidence) => {
                if let GatheredEvidence::Gathered {
                    protection_evidence,
                    ..
                } = &gathered_evidence
                {
                    self.system_scan_control
                        .evidence_gathered(protection_evidence);
                }
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
            ScheduledScansPageInput::SystemScanRequested => {
                match self.system_scan_control.run_requested() {
                    SystemScanStart::StartServiceUnit { service_unit } => {
                        sender.oneshot_command(async move {
                            let start_outcome = start_system_unit(service_unit).await;
                            ScheduledScansPageCommand::SystemScanFinished {
                                start_outcome,
                                scan_service: scan_service_evidence(
                                    service_unit_snapshot(service_unit).await,
                                ),
                            }
                        });
                    }
                    SystemScanStart::NothingToStart => {}
                }
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ScheduledScansPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ScheduledScansPageCommand::SystemScanFinished {
                start_outcome,
                scan_service,
            } => {
                self.system_scan_control.run_finished();
                self.toaster
                    .add_toast(system_scan_toast(&start_outcome, &scan_service));
                let _shell_closed =
                    sender.output(ScheduledScansPageOutput::EvidenceRefreshRequested);
            }
        }
    }
}
