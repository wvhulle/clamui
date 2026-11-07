use futures::StreamExt;
use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    host_services::clamav_programs::distribution_install_guides::{
        DistributionFamily, detect_distribution_family,
    },
    scans::scan_engine_page::{
        clamd_socket_ownership::{ClamdSocketOwnership, inspect_clamd_socket_off_thread},
        daemon_log_reader::daemon_log_updates,
        scan_engine_presentation::{ScanEngineAction, scan_engine_steps},
        scan_engine_state::{ClamdSocketView, ScanEnginePageOutput},
    },
    shared_widgets::{
        engine_settings::engine_settings_sections::{
            EngineSettingsLayout, EngineSettingsNotice, EngineSettingsSections,
            EngineSettingsSectionsOutput, SettingsChangeFollowUp, engine_settings_notice_toast,
            settings_change_follow_up,
        },
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        service_log::service_log_group::{
            ServiceLogGroup, ServiceLogGroupInit, ServiceLogGroupOutput,
        },
        step_timeline::{
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, show_timeline_steps},
        },
        system_changes::{
            system_changes_group::{
                SystemChangesGroup, SystemChangesGroupInit, SystemChangesGroupInput,
            },
            system_changes_state::AuditTopic,
        },
    },
};

pub const SCAN_ENGINE_SETTINGS_LAYOUT: EngineSettingsLayout =
    EngineSettingsLayout::EngineWithDetection;

pub struct ScanEnginePage {
    toaster: Toaster,
    status_rows: FactoryVecDeque<TimelineStepRow<ScanEngineAction>>,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
    clamd_socket_view: ClamdSocketView,
    engine_settings_sections: Controller<EngineSettingsSections>,
    system_changes_group: Controller<SystemChangesGroup>,
    daemon_log_group: Controller<ServiceLogGroup>,
}

#[derive(Debug)]
pub enum ScanEnginePageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    SettingsNoticeReceived(EngineSettingsNotice),
    StepRequested(TimelineStepRowOutput<ScanEngineAction>),
    LogToastRequested(String),
}

#[derive(Debug)]
pub enum ScanEnginePageCommand {
    SocketInspected(ClamdSocketOwnership),
}

pub fn page_input_for_settings_output(
    settings_output: EngineSettingsSectionsOutput,
) -> ScanEnginePageInput {
    match settings_output {
        EngineSettingsSectionsOutput::ToastRequested(settings_notice) => {
            ScanEnginePageInput::SettingsNoticeReceived(settings_notice)
        }
    }
}

pub fn page_input_for_log_output(log_output: ServiceLogGroupOutput) -> ScanEnginePageInput {
    match log_output {
        ServiceLogGroupOutput::ToastRequested(toast_text) => {
            ScanEnginePageInput::LogToastRequested(toast_text)
        }
    }
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

impl ScanEnginePage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn report_output(sender: &ComponentSender<Self>, page_output: ScanEnginePageOutput) {
        let _shell_closed = sender.output(page_output);
    }

    fn inspect_socket(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            ScanEnginePageCommand::SocketInspected(inspect_clamd_socket_off_thread().await)
        });
    }

    fn show_status_steps(&mut self) {
        let GatheredEvidence::Gathered {
            protection_evidence,
            ..
        } = &self.gathered_evidence
        else {
            return;
        };
        show_timeline_steps(
            &mut self.status_rows,
            scan_engine_steps(
                protection_evidence,
                &self.clamd_socket_view,
                self.distribution_family,
            ),
        );
    }
}

#[relm4::component(pub)]
impl Component for ScanEnginePage {
    type Init = ();
    type Input = ScanEnginePageInput;
    type Output = ScanEnginePageOutput;
    type CommandOutput = ScanEnginePageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check again")),
                            connect_clicked => ScanEnginePageInput::RefreshRequested,
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
                        add: model.engine_settings_sections.widget(),
                        add: model.system_changes_group.widget(),
                        add: model.daemon_log_group.widget(),
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
        let model = Self {
            toaster: Toaster::new(&root),
            status_rows: FactoryVecDeque::builder()
                .launch(
                    adw::PreferencesGroup::builder()
                        .title(gettext("Status"))
                        .build(),
                )
                .forward(sender.input_sender(), ScanEnginePageInput::StepRequested),
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            clamd_socket_view: ClamdSocketView::SocketInspecting,
            engine_settings_sections: EngineSettingsSections::builder()
                .launch(SCAN_ENGINE_SETTINGS_LAYOUT)
                .forward(sender.input_sender(), page_input_for_settings_output),
            system_changes_group: SystemChangesGroup::builder()
                .launch(SystemChangesGroupInit {
                    audit_topic: AuditTopic::EngineChanges,
                    group_description: gettext(
                        "Engine and detection settings changed through Lazaret, as recorded by \
                         the system. Software running as you can't remove these records.",
                    ),
                    empty_title: gettext(
                        "No engine or detection settings were changed through Lazaret",
                    ),
                })
                .detach(),
            daemon_log_group: ServiceLogGroup::builder()
                .launch(ServiceLogGroupInit {
                    group_title: gettext("clamd log"),
                    missing_log_title: gettext("No clamd log was found"),
                    export_file_name: "clamd-logs.txt",
                    log_updates: daemon_log_updates().boxed(),
                })
                .forward(sender.input_sender(), page_input_for_log_output),
        };
        let status_group = &model.status_rows.widget().clone();
        let status_loading_page = &loading_status_page(&gettext("Checking the scan engine…"));
        let widgets = view_output!();
        Self::inspect_socket(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScanEnginePageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ScanEnginePageInput::RefreshRequested => {
                Self::report_output(&sender, ScanEnginePageOutput::EvidenceRefreshRequested);
            }
            ScanEnginePageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            ScanEnginePageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
                self.show_status_steps();
                Self::inspect_socket(&sender);
            }
            ScanEnginePageInput::SettingsNoticeReceived(settings_notice) => {
                self.toaster
                    .add_toast(engine_settings_notice_toast(&settings_notice));
                match settings_change_follow_up(&settings_notice) {
                    SettingsChangeFollowUp::ReloadChangesAndEvidence => {
                        self.system_changes_group
                            .emit(SystemChangesGroupInput::ReloadRequested);
                        Self::report_output(
                            &sender,
                            ScanEnginePageOutput::EvidenceRefreshRequested,
                        );
                    }
                    SettingsChangeFollowUp::NothingToReload => {}
                }
            }
            ScanEnginePageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => match chosen_action {},
            ScanEnginePageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            ScanEnginePageInput::LogToastRequested(toast_text) => {
                self.toaster.add_toast(plain_text_toast(&toast_text));
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ScanEnginePageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ScanEnginePageCommand::SocketInspected(socket_ownership) => {
                self.clamd_socket_view = ClamdSocketView::SocketInspected(socket_ownership);
                self.show_status_steps();
            }
        }
    }
}

#[cfg(test)]
mod scan_engine_component_tests {
    use super::*;

    #[test]
    fn child_toast_requests_become_page_notices() {
        assert!(matches!(
            page_input_for_settings_output(EngineSettingsSectionsOutput::ToastRequested(
                EngineSettingsNotice::ChangeSnippetCopied
            )),
            ScanEnginePageInput::SettingsNoticeReceived(EngineSettingsNotice::ChangeSnippetCopied)
        ));
        assert!(matches!(
            page_input_for_log_output(ServiceLogGroupOutput::ToastRequested("Exported.".to_owned())),
            ScanEnginePageInput::LogToastRequested(toast_text) if toast_text == "Exported."
        ));
    }

    #[test]
    fn one_settings_component_and_so_one_unlock_shows_both_engine_groups() {
        assert!(SCAN_ENGINE_SETTINGS_LAYOUT.shows_detection_switches());
    }
}
