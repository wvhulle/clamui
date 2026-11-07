use futures::StreamExt;
use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    host_services::{
        clamav_programs::distribution_install_guides::{
            DistributionFamily, detect_distribution_family,
        },
        protection_evidence::host_protection_evidence::ON_ACCESS_SERVICE_UNITS,
        systemd_journal::service_log_contents::unit_journal_log_updates,
    },
    scans::on_access_page::{
        on_access_presentation::{OnAccessAction, on_access_page_steps},
        on_access_state::OnAccessPageOutput,
    },
    shared_widgets::{
        engine_settings::engine_settings_sections::{
            EngineSettingsLayout, EngineSettingsNotice, EngineSettingsSection,
            EngineSettingsSections, EngineSettingsSectionsInput, EngineSettingsSectionsOutput,
            SettingsChangeFollowUp, engine_settings_notice_toast, settings_change_follow_up,
        },
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        service_log::service_log_group::{
            ServiceLogGroup, ServiceLogGroupInit, ServiceLogGroupOutput,
        },
        step_timeline::{
            runtime_reduction_steps::ReducedSettingGroup,
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, show_timeline_steps},
        },
        system_changes::system_changes_group::{
            SystemChangesGroup, SystemChangesGroupInit, SystemChangesGroupInput,
        },
    },
};

pub struct OnAccessPage {
    toaster: Toaster,
    status_rows: FactoryVecDeque<TimelineStepRow<OnAccessAction>>,
    distribution_family: DistributionFamily,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
    on_access_settings_sections: Controller<EngineSettingsSections>,
    system_changes_group: Controller<SystemChangesGroup>,
    clamonacc_log_group: Controller<ServiceLogGroup>,
}

#[derive(Debug)]
pub enum OnAccessPageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    SettingsRevealRequested,
    SettingsNoticeReceived(EngineSettingsNotice),
    StepRequested(TimelineStepRowOutput<OnAccessAction>),
    LogToastRequested(String),
}

pub fn page_input_for_settings_output(
    settings_output: EngineSettingsSectionsOutput,
) -> OnAccessPageInput {
    match settings_output {
        EngineSettingsSectionsOutput::ToastRequested(settings_notice) => {
            OnAccessPageInput::SettingsNoticeReceived(settings_notice)
        }
    }
}

pub fn page_input_for_log_output(log_output: ServiceLogGroupOutput) -> OnAccessPageInput {
    match log_output {
        ServiceLogGroupOutput::ToastRequested(toast_text) => {
            OnAccessPageInput::LogToastRequested(toast_text)
        }
    }
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

impl OnAccessPage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn report_output(sender: &ComponentSender<Self>, page_output: OnAccessPageOutput) {
        let _shell_closed = sender.output(page_output);
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
            on_access_page_steps(protection_evidence, self.distribution_family),
        );
    }
}

#[relm4::component(pub)]
impl Component for OnAccessPage {
    type Init = ();
    type Input = OnAccessPageInput;
    type Output = OnAccessPageOutput;
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
                            connect_clicked => OnAccessPageInput::RefreshRequested,
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
                        add: model.on_access_settings_sections.widget(),
                        add: model.system_changes_group.widget(),
                        add: model.clamonacc_log_group.widget(),
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
                .forward(sender.input_sender(), OnAccessPageInput::StepRequested),
            distribution_family: detect_distribution_family(),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            on_access_settings_sections: EngineSettingsSections::builder()
                .launch(EngineSettingsLayout::SingleSection(
                    EngineSettingsSection::OnAccessScanning,
                ))
                .forward(sender.input_sender(), page_input_for_settings_output),
            system_changes_group: SystemChangesGroup::builder()
                .launch(SystemChangesGroupInit {
                    setting_group: ReducedSettingGroup::OnAccessSettings,
                    group_description: gettext(
                        "On-access settings changed through Lazaret, as recorded by the system. \
                         Software running as you can't remove these records.",
                    ),
                    empty_title: gettext("No on-access settings were changed through Lazaret"),
                })
                .detach(),
            clamonacc_log_group: ServiceLogGroup::builder()
                .launch(ServiceLogGroupInit {
                    group_title: gettext("clamonacc log"),
                    missing_log_title: gettext("clamonacc has not written to the journal"),
                    export_file_name: "clamonacc-logs.txt",
                    log_updates: unit_journal_log_updates(&ON_ACCESS_SERVICE_UNITS).boxed(),
                })
                .forward(sender.input_sender(), page_input_for_log_output),
        };
        let status_group = &model.status_rows.widget().clone();
        let status_loading_page = &loading_status_page(&gettext("Checking on-access scanning…"));
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: OnAccessPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            OnAccessPageInput::RefreshRequested => {
                Self::report_output(&sender, OnAccessPageOutput::EvidenceRefreshRequested);
            }
            OnAccessPageInput::SettingsRevealRequested => {
                self.on_access_settings_sections.emit(
                    EngineSettingsSectionsInput::RevealRequested(
                        EngineSettingsSection::OnAccessScanning,
                    ),
                );
            }
            OnAccessPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            OnAccessPageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
                self.show_status_steps();
            }
            OnAccessPageInput::SettingsNoticeReceived(settings_notice) => {
                self.toaster
                    .add_toast(engine_settings_notice_toast(&settings_notice));
                match settings_change_follow_up(&settings_notice) {
                    SettingsChangeFollowUp::ReloadChangesAndEvidence => {
                        self.system_changes_group
                            .emit(SystemChangesGroupInput::ReloadRequested);
                        Self::report_output(&sender, OnAccessPageOutput::EvidenceRefreshRequested);
                    }
                    SettingsChangeFollowUp::NothingToReload => {}
                }
            }
            OnAccessPageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => match chosen_action {},
            OnAccessPageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            OnAccessPageInput::LogToastRequested(toast_text) => {
                self.toaster.add_toast(plain_text_toast(&toast_text));
            }
        }
    }
}

#[cfg(test)]
mod on_access_component_tests {
    use super::*;

    #[test]
    fn child_toast_requests_become_page_notices() {
        assert!(matches!(
            page_input_for_settings_output(EngineSettingsSectionsOutput::ToastRequested(
                EngineSettingsNotice::StaleConfirmationDropped
            )),
            OnAccessPageInput::SettingsNoticeReceived(
                EngineSettingsNotice::StaleConfirmationDropped
            )
        ));
        assert!(matches!(
            page_input_for_log_output(ServiceLogGroupOutput::ToastRequested(
                "Log copied to clipboard".to_owned()
            )),
            OnAccessPageInput::LogToastRequested(_)
        ));
    }
}
