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
    host_services::threat_intel::service_key_storage::{ThreatIntelService, read_api_key},
    shared_widgets::{
        loading_indicators::{
            BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
            busy_page_name, loading_status_page,
        },
        step_timeline::{
            timeline_step_contents::TimelineStepRowOutput,
            timeline_step_row::{TimelineStepRow, show_timeline_steps},
        },
    },
    sharing::analysis_page::{
        analysis_presentation::{
            AnalysisStepAction, LookupService, ServiceKeyStatus, analysis_status_steps,
            keyed_service_subtitle, keyless_service_subtitle,
        },
        analysis_state::{AnalysisPageOutput, LookupKeyStatuses},
        trusted_detections_section::trusted_detections_group::{
            TrustedDetectionsSection, TrustedDetectionsSectionOutput,
        },
    },
};

const SHOW_PAGE_ACTION: &str = "win.show-page";

pub struct AnalysisPage {
    toaster: Toaster,
    status_rows: FactoryVecDeque<TimelineStepRow<AnalysisStepAction>>,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
    lookup_key_statuses: LookupKeyStatuses,
    trusted_detections_section: Controller<TrustedDetectionsSection>,
}

#[derive(Debug)]
pub enum AnalysisPageInput {
    RefreshRequested,
    PageShown,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
    StepRequested(TimelineStepRowOutput<AnalysisStepAction>),
    ToastRequested(String),
    TrustListChanged,
}

#[derive(Debug)]
pub enum AnalysisPageCommand {
    KeyStatusRead {
        threat_intel_service: ThreatIntelService,
        key_status: ServiceKeyStatus,
    },
}

pub fn page_input_for_trusted_output(
    trusted_output: TrustedDetectionsSectionOutput,
) -> AnalysisPageInput {
    match trusted_output {
        TrustedDetectionsSectionOutput::ToastRequested(toast_text) => {
            AnalysisPageInput::ToastRequested(toast_text)
        }
        TrustedDetectionsSectionOutput::TrustListChanged => AnalysisPageInput::TrustListChanged,
    }
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn page_target(application_page: ApplicationPage) -> gtk::glib::Variant {
    application_page.page_name().to_variant()
}

impl AnalysisPage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn report_output(sender: &ComponentSender<Self>, page_output: AnalysisPageOutput) {
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
            analysis_status_steps(&protection_evidence.trust_list),
        );
    }

    fn read_key_statuses(sender: &ComponentSender<Self>) {
        [
            ThreatIntelService::AbuseChService,
            ThreatIntelService::VirusTotalService,
        ]
        .into_iter()
        .for_each(|threat_intel_service| {
            sender.oneshot_command(async move {
                AnalysisPageCommand::KeyStatusRead {
                    threat_intel_service,
                    key_status: ServiceKeyStatus::from_key_reading(
                        &read_api_key(threat_intel_service).await,
                    ),
                }
            });
        });
    }
}

#[relm4::component(pub)]
impl Component for AnalysisPage {
    type Init = ();
    type Input = AnalysisPageInput;
    type Output = AnalysisPageOutput;
    type CommandOutput = AnalysisPageCommand;

    view! {
        adw::ToastOverlay {
            connect_map => AnalysisPageInput::PageShown,

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    pack_end = &gtk::Stack {
                        add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                            set_icon_name: "view-refresh-symbolic",
                            set_tooltip_text: Some(&gettext("Check again")),
                            connect_clicked => AnalysisPageInput::RefreshRequested,
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
                        add: model.trusted_detections_section.widget(),

                        add = &adw::PreferencesGroup {
                            set_title: &gettext("Reputation Lookups"),
                            set_description: Some(&gettext(
                                "Lookups only run when you ask for one, and send only what is \
                                 listed here. Files are only uploaded from Submissions, after you \
                                 confirm. Keys are kept there too.",
                            )),

                            adw::ActionRow {
                                set_title: LookupService::CirclHashlookup.service_name(),
                                set_subtitle: &keyless_service_subtitle(LookupService::CirclHashlookup),
                                set_subtitle_lines: 0,
                            },

                            adw::ActionRow {
                                set_title: LookupService::MalwareBazaar.service_name(),
                                set_subtitle_lines: 0,
                                set_use_markup: false,
                                #[watch]
                                set_subtitle: &keyed_service_subtitle(
                                    LookupService::MalwareBazaar,
                                    &model.lookup_key_statuses.abuse_ch_key,
                                ),
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Submissions)),
                                add_suffix = &gtk::Image {
                                    set_icon_name: Some("dialog-warning-symbolic"),
                                    add_css_class: "warning",
                                    #[watch]
                                    set_visible: model.lookup_key_statuses.abuse_ch_key.needs_attention(),
                                },
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },

                            adw::ActionRow {
                                set_title: LookupService::VirusTotal.service_name(),
                                set_subtitle_lines: 0,
                                set_use_markup: false,
                                #[watch]
                                set_subtitle: &keyed_service_subtitle(
                                    LookupService::VirusTotal,
                                    &model.lookup_key_statuses.virustotal_key,
                                ),
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Submissions)),
                                add_suffix = &gtk::Image {
                                    set_icon_name: Some("dialog-warning-symbolic"),
                                    add_css_class: "warning",
                                    #[watch]
                                    set_visible: model.lookup_key_statuses.virustotal_key.needs_attention(),
                                },
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },
                        },

                        add = &adw::PreferencesGroup {
                            set_title: &gettext("Recent Lookups"),
                            set_description: Some(&gettext(
                                "Lookup answers aren't stored. Each lookup runs where you start \
                                 it and shows its answer there.",
                            )),

                            adw::ActionRow {
                                set_title: &gettext("Detections"),
                                set_subtitle: &gettext(
                                    "Look Up in an opened detection asks MalwareBazaar about its \
                                     signature name.",
                                ),
                                set_subtitle_lines: 0,
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Detections)),
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },

                            adw::ActionRow {
                                set_title: &gettext("Quarantine"),
                                set_subtitle: &gettext(
                                    "Reputation in an expanded quarantine entry asks CIRCL, \
                                     MalwareBazaar and VirusTotal about the file's hash.",
                                ),
                                set_subtitle_lines: 0,
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Quarantine)),
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },
                        },

                        add = &adw::PreferencesGroup {
                            set_title: &gettext("Marking a False Positive"),
                            set_description: Some(&gettext(
                                "When ClamAV flags a file you know is safe, you can keep it, \
                                 stop ClamAV reporting it here, or report it so everyone gets \
                                 the fix.",
                            )),

                            adw::ActionRow {
                                set_title: &gettext("Keep the file"),
                                set_subtitle: &gettext(
                                    "Keep in an opened detection closes it and leaves the file \
                                     alone. ClamAV still reports it the next time it is scanned.",
                                ),
                                set_subtitle_lines: 0,
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Detections)),
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },

                            adw::ActionRow {
                                set_title: &gettext("Trust the file or ignore the detection"),
                                set_subtitle: &gettext(
                                    "Trust This File… or Ignore on a scan result or quarantine \
                                     entry adds it to Trusted Detections above, so ClamAV stops \
                                     reporting it on this computer.",
                                ),
                                set_subtitle_lines: 0,
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Quarantine)),
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },

                            adw::ActionRow {
                                set_title: &gettext("Report it to ClamAV"),
                                set_subtitle: &gettext(
                                    "Report… on a quarantine entry, or Report False Positive… on \
                                     a scan result, sends the file to Cisco Talos, so a later \
                                     signature update fixes the detection for everyone. \
                                     Submissions tracks each report.",
                                ),
                                set_subtitle_lines: 0,
                                set_activatable: true,
                                set_action_name: Some(SHOW_PAGE_ACTION),
                                set_action_target_value: Some(&page_target(ApplicationPage::Submissions)),
                                add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                            },
                        },
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
                .forward(sender.input_sender(), AnalysisPageInput::StepRequested),
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            lookup_key_statuses: LookupKeyStatuses::while_checking(),
            trusted_detections_section: TrustedDetectionsSection::builder()
                .launch(())
                .forward(sender.input_sender(), page_input_for_trusted_output),
        };
        let status_group = &model.status_rows.widget().clone();
        let status_loading_page = &loading_status_page(&gettext("Checking trusted detections…"));
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: AnalysisPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            AnalysisPageInput::RefreshRequested => {
                Self::read_key_statuses(&sender);
                Self::report_output(&sender, AnalysisPageOutput::EvidenceRefreshRequested);
            }
            AnalysisPageInput::PageShown => Self::read_key_statuses(&sender),
            AnalysisPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            AnalysisPageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
                self.show_status_steps();
            }
            AnalysisPageInput::StepRequested(TimelineStepRowOutput::ActionChosen(
                chosen_action,
            )) => match chosen_action {},
            AnalysisPageInput::StepRequested(TimelineStepRowOutput::CopyRequested(
                copied_command,
            )) => {
                root.clipboard().set_text(&copied_command);
                self.toaster
                    .add_toast(adw::Toast::new(&gettext("Command copied to clipboard")));
            }
            AnalysisPageInput::ToastRequested(toast_text) => {
                self.toaster.add_toast(plain_text_toast(&toast_text));
            }
            AnalysisPageInput::TrustListChanged => {
                Self::report_output(&sender, AnalysisPageOutput::EvidenceRefreshRequested);
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: AnalysisPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            AnalysisPageCommand::KeyStatusRead {
                threat_intel_service,
                key_status,
            } => {
                self.lookup_key_statuses = self
                    .lookup_key_statuses
                    .clone()
                    .with_service_status(threat_intel_service, key_status);
            }
        }
    }
}

#[cfg(test)]
mod analysis_component_tests {
    use super::*;

    #[test]
    fn trusted_detections_requests_become_page_inputs() {
        assert!(matches!(
            page_input_for_trusted_output(TrustedDetectionsSectionOutput::ToastRequested(
                "Removed".to_owned()
            )),
            AnalysisPageInput::ToastRequested(_)
        ));
        assert!(matches!(
            page_input_for_trusted_output(TrustedDetectionsSectionOutput::TrustListChanged),
            AnalysisPageInput::TrustListChanged
        ));
    }
}
