use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};

use crate::{
    application_window::{
        application_pages::ApplicationPage,
        page_links::{SHOW_PAGE_ACTION, page_target},
        protection_evidence_refresh::{EvidenceRefresh, GatheredEvidence},
    },
    shared_widgets::loading_indicators::{
        BUSY_PAGE_NAME, FirstLoad, IDLE_PAGE_NAME, LOADED_PAGE_NAME, LOADING_PAGE_NAME,
        busy_page_name, loading_status_page,
    },
    sharing::online_lookups_page::{
        online_lookups_presentation::{LookupService, lookup_service_subtitle},
        online_lookups_state::OnlineLookupsPageOutput,
    },
};

pub struct OnlineLookupsPage {
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
}

#[derive(Debug)]
pub enum OnlineLookupsPageInput {
    RefreshRequested,
    EvidenceRefreshChanged(EvidenceRefresh),
    EvidenceGathered(GatheredEvidence),
}

impl OnlineLookupsPage {
    const fn first_load(&self) -> FirstLoad {
        match self.gathered_evidence {
            GatheredEvidence::NotGatheredYet => FirstLoad::StillLoading,
            GatheredEvidence::Gathered { .. } => FirstLoad::LoadFinished,
        }
    }

    fn service_subtitle(&self, lookup_service: LookupService) -> String {
        match &self.gathered_evidence {
            GatheredEvidence::Gathered {
                protection_evidence,
                ..
            } => lookup_service_subtitle(
                lookup_service,
                &lookup_service.service_access(&protection_evidence.lookup_key_statuses),
            ),
            GatheredEvidence::NotGatheredYet => String::new(),
        }
    }

    fn service_needs_attention(&self, lookup_service: LookupService) -> bool {
        match &self.gathered_evidence {
            GatheredEvidence::Gathered {
                protection_evidence,
                ..
            } => lookup_service
                .service_access(&protection_evidence.lookup_key_statuses)
                .needs_attention(),
            GatheredEvidence::NotGatheredYet => false,
        }
    }
}

#[relm4::component(pub)]
impl Component for OnlineLookupsPage {
    type Init = ();
    type Input = OnlineLookupsPageInput;
    type Output = OnlineLookupsPageOutput;
    type CommandOutput = ();

    view! {
        adw::ToolbarView {
            add_top_bar = &adw::HeaderBar {
                pack_end = &gtk::Stack {
                    add_named[Some(IDLE_PAGE_NAME)] = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Check again")),
                        connect_clicked => OnlineLookupsPageInput::RefreshRequested,
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
                add_named[Some(LOADING_PAGE_NAME)] = keys_loading_page -> adw::StatusPage {},
                add_named[Some(LOADED_PAGE_NAME)] = &adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Services"),
                        set_description: Some(&gettext(
                            "Lookups only run when you ask for one, and send only what is listed \
                             here. Files are only uploaded from Submissions, after you confirm. \
                             The API keys are kept on Submissions too.",
                        )),

                        adw::ActionRow {
                            set_title: LookupService::CirclHashlookup.service_name(),
                            set_subtitle_lines: 0,
                            set_use_markup: false,
                            #[watch]
                            set_subtitle: &model.service_subtitle(LookupService::CirclHashlookup),
                        },

                        adw::ActionRow {
                            set_title: LookupService::MalwareBazaar.service_name(),
                            set_subtitle_lines: 0,
                            set_use_markup: false,
                            #[watch]
                            set_subtitle: &model.service_subtitle(LookupService::MalwareBazaar),
                            set_activatable: true,
                            set_action_name: Some(SHOW_PAGE_ACTION),
                            set_action_target_value: Some(&page_target(ApplicationPage::Submissions)),
                            add_suffix = &gtk::Image {
                                set_icon_name: Some("dialog-warning-symbolic"),
                                add_css_class: "warning",
                                #[watch]
                                set_visible: model.service_needs_attention(LookupService::MalwareBazaar),
                            },
                            add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                        },

                        adw::ActionRow {
                            set_title: LookupService::VirusTotal.service_name(),
                            set_subtitle_lines: 0,
                            set_use_markup: false,
                            #[watch]
                            set_subtitle: &model.service_subtitle(LookupService::VirusTotal),
                            set_activatable: true,
                            set_action_name: Some(SHOW_PAGE_ACTION),
                            set_action_target_value: Some(&page_target(ApplicationPage::Submissions)),
                            add_suffix = &gtk::Image {
                                set_icon_name: Some("dialog-warning-symbolic"),
                                add_css_class: "warning",
                                #[watch]
                                set_visible: model.service_needs_attention(LookupService::VirusTotal),
                            },
                            add_suffix = &gtk::Image { set_icon_name: Some("go-next-symbolic") },
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Where Lookups Run"),
                        set_description: Some(&gettext(
                            "Lookup answers aren't stored. Each lookup runs where you start it and \
                             shows its answer there.",
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
                },
                #[watch]
                set_visible_child_name: model.first_load().shown_page_name(),
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
        };
        let keys_loading_page = &loading_status_page(&gettext("Checking the API keys…"));
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: OnlineLookupsPageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_input {
            OnlineLookupsPageInput::RefreshRequested => {
                let _shell_closed =
                    sender.output(OnlineLookupsPageOutput::EvidenceRefreshRequested);
            }
            OnlineLookupsPageInput::EvidenceRefreshChanged(evidence_refresh) => {
                self.evidence_refresh = evidence_refresh;
            }
            OnlineLookupsPageInput::EvidenceGathered(gathered_evidence) => {
                self.gathered_evidence = gathered_evidence;
            }
        }
    }
}
