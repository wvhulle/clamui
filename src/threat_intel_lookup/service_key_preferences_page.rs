use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};

use crate::threat_intel_lookup::service_key_storage::{
    KeyStorageFailure, ThreatIntelService, delete_stored_api_key, masked_api_key,
    read_stored_api_key, save_api_key,
};

const VIRUSTOTAL_KEY_PAGE_URL: &str = "https://www.virustotal.com/gui/my-apikey";
const ABUSE_CH_KEY_PAGE_URL: &str = "https://auth.abuse.ch/";

fn service_page_title(threat_intel_service: ThreatIntelService) -> &'static str {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => "VirusTotal",
        ThreatIntelService::AbuseChService => "abuse.ch",
    }
}

fn service_description(threat_intel_service: ThreatIntelService) -> String {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => gettext(
            "The key is stored in the system keyring. ClamUI first asks VirusTotal about a file's \
             hash, and only uploads the file after you confirm.",
        ),
        ThreatIntelService::AbuseChService => gettext(
            "Used to look up a detection on MalwareBazaar when you ask. The key is stored in the \
             system keyring, and only the signature name is sent. Separate from any key your \
             system uses to download signatures. abuse.ch's fair-use terms say for-profit users \
             may need its commercial API.",
        ),
    }
}

fn service_key_hint(threat_intel_service: ThreatIntelService) -> String {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => gettext(
            "Free tier: 4 requests per minute, 500 per day. Files up to 650 MB can be scanned.",
        ),
        ThreatIntelService::AbuseChService => {
            gettext("Free from the abuse.ch Authentication Portal.")
        }
    }
}

const fn service_key_page_url(threat_intel_service: ThreatIntelService) -> &'static str {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => VIRUSTOTAL_KEY_PAGE_URL,
        ThreatIntelService::AbuseChService => ABUSE_CH_KEY_PAGE_URL,
    }
}

pub struct ServiceKeyPreferencesPage {
    threat_intel_service: ThreatIntelService,
    key_status_text: String,
}

#[derive(Debug)]
pub enum ServiceKeyPreferencesPageInput {
    SaveEnteredKey(String),
    DeleteStoredKey,
    OpenKeyWebsite,
}

#[derive(Debug)]
pub enum ServiceKeyPreferencesPageCommand {
    KeyStatusRead(Result<Option<String>, KeyStorageFailure>),
    KeyChanged(Result<(), KeyStorageFailure>),
}

pub fn describe_key_failure(key_failure: &KeyStorageFailure) -> String {
    match key_failure {
        KeyStorageFailure::KeyFormatInvalid => gettext("This doesn't look like a valid API key"),
        KeyStorageFailure::StoredKeyUnreadable => gettext("Unable to read the stored API key"),
        KeyStorageFailure::KeyringUnavailable(_keyring_failure) => gettext("Keyring unavailable"),
    }
}

impl ServiceKeyPreferencesPage {
    fn refresh_key_status(&self, sender: &ComponentSender<Self>) {
        let threat_intel_service = self.threat_intel_service;
        sender.oneshot_command(async move {
            ServiceKeyPreferencesPageCommand::KeyStatusRead(
                read_stored_api_key(threat_intel_service).await,
            )
        });
    }
}

#[relm4::component(pub)]
impl Component for ServiceKeyPreferencesPage {
    type Init = ThreatIntelService;
    type Input = ServiceKeyPreferencesPageInput;
    type Output = ();
    type CommandOutput = ServiceKeyPreferencesPageCommand;

    view! {
        adw::PreferencesPage {
            set_title: service_page_title(model.threat_intel_service),
            set_icon_name: Some("web-browser-symbolic"),

            add = &adw::PreferencesGroup {
                set_title: &gettext("API Key"),
                set_description: Some(&service_description(model.threat_intel_service)),

                adw::ActionRow {
                    set_title: &gettext("Status"),
                    #[watch]
                    set_subtitle: &model.key_status_text,

                    add_suffix = &gtk::Button {
                        set_label: &gettext("Delete Key"),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        connect_clicked => ServiceKeyPreferencesPageInput::DeleteStoredKey,
                    },
                },

                adw::PasswordEntryRow {
                    set_title: &gettext("API Key"),
                    set_show_apply_button: true,
                    connect_apply[sender] => move |applied_row| {
                        sender.input(ServiceKeyPreferencesPageInput::SaveEnteredKey(
                            applied_row.text().trim().to_owned(),
                        ));
                        applied_row.set_text("");
                    },
                },

                adw::ActionRow {
                    set_title: &gettext("Get a free API key"),
                    set_subtitle: &service_key_hint(model.threat_intel_service),
                    set_activatable: true,
                    add_suffix = &gtk::Image { set_icon_name: Some("adw-external-link-symbolic") },
                    connect_activated => ServiceKeyPreferencesPageInput::OpenKeyWebsite,
                },
            },
        }
    }

    fn init(
        threat_intel_service: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            threat_intel_service,
            key_status_text: gettext("Checking…"),
        };
        let widgets = view_output!();
        model.refresh_key_status(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ServiceKeyPreferencesPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ServiceKeyPreferencesPageInput::SaveEnteredKey(entered_key) => {
                let threat_intel_service = self.threat_intel_service;
                sender.oneshot_command(async move {
                    ServiceKeyPreferencesPageCommand::KeyChanged(
                        save_api_key(threat_intel_service, entered_key).await,
                    )
                });
            }
            ServiceKeyPreferencesPageInput::DeleteStoredKey => {
                let threat_intel_service = self.threat_intel_service;
                sender.oneshot_command(async move {
                    ServiceKeyPreferencesPageCommand::KeyChanged(
                        delete_stored_api_key(threat_intel_service).await,
                    )
                });
            }
            ServiceKeyPreferencesPageInput::OpenKeyWebsite => {
                let parent_window = root.root().and_downcast::<gtk::Window>();
                gtk::UriLauncher::new(service_key_page_url(self.threat_intel_service)).launch(
                    parent_window.as_ref(),
                    relm4::gtk::gio::Cancellable::NONE,
                    |_launch_outcome| {},
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ServiceKeyPreferencesPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ServiceKeyPreferencesPageCommand::KeyStatusRead(Ok(Some(stored_key))) => {
                self.key_status_text = masked_api_key(&stored_key);
            }
            ServiceKeyPreferencesPageCommand::KeyStatusRead(Ok(None)) => {
                self.key_status_text = gettext("Not configured");
            }
            ServiceKeyPreferencesPageCommand::KeyStatusRead(Err(key_failure)) => {
                self.key_status_text = describe_key_failure(&key_failure);
            }
            ServiceKeyPreferencesPageCommand::KeyChanged(Ok(())) => {
                self.refresh_key_status(&sender);
            }
            ServiceKeyPreferencesPageCommand::KeyChanged(Err(key_failure)) => {
                self.key_status_text = describe_key_failure(&key_failure);
            }
        }
    }
}
