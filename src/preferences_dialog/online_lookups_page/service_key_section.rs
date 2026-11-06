use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, adw,
    adw::prelude::*, gtk,
};

use crate::host_services::threat_intel::service_key_storage::{
    KeySource, KeyStorageFailure, ResolvedApiKey, ThreatIntelService, delete_stored_api_key,
    key_source, masked_api_key, read_api_key, save_api_key,
};

const VIRUSTOTAL_KEY_PAGE_URL: &str = "https://www.virustotal.com/gui/my-apikey";
const ABUSE_CH_KEY_PAGE_URL: &str = "https://auth.abuse.ch/";

fn service_group_title(threat_intel_service: ThreatIntelService) -> &'static str {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => "VirusTotal",
        ThreatIntelService::AbuseChService => "MalwareBazaar (abuse.ch)",
    }
}

fn service_description(threat_intel_service: ThreatIntelService) -> String {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => gettext(
            "Optional source for the reputation check on the Quarantine page. Only the file's \
             SHA-256 hash is sent; files are never uploaded.",
        ),
        ThreatIntelService::AbuseChService => gettext(
            "Looks up a detection's signature name, and a quarantined file's SHA-256 hash, when \
             you ask. The same abuse.ch key works for URLhaus signature downloads, but Lazaret \
             needs its own copy it can read. abuse.ch's fair-use terms say for-profit users may \
             need its commercial API.",
        ),
    }
}

fn service_key_hint(threat_intel_service: ThreatIntelService) -> String {
    match threat_intel_service {
        ThreatIntelService::VirusTotalService => {
            gettext("Free tier: 4 requests per minute, 500 per day.")
        }
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

pub fn describe_key_failure(key_failure: &KeyStorageFailure) -> String {
    match key_failure {
        KeyStorageFailure::KeyFormatInvalid => gettext("This doesn't look like a valid API key"),
        KeyStorageFailure::StoredKeyUnreadable => gettext("Unable to read the stored API key"),
        KeyStorageFailure::KeyringUnavailable(_keyring_failure) => gettext("Keyring unavailable"),
        KeyStorageFailure::KeyFileUnreadable { read_failure, .. } => gettext(
            "Lazaret can't read this file: {error}. If it is an agenix or sops-nix secret, set \
             its owner to your user.",
        )
        .replace("{error}", &read_failure.to_string()),
        KeyStorageFailure::KeyFileContentInvalid { .. } => {
            gettext("The file doesn't hold a valid key for this service")
        }
    }
}

fn describe_resolved_key(resolved_key: &ResolvedApiKey) -> String {
    match resolved_key {
        ResolvedApiKey::FromKeyFile(api_key) | ResolvedApiKey::FromKeyring(api_key) => {
            masked_api_key(api_key)
        }
        ResolvedApiKey::NotConfigured => gettext("Not configured"),
    }
}

pub struct ServiceKeySection {
    threat_intel_service: ThreatIntelService,
    key_source: KeySource,
    key_status_text: String,
}

#[derive(Debug)]
pub enum ServiceKeySectionInput {
    SaveEnteredKey(String),
    DeleteStoredKey,
    OpenKeyWebsite,
}

#[derive(Debug)]
pub enum ServiceKeySectionCommand {
    KeyStatusRead(Result<ResolvedApiKey, KeyStorageFailure>),
    KeyChanged(Result<(), KeyStorageFailure>),
}

impl ServiceKeySection {
    fn refresh_key_status(&self, sender: &ComponentSender<Self>) {
        let threat_intel_service = self.threat_intel_service;
        sender.oneshot_command(async move {
            ServiceKeySectionCommand::KeyStatusRead(read_api_key(threat_intel_service).await)
        });
    }

    const fn uses_system_key_file(&self) -> bool {
        matches!(self.key_source, KeySource::SystemKeyFile { .. })
    }

    fn system_key_file_text(&self) -> String {
        match &self.key_source {
            KeySource::SystemKeyFile { key_file_path } => {
                format!("{}\n{}", key_file_path.display(), self.key_status_text)
            }
            KeySource::UserKeyring => String::new(),
        }
    }
}

#[relm4::component(pub)]
impl Component for ServiceKeySection {
    type Init = ThreatIntelService;
    type Input = ServiceKeySectionInput;
    type Output = ();
    type CommandOutput = ServiceKeySectionCommand;

    view! {
        adw::PreferencesGroup {
            set_title: service_group_title(model.threat_intel_service),
            set_description: Some(&service_description(model.threat_intel_service)),

            adw::ActionRow {
                set_title: &gettext("Provided by your system configuration"),
                set_use_markup: false,
                set_subtitle_lines: 0,
                set_visible: model.uses_system_key_file(),
                #[watch]
                set_subtitle: &model.system_key_file_text(),
                add_prefix = &gtk::Image { set_icon_name: Some("changes-prevent-symbolic") },
            },

            adw::ActionRow {
                set_title: &gettext("Key in your keyring"),
                set_visible: !model.uses_system_key_file(),
                #[watch]
                set_subtitle: &model.key_status_text,

                add_suffix = &gtk::Button {
                    set_label: &gettext("Delete Key"),
                    set_valign: gtk::Align::Center,
                    add_css_class: "flat",
                    connect_clicked => ServiceKeySectionInput::DeleteStoredKey,
                },
            },

            adw::PasswordEntryRow {
                set_title: &gettext("Paste API Key"),
                set_show_apply_button: true,
                set_visible: !model.uses_system_key_file(),
                connect_apply[sender] => move |applied_row| {
                    sender.input(ServiceKeySectionInput::SaveEnteredKey(
                        applied_row.text().trim().to_owned(),
                    ));
                    applied_row.set_text("");
                },
            },

            adw::ActionRow {
                set_title: &gettext("Get a free API key"),
                set_subtitle: &service_key_hint(model.threat_intel_service),
                set_activatable: true,
                set_visible: !model.uses_system_key_file(),
                add_suffix = &gtk::Image { set_icon_name: Some("adw-external-link-symbolic") },
                connect_activated => ServiceKeySectionInput::OpenKeyWebsite,
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
            key_source: key_source(threat_intel_service),
            key_status_text: gettext("Checking…"),
        };
        let widgets = view_output!();
        model.refresh_key_status(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        group_input: ServiceKeySectionInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        let threat_intel_service = self.threat_intel_service;
        match group_input {
            ServiceKeySectionInput::SaveEnteredKey(entered_key) => {
                sender.oneshot_command(async move {
                    ServiceKeySectionCommand::KeyChanged(
                        save_api_key(threat_intel_service, entered_key).await,
                    )
                });
            }
            ServiceKeySectionInput::DeleteStoredKey => {
                sender.oneshot_command(async move {
                    ServiceKeySectionCommand::KeyChanged(
                        delete_stored_api_key(threat_intel_service).await,
                    )
                });
            }
            ServiceKeySectionInput::OpenKeyWebsite => {
                gtk::UriLauncher::new(service_key_page_url(threat_intel_service)).launch(
                    root.root().and_downcast::<gtk::Window>().as_ref(),
                    gtk::gio::Cancellable::NONE,
                    |_launch_outcome| {},
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        group_command: ServiceKeySectionCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match group_command {
            ServiceKeySectionCommand::KeyStatusRead(Ok(resolved_key)) => {
                self.key_status_text = describe_resolved_key(&resolved_key);
            }
            ServiceKeySectionCommand::KeyStatusRead(Err(key_failure))
            | ServiceKeySectionCommand::KeyChanged(Err(key_failure)) => {
                self.key_status_text = describe_key_failure(&key_failure);
            }
            ServiceKeySectionCommand::KeyChanged(Ok(())) => self.refresh_key_status(&sender),
        }
    }
}

pub struct OnlineLookupsPage {
    pub lookups_page: adw::PreferencesPage,
    pub key_groups: Vec<Controller<ServiceKeySection>>,
}

pub fn online_lookups_page() -> OnlineLookupsPage {
    let lookups_page = adw::PreferencesPage::builder()
        .title(gettext("Online Lookups"))
        .icon_name("network-server-symbolic")
        .name(ONLINE_LOOKUPS_PAGE_NAME)
        .build();
    let circl_group = adw::PreferencesGroup::builder()
        .title("CIRCL hashlookup")
        .description(gettext(
            "Always used by the reputation check on the Quarantine page. No key needed; only a \
             file's SHA-256 hash is sent.",
        ))
        .build();
    lookups_page.add(&circl_group);
    let key_groups = [
        ThreatIntelService::AbuseChService,
        ThreatIntelService::VirusTotalService,
    ]
    .into_iter()
    .map(|threat_intel_service| {
        let key_group = ServiceKeySection::builder()
            .launch(threat_intel_service)
            .detach();
        lookups_page.add(key_group.widget());
        key_group
    })
    .collect();
    OnlineLookupsPage {
        lookups_page,
        key_groups,
    }
}

pub const ONLINE_LOOKUPS_PAGE_NAME: &str = "online-lookups";
