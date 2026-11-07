use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};

use crate::host_services::threat_intel::service_key_storage::{
    KeySource, KeyStorageFailure, ResolvedApiKey, ThreatIntelService, delete_stored_api_key,
    describe_key_failure, key_source, masked_api_key, read_api_key, save_api_key,
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
            "Lookups send VirusTotal only a file's SHA-256 hash. An upload you confirm sends the \
             quarantined file itself, which VirusTotal shares with its paying customers. Uploads \
             are skipped when VirusTotal already has a report, and refused above 32 MB.",
        ),
        ThreatIntelService::AbuseChService => gettext(
            "MalwareBazaar lookups send a detection's signature name or a file's SHA-256 hash. An \
             upload you confirm sends the quarantined file with its ClamAV signature as a tag, \
             and the sample becomes public. The same abuse.ch key also unlocks URLhaus signature \
             downloads through fangfrisch; on NixOS, Lazaret reuses fangfrisch's key file when \
             your user can read it. abuse.ch's fair-use terms say for-profit users may need its \
             commercial API.",
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

fn describe_resolved_key(resolved_key: &ResolvedApiKey) -> String {
    match resolved_key {
        ResolvedApiKey::FromKeyFile(api_key) | ResolvedApiKey::FromKeyring(api_key) => {
            masked_api_key(api_key)
        }
        ResolvedApiKey::NotConfigured => gettext("Not configured"),
    }
}

enum SystemKeyFileStatus {
    CheckingKeyFile,
    KeyFileReadable { masked_key: String },
    KeyFileFailed(KeyStorageFailure),
}

impl SystemKeyFileStatus {
    fn from_key_status(key_status: Result<ResolvedApiKey, KeyStorageFailure>) -> Self {
        match key_status {
            Ok(resolved_key) => Self::KeyFileReadable {
                masked_key: describe_resolved_key(&resolved_key),
            },
            Err(key_failure) => Self::KeyFileFailed(key_failure),
        }
    }
}

pub struct ServiceKeySection {
    threat_intel_service: ThreatIntelService,
    key_source: KeySource,
    key_status_text: String,
    system_key_file_status: SystemKeyFileStatus,
    keyring_key_stored: bool,
    entered_key_cleared: bool,
}

#[derive(Debug)]
pub enum ServiceKeySectionInput {
    KeyEntered(String),
    KeyDeletionRequested,
    KeyWebsiteRequested,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceKeySectionOutput {
    StoredKeyChanged,
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
                let shown_path = key_file_path.display();
                match &self.system_key_file_status {
                    SystemKeyFileStatus::CheckingKeyFile => {
                        format!("{shown_path}\n{}", gettext("Checking…"))
                    }
                    SystemKeyFileStatus::KeyFileReadable { masked_key } => {
                        format!("{masked_key}\n{shown_path}")
                    }
                    SystemKeyFileStatus::KeyFileFailed(
                        key_failure @ KeyStorageFailure::KeyFilePermissionDenied { .. },
                    ) => format!("••••\n{shown_path}\n{}", describe_key_failure(key_failure)),
                    SystemKeyFileStatus::KeyFileFailed(key_failure) => {
                        format!("{shown_path}\n{}", describe_key_failure(key_failure))
                    }
                }
            }
            KeySource::UserKeyring => String::new(),
        }
    }
}

#[relm4::component(pub)]
impl Component for ServiceKeySection {
    type Init = ThreatIntelService;
    type Input = ServiceKeySectionInput;
    type Output = ServiceKeySectionOutput;
    type CommandOutput = ServiceKeySectionCommand;

    view! {
        adw::PreferencesGroup {
            set_title: service_group_title(model.threat_intel_service),
            set_description: Some(&service_description(model.threat_intel_service)),

            adw::ActionRow {
                set_title: &gettext("Set by your system configuration"),
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
                    #[watch]
                    set_visible: model.keyring_key_stored,
                    add_css_class: "flat",
                    connect_clicked => ServiceKeySectionInput::KeyDeletionRequested,
                },
            },

            adw::PasswordEntryRow {
                set_title: &gettext("Paste API Key"),
                set_show_apply_button: true,
                set_visible: !model.uses_system_key_file(),
                #[track(model.entered_key_cleared)]
                set_text: "",
                connect_apply[sender] => move |applied_row| {
                    sender.input(ServiceKeySectionInput::KeyEntered(
                        applied_row.text().trim().to_owned(),
                    ));
                },
            },

            adw::ActionRow {
                set_title: &gettext("Get a free API key"),
                set_subtitle: &service_key_hint(model.threat_intel_service),
                set_activatable: true,
                set_visible: !model.uses_system_key_file(),
                add_suffix = &gtk::Image { set_icon_name: Some("adw-external-link-symbolic") },
                connect_activated => ServiceKeySectionInput::KeyWebsiteRequested,
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
            system_key_file_status: SystemKeyFileStatus::CheckingKeyFile,
            keyring_key_stored: false,
            entered_key_cleared: false,
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
        self.entered_key_cleared = false;
        match group_input {
            ServiceKeySectionInput::KeyEntered(entered_key) => {
                self.entered_key_cleared = true;
                sender.oneshot_command(async move {
                    ServiceKeySectionCommand::KeyChanged(
                        save_api_key(threat_intel_service, entered_key).await,
                    )
                });
            }
            ServiceKeySectionInput::KeyDeletionRequested => {
                sender.oneshot_command(async move {
                    ServiceKeySectionCommand::KeyChanged(
                        delete_stored_api_key(threat_intel_service).await,
                    )
                });
            }
            ServiceKeySectionInput::KeyWebsiteRequested => {
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
        self.entered_key_cleared = false;
        match group_command {
            ServiceKeySectionCommand::KeyStatusRead(key_status) => {
                self.keyring_key_stored = matches!(key_status, Ok(ResolvedApiKey::FromKeyring(_)));
                self.key_status_text = match &key_status {
                    Ok(resolved_key) => describe_resolved_key(resolved_key),
                    Err(key_failure) => describe_key_failure(key_failure),
                };
                self.system_key_file_status = SystemKeyFileStatus::from_key_status(key_status);
            }
            ServiceKeySectionCommand::KeyChanged(Err(key_failure)) => {
                self.key_status_text = describe_key_failure(&key_failure);
            }
            ServiceKeySectionCommand::KeyChanged(Ok(())) => {
                self.refresh_key_status(&sender);
                let _page_closed = sender.output(ServiceKeySectionOutput::StoredKeyChanged);
            }
        }
    }
}
