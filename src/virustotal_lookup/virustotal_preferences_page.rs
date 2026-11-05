use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};

use crate::virustotal_lookup::virustotal_key_storage::{
    KeyStorageFailure, delete_stored_api_key, masked_api_key, read_stored_api_key, save_api_key,
};

const API_KEY_PAGE_URL: &str = "https://www.virustotal.com/gui/my-apikey";

pub struct VirusTotalPreferencesPage {
    key_status_text: String,
}

#[derive(Debug)]
pub enum VirusTotalPreferencesPageInput {
    SaveEnteredKey(String),
    DeleteStoredKey,
    OpenKeyWebsite,
}

#[derive(Debug)]
pub enum VirusTotalPreferencesPageCommand {
    KeyStatusRead(Result<Option<String>, KeyStorageFailure>),
    KeyChanged(Result<(), KeyStorageFailure>),
}

pub fn describe_key_failure(key_failure: &KeyStorageFailure) -> String {
    match key_failure {
        KeyStorageFailure::KeyFormatInvalid => {
            gettext("VirusTotal API keys must be exactly 64 hexadecimal characters")
        }
        KeyStorageFailure::StoredKeyUnreadable => gettext("Unable to read the stored API key"),
        KeyStorageFailure::KeyringUnavailable(_keyring_failure) => gettext("Keyring unavailable"),
    }
}

impl VirusTotalPreferencesPage {
    fn refresh_key_status(&self, sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            VirusTotalPreferencesPageCommand::KeyStatusRead(read_stored_api_key().await)
        });
    }
}

#[relm4::component(pub)]
impl Component for VirusTotalPreferencesPage {
    type Init = ();
    type Input = VirusTotalPreferencesPageInput;
    type Output = ();
    type CommandOutput = VirusTotalPreferencesPageCommand;

    view! {
        adw::PreferencesPage {
            set_title: "VirusTotal",
            set_icon_name: Some("web-browser-symbolic"),

            add = &adw::PreferencesGroup {
                set_title: &gettext("API Key"),
                set_description: Some(&gettext("The key is stored in the system keyring. ClamUI first asks VirusTotal about a file's hash, and only uploads the file after you confirm.")),

                adw::ActionRow {
                    set_title: &gettext("Status"),
                    #[watch]
                    set_subtitle: &model.key_status_text,

                    add_suffix = &gtk::Button {
                        set_label: &gettext("Delete Key"),
                        set_valign: gtk::Align::Center,
                        add_css_class: "flat",
                        connect_clicked => VirusTotalPreferencesPageInput::DeleteStoredKey,
                    },
                },

                adw::PasswordEntryRow {
                    set_title: &gettext("API Key"),
                    set_show_apply_button: true,
                    connect_apply[sender] => move |applied_row| {
                        sender.input(VirusTotalPreferencesPageInput::SaveEnteredKey(
                            applied_row.text().trim().to_owned(),
                        ));
                        applied_row.set_text("");
                    },
                },

                adw::ActionRow {
                    set_title: &gettext("Get a free API key"),
                    set_subtitle: &gettext("Free tier: 4 requests per minute, 500 per day. Files up to 650 MB can be scanned."),
                    set_activatable: true,
                    add_suffix = &gtk::Image { set_icon_name: Some("adw-external-link-symbolic") },
                    connect_activated => VirusTotalPreferencesPageInput::OpenKeyWebsite,
                },
            },
        }
    }

    fn init((): (), root: Self::Root, sender: ComponentSender<Self>) -> ComponentParts<Self> {
        let model = Self {
            key_status_text: gettext("Checking…"),
        };
        let widgets = view_output!();
        model.refresh_key_status(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: VirusTotalPreferencesPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            VirusTotalPreferencesPageInput::SaveEnteredKey(entered_key) => {
                sender.oneshot_command(async move {
                    VirusTotalPreferencesPageCommand::KeyChanged(save_api_key(entered_key).await)
                });
            }
            VirusTotalPreferencesPageInput::DeleteStoredKey => {
                sender.oneshot_command(async {
                    VirusTotalPreferencesPageCommand::KeyChanged(delete_stored_api_key().await)
                });
            }
            VirusTotalPreferencesPageInput::OpenKeyWebsite => {
                let parent_window = root.root().and_downcast::<gtk::Window>();
                gtk::UriLauncher::new(API_KEY_PAGE_URL).launch(
                    parent_window.as_ref(),
                    relm4::gtk::gio::Cancellable::NONE,
                    |_launch_outcome| {},
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: VirusTotalPreferencesPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            VirusTotalPreferencesPageCommand::KeyStatusRead(Ok(Some(stored_key))) => {
                self.key_status_text = masked_api_key(&stored_key);
            }
            VirusTotalPreferencesPageCommand::KeyStatusRead(Ok(None)) => {
                self.key_status_text = gettext("Not configured");
            }
            VirusTotalPreferencesPageCommand::KeyStatusRead(Err(key_failure)) => {
                self.key_status_text = describe_key_failure(&key_failure);
            }
            VirusTotalPreferencesPageCommand::KeyChanged(Ok(())) => {
                self.refresh_key_status(&sender);
            }
            VirusTotalPreferencesPageCommand::KeyChanged(Err(key_failure)) => {
                self.key_status_text = describe_key_failure(&key_failure);
            }
        }
    }
}
