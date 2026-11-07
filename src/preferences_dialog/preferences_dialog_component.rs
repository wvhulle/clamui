use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual},
    prelude::{ComponentController, Controller, FactoryVecDeque},
};

use crate::{
    application_window::window_close_behavior::{CLOSE_ACTION_CHOICES, CloseAction},
    host_services::{
        desktop::{
            file_manager_actions::SUPPORTED_FILE_MANAGERS,
            flatpak_sandbox::{request_background_autostart, running_in_flatpak},
            stored_settings::{CLOSE_ACTION_KEY, application_settings},
            stored_settings_watch::forward_setting_changes,
        },
        threat_intel::service_key_storage::ThreatIntelService,
    },
    preferences_dialog::{
        file_manager_row::FileManagerRow,
        service_key_section::{ServiceKeySection, ServiceKeySectionOutput},
    },
};

pub const ONLINE_SERVICES_PAGE_NAME: &str = "online-services";

const START_IN_BACKGROUND_KEY: &str = "start-in-background";
const NOTIFICATIONS_ENABLED_KEY: &str = "notifications-enabled";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowBehaviorSettings {
    close_action: CloseAction,
    start_in_background: bool,
    notifications_enabled: bool,
}

impl WindowBehaviorSettings {
    fn read_from(stored_settings: &gio::Settings) -> Self {
        Self {
            close_action: CloseAction::read_from(stored_settings),
            start_in_background: stored_settings.boolean(START_IN_BACKGROUND_KEY),
            notifications_enabled: stored_settings.boolean(NOTIFICATIONS_ENABLED_KEY),
        }
    }
}

pub struct PreferencesDialog {
    stored_settings: gio::Settings,
    window_behavior: WindowBehaviorSettings,
    file_manager_rows: FactoryVecDeque<FileManagerRow>,
    abuse_ch_section: Controller<ServiceKeySection>,
    virustotal_section: Controller<ServiceKeySection>,
}

#[derive(Debug)]
pub enum PreferencesDialogInput {
    CloseActionChosen(u32),
    StartInBackgroundToggled(bool),
    NotificationsToggled(bool),
    StoredSettingChanged,
    StoredServiceKeyChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreferencesDialogOutput {
    StoredServiceKeyChanged,
}

const fn dialog_input_for_key_output(
    key_output: ServiceKeySectionOutput,
) -> PreferencesDialogInput {
    match key_output {
        ServiceKeySectionOutput::StoredKeyChanged => {
            PreferencesDialogInput::StoredServiceKeyChanged
        }
    }
}

#[derive(Debug)]
pub enum PreferencesDialogCommand {
    AutostartRequestFinished(zbus::Result<()>),
}

fn close_action_labels() -> gtk::StringList {
    let close_labels = CLOSE_ACTION_CHOICES.map(CloseAction::choice_label);
    gtk::StringList::new(&close_labels.iter().map(String::as_str).collect::<Vec<_>>())
}

#[relm4::component(pub)]
impl Component for PreferencesDialog {
    type Init = ();
    type Input = PreferencesDialogInput;
    type Output = PreferencesDialogOutput;
    type CommandOutput = PreferencesDialogCommand;

    view! {
        adw::PreferencesDialog {
            set_title: &gettext("Preferences"),
            set_search_enabled: true,

            add = &adw::PreferencesPage {
                set_title: &gettext("General"),
                set_icon_name: Some("preferences-system-symbolic"),

                adw::PreferencesGroup {
                    set_title: &gettext("Window Behavior"),
                    set_description: Some(&gettext(
                        "Detection alerts only work while Lazaret is running.",
                    )),

                    adw::ComboRow {
                        set_title: &gettext("When closing window"),
                        set_model: Some(&close_action_labels()),
                        #[watch]
                        #[block_signal(close_action_handler)]
                        set_selected: model.window_behavior.close_action.choice_position(),
                        connect_selected_notify[sender] => move |changed_row| {
                            sender.input(PreferencesDialogInput::CloseActionChosen(changed_row.selected()));
                        } @close_action_handler,
                    },

                    adw::SwitchRow {
                        set_title: &gettext("Start in the Background"),
                        set_subtitle: &gettext("Launch in the background without opening a window."),
                        #[watch]
                        #[block_signal(start_in_background_handler)]
                        set_active: model.window_behavior.start_in_background,
                        connect_active_notify[sender] => move |changed_row| {
                            sender.input(PreferencesDialogInput::StartInBackgroundToggled(changed_row.is_active()));
                        } @start_in_background_handler,
                    },

                    adw::SwitchRow {
                        set_title: &gettext("Desktop Notifications"),
                        set_subtitle: &gettext(
                            "Notify about detections, and about finished scans and updates while \
                             the window is not in focus.",
                        ),
                        #[watch]
                        #[block_signal(notifications_handler)]
                        set_active: model.window_behavior.notifications_enabled,
                        connect_active_notify[sender] => move |changed_row| {
                            sender.input(PreferencesDialogInput::NotificationsToggled(changed_row.is_active()));
                        } @notifications_handler,
                    },
                },

                #[local_ref]
                file_manager_group -> adw::PreferencesGroup {
                    set_title: &gettext("File Manager Integration"),
                    set_description: Some(&gettext(
                        "Add context menu actions for supported file managers.",
                    )),
                    set_visible: !running_in_flatpak(),
                },
            },

            add = &adw::PreferencesPage {
                set_name: Some(ONLINE_SERVICES_PAGE_NAME),
                set_title: &gettext("Online Services"),
                set_icon_name: Some("network-server-symbolic"),
                set_description: &gettext(
                    "Services that tell you more about a detected or quarantined file. Lookups \
                     run only when you press Look Up on a detection or Check in a quarantine \
                     entry, and send only a hash or a signature name. A file leaves this \
                     computer only when you submit it and confirm what is sent.",
                ),

                adw::PreferencesGroup {
                    set_title: "CIRCL hashlookup",
                    set_description: Some(&gettext(
                        "Lookups send only a file's SHA-256 hash and tell whether it belongs to a \
                         known, harmless file. No key needed.",
                    )),
                },

                #[local_ref]
                abuse_ch_group -> adw::PreferencesGroup {},

                #[local_ref]
                virustotal_group -> adw::PreferencesGroup {},

                adw::PreferencesGroup {
                    set_title: "ClamAV (Cisco Talos)",
                    set_description: Some(&gettext(
                        "No lookups. A report you confirm sends the file, the detection name for \
                         a false positive, and your name and email address. Talos processes \
                         samples by automation, never makes them public and doesn't share them \
                         with other companies. A review takes at least 48 hours. No key needed.",
                    )),
                },
            },

        }
    }

    fn init(
        _dialog_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &[
                CLOSE_ACTION_KEY,
                START_IN_BACKGROUND_KEY,
                NOTIFICATIONS_ENABLED_KEY,
            ],
            sender.input_sender(),
            |_changed_settings, _changed_key| PreferencesDialogInput::StoredSettingChanged,
        );
        let mut file_manager_rows = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .detach();
        if !running_in_flatpak() {
            let mut row_guard = file_manager_rows.guard();
            SUPPORTED_FILE_MANAGERS
                .into_iter()
                .for_each(|file_manager| {
                    row_guard.push_back(file_manager);
                });
        }
        let model = Self {
            window_behavior: WindowBehaviorSettings::read_from(&stored_settings),
            stored_settings,
            file_manager_rows,
            abuse_ch_section: ServiceKeySection::builder()
                .launch(ThreatIntelService::AbuseChService)
                .forward(sender.input_sender(), dialog_input_for_key_output),
            virustotal_section: ServiceKeySection::builder()
                .launch(ThreatIntelService::VirusTotalService)
                .forward(sender.input_sender(), dialog_input_for_key_output),
        };
        let file_manager_group = model.file_manager_rows.widget();
        let abuse_ch_group = model.abuse_ch_section.widget();
        let virustotal_group = model.virustotal_section.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        dialog_input: PreferencesDialogInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match dialog_input {
            PreferencesDialogInput::CloseActionChosen(choice_position) => {
                if let Some(close_action) = CloseAction::from_choice_position(choice_position) {
                    self.window_behavior.close_action = close_action;
                    close_action.store_into(&self.stored_settings);
                }
            }
            PreferencesDialogInput::StartInBackgroundToggled(start_in_background) => {
                self.window_behavior.start_in_background = start_in_background;
                let _read_only_settings = self
                    .stored_settings
                    .set(START_IN_BACKGROUND_KEY, start_in_background);
                if running_in_flatpak() {
                    sender.oneshot_command(async move {
                        PreferencesDialogCommand::AutostartRequestFinished(
                            request_background_autostart(start_in_background).await,
                        )
                    });
                }
            }
            PreferencesDialogInput::NotificationsToggled(notifications_enabled) => {
                self.window_behavior.notifications_enabled = notifications_enabled;
                let _read_only_settings = self
                    .stored_settings
                    .set(NOTIFICATIONS_ENABLED_KEY, notifications_enabled);
            }
            PreferencesDialogInput::StoredSettingChanged => {
                self.window_behavior = WindowBehaviorSettings::read_from(&self.stored_settings);
            }
            PreferencesDialogInput::StoredServiceKeyChanged => {
                let _shell_closed = sender.output(PreferencesDialogOutput::StoredServiceKeyChanged);
            }
        }
    }

    fn update_cmd(
        &mut self,
        dialog_command: PreferencesDialogCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match dialog_command {
            PreferencesDialogCommand::AutostartRequestFinished(Ok(())) => {}
            PreferencesDialogCommand::AutostartRequestFinished(Err(portal_failure)) => {
                eprintln!("lazaret: the Background portal refused autostart: {portal_failure}");
            }
        }
    }
}
