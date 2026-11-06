use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual},
    prelude::FactoryVecDeque,
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
        online_lookups_page::service_key_section::ServiceKeySection,
    },
};

const GENERAL_PAGE_NAME: &str = "general";
const ONLINE_LOOKUPS_PAGE_NAME: &str = "online-lookups";
const START_IN_BACKGROUND_KEY: &str = "start-in-background";
const NOTIFICATIONS_ENABLED_KEY: &str = "notifications-enabled";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreferencesPageName {
    GeneralPreferences,
    OnlineLookups,
}

impl PreferencesPageName {
    pub const fn page_name(self) -> &'static str {
        match self {
            Self::GeneralPreferences => GENERAL_PAGE_NAME,
            Self::OnlineLookups => ONLINE_LOOKUPS_PAGE_NAME,
        }
    }

    pub fn from_page_name(page_name: &str) -> Option<Self> {
        [Self::GeneralPreferences, Self::OnlineLookups]
            .into_iter()
            .find(|preferences_page| preferences_page.page_name() == page_name)
    }
}

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
    visible_page: PreferencesPageName,
    file_manager_rows: FactoryVecDeque<FileManagerRow>,
    abuse_ch_section: Controller<ServiceKeySection>,
    virustotal_section: Controller<ServiceKeySection>,
}

#[derive(Debug)]
pub enum PreferencesDialogInput {
    PageShown(PreferencesPageName),
    CloseActionChosen(u32),
    StartInBackgroundToggled(bool),
    NotificationsToggled(bool),
    StoredSettingChanged,
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
    type Output = ();
    type CommandOutput = PreferencesDialogCommand;

    view! {
        adw::PreferencesDialog {
            set_title: &gettext("Preferences"),
            set_search_enabled: true,
            #[watch]
            #[block_signal(visible_page_handler)]
            set_visible_page_name: model.visible_page.page_name(),
            connect_visible_page_name_notify[sender] => move |changed_dialog| {
                if let Some(preferences_page) = changed_dialog
                    .visible_page_name()
                    .and_then(|page_name| PreferencesPageName::from_page_name(&page_name))
                {
                    sender.input(PreferencesDialogInput::PageShown(preferences_page));
                }
            } @visible_page_handler,

            add = &adw::PreferencesPage {
                set_title: &gettext("General"),
                set_icon_name: Some("preferences-system-symbolic"),
                set_name: Some(GENERAL_PAGE_NAME),

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
                set_title: &gettext("Online Lookups"),
                set_icon_name: Some("network-server-symbolic"),
                set_name: Some(ONLINE_LOOKUPS_PAGE_NAME),

                adw::PreferencesGroup {
                    set_title: "CIRCL hashlookup",
                    set_description: Some(&gettext(
                        "Always used by the reputation check on the Quarantine page. No key \
                         needed; only a file's SHA-256 hash is sent.",
                    )),
                },

                add: model.abuse_ch_section.widget(),
                add: model.virustotal_section.widget(),
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
            visible_page: PreferencesPageName::GeneralPreferences,
            file_manager_rows,
            abuse_ch_section: ServiceKeySection::builder()
                .launch(ThreatIntelService::AbuseChService)
                .detach(),
            virustotal_section: ServiceKeySection::builder()
                .launch(ThreatIntelService::VirusTotalService)
                .detach(),
        };
        let file_manager_group = model.file_manager_rows.widget();
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
            PreferencesDialogInput::PageShown(preferences_page) => {
                self.visible_page = preferences_page;
            }
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
