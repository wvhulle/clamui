use std::time::Duration;

use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender,
    abstractions::Toaster,
    adw,
    adw::prelude::*,
    gtk,
    gtk::glib,
    prelude::{DynamicIndex, FactoryVecDeque},
};

use crate::{
    host_services::{
        clamav_config::{
            clamav_host_config::{
                ConfigSetting, HostConfigView, is_on_access_setting, read_clamd_config,
                read_freshclam_config,
            },
            setting_provenance::{
                ClamavConfigKind, ConfigFileOwner, change_snippet, drift_snippet_text,
                inspect_config_file_owner, managed_config_description, setting_lock_for_key,
                values_with_edit,
            },
        },
        clamav_scanner::scanner_output_parser::{sanitize_scanner_line, sanitize_scanner_text},
        settings_helper::{
            live_settings_client::{
                LiveChangeOutcome, LiveTuningState, apply_live_change, change_confirmation_text,
                change_effect, read_live_tuning_state,
            },
            protection_change_rules::ProtectionReduction,
        },
    },
    shared_widgets::engine_settings::config_setting_row::{
        ConfigSettingRow, ConfigSettingRowInit, ConfigSettingRowInput, ConfigSettingRowOutput,
    },
};

const UNLOCK_DURATION: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSettingsSection {
    ScannerEngine,
    OnAccessScanning,
    SignatureUpdates,
}

impl EngineSettingsSection {
    fn page_title(self) -> String {
        match self {
            Self::ScannerEngine => gettext("Scanner Engine"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::SignatureUpdates => gettext("Signature Updates"),
        }
    }

    const fn page_icon(self) -> &'static str {
        match self {
            Self::ScannerEngine => "system-search-symbolic",
            Self::OnAccessScanning => "security-high-symbolic",
            Self::SignatureUpdates => "drive-harddisk-symbolic",
        }
    }

    fn group_title(self) -> String {
        match self {
            Self::ScannerEngine => gettext("clamd settings"),
            Self::OnAccessScanning => gettext("On-access scanning settings"),
            Self::SignatureUpdates => gettext("freshclam settings"),
        }
    }

    const fn config_kind(self) -> ClamavConfigKind {
        match self {
            Self::ScannerEngine | Self::OnAccessScanning => ClamavConfigKind::ClamdDaemonConfig,
            Self::SignatureUpdates => ClamavConfigKind::FreshclamUpdaterConfig,
        }
    }

    const fn offers_live_tuning(self) -> bool {
        matches!(self, Self::ScannerEngine | Self::OnAccessScanning)
    }

    fn read_host_config(self) -> HostConfigView {
        match self {
            Self::ScannerEngine | Self::OnAccessScanning => read_clamd_config(),
            Self::SignatureUpdates => read_freshclam_config(),
        }
    }

    fn shows_setting(self, config_setting: &ConfigSetting) -> bool {
        match self {
            Self::ScannerEngine => !is_on_access_setting(config_setting),
            Self::OnAccessScanning => is_on_access_setting(config_setting),
            Self::SignatureUpdates => true,
        }
    }
}

enum ConfigLoad {
    LoadingConfig,
    ConfigShown {
        config_path: String,
        config_file_owner: ConfigFileOwner,
    },
    ConfigMissing,
}

enum UnlockState {
    Locked,
    Unlocked { relock_generation: u64 },
}

enum ChangeProgress {
    NoChangeRunning,
    ChangeRunning { row_index: DynamicIndex },
}

pub struct EngineSettingsPage {
    settings_section: EngineSettingsSection,
    config_load: ConfigLoad,
    tuning_state: LiveTuningState,
    unlock_state: UnlockState,
    unlock_count: u64,
    change_progress: ChangeProgress,
    setting_rows: FactoryVecDeque<ConfigSettingRow>,
    toaster: Toaster,
}

#[derive(Debug)]
pub enum EngineSettingsPageInput {
    UnlockToggled(bool),
    ValueApplied {
        row_index: DynamicIndex,
        setting_key: String,
        sibling_values: Vec<String>,
        value_position: usize,
        edited_text: String,
    },
    LiveChangeConfirmed {
        row_index: DynamicIndex,
        setting_key: String,
        new_values: Vec<String>,
    },
    DriftSnippetCopyRequested,
}

#[derive(Debug)]
pub enum EngineSettingsPageCommand {
    ConfigLoaded {
        host_config: HostConfigView,
        config_file_owner: ConfigFileOwner,
        tuning_state: LiveTuningState,
    },
    RelockDue {
        relock_generation: u64,
    },
    LiveChangeFinished {
        change_outcome: LiveChangeOutcome,
        tuning_state: LiveTuningState,
    },
}

fn describe_live_change_outcome(change_outcome: &LiveChangeOutcome) -> String {
    match change_outcome {
        LiveChangeOutcome::SettingsApplied => {
            gettext("Applied, but not yet in your system configuration.")
        }
        LiveChangeOutcome::PreviousRestored => gettext(
            "ClamAV didn't come back healthy with that value, so the previous settings were \
             restored.",
        ),
        LiveChangeOutcome::NothingChanged { failure_text } => {
            gettext("The change was not made: {error}")
                .replace("{error}", &sanitize_scanner_line(failure_text))
        }
    }
}

fn live_tunable_config_description(config_path: &str) -> String {
    gettext(
        "{path} combines your system configuration with the changes made here. While locked, \
         editing a value and pressing the check mark copies the line for your configuration. \
         After unlocking, the allowed settings change directly.",
    )
    .replace("{path}", config_path)
}

fn present_live_change_confirmation(
    parent_widget: &impl IsA<gtk::Widget>,
    row_index: DynamicIndex,
    setting_key: String,
    current_values: &[String],
    new_values: Vec<String>,
    sender: &ComponentSender<EngineSettingsPage>,
) {
    let effect = change_effect(&setting_key, current_values, &new_values);
    let confirmation_dialog = adw::AlertDialog::new(
        Some(&gettext("Change this setting?")),
        Some(&change_confirmation_text(
            &setting_key,
            current_values,
            &new_values,
            effect,
        )),
    );
    confirmation_dialog.add_response("cancel", &gettext("Cancel"));
    confirmation_dialog.add_response(
        "apply",
        &if effect != ProtectionReduction::NoReduction {
            gettext("Reduce Protection")
        } else {
            gettext("Apply")
        },
    );
    if effect != ProtectionReduction::NoReduction {
        confirmation_dialog.set_response_appearance("apply", adw::ResponseAppearance::Destructive);
    }
    confirmation_dialog.set_default_response(Some("cancel"));
    confirmation_dialog.set_close_response("cancel");
    let input_sender = sender.input_sender().clone();
    confirmation_dialog.connect_response(Some("apply"), move |_dialog, _response| {
        input_sender.emit(EngineSettingsPageInput::LiveChangeConfirmed {
            row_index: row_index.clone(),
            setting_key: setting_key.clone(),
            new_values: new_values.clone(),
        });
    });
    confirmation_dialog.present(Some(parent_widget));
}

fn shown_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

fn setting_row_inits(
    config_settings: &[ConfigSetting],
    settings_section: EngineSettingsSection,
) -> Vec<ConfigSettingRowInit> {
    let shown_settings = config_settings
        .iter()
        .filter(|config_setting| settings_section.shows_setting(config_setting))
        .collect::<Vec<_>>();
    shown_settings
        .iter()
        .map(|config_setting| {
            let same_key_settings = shown_settings
                .iter()
                .filter(|other_setting| other_setting.setting_key == config_setting.setting_key)
                .collect::<Vec<_>>();
            ConfigSettingRowInit {
                setting_key: sanitize_scanner_line(&config_setting.setting_key),
                setting_value: sanitize_scanner_line(&config_setting.setting_value),
                setting_lock: setting_lock_for_key(&config_setting.setting_key),
                sibling_values: same_key_settings
                    .iter()
                    .map(|same_key_setting| sanitize_scanner_line(&same_key_setting.setting_value))
                    .collect(),
                value_position: same_key_settings
                    .iter()
                    .position(|same_key_setting| std::ptr::eq(**same_key_setting, *config_setting))
                    .unwrap_or_default(),
            }
        })
        .collect()
}

impl EngineSettingsPage {
    fn offers_live_changes(&self) -> bool {
        self.settings_section.offers_live_tuning() && !self.tuning_state.tunable_settings.is_empty()
    }

    const fn is_unlocked(&self) -> bool {
        matches!(self.unlock_state, UnlockState::Unlocked { .. })
    }

    fn allows_live_change(&self, setting_key: &str) -> bool {
        self.is_unlocked()
            && self.offers_live_changes()
            && self
                .tuning_state
                .tunable_settings
                .iter()
                .any(|tunable_key| tunable_key == setting_key)
    }

    fn current_setting_values(
        &self,
        setting_key: &str,
        configured_values: &[String],
    ) -> Vec<String> {
        let overridden_values = self
            .tuning_state
            .active_overrides
            .iter()
            .filter(|active_override| active_override.0 == setting_key)
            .map(|active_override| sanitize_scanner_line(&active_override.1))
            .collect::<Vec<_>>();
        if overridden_values.is_empty() {
            configured_values.to_vec()
        } else {
            overridden_values
        }
    }

    fn drift_snippet(&self) -> String {
        drift_snippet_text(
            &self.tuning_state.active_overrides,
            self.settings_section.config_kind(),
            ConfigFileOwner::NixOsConfiguration,
        )
    }

    fn config_group_description(&self) -> String {
        match &self.config_load {
            ConfigLoad::ConfigShown {
                config_path,
                config_file_owner,
            } => {
                if self.offers_live_changes() {
                    live_tunable_config_description(config_path)
                } else {
                    managed_config_description(*config_file_owner, config_path)
                }
            }
            ConfigLoad::LoadingConfig => gettext("Reading the configuration…"),
            ConfigLoad::ConfigMissing => gettext("Configuration file not found"),
        }
    }

    fn shows_empty_section_row(&self) -> bool {
        matches!(self.config_load, ConfigLoad::ConfigShown { .. }) && self.setting_rows.is_empty()
    }

    fn config_file_owner(&self) -> ConfigFileOwner {
        match &self.config_load {
            ConfigLoad::ConfigShown {
                config_file_owner, ..
            } => *config_file_owner,
            ConfigLoad::LoadingConfig | ConfigLoad::ConfigMissing => ConfigFileOwner::SystemPackage,
        }
    }

    fn unlock_label(&self) -> String {
        if self.is_unlocked() {
            gettext("Lock")
        } else {
            gettext("Unlock")
        }
    }
}

#[relm4::component(pub)]
impl Component for EngineSettingsPage {
    type Init = EngineSettingsSection;
    type Input = EngineSettingsPageInput;
    type Output = ();
    type CommandOutput = EngineSettingsPageCommand;

    view! {
        adw::ToastOverlay {
            adw::PreferencesPage {
                set_title: &model.settings_section.page_title(),
                set_icon_name: Some(model.settings_section.page_icon()),

                adw::PreferencesGroup {
                    set_title: &gettext("Change Settings"),
                    set_description: Some(&gettext(
                        "Unlock to change the settings your system allows at runtime. Unlocking \
                         grants nothing by itself: each change shows what will happen and asks \
                         for administrator authorization. It locks again after two minutes.",
                    )),
                    #[watch]
                    set_visible: model.offers_live_changes(),

                    #[wrap(Some)]
                    set_header_suffix = &gtk::ToggleButton {
                        set_valign: gtk::Align::Center,
                        #[watch]
                        set_label: &model.unlock_label(),
                        #[watch]
                        #[block_signal(unlock_toggled_handler)]
                        set_active: model.is_unlocked(),
                        connect_toggled[sender] => move |toggled_button| {
                            sender.input(EngineSettingsPageInput::UnlockToggled(
                                toggled_button.is_active(),
                            ));
                        } @unlock_toggled_handler,
                    },

                    adw::ActionRow {
                        set_use_markup: false,
                        set_title: &gettext("Changes your system configuration doesn't know about"),
                        set_subtitle_selectable: true,
                        set_subtitle_lines: 0,
                        #[watch]
                        set_subtitle: &sanitize_scanner_text(&model.drift_snippet()),
                        #[watch]
                        set_visible: !model.drift_snippet().is_empty(),

                        add_suffix = &gtk::Button {
                            set_icon_name: "edit-copy-symbolic",
                            set_tooltip_text: Some(&gettext("Copy")),
                            set_valign: gtk::Align::Center,
                            add_css_class: "flat",
                            connect_clicked => EngineSettingsPageInput::DriftSnippetCopyRequested,
                        },
                    },
                },

                #[local_ref]
                setting_rows_group -> adw::PreferencesGroup {
                    set_title: &model.settings_section.group_title(),
                    #[watch]
                    set_description: Some(&glib::markup_escape_text(
                        &model.config_group_description(),
                    )),

                    adw::ActionRow {
                        set_title: &gettext("No settings in this section"),
                        #[watch]
                        set_visible: model.shows_empty_section_row(),
                    },
                },
            },
        }
    }

    fn init(
        settings_section: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let setting_rows = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                ConfigSettingRowOutput::ValueApplied {
                    row_index,
                    setting_key,
                    sibling_values,
                    value_position,
                    edited_text,
                } => EngineSettingsPageInput::ValueApplied {
                    row_index,
                    setting_key,
                    sibling_values,
                    value_position,
                    edited_text,
                },
            });
        let model = Self {
            settings_section,
            config_load: ConfigLoad::LoadingConfig,
            tuning_state: LiveTuningState::default(),
            unlock_state: UnlockState::Locked,
            unlock_count: 0,
            change_progress: ChangeProgress::NoChangeRunning,
            setting_rows,
            toaster: Toaster::new(&root),
        };
        let setting_rows_group = model.setting_rows.widget();
        let widgets = view_output!();
        sender.oneshot_command(async move {
            let host_config = settings_section.read_host_config();
            let config_file_owner = match &host_config {
                HostConfigView::ConfigFound { config_path, .. } => {
                    inspect_config_file_owner(std::path::Path::new(config_path))
                }
                HostConfigView::ConfigNotFound => ConfigFileOwner::SystemPackage,
            };
            let tuning_state = if settings_section.offers_live_tuning() {
                read_live_tuning_state().await
            } else {
                LiveTuningState::default()
            };
            EngineSettingsPageCommand::ConfigLoaded {
                host_config,
                config_file_owner,
                tuning_state,
            }
        });
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: EngineSettingsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            EngineSettingsPageInput::UnlockToggled(true) => {
                self.unlock_count += 1;
                let relock_generation = self.unlock_count;
                self.unlock_state = UnlockState::Unlocked { relock_generation };
                sender.oneshot_command(async move {
                    tokio::time::sleep(UNLOCK_DURATION).await;
                    EngineSettingsPageCommand::RelockDue { relock_generation }
                });
            }
            EngineSettingsPageInput::UnlockToggled(false) => {
                self.unlock_state = UnlockState::Locked;
            }
            EngineSettingsPageInput::ValueApplied {
                row_index,
                setting_key,
                sibling_values,
                value_position,
                edited_text,
            } => {
                let edited_text = sanitize_scanner_line(&edited_text);
                if self.allows_live_change(&setting_key) {
                    let current_values = self.current_setting_values(&setting_key, &sibling_values);
                    let new_values = values_with_edit(&current_values, value_position, edited_text);
                    present_live_change_confirmation(
                        root,
                        row_index,
                        setting_key,
                        &current_values,
                        new_values,
                        &sender,
                    );
                } else {
                    root.clipboard().set_text(&change_snippet(
                        self.config_file_owner(),
                        self.settings_section.config_kind(),
                        &setting_key,
                        &values_with_edit(&sibling_values, value_position, edited_text),
                    ));
                    self.toaster.add_toast(shown_toast(&gettext(
                        "Copied. Add it to your configuration to apply it.",
                    )));
                }
            }
            EngineSettingsPageInput::LiveChangeConfirmed {
                row_index,
                setting_key,
                new_values,
            } => {
                self.setting_rows.send(
                    row_index.current_index(),
                    ConfigSettingRowInput::ChangeRunningChanged(true),
                );
                self.change_progress = ChangeProgress::ChangeRunning { row_index };
                sender.oneshot_command(async move {
                    let change_outcome = apply_live_change(setting_key, new_values).await;
                    EngineSettingsPageCommand::LiveChangeFinished {
                        change_outcome,
                        tuning_state: read_live_tuning_state().await,
                    }
                });
            }
            EngineSettingsPageInput::DriftSnippetCopyRequested => {
                root.clipboard().set_text(&self.drift_snippet());
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: EngineSettingsPageCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            EngineSettingsPageCommand::ConfigLoaded {
                host_config,
                config_file_owner,
                tuning_state,
            } => {
                self.tuning_state = tuning_state;
                match host_config {
                    HostConfigView::ConfigFound {
                        config_path,
                        config_settings,
                    } => {
                        let mut row_guard = self.setting_rows.guard();
                        setting_row_inits(&config_settings, self.settings_section)
                            .into_iter()
                            .for_each(|row_init| {
                                row_guard.push_back(row_init);
                            });
                        drop(row_guard);
                        self.config_load = ConfigLoad::ConfigShown {
                            config_path,
                            config_file_owner,
                        };
                    }
                    HostConfigView::ConfigNotFound => self.config_load = ConfigLoad::ConfigMissing,
                }
            }
            EngineSettingsPageCommand::RelockDue { relock_generation } => {
                if matches!(
                    self.unlock_state,
                    UnlockState::Unlocked { relock_generation: unlocked_generation }
                        if unlocked_generation == relock_generation
                ) {
                    self.unlock_state = UnlockState::Locked;
                }
            }
            EngineSettingsPageCommand::LiveChangeFinished {
                change_outcome,
                tuning_state,
            } => {
                if let ChangeProgress::ChangeRunning { row_index } =
                    std::mem::replace(&mut self.change_progress, ChangeProgress::NoChangeRunning)
                {
                    self.setting_rows.send(
                        row_index.current_index(),
                        ConfigSettingRowInput::ChangeRunningChanged(false),
                    );
                }
                self.toaster
                    .add_toast(shown_toast(&describe_live_change_outcome(&change_outcome)));
                self.tuning_state = tuning_state;
            }
        }
    }
}
