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
            detection_options::{
                DETECTION_OPTIONS, DetectionOption, configured_values, effective_switch,
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
                LiveChangeOutcome, LiveTuning, OverrideSetting, apply_live_change,
                change_confirmation_text, change_effect, read_live_tuning,
            },
            protection_change_rules::ProtectionReduction,
        },
    },
    shared_widgets::{
        awaited_dialogs::{alert_response, deliver_local_outcome},
        engine_settings::{
            config_setting_row::{
                ConfigSettingRow, ConfigSettingRowInit, ConfigSettingRowInput,
                ConfigSettingRowOutput,
            },
            detection_switch_row::{
                DetectionSwitchRow, DetectionSwitchRowInput, DetectionSwitchRowOutput,
                DetectionSwitchState, SwitchAvailability,
            },
        },
    },
};

const UNLOCK_DURATION: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSettingsSection {
    ScannerEngine,
    DetectionChoices,
    OnAccessScanning,
    SignatureUpdates,
}

impl EngineSettingsSection {
    fn page_title(self) -> String {
        match self {
            Self::ScannerEngine => gettext("Scanner Engine"),
            Self::DetectionChoices => gettext("Detection"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::SignatureUpdates => gettext("Signature Updates"),
        }
    }

    const fn page_icon(self) -> &'static str {
        match self {
            Self::ScannerEngine => "system-search-symbolic",
            Self::DetectionChoices => "security-medium-symbolic",
            Self::OnAccessScanning => "security-high-symbolic",
            Self::SignatureUpdates => "drive-harddisk-symbolic",
        }
    }

    fn group_title(self) -> String {
        match self {
            Self::ScannerEngine | Self::DetectionChoices => gettext("clamd settings"),
            Self::OnAccessScanning => gettext("On-access scanning settings"),
            Self::SignatureUpdates => gettext("freshclam settings"),
        }
    }

    const fn config_kind(self) -> ClamavConfigKind {
        match self {
            Self::ScannerEngine | Self::DetectionChoices | Self::OnAccessScanning => {
                ClamavConfigKind::ClamdDaemonConfig
            }
            Self::SignatureUpdates => ClamavConfigKind::FreshclamUpdaterConfig,
        }
    }

    const fn offers_live_tuning(self) -> bool {
        matches!(
            self,
            Self::ScannerEngine | Self::DetectionChoices | Self::OnAccessScanning
        )
    }

    fn read_host_config(self) -> HostConfigView {
        match self {
            Self::ScannerEngine | Self::DetectionChoices | Self::OnAccessScanning => {
                read_clamd_config()
            }
            Self::SignatureUpdates => read_freshclam_config(),
        }
    }

    fn shows_setting(self, config_setting: &ConfigSetting) -> bool {
        match self {
            Self::ScannerEngine => !is_on_access_setting(config_setting),
            Self::DetectionChoices => false,
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

#[derive(Debug)]
pub enum LiveTuningLoad {
    TuningNotOffered,
    LoadingTuning,
    TuningRead(LiveTuning),
}

enum UnlockState {
    Locked,
    Unlocked { relock_generation: u64 },
}

#[derive(Clone, Debug)]
pub enum ChangedRow {
    ConfigRow(DynamicIndex),
    DetectionSwitch(DetectionOption),
}

enum ChangeProgress {
    NoChangeRunning,
    ChangeRunning { changed_row: ChangedRow },
}

pub struct EngineSettingsPage {
    settings_section: EngineSettingsSection,
    config_load: ConfigLoad,
    tuning_load: LiveTuningLoad,
    unlock_state: UnlockState,
    unlock_count: u64,
    change_progress: ChangeProgress,
    setting_rows: FactoryVecDeque<ConfigSettingRow>,
    detection_switches: FactoryVecDeque<DetectionSwitchRow>,
    configured_settings: Vec<ConfigSetting>,
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
        changed_row: ChangedRow,
        setting_key: String,
        new_values: Vec<String>,
    },
    DetectionSwitchRequested {
        detection_option: DetectionOption,
        switched_on: bool,
    },
    DriftSnippetCopyRequested,
}

#[derive(Debug)]
pub enum EngineSettingsPageCommand {
    ConfigLoaded {
        host_config: HostConfigView,
        config_file_owner: ConfigFileOwner,
        tuning_load: LiveTuningLoad,
    },
    RelockDue {
        relock_generation: u64,
    },
    LiveChangeFinished {
        change_outcome: LiveChangeOutcome,
        live_tuning: LiveTuning,
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
    changed_row: ChangedRow,
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
    deliver_local_outcome(
        sender.input_sender().clone(),
        alert_response(confirmation_dialog, parent_widget.clone().upcast()),
        move |chosen_response| {
            (chosen_response == "apply").then_some(EngineSettingsPageInput::LiveChangeConfirmed {
                changed_row,
                setting_key,
                new_values,
            })
        },
    );
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
        self.settings_section.offers_live_tuning()
            && match &self.tuning_load {
                LiveTuningLoad::TuningRead(LiveTuning::Available {
                    tunable_settings, ..
                }) => !tunable_settings.is_empty(),
                LiveTuningLoad::TuningRead(LiveTuning::HelperUnavailable(_))
                | LiveTuningLoad::TuningNotOffered
                | LiveTuningLoad::LoadingTuning => false,
            }
    }

    fn setting_is_tunable(&self, setting_key: &str) -> bool {
        match &self.tuning_load {
            LiveTuningLoad::TuningRead(LiveTuning::Available {
                tunable_settings, ..
            }) => tunable_settings
                .iter()
                .any(|tunable_key| tunable_key == setting_key),
            LiveTuningLoad::TuningRead(LiveTuning::HelperUnavailable(_))
            | LiveTuningLoad::TuningNotOffered
            | LiveTuningLoad::LoadingTuning => false,
        }
    }

    fn active_overrides(&self) -> &[OverrideSetting] {
        match &self.tuning_load {
            LiveTuningLoad::TuningRead(LiveTuning::Available {
                active_overrides, ..
            }) => active_overrides,
            LiveTuningLoad::TuningRead(LiveTuning::HelperUnavailable(_))
            | LiveTuningLoad::TuningNotOffered
            | LiveTuningLoad::LoadingTuning => &[],
        }
    }

    const fn helper_is_unavailable(&self) -> bool {
        self.settings_section.offers_live_tuning()
            && matches!(
                self.tuning_load,
                LiveTuningLoad::TuningRead(LiveTuning::HelperUnavailable(_))
            )
    }

    const fn is_unlocked(&self) -> bool {
        matches!(self.unlock_state, UnlockState::Unlocked { .. })
    }

    fn allows_live_change(&self, setting_key: &str) -> bool {
        self.is_unlocked() && self.offers_live_changes() && self.setting_is_tunable(setting_key)
    }

    fn current_setting_values(
        &self,
        setting_key: &str,
        configured_values: &[String],
    ) -> Vec<String> {
        let overridden_values = self
            .active_overrides()
            .iter()
            .filter(|active_override| active_override.setting_key == setting_key)
            .map(|active_override| sanitize_scanner_line(&active_override.setting_value))
            .collect::<Vec<_>>();
        if overridden_values.is_empty() {
            configured_values.to_vec()
        } else {
            overridden_values
        }
    }

    fn drift_snippet(&self) -> String {
        drift_snippet_text(
            self.active_overrides(),
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
                } else if self.helper_is_unavailable() {
                    format!(
                        "{}\n\n{}",
                        managed_config_description(*config_file_owner, config_path),
                        gettext(
                            "Settings can't be changed here right now: the Lazaret settings \
                             helper could not be reached."
                        )
                    )
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

    const fn shows_detection_switches(&self) -> bool {
        matches!(
            self.settings_section,
            EngineSettingsSection::DetectionChoices
        ) && matches!(self.config_load, ConfigLoad::ConfigShown { .. })
    }

    const fn shows_config_rows(&self) -> bool {
        !matches!(
            self.settings_section,
            EngineSettingsSection::DetectionChoices
        )
    }

    fn detection_values(&self, detection_option: DetectionOption) -> Vec<String> {
        self.current_setting_values(
            detection_option.setting_key(),
            &configured_values(&self.configured_settings, detection_option.setting_key()),
        )
    }

    fn detection_switch_state(&self, detection_option: DetectionOption) -> DetectionSwitchState {
        let setting_key = detection_option.setting_key();
        let tunable = self.offers_live_changes() && self.setting_is_tunable(setting_key);
        DetectionSwitchState {
            detection_option,
            switched_on: effective_switch(
                &self.detection_values(detection_option),
                detection_option,
            ),
            switch_availability: match (tunable, self.is_unlocked()) {
                (true, true) => SwitchAvailability::ChangeableNow,
                (true, false) => SwitchAvailability::LockedUntilUnlocked,
                (false, _not_tunable) => SwitchAvailability::NotAllowedAtRuntime,
            },
            change_running: matches!(
                &self.change_progress,
                ChangeProgress::ChangeRunning {
                    changed_row: ChangedRow::DetectionSwitch(running_option)
                } if *running_option == detection_option
            ),
        }
    }

    fn refresh_detection_switches(&self) {
        DETECTION_OPTIONS
            .iter()
            .enumerate()
            .for_each(|(switch_position, detection_option)| {
                self.detection_switches.send(
                    switch_position,
                    DetectionSwitchRowInput::SwitchStateChanged(
                        self.detection_switch_state(*detection_option),
                    ),
                );
            });
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
                detection_switch_group -> adw::PreferencesGroup {
                    set_title: &gettext("Detection"),
                    set_description: Some(&gettext(
                        "What ClamAV reports in every scan on this computer. Lazaret passes the \
                         same choices to clamscan, so both scanners agree.",
                    )),
                    #[watch]
                    set_visible: model.shows_detection_switches(),
                },

                #[local_ref]
                setting_rows_group -> adw::PreferencesGroup {
                    set_title: &model.settings_section.group_title(),
                    set_visible: model.shows_config_rows(),
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
        let detection_switches = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(sender.input_sender(), |switch_output| match switch_output {
                DetectionSwitchRowOutput::SwitchChangeRequested {
                    detection_option,
                    switched_on,
                } => EngineSettingsPageInput::DetectionSwitchRequested {
                    detection_option,
                    switched_on,
                },
            });
        let model = Self {
            settings_section,
            config_load: ConfigLoad::LoadingConfig,
            tuning_load: if settings_section.offers_live_tuning() {
                LiveTuningLoad::LoadingTuning
            } else {
                LiveTuningLoad::TuningNotOffered
            },
            unlock_state: UnlockState::Locked,
            unlock_count: 0,
            change_progress: ChangeProgress::NoChangeRunning,
            setting_rows,
            detection_switches,
            configured_settings: Vec::new(),
            toaster: Toaster::new(&root),
        };
        let setting_rows_group = model.setting_rows.widget();
        let detection_switch_group = model.detection_switches.widget();
        let widgets = view_output!();
        sender.oneshot_command(async move {
            let host_config = settings_section.read_host_config();
            let config_file_owner = match &host_config {
                HostConfigView::ConfigFound { config_path, .. } => {
                    inspect_config_file_owner(std::path::Path::new(config_path))
                }
                HostConfigView::ConfigNotFound => ConfigFileOwner::SystemPackage,
            };
            let tuning_load = if settings_section.offers_live_tuning() {
                LiveTuningLoad::TuningRead(read_live_tuning().await)
            } else {
                LiveTuningLoad::TuningNotOffered
            };
            EngineSettingsPageCommand::ConfigLoaded {
                host_config,
                config_file_owner,
                tuning_load,
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
                self.refresh_detection_switches();
                sender.oneshot_command(async move {
                    tokio::time::sleep(UNLOCK_DURATION).await;
                    EngineSettingsPageCommand::RelockDue { relock_generation }
                });
            }
            EngineSettingsPageInput::UnlockToggled(false) => {
                self.unlock_state = UnlockState::Locked;
                self.refresh_detection_switches();
            }
            EngineSettingsPageInput::DetectionSwitchRequested {
                detection_option,
                switched_on,
            } => {
                let setting_key = detection_option.setting_key().to_owned();
                if self.allows_live_change(&setting_key) {
                    let current_values = self.detection_values(detection_option);
                    let shown_current_values = if current_values.is_empty() {
                        vec![if detection_option.enabled_by_default() {
                            "yes".to_owned()
                        } else {
                            "no".to_owned()
                        }]
                    } else {
                        current_values
                    };
                    present_live_change_confirmation(
                        root,
                        ChangedRow::DetectionSwitch(detection_option),
                        setting_key,
                        &shown_current_values,
                        vec![if switched_on { "yes" } else { "no" }.to_owned()],
                        &sender,
                    );
                }
                self.refresh_detection_switches();
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
                        ChangedRow::ConfigRow(row_index),
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
                changed_row,
                setting_key,
                new_values,
            } => {
                if let ChangedRow::ConfigRow(row_index) = &changed_row {
                    self.setting_rows.send(
                        row_index.current_index(),
                        ConfigSettingRowInput::ChangeRunningChanged(true),
                    );
                }
                self.change_progress = ChangeProgress::ChangeRunning { changed_row };
                self.refresh_detection_switches();
                sender.oneshot_command(async move {
                    let change_outcome = apply_live_change(setting_key, new_values).await;
                    EngineSettingsPageCommand::LiveChangeFinished {
                        change_outcome,
                        live_tuning: read_live_tuning().await,
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
                tuning_load,
            } => {
                self.tuning_load = tuning_load;
                match host_config {
                    HostConfigView::ConfigFound {
                        config_path,
                        config_settings,
                    } => {
                        let mut switch_guard = self.detection_switches.guard();
                        switch_guard.clear();
                        drop(switch_guard);
                        self.configured_settings.clone_from(&config_settings);
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
                        let switch_states = DETECTION_OPTIONS
                            .map(|detection_option| self.detection_switch_state(detection_option));
                        let mut switch_guard = self.detection_switches.guard();
                        switch_states.into_iter().for_each(|switch_state| {
                            switch_guard.push_back(switch_state);
                        });
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
                    self.refresh_detection_switches();
                }
            }
            EngineSettingsPageCommand::LiveChangeFinished {
                change_outcome,
                live_tuning,
            } => {
                if let ChangeProgress::ChangeRunning {
                    changed_row: ChangedRow::ConfigRow(row_index),
                } = std::mem::replace(&mut self.change_progress, ChangeProgress::NoChangeRunning)
                {
                    self.setting_rows.send(
                        row_index.current_index(),
                        ConfigSettingRowInput::ChangeRunningChanged(false),
                    );
                }
                self.toaster
                    .add_toast(shown_toast(&describe_live_change_outcome(&change_outcome)));
                self.tuning_load = LiveTuningLoad::TuningRead(live_tuning);
                self.refresh_detection_switches();
            }
        }
    }
}
