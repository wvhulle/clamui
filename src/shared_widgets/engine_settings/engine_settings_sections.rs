use std::time::Duration;

use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, adw,
    adw::prelude::*, gtk, gtk::glib, prelude::FactoryVecDeque,
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
                ClamavConfigKind, ConfigFileOwner, drift_snippet_text, inspect_config_file_owner,
                managed_config_description, setting_lock_for_key, values_with_edit,
            },
            typed_setting_values::TypedSettingValue,
        },
        clamav_scanner::scanner_output_parser::{sanitize_scanner_line, sanitize_scanner_text},
        settings_helper::{
            live_settings_client::{
                LiveChangeFailure, LiveChangeOutcome, LiveTuning, OverrideSetting,
                apply_live_change, change_confirmation_text, change_effect, read_live_tuning,
            },
            protection_change_rules::ProtectionReduction,
        },
    },
    shared_widgets::{
        awaited_dialogs::{
            AlertChoice, add_alert_choice, add_dismissing_choice, alert_choice,
            deliver_local_outcome,
        },
        engine_settings::{
            config_line_copy_dialog::{
                ConfigLineCopyDialog, ConfigLineCopyDialogOutput, ConfigLineCopyInit,
            },
            config_setting_row::{
                ConfigSettingRow, ConfigSettingRowInit, ConfigSettingRowInput,
                ConfigSettingRowOutput, RowChangeActivity, SettingAvailability,
                config_row_presentation,
            },
            detection_switch_row::{
                DetectionSwitchRow, DetectionSwitchRowInput, DetectionSwitchRowOutput,
                DetectionSwitchState,
            },
        },
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
    fn group_title(self) -> String {
        match self {
            Self::ScannerEngine => gettext("clamd settings"),
            Self::OnAccessScanning => gettext("On-access scanning settings"),
            Self::SignatureUpdates => gettext("Update settings"),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSettingsLayout {
    SingleSection(EngineSettingsSection),
    EngineWithDetection,
}

impl EngineSettingsLayout {
    const fn config_section(self) -> EngineSettingsSection {
        match self {
            Self::SingleSection(settings_section) => settings_section,
            Self::EngineWithDetection => EngineSettingsSection::ScannerEngine,
        }
    }

    pub const fn shows_detection_switches(self) -> bool {
        matches!(self, Self::EngineWithDetection)
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangedRow {
    ConfigRow {
        setting_key: String,
        value_position: usize,
    },
    DetectionSwitch(DetectionOption),
}

enum CopyDialogState {
    NoCopyDialog,
    CopyDialogOpen(Controller<ConfigLineCopyDialog>),
}

#[derive(Debug)]
enum ChangeProgress {
    NoChangeRunning,
    ChangeRunning { changed_row: ChangedRow },
}

impl ChangedRow {
    fn is_config_row(&self, setting_key: &str, value_position: usize) -> bool {
        match self {
            Self::ConfigRow {
                setting_key: changed_key,
                value_position: changed_position,
            } => changed_key == setting_key && *changed_position == value_position,
            Self::DetectionSwitch(_) => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingTunability {
    TunableAtRuntime,
    NotTunableAtRuntime,
}

const fn setting_availability_for(
    setting_tunability: SettingTunability,
    unlock_state: &UnlockState,
) -> SettingAvailability {
    match (setting_tunability, unlock_state) {
        (SettingTunability::TunableAtRuntime, UnlockState::Unlocked { .. }) => {
            SettingAvailability::ChangeableNow
        }
        (SettingTunability::TunableAtRuntime, UnlockState::Locked) => {
            SettingAvailability::LockedUntilUnlocked
        }
        (
            SettingTunability::NotTunableAtRuntime,
            UnlockState::Locked | UnlockState::Unlocked { .. },
        ) => SettingAvailability::NotAllowedAtRuntime,
    }
}

impl ChangeProgress {
    fn row_change_activity(
        &self,
        is_this_row: impl FnOnce(&ChangedRow) -> bool,
    ) -> RowChangeActivity {
        match self {
            Self::NoChangeRunning => RowChangeActivity::ChangesAllowed,
            Self::ChangeRunning { changed_row } => {
                if is_this_row(changed_row) {
                    RowChangeActivity::ApplyingThisRow
                } else {
                    RowChangeActivity::ApplyingOtherRow
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveChangeReadiness {
    ReadyToChange { unlock_generation: u64 },
    ChangesLocked,
    ChangeAlreadyRunning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfirmationVerdict {
    StartConfirmedChange,
    DropStaleConfirmation,
}

const fn live_change_readiness(
    unlock_state: &UnlockState,
    change_progress: &ChangeProgress,
) -> LiveChangeReadiness {
    match change_progress {
        ChangeProgress::ChangeRunning { .. } => LiveChangeReadiness::ChangeAlreadyRunning,
        ChangeProgress::NoChangeRunning => match unlock_state {
            UnlockState::Locked => LiveChangeReadiness::ChangesLocked,
            UnlockState::Unlocked { relock_generation } => LiveChangeReadiness::ReadyToChange {
                unlock_generation: *relock_generation,
            },
        },
    }
}

const fn confirmation_verdict(
    change_readiness: LiveChangeReadiness,
    confirmed_generation: u64,
) -> ConfirmationVerdict {
    match change_readiness {
        LiveChangeReadiness::ReadyToChange { unlock_generation }
            if unlock_generation == confirmed_generation =>
        {
            ConfirmationVerdict::StartConfirmedChange
        }
        LiveChangeReadiness::ReadyToChange { .. }
        | LiveChangeReadiness::ChangesLocked
        | LiveChangeReadiness::ChangeAlreadyRunning => ConfirmationVerdict::DropStaleConfirmation,
    }
}

pub struct EngineSettingsSections {
    settings_layout: EngineSettingsLayout,
    settings_section: EngineSettingsSection,
    config_load: ConfigLoad,
    tuning_load: LiveTuningLoad,
    unlock_state: UnlockState,
    unlock_count: u64,
    change_progress: ChangeProgress,
    setting_rows: FactoryVecDeque<ConfigSettingRow>,
    detection_switches: FactoryVecDeque<DetectionSwitchRow>,
    configured_settings: Vec<ConfigSetting>,
    copy_dialog: CopyDialogState,
}

#[derive(Debug)]
pub enum EngineSettingsNotice {
    ChangeSnippetCopied,
    StaleConfirmationDropped,
    LiveChangeReported(LiveChangeOutcome),
}

#[derive(Debug)]
pub enum EngineSettingsSectionsOutput {
    ToastRequested(EngineSettingsNotice),
}

#[derive(Debug)]
pub enum EngineSettingsSectionsInput {
    UnlockToggled(bool),
    ValueApplied {
        setting_key: String,
        sibling_values: Vec<String>,
        value_position: usize,
        config_value: String,
    },
    LineCopyRequested {
        setting_key: String,
        sibling_values: Vec<String>,
        value_position: usize,
        editor_draft: TypedSettingValue,
    },
    ConfigLineCopied(String),
    CopyDialogClosed,
    LiveChangeConfirmed {
        unlock_generation: u64,
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
pub enum EngineSettingsSectionsCommand {
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

pub fn describe_engine_settings_notice(settings_notice: &EngineSettingsNotice) -> String {
    match settings_notice {
        EngineSettingsNotice::ChangeSnippetCopied => {
            gettext("Copied. Add it to your configuration to apply it.")
        }
        EngineSettingsNotice::StaleConfirmationDropped => gettext(
            "The change was not made: the settings locked again or another change started first.",
        ),
        EngineSettingsNotice::LiveChangeReported(change_outcome) => {
            describe_live_change_outcome(change_outcome)
        }
    }
}

pub fn engine_settings_notice_toast(settings_notice: &EngineSettingsNotice) -> adw::Toast {
    adw::Toast::builder()
        .title(describe_engine_settings_notice(settings_notice))
        .use_markup(false)
        .build()
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
        LiveChangeOutcome::NothingChanged(change_failure) => {
            live_change_failure_text(change_failure)
        }
    }
}

fn live_change_failure_text(change_failure: &LiveChangeFailure) -> String {
    let change_not_made = |failure_reason: &str| {
        gettext("The change was not made: {error}")
            .replace("{error}", &sanitize_scanner_line(failure_reason))
    };
    match change_failure {
        LiveChangeFailure::AuthorizationRefused => gettext("Nothing changed without your password"),
        LiveChangeFailure::HelperMissing => gettext(
            "This installation has no settings helper, so ClamAV's settings can't be changed from \
             Lazaret",
        ),
        LiveChangeFailure::UnknownHelperAnswer { helper_answer } => change_not_made(helper_answer),
        LiveChangeFailure::ReportedByHelper { helper_message } => change_not_made(helper_message),
        LiveChangeFailure::HelperCallFailed(call_failure) => {
            change_not_made(&call_failure.to_string())
        }
    }
}

fn live_tunable_config_description(config_path: &str) -> String {
    gettext(
        "{path} combines your system configuration with the changes made here. While locked, \
         settings are read-only: use Copy configuration line to copy one for your configuration. \
         After unlocking, the allowed settings change directly.",
    )
    .replace("{path}", config_path)
}

struct ProposedLiveChange {
    unlock_generation: u64,
    changed_row: ChangedRow,
    setting_key: String,
    new_values: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingChangeChoice {
    ChangeApplied,
    ChangeCancelled,
}

impl AlertChoice for SettingChangeChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[Self::ChangeApplied];
    const DISMISSING_CHOICE: Self = Self::ChangeCancelled;

    fn response_id(self) -> &'static str {
        match self {
            Self::ChangeApplied => "apply",
            Self::ChangeCancelled => "cancel",
        }
    }
}

fn present_live_change_confirmation(
    parent_widget: &impl IsA<gtk::Widget>,
    proposed_change: ProposedLiveChange,
    current_values: &[String],
    sender: &ComponentSender<EngineSettingsSections>,
) {
    let ProposedLiveChange {
        unlock_generation,
        changed_row,
        setting_key,
        new_values,
    } = proposed_change;
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
    add_dismissing_choice::<SettingChangeChoice>(&confirmation_dialog, &gettext("Cancel"));
    add_alert_choice(
        &confirmation_dialog,
        SettingChangeChoice::ChangeApplied,
        &if effect != ProtectionReduction::NoReduction {
            gettext("Reduce Protection")
        } else {
            gettext("Apply")
        },
    );
    if effect != ProtectionReduction::NoReduction {
        confirmation_dialog.set_response_appearance(
            SettingChangeChoice::ChangeApplied.response_id(),
            adw::ResponseAppearance::Destructive,
        );
    }
    confirmation_dialog
        .set_default_response(Some(SettingChangeChoice::ChangeCancelled.response_id()));
    deliver_local_outcome(
        sender.input_sender().clone(),
        alert_choice(confirmation_dialog, parent_widget.clone().upcast()),
        move |change_choice| match change_choice {
            SettingChangeChoice::ChangeApplied => {
                Some(EngineSettingsSectionsInput::LiveChangeConfirmed {
                    unlock_generation,
                    changed_row,
                    setting_key,
                    new_values,
                })
            }
            SettingChangeChoice::ChangeCancelled => None,
        },
    );
}

fn setting_row_inits(
    config_settings: &[ConfigSetting],
    settings_section: EngineSettingsSection,
    setting_availability: impl Fn(&str) -> SettingAvailability,
    change_activity: impl Fn(&str, usize) -> RowChangeActivity,
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
            let setting_key = sanitize_scanner_line(&config_setting.setting_key);
            let setting_value = sanitize_scanner_line(&config_setting.setting_value);
            let value_position = same_key_settings
                .iter()
                .position(|same_key_setting| std::ptr::eq(**same_key_setting, *config_setting))
                .unwrap_or_default();
            ConfigSettingRowInit {
                row_presentation: config_row_presentation(
                    &setting_key,
                    &setting_value,
                    setting_lock_for_key(&config_setting.setting_key),
                    setting_availability(&config_setting.setting_key),
                ),
                change_activity: change_activity(&setting_key, value_position),
                sibling_values: same_key_settings
                    .iter()
                    .map(|same_key_setting| sanitize_scanner_line(&same_key_setting.setting_value))
                    .collect(),
                setting_key,
                setting_value,
                value_position,
            }
        })
        .collect()
}

impl EngineSettingsSections {
    fn report_notice(sender: &ComponentSender<Self>, settings_notice: EngineSettingsNotice) {
        let _host_closed = sender.output(EngineSettingsSectionsOutput::ToastRequested(
            settings_notice,
        ));
    }

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

    fn live_change_readiness_for(&self, setting_key: &str) -> LiveChangeReadiness {
        let change_readiness = live_change_readiness(&self.unlock_state, &self.change_progress);
        if self.offers_live_changes() && self.setting_is_tunable(setting_key) {
            return change_readiness;
        }
        match change_readiness {
            LiveChangeReadiness::ChangeAlreadyRunning => LiveChangeReadiness::ChangeAlreadyRunning,
            LiveChangeReadiness::ReadyToChange { .. } | LiveChangeReadiness::ChangesLocked => {
                LiveChangeReadiness::ChangesLocked
            }
        }
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
        self.settings_layout.shows_detection_switches()
            && matches!(self.config_load, ConfigLoad::ConfigShown { .. })
    }

    fn detection_values(&self, detection_option: DetectionOption) -> Vec<String> {
        self.current_setting_values(
            detection_option.setting_key(),
            &configured_values(&self.configured_settings, detection_option.setting_key()),
        )
    }

    fn setting_tunability(&self, setting_key: &str) -> SettingTunability {
        if self.offers_live_changes() && self.setting_is_tunable(setting_key) {
            SettingTunability::TunableAtRuntime
        } else {
            SettingTunability::NotTunableAtRuntime
        }
    }

    fn setting_availability(&self, setting_key: &str) -> SettingAvailability {
        setting_availability_for(self.setting_tunability(setting_key), &self.unlock_state)
    }

    fn detection_switch_state(&self, detection_option: DetectionOption) -> DetectionSwitchState {
        DetectionSwitchState {
            detection_option,
            switched_on: effective_switch(
                &self.detection_values(detection_option),
                detection_option,
            ),
            switch_availability: self.setting_availability(detection_option.setting_key()),
            change_activity: self.change_progress.row_change_activity(|changed_row| {
                *changed_row == ChangedRow::DetectionSwitch(detection_option)
            }),
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

    fn config_row_activity(&self, setting_key: &str, value_position: usize) -> RowChangeActivity {
        self.change_progress.row_change_activity(|changed_row| {
            changed_row.is_config_row(setting_key, value_position)
        })
    }

    fn refresh_setting_rows(&self) {
        self.setting_rows
            .iter()
            .enumerate()
            .for_each(|(row_position, setting_row)| {
                self.setting_rows.send(
                    row_position,
                    ConfigSettingRowInput::ChangeActivityChanged(
                        self.change_progress
                            .row_change_activity(|changed_row| match changed_row {
                                ChangedRow::ConfigRow {
                                    setting_key,
                                    value_position,
                                } => setting_row.is_changed_row(setting_key, *value_position),
                                ChangedRow::DetectionSwitch(_) => false,
                            }),
                    ),
                );
            });
    }

    fn rebuild_setting_rows(&mut self) {
        let row_inits = setting_row_inits(
            &self.configured_settings,
            self.settings_section,
            |setting_key| self.setting_availability(setting_key),
            |setting_key, value_position| self.config_row_activity(setting_key, value_position),
        );
        let mut row_guard = self.setting_rows.guard();
        row_guard.clear();
        row_inits.into_iter().for_each(|row_init| {
            row_guard.push_back(row_init);
        });
    }

    fn refresh_lockable_rows(&mut self) {
        self.refresh_detection_switches();
        self.rebuild_setting_rows();
    }

    fn refresh_changeable_rows(&self) {
        self.refresh_detection_switches();
        self.refresh_setting_rows();
    }

    fn unlock_label(&self) -> String {
        if self.is_unlocked() {
            gettext("Lock")
        } else {
            gettext("Unlock")
        }
    }
}

fn load_section_config(
    sender: &ComponentSender<EngineSettingsSections>,
    settings_section: EngineSettingsSection,
) {
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
        EngineSettingsSectionsCommand::ConfigLoaded {
            host_config,
            config_file_owner,
            tuning_load,
        }
    });
}

#[relm4::component(pub)]
impl Component for EngineSettingsSections {
    type Init = EngineSettingsLayout;
    type Input = EngineSettingsSectionsInput;
    type Output = EngineSettingsSectionsOutput;
    type CommandOutput = EngineSettingsSectionsCommand;

    view! {
        adw::PreferencesGroup {

            gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_spacing: 24,

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
                            sender.input(EngineSettingsSectionsInput::UnlockToggled(
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
                            connect_clicked => EngineSettingsSectionsInput::DriftSnippetCopyRequested,
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
        settings_layout: Self::Init,
        _root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let settings_section = settings_layout.config_section();
        let setting_rows = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                ConfigSettingRowOutput::ValueApplied {
                    setting_key,
                    sibling_values,
                    value_position,
                    config_value,
                } => EngineSettingsSectionsInput::ValueApplied {
                    setting_key,
                    sibling_values,
                    value_position,
                    config_value,
                },
                ConfigSettingRowOutput::LineCopyRequested {
                    setting_key,
                    sibling_values,
                    value_position,
                    editor_draft,
                } => EngineSettingsSectionsInput::LineCopyRequested {
                    setting_key,
                    sibling_values,
                    value_position,
                    editor_draft,
                },
            });
        let detection_switches = FactoryVecDeque::builder()
            .launch(adw::PreferencesGroup::default())
            .forward(sender.input_sender(), |switch_output| match switch_output {
                DetectionSwitchRowOutput::SwitchChangeRequested {
                    detection_option,
                    switched_on,
                } => EngineSettingsSectionsInput::DetectionSwitchRequested {
                    detection_option,
                    switched_on,
                },
            });
        let model = Self {
            settings_layout,
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
            copy_dialog: CopyDialogState::NoCopyDialog,
        };
        let setting_rows_group = model.setting_rows.widget();
        let detection_switch_group = model.detection_switches.widget();
        let widgets = view_output!();
        load_section_config(&sender, settings_section);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: EngineSettingsSectionsInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            EngineSettingsSectionsInput::UnlockToggled(true) => {
                self.unlock_count += 1;
                let relock_generation = self.unlock_count;
                self.unlock_state = UnlockState::Unlocked { relock_generation };
                self.refresh_lockable_rows();
                sender.oneshot_command(async move {
                    tokio::time::sleep(UNLOCK_DURATION).await;
                    EngineSettingsSectionsCommand::RelockDue { relock_generation }
                });
            }
            EngineSettingsSectionsInput::UnlockToggled(false) => {
                self.unlock_state = UnlockState::Locked;
                self.refresh_lockable_rows();
            }
            EngineSettingsSectionsInput::DetectionSwitchRequested {
                detection_option,
                switched_on,
            } => {
                let setting_key = detection_option.setting_key().to_owned();
                match self.live_change_readiness_for(&setting_key) {
                    LiveChangeReadiness::ReadyToChange { unlock_generation } => {
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
                            ProposedLiveChange {
                                unlock_generation,
                                changed_row: ChangedRow::DetectionSwitch(detection_option),
                                setting_key,
                                new_values: vec![if switched_on { "yes" } else { "no" }.to_owned()],
                            },
                            &shown_current_values,
                            &sender,
                        );
                    }
                    LiveChangeReadiness::ChangesLocked
                    | LiveChangeReadiness::ChangeAlreadyRunning => {}
                }
                self.refresh_detection_switches();
            }
            EngineSettingsSectionsInput::ValueApplied {
                setting_key,
                sibling_values,
                value_position,
                config_value,
            } => match self.live_change_readiness_for(&setting_key) {
                LiveChangeReadiness::ReadyToChange { unlock_generation } => {
                    let current_values = self.current_setting_values(&setting_key, &sibling_values);
                    let new_values = values_with_edit(
                        &current_values,
                        value_position,
                        sanitize_scanner_line(&config_value),
                    );
                    present_live_change_confirmation(
                        root,
                        ProposedLiveChange {
                            unlock_generation,
                            changed_row: ChangedRow::ConfigRow {
                                setting_key: setting_key.clone(),
                                value_position,
                            },
                            setting_key,
                            new_values,
                        },
                        &current_values,
                        &sender,
                    );
                }
                LiveChangeReadiness::ChangesLocked => {
                    Self::report_notice(&sender, EngineSettingsNotice::StaleConfirmationDropped);
                    self.rebuild_setting_rows();
                }
                LiveChangeReadiness::ChangeAlreadyRunning => {}
            },
            EngineSettingsSectionsInput::LineCopyRequested {
                setting_key,
                sibling_values,
                value_position,
                editor_draft,
            } => {
                let copy_dialog = ConfigLineCopyDialog::builder()
                    .launch(ConfigLineCopyInit {
                        setting_key,
                        sibling_values,
                        value_position,
                        editor_draft,
                        config_file_owner: self.config_file_owner(),
                        config_kind: self.settings_section.config_kind(),
                    })
                    .forward(sender.input_sender(), |dialog_output| match dialog_output {
                        ConfigLineCopyDialogOutput::ConfigLineCopied(config_line) => {
                            EngineSettingsSectionsInput::ConfigLineCopied(config_line)
                        }
                        ConfigLineCopyDialogOutput::CopyDialogClosed => {
                            EngineSettingsSectionsInput::CopyDialogClosed
                        }
                    });
                copy_dialog.widget().present(Some(root));
                self.copy_dialog = CopyDialogState::CopyDialogOpen(copy_dialog);
            }
            EngineSettingsSectionsInput::ConfigLineCopied(config_line) => {
                root.clipboard().set_text(&config_line);
                Self::report_notice(&sender, EngineSettingsNotice::ChangeSnippetCopied);
                match &self.copy_dialog {
                    CopyDialogState::CopyDialogOpen(copy_dialog) => {
                        let _dialog_closed = copy_dialog.widget().close();
                    }
                    CopyDialogState::NoCopyDialog => {}
                }
            }
            EngineSettingsSectionsInput::CopyDialogClosed => {
                self.copy_dialog = CopyDialogState::NoCopyDialog;
            }
            EngineSettingsSectionsInput::LiveChangeConfirmed {
                unlock_generation,
                changed_row,
                setting_key,
                new_values,
            } => {
                match confirmation_verdict(
                    live_change_readiness(&self.unlock_state, &self.change_progress),
                    unlock_generation,
                ) {
                    ConfirmationVerdict::StartConfirmedChange => {
                        self.change_progress = ChangeProgress::ChangeRunning { changed_row };
                        sender.oneshot_command(async move {
                            let change_outcome = apply_live_change(setting_key, new_values).await;
                            EngineSettingsSectionsCommand::LiveChangeFinished {
                                change_outcome,
                                live_tuning: read_live_tuning().await,
                            }
                        });
                    }
                    ConfirmationVerdict::DropStaleConfirmation => {
                        Self::report_notice(
                            &sender,
                            EngineSettingsNotice::StaleConfirmationDropped,
                        );
                    }
                }
                self.refresh_changeable_rows();
            }
            EngineSettingsSectionsInput::DriftSnippetCopyRequested => {
                root.clipboard().set_text(&self.drift_snippet());
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: EngineSettingsSectionsCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            EngineSettingsSectionsCommand::ConfigLoaded {
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
                        self.configured_settings = config_settings;
                        self.config_load = ConfigLoad::ConfigShown {
                            config_path,
                            config_file_owner,
                        };
                        let switch_states = DETECTION_OPTIONS
                            .map(|detection_option| self.detection_switch_state(detection_option));
                        let mut switch_guard = self.detection_switches.guard();
                        switch_guard.clear();
                        switch_states.into_iter().for_each(|switch_state| {
                            switch_guard.push_back(switch_state);
                        });
                        drop(switch_guard);
                        self.rebuild_setting_rows();
                    }
                    HostConfigView::ConfigNotFound => self.config_load = ConfigLoad::ConfigMissing,
                }
            }
            EngineSettingsSectionsCommand::RelockDue { relock_generation } => {
                if matches!(
                    self.unlock_state,
                    UnlockState::Unlocked { relock_generation: unlocked_generation }
                        if unlocked_generation == relock_generation
                ) {
                    self.unlock_state = UnlockState::Locked;
                    self.refresh_lockable_rows();
                }
            }
            EngineSettingsSectionsCommand::LiveChangeFinished {
                change_outcome,
                live_tuning,
            } => {
                self.change_progress = ChangeProgress::NoChangeRunning;
                Self::report_notice(
                    &sender,
                    EngineSettingsNotice::LiveChangeReported(change_outcome),
                );
                self.tuning_load = LiveTuningLoad::TuningRead(live_tuning);
                self.refresh_changeable_rows();
                load_section_config(&sender, self.settings_section);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingsChangeFollowUp {
    ReloadChangesAndEvidence,
    NothingToReload,
}

pub const fn settings_change_follow_up(
    settings_notice: &EngineSettingsNotice,
) -> SettingsChangeFollowUp {
    match settings_notice {
        EngineSettingsNotice::LiveChangeReported(_) => {
            SettingsChangeFollowUp::ReloadChangesAndEvidence
        }
        EngineSettingsNotice::ChangeSnippetCopied
        | EngineSettingsNotice::StaleConfirmationDropped => SettingsChangeFollowUp::NothingToReload,
    }
}

#[cfg(test)]
mod engine_settings_sections_tests {
    use super::*;
    use crate::shared_widgets::engine_settings::config_setting_row::ConfigRowPresentation;

    #[test]
    fn a_live_change_reloads_the_audit_and_the_evidence() {
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::LiveChangeReported(
                LiveChangeOutcome::SettingsApplied
            )),
            SettingsChangeFollowUp::ReloadChangesAndEvidence
        );
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::LiveChangeReported(
                LiveChangeOutcome::PreviousRestored
            )),
            SettingsChangeFollowUp::ReloadChangesAndEvidence
        );
    }

    #[test]
    fn copying_a_snippet_reloads_nothing() {
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::ChangeSnippetCopied),
            SettingsChangeFollowUp::NothingToReload
        );
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::StaleConfirmationDropped),
            SettingsChangeFollowUp::NothingToReload
        );
    }

    const RUNNING_SWITCH_CHANGE: ChangeProgress = ChangeProgress::ChangeRunning {
        changed_row: ChangedRow::DetectionSwitch(DetectionOption::HeuristicAlerts),
    };

    #[test]
    fn every_settings_notice_describes_its_own_toast() {
        assert_eq!(
            describe_engine_settings_notice(&EngineSettingsNotice::ChangeSnippetCopied),
            "Copied. Add it to your configuration to apply it."
        );
        assert_eq!(
            describe_engine_settings_notice(&EngineSettingsNotice::StaleConfirmationDropped),
            "The change was not made: the settings locked again or another change started first."
        );
        assert_eq!(
            describe_engine_settings_notice(&EngineSettingsNotice::LiveChangeReported(
                LiveChangeOutcome::NothingChanged(LiveChangeFailure::AuthorizationRefused)
            )),
            "Nothing changed without your password"
        );
        assert_eq!(
            describe_engine_settings_notice(&EngineSettingsNotice::LiveChangeReported(
                LiveChangeOutcome::SettingsApplied
            )),
            describe_live_change_outcome(&LiveChangeOutcome::SettingsApplied)
        );
    }

    #[test]
    fn a_second_live_change_is_refused_while_one_runs() {
        let unlock_state = UnlockState::Unlocked {
            relock_generation: 1,
        };
        assert_eq!(
            live_change_readiness(&unlock_state, &RUNNING_SWITCH_CHANGE),
            LiveChangeReadiness::ChangeAlreadyRunning
        );
        assert_eq!(
            confirmation_verdict(
                live_change_readiness(&unlock_state, &RUNNING_SWITCH_CHANGE),
                1
            ),
            ConfirmationVerdict::DropStaleConfirmation
        );
    }

    #[test]
    fn a_confirmation_from_the_current_unlock_starts_the_change() {
        assert_eq!(
            confirmation_verdict(
                live_change_readiness(
                    &UnlockState::Unlocked {
                        relock_generation: 3
                    },
                    &ChangeProgress::NoChangeRunning
                ),
                3
            ),
            ConfirmationVerdict::StartConfirmedChange
        );
    }

    #[test]
    fn a_stale_confirmation_after_the_relock_is_dropped() {
        assert_eq!(
            confirmation_verdict(
                live_change_readiness(&UnlockState::Locked, &ChangeProgress::NoChangeRunning),
                1
            ),
            ConfirmationVerdict::DropStaleConfirmation
        );
        assert_eq!(
            confirmation_verdict(
                live_change_readiness(
                    &UnlockState::Unlocked {
                        relock_generation: 2
                    },
                    &ChangeProgress::NoChangeRunning
                ),
                1
            ),
            ConfirmationVerdict::DropStaleConfirmation
        );
    }

    #[test]
    fn every_row_is_insensitive_while_a_change_runs_and_only_one_spins() {
        let running_activity = RUNNING_SWITCH_CHANGE.row_change_activity(|changed_row| {
            *changed_row == ChangedRow::DetectionSwitch(DetectionOption::HeuristicAlerts)
        });
        let other_activity = RUNNING_SWITCH_CHANGE.row_change_activity(|changed_row| {
            *changed_row == ChangedRow::DetectionSwitch(DetectionOption::OfficeMacros)
        });
        assert_eq!(running_activity, RowChangeActivity::ApplyingThisRow);
        assert_eq!(other_activity, RowChangeActivity::ApplyingOtherRow);
        assert!(!running_activity.accepts_changes() && running_activity.shows_applying_spinner());
        assert!(!other_activity.accepts_changes() && !other_activity.shows_applying_spinner());
        assert_eq!(
            ChangeProgress::NoChangeRunning.row_change_activity(|_changed_row| true),
            RowChangeActivity::ChangesAllowed
        );
    }

    fn config_setting_of(setting_key: &str, setting_value: &str) -> ConfigSetting {
        ConfigSetting {
            setting_key: setting_key.to_owned(),
            setting_value: setting_value.to_owned(),
        }
    }

    #[test]
    fn only_tunable_settings_become_changeable_and_only_after_unlocking() {
        let unlocked_state = UnlockState::Unlocked {
            relock_generation: 1,
        };
        assert_eq!(
            setting_availability_for(SettingTunability::TunableAtRuntime, &unlocked_state),
            SettingAvailability::ChangeableNow
        );
        assert_eq!(
            setting_availability_for(SettingTunability::TunableAtRuntime, &UnlockState::Locked),
            SettingAvailability::LockedUntilUnlocked
        );
        assert_eq!(
            setting_availability_for(SettingTunability::NotTunableAtRuntime, &unlocked_state),
            SettingAvailability::NotAllowedAtRuntime
        );
    }

    #[test]
    fn unlocked_rows_get_editors_and_locked_rows_stay_read_only() {
        let config_settings = [
            config_setting_of("MaxThreads", "4"),
            config_setting_of("LogFile", "/var/log/clamd.log"),
        ];
        let row_presentations = |setting_availability| {
            setting_row_inits(
                &config_settings,
                EngineSettingsSection::ScannerEngine,
                |_setting_key| setting_availability,
                |_setting_key, _value_position| RowChangeActivity::ChangesAllowed,
            )
            .into_iter()
            .map(|row_init| row_init.row_presentation)
            .collect::<Vec<_>>()
        };
        assert!(matches!(
            row_presentations(SettingAvailability::ChangeableNow).as_slice(),
            [
                ConfigRowPresentation::EditableSettingRow(TypedSettingValue::CountValue {
                    count_value: 4,
                    ..
                }),
                ConfigRowPresentation::ProtectedSettingRow(_)
            ]
        ));
        assert!(matches!(
            row_presentations(SettingAvailability::LockedUntilUnlocked).as_slice(),
            [
                ConfigRowPresentation::LockedSettingRow { .. },
                ConfigRowPresentation::ProtectedSettingRow(_)
            ]
        ));
    }

    #[test]
    fn an_unlocked_edit_still_goes_through_the_confirmed_change() {
        let unlock_state = UnlockState::Unlocked {
            relock_generation: 4,
        };
        let change_readiness =
            live_change_readiness(&unlock_state, &ChangeProgress::NoChangeRunning);
        assert_eq!(
            change_readiness,
            LiveChangeReadiness::ReadyToChange {
                unlock_generation: 4
            }
        );
        assert_eq!(
            confirmation_verdict(change_readiness, 4),
            ConfirmationVerdict::StartConfirmedChange
        );
        let running_change = ChangeProgress::ChangeRunning {
            changed_row: ChangedRow::ConfigRow {
                setting_key: "MaxThreads".to_owned(),
                value_position: 0,
            },
        };
        assert_eq!(
            running_change
                .row_change_activity(|changed_row| changed_row.is_config_row("MaxThreads", 0)),
            RowChangeActivity::ApplyingThisRow
        );
        assert_eq!(
            running_change
                .row_change_activity(|changed_row| changed_row.is_config_row("MaxThreads", 1)),
            RowChangeActivity::ApplyingOtherRow
        );
    }

    #[test]
    fn copying_a_line_reports_a_copy_and_never_a_change() {
        assert_eq!(
            settings_change_follow_up(&EngineSettingsNotice::ChangeSnippetCopied),
            SettingsChangeFollowUp::NothingToReload
        );
    }

    #[test]
    fn the_scan_engine_layout_shows_both_sections_under_one_unlock() {
        assert!(EngineSettingsLayout::EngineWithDetection.shows_detection_switches());
    }
}
