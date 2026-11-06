use std::{cell::RefCell, rc::Rc};

use gettextrs::gettext;
use relm4::{adw, adw::prelude::*, gtk, gtk::glib};

use crate::{
    application_settings::{
        clamav_host_config::{
            ConfigSetting, HostConfigView, is_on_access_setting, read_clamd_config,
            read_freshclam_config,
        },
        live_settings_client::{
            ChangeEffect, LiveChangeOutcome, LiveTuningState, apply_live_change,
            change_confirmation_text, change_effect, read_live_tuning_state,
        },
        setting_provenance::{
            ClamavConfigKind, ConfigFileOwner, SettingLock, change_snippet,
            inspect_config_file_owner, managed_config_description, setting_lock_for_key,
        },
    },
    malware_scan::scanner_output_parser::{sanitize_scanner_line, sanitize_scanner_text},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSettingsSection {
    ScannerEngine,
    OnAccessScanning,
    SignatureUpdates,
}

const UNLOCK_SECONDS: u32 = 120;

fn lock_indicator(tooltip_text: &str) -> gtk::Image {
    gtk::Image::builder()
        .icon_name("changes-prevent-symbolic")
        .tooltip_text(tooltip_text)
        .valign(gtk::Align::Center)
        .css_classes(["dim-label"])
        .build()
}

fn protected_setting_row(config_setting: &ConfigSetting) -> gtk::Widget {
    let setting_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(sanitize_scanner_line(&config_setting.setting_key))
        .subtitle(sanitize_scanner_line(&config_setting.setting_value))
        .subtitle_selectable(true)
        .build();
    setting_row.add_suffix(&lock_indicator(&gettext(
        "This setting runs commands or changes who ClamAV runs as, so ClamUI never offers to \
         change it",
    )));
    setting_row.upcast()
}

fn show_toast_near(shown_widget: &impl IsA<gtk::Widget>, toast_text: &str) {
    let shown_toast = adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build();
    if let Some(toast_overlay) = shown_widget
        .ancestor(adw::ToastOverlay::static_type())
        .and_downcast::<adw::ToastOverlay>()
    {
        toast_overlay.add_toast(shown_toast);
    } else if let Some(preferences_dialog) = shown_widget
        .ancestor(adw::PreferencesDialog::static_type())
        .and_downcast::<adw::PreferencesDialog>()
    {
        preferences_dialog.add_toast(shown_toast);
    }
}

fn show_snippet_copied(edited_row: &adw::EntryRow, copied_snippet: &str) {
    edited_row.clipboard().set_text(copied_snippet);
    show_toast_near(
        edited_row,
        &gettext("Copied. Add it to your configuration to apply it."),
    );
}

#[derive(Clone)]
struct LiveTuningControls {
    unlock_toggle: gtk::ToggleButton,
    tuning_state: Rc<RefCell<LiveTuningState>>,
    drift_display: Rc<RefCell<Vec<DriftDisplay>>>,
}

#[derive(Clone)]
struct DriftDisplay {
    drift_row: adw::ActionRow,
    drift_snippet: Rc<RefCell<String>>,
    config_kind: ClamavConfigKind,
}

fn refresh_drift_displays(drift_displays: &[DriftDisplay], active_overrides: &[(String, String)]) {
    drift_displays.iter().for_each(|drift_display| {
        let refreshed_snippet = drift_snippet_text(
            active_overrides,
            drift_display.config_kind,
            ConfigFileOwner::NixOsConfiguration,
        );
        drift_display
            .drift_row
            .set_subtitle(&sanitize_scanner_text(&refreshed_snippet));
        drift_display
            .drift_row
            .set_visible(!refreshed_snippet.is_empty());
        *drift_display.drift_snippet.borrow_mut() = refreshed_snippet;
    });
}

impl LiveTuningControls {
    fn offers_live_changes(&self) -> bool {
        !self.tuning_state.borrow().tunable_settings.is_empty()
    }

    fn current_setting_values(
        &self,
        setting_key: &str,
        configured_values: &[String],
    ) -> Vec<String> {
        let overridden_values = self
            .tuning_state
            .borrow()
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

    fn allows_live_change(&self, setting_key: &str) -> bool {
        self.unlock_toggle.is_active()
            && self
                .tuning_state
                .borrow()
                .tunable_settings
                .iter()
                .any(|tunable_key| tunable_key == setting_key)
    }
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

fn confirm_live_change(
    edited_row: &adw::EntryRow,
    setting_key: String,
    current_values: Vec<String>,
    new_values: Vec<String>,
    live_tuning: LiveTuningControls,
) {
    let effect = change_effect(&setting_key, &current_values, &new_values);
    let confirmation_dialog = adw::AlertDialog::new(
        Some(&gettext("Change this setting?")),
        Some(&change_confirmation_text(
            &setting_key,
            &current_values,
            &new_values,
            effect,
        )),
    );
    confirmation_dialog.add_response("cancel", &gettext("Cancel"));
    confirmation_dialog.add_response(
        "apply",
        &if effect == ChangeEffect::WeakensProtection {
            gettext("Reduce Protection")
        } else {
            gettext("Apply")
        },
    );
    if effect == ChangeEffect::WeakensProtection {
        confirmation_dialog.set_response_appearance("apply", adw::ResponseAppearance::Destructive);
    }
    confirmation_dialog.set_default_response(Some("cancel"));
    confirmation_dialog.set_close_response("cancel");
    let answered_row = edited_row.clone();
    confirmation_dialog.connect_response(Some("apply"), move |_dialog, _response| {
        let applying_row = answered_row.clone();
        let applied_key = setting_key.clone();
        let applied_values = new_values.clone();
        let refreshed_live_tuning = live_tuning.clone();
        relm4::spawn_local(async move {
            let applying_spinner = adw::Spinner::builder()
                .tooltip_text(gettext("Applying, and restarting ClamAV"))
                .build();
            applying_row.add_suffix(&applying_spinner);
            applying_row.set_sensitive(false);
            let change_outcome = relm4::spawn(apply_live_change(applied_key, applied_values)).await;
            applying_row.remove(&applying_spinner);
            applying_row.set_sensitive(true);
            show_toast_near(
                &applying_row,
                &change_outcome.map_or_else(
                    |task_failure| task_failure.to_string(),
                    |change_outcome| describe_live_change_outcome(&change_outcome),
                ),
            );
            if let Ok(refreshed_state) = relm4::spawn(read_live_tuning_state()).await {
                refresh_drift_displays(
                    &refreshed_live_tuning.drift_display.borrow(),
                    &refreshed_state.active_overrides,
                );
                *refreshed_live_tuning.tuning_state.borrow_mut() = refreshed_state;
            }
        });
    });
    confirmation_dialog.present(Some(edited_row));
}

fn live_tuning_group(unlock_toggle: &gtk::ToggleButton) -> adw::PreferencesGroup {
    let tuning_group = adw::PreferencesGroup::builder()
        .title(gettext("Change Settings"))
        .description(gettext(
            "Unlock to change the settings your system allows at runtime. Unlocking grants \
             nothing by itself: each change shows what will happen and asks for administrator \
             authorization. It locks again after two minutes.",
        ))
        .visible(false)
        .build();
    tuning_group.set_header_suffix(Some(unlock_toggle));
    tuning_group
}

fn drift_snippet_text(
    active_overrides: &[(String, String)],
    config_kind: ClamavConfigKind,
    config_file_owner: ConfigFileOwner,
) -> String {
    let mut override_keys = active_overrides
        .iter()
        .map(|active_override| active_override.0.as_str())
        .collect::<Vec<_>>();
    override_keys.dedup();
    override_keys
        .iter()
        .map(|override_key| {
            let override_values = active_overrides
                .iter()
                .filter(|active_override| active_override.0 == *override_key)
                .map(|active_override| active_override.1.clone())
                .collect::<Vec<_>>();
            change_snippet(
                config_file_owner,
                config_kind,
                override_key,
                &override_values,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn drift_snippet_row(drift_snippet: Rc<RefCell<String>>) -> adw::ActionRow {
    let drift_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(gettext(
            "Changes your system configuration doesn't know about",
        ))
        .subtitle(sanitize_scanner_text(&drift_snippet.borrow()))
        .subtitle_selectable(true)
        .subtitle_lines(0)
        .visible(!drift_snippet.borrow().is_empty())
        .build();
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(gettext("Copy"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    copy_button.connect_clicked(move |clicked_button| {
        clicked_button.clipboard().set_text(&drift_snippet.borrow());
    });
    drift_row.add_suffix(&copy_button);
    drift_row
}

fn values_with_edit(
    setting_values: &[String],
    value_position: usize,
    edited_text: String,
) -> Vec<String> {
    let mut edited_values = setting_values.to_vec();
    if let Some(edited_value) = edited_values.get_mut(value_position) {
        *edited_value = edited_text;
    }
    edited_values
}

fn snippet_setting_row(
    config_setting: &ConfigSetting,
    sibling_values: Vec<String>,
    value_position: usize,
    config_kind: ClamavConfigKind,
    config_file_owner: ConfigFileOwner,
    live_tuning: Option<LiveTuningControls>,
) -> gtk::Widget {
    let setting_key = sanitize_scanner_line(&config_setting.setting_key);
    let setting_row = adw::EntryRow::builder()
        .title(&setting_key)
        .text(sanitize_scanner_line(&config_setting.setting_value))
        .show_apply_button(true)
        .build();
    setting_row.add_suffix(&lock_indicator(&gettext(
        "Managed outside ClamUI. Unless the setting is unlocked, applying copies the change \
         instead of making it.",
    )));
    setting_row.connect_apply(move |edited_row| {
        let edited_text = sanitize_scanner_line(&edited_row.text());
        if let Some(live_tuning) = live_tuning
            .as_ref()
            .filter(|live_tuning| live_tuning.allows_live_change(&setting_key))
        {
            let current_values = live_tuning.current_setting_values(&setting_key, &sibling_values);
            let new_values = values_with_edit(&current_values, value_position, edited_text);
            confirm_live_change(
                edited_row,
                setting_key.clone(),
                current_values,
                new_values,
                live_tuning.clone(),
            );
        } else {
            show_snippet_copied(
                edited_row,
                &change_snippet(
                    config_file_owner,
                    config_kind,
                    &setting_key,
                    &values_with_edit(&sibling_values, value_position, edited_text),
                ),
            );
        }
    });
    setting_row.upcast()
}

fn live_tunable_config_description(config_path: &str) -> String {
    gettext(
        "{path} combines your system configuration with the changes made here. While locked, \
         editing a value and pressing the check mark copies the line for your configuration. \
         After unlocking, the allowed settings change directly.",
    )
    .replace("{path}", config_path)
}

fn host_config_page(
    page_title: String,
    page_icon: &str,
    group_title: String,
    config_kind: ClamavConfigKind,
    host_config: HostConfigView,
    live_tuning: Option<LiveTuningControls>,
    shows_setting: impl Fn(&ConfigSetting) -> bool,
) -> adw::PreferencesPage {
    let config_page = adw::PreferencesPage::builder()
        .title(page_title)
        .icon_name(page_icon)
        .build();
    let config_group = adw::PreferencesGroup::builder().title(group_title).build();
    match host_config {
        HostConfigView::ConfigFound {
            config_path,
            config_settings,
        } => {
            let config_file_owner = inspect_config_file_owner(std::path::Path::new(&config_path));
            let config_description = if live_tuning
                .as_ref()
                .is_some_and(LiveTuningControls::offers_live_changes)
            {
                live_tunable_config_description(&config_path)
            } else {
                managed_config_description(config_file_owner, &config_path)
            };
            config_group.set_description(Some(&glib::markup_escape_text(&config_description)));
            let shown_settings = config_settings
                .iter()
                .filter(|config_setting| shows_setting(config_setting))
                .collect::<Vec<_>>();
            if shown_settings.is_empty() {
                config_group.add(
                    &adw::ActionRow::builder()
                        .title(gettext("No settings in this section"))
                        .build(),
                );
            }
            shown_settings.iter().for_each(|config_setting| {
                let setting_row = match setting_lock_for_key(&config_setting.setting_key) {
                    SettingLock::NeverChangedHere => protected_setting_row(config_setting),
                    SettingLock::ChangedThroughSnippet => {
                        let same_key_settings = shown_settings
                            .iter()
                            .filter(|other_setting| {
                                other_setting.setting_key == config_setting.setting_key
                            })
                            .collect::<Vec<_>>();
                        let value_position = same_key_settings
                            .iter()
                            .position(|same_key_setting| {
                                std::ptr::eq(**same_key_setting, *config_setting)
                            })
                            .unwrap_or_default();
                        snippet_setting_row(
                            config_setting,
                            same_key_settings
                                .iter()
                                .map(|same_key_setting| {
                                    sanitize_scanner_line(&same_key_setting.setting_value)
                                })
                                .collect(),
                            value_position,
                            config_kind,
                            config_file_owner,
                            live_tuning.clone(),
                        )
                    }
                };
                config_group.add(&setting_row);
            });
        }
        HostConfigView::ConfigNotFound => {
            config_group.add(
                &adw::ActionRow::builder()
                    .title(gettext("Configuration file not found"))
                    .build(),
            );
        }
    }
    if let Some(live_tuning) = &live_tuning {
        let tuning_group = live_tuning_group(&live_tuning.unlock_toggle);
        let tuning_state = live_tuning.tuning_state.borrow();
        tuning_group.set_visible(!tuning_state.tunable_settings.is_empty());
        let drift_snippet = Rc::new(RefCell::new(drift_snippet_text(
            &tuning_state.active_overrides,
            config_kind,
            ConfigFileOwner::NixOsConfiguration,
        )));
        let drift_row = drift_snippet_row(Rc::clone(&drift_snippet));
        tuning_group.add(&drift_row);
        live_tuning.drift_display.borrow_mut().push(DriftDisplay {
            drift_row,
            drift_snippet,
            config_kind,
        });
        config_page.add(&tuning_group);
    }
    config_page.add(&config_group);
    config_page
}

fn new_unlock_toggle() -> gtk::ToggleButton {
    let unlock_toggle = gtk::ToggleButton::builder()
        .label(gettext("Unlock"))
        .valign(gtk::Align::Center)
        .build();
    unlock_toggle.connect_toggled(|toggled_button| {
        toggled_button.set_label(&if toggled_button.is_active() {
            gettext("Lock")
        } else {
            gettext("Unlock")
        });
        if toggled_button.is_active() {
            let relocked_button = toggled_button.downgrade();
            glib::timeout_add_seconds_local_once(UNLOCK_SECONDS, move || {
                if let Some(relocked_button) = relocked_button.upgrade() {
                    relocked_button.set_active(false);
                }
            });
        }
    });
    unlock_toggle
}

fn live_tuning_controls(tuning_state: LiveTuningState) -> LiveTuningControls {
    LiveTuningControls {
        unlock_toggle: new_unlock_toggle(),
        tuning_state: Rc::new(RefCell::new(tuning_state)),
        drift_display: Rc::new(RefCell::new(Vec::new())),
    }
}

pub fn engine_settings_page(
    settings_section: EngineSettingsSection,
    tuning_state: LiveTuningState,
) -> adw::PreferencesPage {
    match settings_section {
        EngineSettingsSection::ScannerEngine => host_config_page(
            gettext("Scanner Engine"),
            "system-search-symbolic",
            gettext("clamd settings"),
            ClamavConfigKind::ClamdDaemonConfig,
            read_clamd_config(),
            Some(live_tuning_controls(tuning_state)),
            |config_setting| !is_on_access_setting(config_setting),
        ),
        EngineSettingsSection::OnAccessScanning => host_config_page(
            gettext("On-Access Scanning"),
            "security-high-symbolic",
            gettext("On-access scanning settings"),
            ClamavConfigKind::ClamdDaemonConfig,
            read_clamd_config(),
            Some(live_tuning_controls(tuning_state)),
            is_on_access_setting,
        ),
        EngineSettingsSection::SignatureUpdates => host_config_page(
            gettext("Signature Updates"),
            "drive-harddisk-symbolic",
            gettext("freshclam settings"),
            ClamavConfigKind::FreshclamUpdaterConfig,
            read_freshclam_config(),
            None,
            |_config_setting| true,
        ),
    }
}

pub async fn current_live_tuning_state() -> LiveTuningState {
    relm4::spawn(read_live_tuning_state())
        .await
        .unwrap_or_default()
}
