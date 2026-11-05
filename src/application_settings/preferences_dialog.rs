use gettextrs::gettext;
use relm4::{
    Component, ComponentController, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual, glib},
};

use crate::{
    APPLICATION_ID,
    application_settings::{
        clamav_host_config::{
            ConfigSetting, HostConfigView, is_on_access_setting, read_clamd_config,
            read_freshclam_config,
        },
        scan_exclusion_rules::{ExclusionEntry, ExclusionKind, PRESET_DIRECTORY_NAMES},
        setting_provenance::{
            ClamavConfigKind, ConfigFileOwner, SettingLock, change_snippet,
            inspect_config_file_owner, managed_config_description, setting_lock_for_key,
        },
    },
    desktop_integration::{
        device_mount_scans::{
            DEVICE_SCAN_ENABLED_KEY, DEVICE_SCAN_MAX_GIGABYTES_KEY, DEVICE_SCAN_SKIP_BATTERY_KEY,
        },
        file_manager_actions::{
            SUPPORTED_FILE_MANAGERS, file_manager_action_installed, install_file_manager_action,
            remove_file_manager_action,
        },
    },
    malware_scan::{
        scanner_command_builder::ScannerBackendPreference,
        scanner_output_parser::sanitize_scanner_line,
    },
    scheduled_scans::{
        scan_schedule_units::current_launcher_path,
        schedule_preferences_page::SchedulePreferencesPage,
    },
    virustotal_lookup::virustotal_preferences_page::VirusTotalPreferencesPage,
};

const EXCLUSION_RULES_KEY: &str = "exclusion-rules";
const SCAN_BACKEND_KEY: &str = "scan-backend";
pub const SHOW_LIVE_PROGRESS_KEY: &str = "show-live-progress";
const SCAN_BACKEND_CHOICES: [&str; 3] = ["auto", "clamd", "clamscan"];
pub const CLOSE_ACTION_KEY: &str = "close-action";
const CLOSE_ACTION_CHOICES: [&str; 3] = ["quit", "minimize", "ask"];

pub fn application_settings() -> gio::Settings {
    gio::Settings::new(APPLICATION_ID)
}

pub fn settings_schema_is_installed() -> bool {
    gio::SettingsSchemaSource::default()
        .and_then(|schema_source| schema_source.lookup(APPLICATION_ID, true))
        .is_some()
}

pub fn read_exclusion_entries(settings: &gio::Settings) -> Vec<ExclusionEntry> {
    settings
        .get::<Vec<(String, String, bool)>>(EXCLUSION_RULES_KEY)
        .into_iter()
        .map(|stored_rule| ExclusionEntry {
            exclusion_pattern: stored_rule.0,
            exclusion_kind: ExclusionKind::from_stored_text(&stored_rule.1),
            is_enabled: stored_rule.2,
        })
        .collect()
}

fn write_exclusion_entries(settings: &gio::Settings, exclusion_entries: &[ExclusionEntry]) {
    let stored_rules = exclusion_entries
        .iter()
        .map(|exclusion_entry| {
            (
                exclusion_entry.exclusion_pattern.clone(),
                exclusion_entry.exclusion_kind.stored_text().to_owned(),
                exclusion_entry.is_enabled,
            )
        })
        .collect::<Vec<_>>();
    let _read_only_settings = settings.set(EXCLUSION_RULES_KEY, stored_rules);
}

pub fn add_exclusion_entry(settings: &gio::Settings, added_entry: ExclusionEntry) -> bool {
    let mut exclusion_entries = read_exclusion_entries(settings);
    if exclusion_entries
        .iter()
        .any(|exclusion_entry| exclusion_entry.exclusion_pattern == added_entry.exclusion_pattern)
    {
        return false;
    }
    exclusion_entries.push(added_entry);
    write_exclusion_entries(settings, &exclusion_entries);
    true
}

fn set_entry_enabled(settings: &gio::Settings, changed_pattern: &str, is_enabled: bool) {
    let exclusion_entries = read_exclusion_entries(settings)
        .into_iter()
        .map(|exclusion_entry| {
            if exclusion_entry.exclusion_pattern == changed_pattern {
                ExclusionEntry {
                    is_enabled,
                    ..exclusion_entry
                }
            } else {
                exclusion_entry
            }
        })
        .collect::<Vec<_>>();
    write_exclusion_entries(settings, &exclusion_entries);
}

fn remove_exclusion_entry(settings: &gio::Settings, removed_pattern: &str) {
    let exclusion_entries = read_exclusion_entries(settings)
        .into_iter()
        .filter(|exclusion_entry| exclusion_entry.exclusion_pattern != removed_pattern)
        .collect::<Vec<_>>();
    write_exclusion_entries(settings, &exclusion_entries);
}

pub fn scanner_backend_preference(settings: &gio::Settings) -> ScannerBackendPreference {
    match settings.string(SCAN_BACKEND_KEY).as_str() {
        "clamd" => ScannerBackendPreference::AlwaysClamd,
        "clamscan" => ScannerBackendPreference::AlwaysClamscan,
        _automatic => ScannerBackendPreference::PreferClamdWhenAvailable,
    }
}

fn is_preset_pattern(exclusion_pattern: &str) -> bool {
    PRESET_DIRECTORY_NAMES.contains(&exclusion_pattern)
}

fn preset_description(exclusion_pattern: &str) -> String {
    match exclusion_pattern {
        "node_modules" => gettext("Node.js dependencies"),
        ".git" => gettext("Git repository data"),
        ".venv" => gettext("Python virtual environment"),
        "build" => gettext("Build output directory"),
        "dist" => gettext("Distribution output directory"),
        "__pycache__" => gettext("Python bytecode cache"),
        _other_pattern => String::new(),
    }
}

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

fn show_snippet_copied(edited_row: &adw::EntryRow, copied_snippet: &str) {
    edited_row.clipboard().set_text(copied_snippet);
    if let Some(preferences_dialog) = edited_row
        .ancestor(adw::PreferencesDialog::static_type())
        .and_downcast::<adw::PreferencesDialog>()
    {
        preferences_dialog.add_toast(adw::Toast::new(&gettext(
            "Copied. Add it to your configuration to apply it.",
        )));
    }
}

fn snippet_setting_row(
    config_setting: &ConfigSetting,
    sibling_values: Vec<String>,
    value_position: usize,
    config_kind: ClamavConfigKind,
    config_file_owner: ConfigFileOwner,
) -> gtk::Widget {
    let setting_key = sanitize_scanner_line(&config_setting.setting_key);
    let setting_row = adw::EntryRow::builder()
        .title(&setting_key)
        .text(sanitize_scanner_line(&config_setting.setting_value))
        .show_apply_button(true)
        .build();
    setting_row.add_suffix(&lock_indicator(&gettext(
        "Managed outside ClamUI. Applying copies the change instead of making it.",
    )));
    setting_row.connect_apply(move |edited_row| {
        let mut edited_values = sibling_values.clone();
        if let Some(edited_value) = edited_values.get_mut(value_position) {
            *edited_value = sanitize_scanner_line(&edited_row.text());
        }
        show_snippet_copied(
            edited_row,
            &change_snippet(config_file_owner, config_kind, &setting_key, &edited_values),
        );
    });
    setting_row.upcast()
}

fn host_config_page(
    page_title: String,
    page_icon: &str,
    group_title: String,
    config_kind: ClamavConfigKind,
    host_config: HostConfigView,
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
            config_group.set_description(Some(&glib::markup_escape_text(
                &managed_config_description(config_file_owner, &config_path),
            )));
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
    config_page.add(&config_group);
    config_page
}

fn file_manager_group() -> adw::PreferencesGroup {
    let integration_group = adw::PreferencesGroup::builder()
        .title(gettext("File Manager Integration"))
        .description(gettext(
            "Add context menu actions for supported file managers.",
        ))
        .build();
    SUPPORTED_FILE_MANAGERS.iter().for_each(|file_manager| {
        let file_manager = *file_manager;
        let data_directory = glib::user_data_dir();
        let manager_row = adw::SwitchRow::builder()
            .title(file_manager.displayed_name())
            .active(file_manager_action_installed(file_manager, &data_directory))
            .build();
        manager_row.connect_active_notify(move |changed_row| {
            let change_outcome = if changed_row.is_active() {
                current_launcher_path().and_then(|launcher_path| {
                    install_file_manager_action(file_manager, &data_directory, &launcher_path)
                })
            } else {
                remove_file_manager_action(file_manager, &data_directory)
            };
            changed_row.set_subtitle(&change_outcome.map_or_else(
                |change_failure| change_failure.to_string(),
                |()| String::new(),
            ));
        });
        integration_group.add(&manager_row);
    });
    integration_group
}

fn device_scan_group(settings: &gio::Settings) -> adw::PreferencesGroup {
    let device_group = adw::PreferencesGroup::builder()
        .title(gettext("Device Auto-Scan"))
        .description(gettext(
            "Automatically scan removable and external drives when they are connected.",
        ))
        .build();
    let enabled_row = adw::SwitchRow::builder()
        .title(gettext("Enable Device Auto-Scan"))
        .build();
    settings
        .bind(DEVICE_SCAN_ENABLED_KEY, &enabled_row, "active")
        .build();
    device_group.add(&enabled_row);
    let size_row = adw::SpinRow::builder()
        .title(gettext("Max Device Size (GB)"))
        .subtitle(gettext("0 means no size limit."))
        .adjustment(&gtk::Adjustment::new(32.0, 0.0, 10_000.0, 1.0, 10.0, 0.0))
        .build();
    settings
        .bind(DEVICE_SCAN_MAX_GIGABYTES_KEY, &size_row, "value")
        .mapping(|stored_value, _value_type| {
            stored_value
                .get::<u32>()
                .map(|maximum_gigabytes| f64::from(maximum_gigabytes).to_value())
        })
        .set_mapping(|spin_value, _variant_type| {
            spin_value
                .get::<f64>()
                .ok()
                .map(|maximum_gigabytes| (maximum_gigabytes as u32).to_variant())
        })
        .build();
    device_group.add(&size_row);
    let battery_row = adw::SwitchRow::builder()
        .title(gettext("Skip on Battery"))
        .build();
    settings
        .bind(DEVICE_SCAN_SKIP_BATTERY_KEY, &battery_row, "active")
        .build();
    device_group.add(&battery_row);
    device_group
}

fn window_group(settings: &gio::Settings) -> adw::PreferencesGroup {
    let window_group = adw::PreferencesGroup::builder()
        .title(gettext("Window Behavior"))
        .description(gettext(
            "Running in the background needs a desktop with a system tray.",
        ))
        .build();
    let close_labels = [
        gettext("Quit completely"),
        gettext("Minimize to tray"),
        gettext("Always ask"),
    ];
    let close_row = adw::ComboRow::builder()
        .title(gettext("When closing window"))
        .model(&gtk::StringList::new(
            &close_labels.iter().map(String::as_str).collect::<Vec<_>>(),
        ))
        .selected(
            CLOSE_ACTION_CHOICES
                .iter()
                .position(|close_choice| *close_choice == settings.string(CLOSE_ACTION_KEY))
                .unwrap_or(0) as u32,
        )
        .build();
    let close_settings = settings.clone();
    close_row.connect_selected_notify(move |changed_row| {
        if let Some(close_choice) = CLOSE_ACTION_CHOICES.get(changed_row.selected() as usize) {
            let _read_only_settings = close_settings.set_string(CLOSE_ACTION_KEY, close_choice);
        }
    });
    window_group.add(&close_row);
    let background_row = adw::SwitchRow::builder()
        .title(gettext("Start in System Tray"))
        .subtitle(gettext(
            "Launch in the background and show only the tray icon.",
        ))
        .build();
    settings
        .bind("start-in-background", &background_row, "active")
        .build();
    window_group.add(&background_row);
    let notifications_row = adw::SwitchRow::builder()
        .title(gettext("Desktop Notifications"))
        .subtitle(gettext(
            "Notify about finished scans and updates while the window is not in focus.",
        ))
        .build();
    settings
        .bind("notifications-enabled", &notifications_row, "active")
        .build();
    window_group.add(&notifications_row);
    window_group
}

fn behavior_page(settings: &gio::Settings) -> adw::PreferencesPage {
    let behavior_page = adw::PreferencesPage::builder()
        .title(gettext("Behavior"))
        .icon_name("preferences-system-symbolic")
        .build();
    let scan_group = adw::PreferencesGroup::builder()
        .title(gettext("Scan Behavior"))
        .description(gettext("Configure how scans run and are displayed"))
        .build();
    let live_progress_row = adw::SwitchRow::builder()
        .title(gettext("Show Live Scan Progress"))
        .subtitle(gettext("Display files being scanned in real time."))
        .build();
    settings
        .bind(SHOW_LIVE_PROGRESS_KEY, &live_progress_row, "active")
        .build();
    scan_group.add(&live_progress_row);
    let backend_labels = [
        gettext("Automatic"),
        gettext("clamd (daemon)"),
        gettext("clamscan (standalone)"),
    ];
    let backend_row = adw::ComboRow::builder()
        .title(gettext("Scan Backend"))
        .subtitle(gettext(
            "Automatic uses the daemon when it answers and clamscan otherwise.",
        ))
        .model(&gtk::StringList::new(
            &backend_labels
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
        .selected(
            SCAN_BACKEND_CHOICES
                .iter()
                .position(|backend_choice| *backend_choice == settings.string(SCAN_BACKEND_KEY))
                .unwrap_or(0) as u32,
        )
        .build();
    let backend_settings = settings.clone();
    backend_row.connect_selected_notify(move |changed_row| {
        if let Some(backend_choice) = SCAN_BACKEND_CHOICES.get(changed_row.selected() as usize) {
            let _read_only_settings = backend_settings.set_string(SCAN_BACKEND_KEY, backend_choice);
        }
    });
    scan_group.add(&backend_row);
    behavior_page.add(&scan_group);
    behavior_page.add(&window_group(settings));
    behavior_page.add(&device_scan_group(settings));
    behavior_page.add(&file_manager_group());
    behavior_page
}

fn preset_exclusion_row(
    settings: &gio::Settings,
    exclusion_entry: &ExclusionEntry,
) -> adw::SwitchRow {
    let preset_row = adw::SwitchRow::builder()
        .title(&exclusion_entry.exclusion_pattern)
        .subtitle(preset_description(&exclusion_entry.exclusion_pattern))
        .use_markup(false)
        .active(exclusion_entry.is_enabled)
        .build();
    let row_settings = settings.clone();
    let row_pattern = exclusion_entry.exclusion_pattern.clone();
    preset_row.connect_active_notify(move |changed_row| {
        set_entry_enabled(&row_settings, &row_pattern, changed_row.is_active());
    });
    preset_row
}

fn custom_exclusion_row(
    settings: &gio::Settings,
    exclusion_entry: &ExclusionEntry,
) -> adw::SwitchRow {
    let custom_row = adw::SwitchRow::builder()
        .title(sanitize_scanner_line(&exclusion_entry.exclusion_pattern))
        .use_markup(false)
        .active(exclusion_entry.is_enabled)
        .build();
    let toggle_settings = settings.clone();
    let toggle_pattern = exclusion_entry.exclusion_pattern.clone();
    custom_row.connect_active_notify(move |changed_row| {
        set_entry_enabled(&toggle_settings, &toggle_pattern, changed_row.is_active());
    });
    let remove_button = gtk::Button::builder()
        .icon_name("user-trash-symbolic")
        .tooltip_text(gettext("Remove"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let remove_settings = settings.clone();
    let remove_pattern = exclusion_entry.exclusion_pattern.clone();
    remove_button.connect_clicked(move |_clicked_button| {
        remove_exclusion_entry(&remove_settings, &remove_pattern);
    });
    custom_row.add_suffix(&remove_button);
    custom_row
}

fn refill_exclusion_group(
    settings: &gio::Settings,
    preset_list: &gtk::ListBox,
    custom_list: &gtk::ListBox,
) {
    preset_list.remove_all();
    custom_list.remove_all();
    read_exclusion_entries(settings)
        .iter()
        .for_each(|exclusion_entry| {
            if is_preset_pattern(&exclusion_entry.exclusion_pattern) {
                preset_list.append(&preset_exclusion_row(settings, exclusion_entry));
            } else {
                custom_list.append(&custom_exclusion_row(settings, exclusion_entry));
            }
        });
}

fn exclusions_page(settings: &gio::Settings) -> adw::PreferencesPage {
    let exclusions_page = adw::PreferencesPage::builder()
        .title(gettext("Exclusions"))
        .icon_name("action-unavailable-symbolic")
        .build();
    let preset_list = gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .build();
    let custom_list = gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .build();
    let preset_group = adw::PreferencesGroup::builder()
        .description(gettext(
            "These apply to scans started from ClamUI. They don't change what on-access scanning \
             or a system scan timer checks.",
        ))
        .title(gettext("Preset Exclusions"))
        .description(gettext(
            "Common directories to exclude from scanning. Changes save immediately.",
        ))
        .build();
    preset_group.add(&preset_list);
    let custom_group = adw::PreferencesGroup::builder()
        .title(gettext("Custom Exclusions"))
        .description(gettext(
            "Enter an absolute path or a pattern such as *.tmp. Changes save immediately.",
        ))
        .build();
    let add_row = adw::EntryRow::builder()
        .title(gettext("/path/to/exclude or *.tmp"))
        .show_apply_button(true)
        .build();
    let add_settings = settings.clone();
    add_row.connect_apply(move |applied_row| {
        let added_pattern = applied_row.text().trim().to_owned();
        if !added_pattern.is_empty() {
            add_exclusion_entry(
                &add_settings,
                ExclusionEntry::enabled_pattern(added_pattern),
            );
            applied_row.set_text("");
        }
    });
    let add_list = gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .margin_bottom(12)
        .build();
    add_list.append(&add_row);
    custom_group.add(&add_list);
    custom_group.add(&custom_list);
    refill_exclusion_group(settings, &preset_list, &custom_list);
    let refill_preset_list = preset_list.clone();
    let refill_custom_list = custom_list.clone();
    settings.connect_changed(Some(EXCLUSION_RULES_KEY), move |changed_settings, _key| {
        let changed_settings = changed_settings.clone();
        let refill_preset_list = refill_preset_list.clone();
        let refill_custom_list = refill_custom_list.clone();
        glib::idle_add_local_once(move || {
            refill_exclusion_group(&changed_settings, &refill_preset_list, &refill_custom_list);
        });
    });
    exclusions_page.add(&preset_group);
    exclusions_page.add(&custom_group);
    exclusions_page
}

pub fn present_preferences_dialog() {
    let settings = application_settings();
    let preferences_dialog = adw::PreferencesDialog::builder()
        .title(gettext("Preferences"))
        .search_enabled(true)
        .build();
    preferences_dialog.add(&behavior_page(&settings));
    preferences_dialog.add(&exclusions_page(&settings));
    let schedule_page = SchedulePreferencesPage::builder().launch(()).detach();
    preferences_dialog.add(schedule_page.widget());
    preferences_dialog.add(&host_config_page(
        gettext("Database"),
        "drive-harddisk-symbolic",
        gettext("freshclam settings"),
        ClamavConfigKind::FreshclamUpdaterConfig,
        read_freshclam_config(),
        |_config_setting| true,
    ));
    let clamd_config = read_clamd_config();
    preferences_dialog.add(&host_config_page(
        gettext("Scanner"),
        "system-search-symbolic",
        gettext("clamd settings"),
        ClamavConfigKind::ClamdDaemonConfig,
        clamd_config.clone(),
        |config_setting| !is_on_access_setting(config_setting),
    ));
    preferences_dialog.add(&host_config_page(
        gettext("On-Access"),
        "security-high-symbolic",
        gettext("On-access scanning settings"),
        ClamavConfigKind::ClamdDaemonConfig,
        clamd_config,
        is_on_access_setting,
    ));
    let virustotal_page = VirusTotalPreferencesPage::builder().launch(()).detach();
    preferences_dialog.add(virustotal_page.widget());
    preferences_dialog.connect_closed(move |_closed_dialog| {
        let _keep_pages_until_closed = (&schedule_page, &virustotal_page);
    });
    preferences_dialog.present(relm4::main_application().active_window().as_ref());
}
