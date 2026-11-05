use gettextrs::gettext;
use relm4::{
    adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual, glib},
};

use crate::{
    APPLICATION_ID,
    application_settings::scan_exclusion_rules::{
        ExclusionEntry, ExclusionKind, PRESET_DIRECTORY_NAMES,
    },
    malware_scan::{
        scanner_command_builder::ScannerBackendPreference,
        scanner_output_parser::sanitize_scanner_line,
    },
};

const EXCLUSION_RULES_KEY: &str = "exclusion-rules";
const SCAN_BACKEND_KEY: &str = "scan-backend";
pub const SHOW_LIVE_PROGRESS_KEY: &str = "show-live-progress";
const SCAN_BACKEND_CHOICES: [&str; 3] = ["auto", "clamd", "clamscan"];

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
    preferences_dialog.present(relm4::main_application().active_window().as_ref());
}
