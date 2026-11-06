use relm4::gtk::{gio, gio::prelude::SettingsExtManual, prelude::*};

use crate::{
    SETTINGS_SCHEMA_ID,
    application_settings::scan_exclusion_rules::{ExclusionEntry, ExclusionKind},
    malware_scan::scanner_command_builder::ScannerBackendPreference,
};

pub const EXCLUSION_RULES_KEY: &str = "exclusion-rules";
pub const SCAN_BACKEND_KEY: &str = "scan-backend";
pub const SHOW_LIVE_PROGRESS_KEY: &str = "show-live-progress";
pub const SCAN_BACKEND_CHOICES: [&str; 3] = ["auto", "clamd", "clamscan"];
pub const CLOSE_ACTION_KEY: &str = "close-action";
pub const CLOSE_ACTION_CHOICES: [&str; 3] = ["quit", "minimize", "ask"];

pub fn application_settings() -> gio::Settings {
    gio::Settings::new(SETTINGS_SCHEMA_ID)
}

pub fn settings_schema_is_installed() -> bool {
    gio::SettingsSchemaSource::default()
        .and_then(|schema_source| schema_source.lookup(SETTINGS_SCHEMA_ID, true))
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

pub fn set_entry_enabled(settings: &gio::Settings, changed_pattern: &str, is_enabled: bool) {
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

pub fn remove_exclusion_entry(settings: &gio::Settings, removed_pattern: &str) {
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
