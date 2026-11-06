use relm4::gtk::{gio, gio::prelude::SettingsExtManual, prelude::*};

use crate::{
    SETTINGS_SCHEMA_ID,
    host_services::clamav_scanner::{
        scan_exclusion_rules::{ExclusionEntry, ExclusionKind},
        scanner_command_builder::ScannerBackendPreference,
    },
};

pub const EXCLUSION_RULES_KEY: &str = "exclusion-rules";
pub const SCAN_BACKEND_KEY: &str = "scan-backend";
pub const SHOW_LIVE_PROGRESS_KEY: &str = "show-live-progress";
pub const SCAN_BACKEND_CHOICES: [ScannerBackendPreference; 3] = [
    ScannerBackendPreference::PreferClamdWhenAvailable,
    ScannerBackendPreference::AlwaysClamd,
    ScannerBackendPreference::AlwaysClamscan,
];
const SCHEMA_DEFAULT_SCAN_BACKEND: ScannerBackendPreference =
    ScannerBackendPreference::PreferClamdWhenAvailable;
pub const CLOSE_ACTION_KEY: &str = "close-action";

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
        .map(
            |(exclusion_pattern, stored_kind_text, is_enabled)| ExclusionEntry {
                exclusion_pattern,
                exclusion_kind: ExclusionKind::from_stored_text(&stored_kind_text),
                is_enabled,
            },
        )
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

impl ScannerBackendPreference {
    pub const fn stored_text(self) -> &'static str {
        match self {
            Self::PreferClamdWhenAvailable => "auto",
            Self::AlwaysClamd => "clamd",
            Self::AlwaysClamscan => "clamscan",
        }
    }

    pub const fn choice_position(self) -> u32 {
        match self {
            Self::PreferClamdWhenAvailable => 0,
            Self::AlwaysClamd => 1,
            Self::AlwaysClamscan => 2,
        }
    }

    pub fn from_choice_position(choice_position: u32) -> Option<Self> {
        usize::try_from(choice_position)
            .ok()
            .and_then(|choice_index| SCAN_BACKEND_CHOICES.get(choice_index))
            .copied()
    }

    fn from_stored_text(stored_text: &str) -> Option<Self> {
        SCAN_BACKEND_CHOICES
            .into_iter()
            .find(|backend_choice| backend_choice.stored_text() == stored_text)
    }

    pub fn store_into(self, settings: &gio::Settings) {
        let _read_only_settings = settings.set_string(SCAN_BACKEND_KEY, self.stored_text());
    }
}

pub fn scanner_backend_preference(settings: &gio::Settings) -> ScannerBackendPreference {
    ScannerBackendPreference::from_stored_text(&settings.string(SCAN_BACKEND_KEY))
        .unwrap_or(SCHEMA_DEFAULT_SCAN_BACKEND)
}

#[cfg(test)]
mod scan_backend_choice_tests {
    use super::*;

    #[test]
    fn every_scan_backend_sits_at_its_own_choice_position() {
        SCAN_BACKEND_CHOICES.into_iter().for_each(|backend_choice| {
            assert_eq!(
                ScannerBackendPreference::from_choice_position(backend_choice.choice_position()),
                Some(backend_choice)
            );
            assert_eq!(
                ScannerBackendPreference::from_stored_text(backend_choice.stored_text()),
                Some(backend_choice)
            );
        });
    }
}
