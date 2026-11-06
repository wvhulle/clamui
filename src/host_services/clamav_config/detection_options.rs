use std::ffi::OsString;

use crate::host_services::{
    clamav_config::clamav_host_config::{ConfigSetting, HostConfigView, read_clamd_config},
    settings_helper::protection_change_rules::protective_switch_named,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectionOption {
    PotentiallyUnwantedPrograms,
    HeuristicAlerts,
    OfficeMacros,
    EncryptedContent,
    ArchiveContents,
    OversizedFiles,
}

pub const DETECTION_OPTIONS: [DetectionOption; 6] = [
    DetectionOption::PotentiallyUnwantedPrograms,
    DetectionOption::HeuristicAlerts,
    DetectionOption::OfficeMacros,
    DetectionOption::EncryptedContent,
    DetectionOption::ArchiveContents,
    DetectionOption::OversizedFiles,
];

impl DetectionOption {
    pub const fn setting_key(self) -> &'static str {
        match self {
            Self::PotentiallyUnwantedPrograms => "DetectPUA",
            Self::HeuristicAlerts => "HeuristicAlerts",
            Self::OfficeMacros => "AlertOLE2Macros",
            Self::EncryptedContent => "AlertEncrypted",
            Self::ArchiveContents => "ScanArchive",
            Self::OversizedFiles => "AlertExceedsMax",
        }
    }

    const fn clamscan_flag(self) -> &'static str {
        match self {
            Self::PotentiallyUnwantedPrograms => "--detect-pua",
            Self::HeuristicAlerts => "--heuristic-alerts",
            Self::OfficeMacros => "--alert-macros",
            Self::EncryptedContent => "--alert-encrypted",
            Self::ArchiveContents => "--scan-archive",
            Self::OversizedFiles => "--alert-exceeds-max",
        }
    }

    pub fn enabled_by_default(self) -> bool {
        protective_switch_named(self.setting_key())
            .is_some_and(|protective_switch| protective_switch.on_by_default)
    }
}

pub fn switch_value_is_on(setting_value: &str) -> bool {
    matches!(setting_value.trim(), "yes" | "true")
}

pub fn effective_switch(setting_values: &[String], detection_option: DetectionOption) -> bool {
    setting_values
        .last()
        .map_or(detection_option.enabled_by_default(), |configured_value| {
            switch_value_is_on(configured_value)
        })
}

pub fn configured_values(config_settings: &[ConfigSetting], setting_key: &str) -> Vec<String> {
    config_settings
        .iter()
        .filter(|config_setting| config_setting.setting_key == setting_key)
        .map(|config_setting| config_setting.setting_value.clone())
        .collect()
}

pub fn clamscan_detection_arguments(config_settings: &[ConfigSetting]) -> Vec<OsString> {
    DETECTION_OPTIONS
        .iter()
        .map(|detection_option| {
            let switched_on = effective_switch(
                &configured_values(config_settings, detection_option.setting_key()),
                *detection_option,
            );
            OsString::from(format!(
                "{}={}",
                detection_option.clamscan_flag(),
                if switched_on { "yes" } else { "no" }
            ))
        })
        .collect()
}

pub fn host_clamscan_detection_arguments() -> Vec<OsString> {
    match read_clamd_config() {
        HostConfigView::ConfigFound {
            config_settings, ..
        } => clamscan_detection_arguments(&config_settings),
        HostConfigView::ConfigNotFound => clamscan_detection_arguments(&[]),
    }
}

#[cfg(test)]
mod detection_options_tests {
    use super::*;

    fn setting(setting_key: &str, setting_value: &str) -> ConfigSetting {
        ConfigSetting {
            setting_key: setting_key.to_owned(),
            setting_value: setting_value.to_owned(),
        }
    }

    #[test]
    fn clamscan_follows_the_clamd_configuration_and_its_defaults() {
        let clamscan_arguments = clamscan_detection_arguments(&[
            setting("DetectPUA", "yes"),
            setting("ScanArchive", "no"),
        ]);
        assert_eq!(
            clamscan_arguments,
            [
                "--detect-pua=yes",
                "--heuristic-alerts=yes",
                "--alert-macros=no",
                "--alert-encrypted=no",
                "--scan-archive=no",
                "--alert-exceeds-max=no",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn every_detection_option_has_a_clamav_default() {
        DETECTION_OPTIONS.into_iter().for_each(|detection_option| {
            assert!(
                protective_switch_named(detection_option.setting_key()).is_some(),
                "{detection_option:?}"
            );
        });
        assert!(DetectionOption::HeuristicAlerts.enabled_by_default());
        assert!(DetectionOption::ArchiveContents.enabled_by_default());
        assert!(!DetectionOption::PotentiallyUnwantedPrograms.enabled_by_default());
    }
}
