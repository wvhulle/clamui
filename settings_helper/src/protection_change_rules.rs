use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchRole {
    BlocksAccess,
    ChecksContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectiveSwitch {
    pub setting_key: &'static str,
    pub on_by_default: bool,
    pub switch_role: SwitchRole,
}

const fn content_check(setting_key: &'static str, on_by_default: bool) -> ProtectiveSwitch {
    ProtectiveSwitch {
        setting_key,
        on_by_default,
        switch_role: SwitchRole::ChecksContent,
    }
}

const PROTECTIVE_SWITCHES: [ProtectiveSwitch; 21] = [
    ProtectiveSwitch {
        setting_key: "OnAccessPrevention",
        on_by_default: false,
        switch_role: SwitchRole::BlocksAccess,
    },
    content_check("OnAccessExtraScanning", false),
    content_check("ScanPE", true),
    content_check("ScanELF", true),
    content_check("ScanOLE2", true),
    content_check("ScanPDF", true),
    content_check("ScanHTML", true),
    content_check("ScanMail", true),
    content_check("ScanArchive", true),
    content_check("ScanSWF", true),
    content_check("ScanXMLDOCS", true),
    content_check("ScanHWP3", true),
    content_check("AlertBrokenExecutables", false),
    content_check("AlertEncrypted", false),
    content_check("AlertEncryptedArchive", false),
    content_check("AlertEncryptedDoc", false),
    content_check("AlertOLE2Macros", false),
    content_check("AlertExceedsMax", false),
    content_check("DetectPUA", false),
    content_check("HeuristicAlerts", true),
    content_check("Bytecode", true),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanLimitDefault {
    setting_key: &'static str,
    default_limit: u64,
}

const MEBIBYTE: u64 = 1024 * 1024;

const SCAN_LIMIT_DEFAULTS: [ScanLimitDefault; 9] = [
    ScanLimitDefault {
        setting_key: "MaxScanTime",
        default_limit: 120_000,
    },
    ScanLimitDefault {
        setting_key: "MaxRecursion",
        default_limit: 17,
    },
    ScanLimitDefault {
        setting_key: "MaxFiles",
        default_limit: 10_000,
    },
    ScanLimitDefault {
        setting_key: "MaxDirectoryRecursion",
        default_limit: 15,
    },
    ScanLimitDefault {
        setting_key: "MaxEmbeddedPE",
        default_limit: 40 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "MaxScanSize",
        default_limit: 400 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "MaxFileSize",
        default_limit: 100 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "OnAccessMaxFileSize",
        default_limit: 5 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "PCREMaxFileSize",
        default_limit: 100 * MEBIBYTE,
    },
];

const SKIP_LIST_SETTINGS: [&str; 6] = [
    "OnAccessExcludePath",
    "OnAccessExcludeRootUID",
    "OnAccessExcludeUID",
    "OnAccessExcludeUname",
    "ExcludePath",
    "ExcludePUA",
];
const WATCHED_FOLDER_SETTING: &str = "OnAccessIncludePath";

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum ConfigReadFailure {
    #[error(
        "neither the merged clamd configuration ({merged_failure}) nor the base configuration \
         ({base_failure}) could be read"
    )]
    MergedAndBaseUnreadable {
        merged_failure: io::Error,
        base_failure: io::Error,
    },
}

#[derive(Debug)]
pub enum ValuesInEffect {
    NotConfigured,
    Configured {
        setting_values: Vec<String>,
    },
    #[allow(dead_code)]
    ConfigUnreadable(ConfigReadFailure),
}

impl ValuesInEffect {
    pub fn from_config_values(setting_values: Vec<String>) -> Self {
        if setting_values.is_empty() {
            Self::NotConfigured
        } else {
            Self::Configured { setting_values }
        }
    }
}

pub fn protective_switch_named(setting_key: &str) -> Option<&'static ProtectiveSwitch> {
    PROTECTIVE_SWITCHES
        .iter()
        .find(|protective_switch| protective_switch.setting_key == setting_key)
}

fn default_scan_limit(setting_key: &str) -> Option<u64> {
    SCAN_LIMIT_DEFAULTS
        .iter()
        .find(|limit_default| limit_default.setting_key == setting_key)
        .map(|limit_default| limit_default.default_limit)
}

fn is_scan_limit(setting_key: &str) -> bool {
    setting_key.ends_with("Size") || default_scan_limit(setting_key).is_some()
}

fn switch_is_on(setting_value: &str) -> bool {
    matches!(setting_value, "true" | "yes")
}

pub fn limit_in_units(limit_text: &str) -> Option<u64> {
    let (digits, multiplier) = match limit_text.chars().last()? {
        'k' | 'K' => (&limit_text[..limit_text.len() - 1], 1024),
        'm' | 'M' => (&limit_text[..limit_text.len() - 1], 1024 * 1024),
        _no_suffix => (limit_text, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
}

fn largest_limit(limit_values: &[String]) -> Option<u64> {
    limit_values
        .iter()
        .filter_map(|limit_value| limit_in_units(limit_value))
        .max()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionReduction {
    BlockingTurnedOff,
    CheckTurnedOff,
    WatchedFolderRemoved,
    SkippedLocationAdded,
    ScanLimitLowered,
    CurrentValuesUnknown,
    DetectionTrusted,
    NoReduction,
}

#[allow(dead_code)]
const ALL_PROTECTION_REDUCTIONS: [ProtectionReduction; 8] = [
    ProtectionReduction::BlockingTurnedOff,
    ProtectionReduction::CheckTurnedOff,
    ProtectionReduction::WatchedFolderRemoved,
    ProtectionReduction::SkippedLocationAdded,
    ProtectionReduction::ScanLimitLowered,
    ProtectionReduction::CurrentValuesUnknown,
    ProtectionReduction::DetectionTrusted,
    ProtectionReduction::NoReduction,
];

impl ProtectionReduction {
    pub const fn weakens_protection(self) -> bool {
        !matches!(self, Self::NoReduction)
    }

    pub const fn journal_field_value(self) -> &'static str {
        match self {
            Self::BlockingTurnedOff => "blocking-turned-off",
            Self::CheckTurnedOff => "check-turned-off",
            Self::WatchedFolderRemoved => "watched-folder-removed",
            Self::SkippedLocationAdded => "skipped-location-added",
            Self::ScanLimitLowered => "scan-limit-lowered",
            Self::CurrentValuesUnknown => "current-values-unknown",
            Self::DetectionTrusted => "detection-trusted",
            Self::NoReduction => "no-reduction",
        }
    }

    #[allow(dead_code)]
    pub fn from_journal_field_value(field_value: &str) -> Option<Self> {
        ALL_PROTECTION_REDUCTIONS
            .into_iter()
            .find(|protection_reduction| protection_reduction.journal_field_value() == field_value)
    }
}

const fn switch_reduction(protective_switch: &ProtectiveSwitch) -> ProtectionReduction {
    match protective_switch.switch_role {
        SwitchRole::BlocksAccess => ProtectionReduction::BlockingTurnedOff,
        SwitchRole::ChecksContent => ProtectionReduction::CheckTurnedOff,
    }
}

fn switch_change_reduction(
    protective_switch: &ProtectiveSwitch,
    values_in_effect: &ValuesInEffect,
    new_values: &[String],
) -> ProtectionReduction {
    if new_values.iter().any(|new_value| switch_is_on(new_value)) {
        return ProtectionReduction::NoReduction;
    }
    let was_on = match values_in_effect {
        ValuesInEffect::NotConfigured => protective_switch.on_by_default,
        ValuesInEffect::Configured { setting_values } => setting_values
            .iter()
            .any(|current_value| switch_is_on(current_value)),
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            return ProtectionReduction::CurrentValuesUnknown;
        }
    };
    if was_on {
        switch_reduction(protective_switch)
    } else {
        ProtectionReduction::NoReduction
    }
}

fn skip_list_reduction(
    values_in_effect: &ValuesInEffect,
    new_values: &[String],
) -> ProtectionReduction {
    let skipped_before: &[String] = match values_in_effect {
        ValuesInEffect::NotConfigured => &[],
        ValuesInEffect::Configured { setting_values } => setting_values,
        ValuesInEffect::ConfigUnreadable(_read_failure) if new_values.is_empty() => {
            return ProtectionReduction::NoReduction;
        }
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            return ProtectionReduction::CurrentValuesUnknown;
        }
    };
    if new_values
        .iter()
        .any(|new_value| !skipped_before.contains(new_value))
    {
        ProtectionReduction::SkippedLocationAdded
    } else {
        ProtectionReduction::NoReduction
    }
}

fn watched_folder_reduction(
    values_in_effect: &ValuesInEffect,
    new_values: &[String],
) -> ProtectionReduction {
    match values_in_effect {
        ValuesInEffect::NotConfigured => ProtectionReduction::NoReduction,
        ValuesInEffect::Configured { setting_values }
            if setting_values
                .iter()
                .any(|current_value| !new_values.contains(current_value)) =>
        {
            ProtectionReduction::WatchedFolderRemoved
        }
        ValuesInEffect::Configured { .. } => ProtectionReduction::NoReduction,
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            ProtectionReduction::CurrentValuesUnknown
        }
    }
}

fn scan_limit_reduction(
    setting_key: &str,
    values_in_effect: &ValuesInEffect,
    new_values: &[String],
) -> ProtectionReduction {
    let Some(new_limit) = largest_limit(new_values) else {
        return ProtectionReduction::NoReduction;
    };
    let current_limit = match values_in_effect {
        ValuesInEffect::NotConfigured => default_scan_limit(setting_key),
        ValuesInEffect::Configured { setting_values } => largest_limit(setting_values),
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            return ProtectionReduction::CurrentValuesUnknown;
        }
    };
    match current_limit {
        Some(current_limit) if new_limit >= current_limit => ProtectionReduction::NoReduction,
        Some(_) | None => ProtectionReduction::ScanLimitLowered,
    }
}

pub fn protection_reduction(
    setting_key: &str,
    values_in_effect: &ValuesInEffect,
    new_values: &[String],
) -> ProtectionReduction {
    if let Some(protective_switch) = protective_switch_named(setting_key) {
        return switch_change_reduction(protective_switch, values_in_effect, new_values);
    }
    if SKIP_LIST_SETTINGS.contains(&setting_key) {
        return skip_list_reduction(values_in_effect, new_values);
    }
    if setting_key == WATCHED_FOLDER_SETTING {
        return watched_folder_reduction(values_in_effect, new_values);
    }
    if is_scan_limit(setting_key) {
        return scan_limit_reduction(setting_key, values_in_effect, new_values);
    }
    ProtectionReduction::NoReduction
}

#[cfg(test)]
mod protection_change_rules_tests {
    use super::*;

    fn configured_values(setting_values: &[&str]) -> ValuesInEffect {
        ValuesInEffect::from_config_values(values(setting_values))
    }

    fn values(setting_values: &[&str]) -> Vec<String> {
        setting_values
            .iter()
            .map(|setting_value| (*setting_value).to_owned())
            .collect()
    }

    fn unreadable_config() -> ValuesInEffect {
        ValuesInEffect::ConfigUnreadable(ConfigReadFailure::MergedAndBaseUnreadable {
            merged_failure: io::Error::from(io::ErrorKind::PermissionDenied),
            base_failure: io::Error::from(io::ErrorKind::NotFound),
        })
    }

    fn change_weakens(
        setting_key: &str,
        values_in_effect: &ValuesInEffect,
        new_values: &[&str],
    ) -> bool {
        protection_reduction(setting_key, values_in_effect, &values(new_values))
            .weakens_protection()
    }

    #[test]
    fn limit_suffixes_are_binary_multiples() {
        assert_eq!(limit_in_units("100M"), Some(104_857_600));
        assert_eq!(limit_in_units("102400k"), Some(104_857_600));
        assert_eq!(limit_in_units("512"), Some(512));
        assert_eq!(limit_in_units("lots"), None);
    }

    #[test]
    fn switching_protection_off_weakens_it_and_switching_it_on_does_not() {
        assert!(change_weakens(
            "OnAccessPrevention",
            &configured_values(&["yes"]),
            &["no"]
        ));
        assert!(change_weakens(
            "ScanArchive",
            &ValuesInEffect::NotConfigured,
            &["no"]
        ));
        assert!(!change_weakens(
            "DetectPUA",
            &configured_values(&["no"]),
            &["yes"]
        ));
    }

    #[test]
    fn switches_that_default_to_off_are_not_assumed_on() {
        ["OnAccessPrevention", "DetectPUA", "AlertOLE2Macros"]
            .into_iter()
            .for_each(|setting_key| {
                assert_eq!(
                    protection_reduction(
                        setting_key,
                        &ValuesInEffect::NotConfigured,
                        &values(&["no"])
                    ),
                    ProtectionReduction::NoReduction,
                    "{setting_key}"
                );
            });
        assert_eq!(
            protection_reduction(
                "HeuristicAlerts",
                &ValuesInEffect::NotConfigured,
                &values(&["no"])
            ),
            ProtectionReduction::CheckTurnedOff
        );
    }

    #[test]
    fn turning_off_prevention_is_reported_as_losing_blocking() {
        assert_eq!(
            protection_reduction(
                "OnAccessPrevention",
                &configured_values(&["yes"]),
                &values(&["no"])
            ),
            ProtectionReduction::BlockingTurnedOff
        );
        assert_eq!(
            protection_reduction("ScanPDF", &configured_values(&["yes"]), &values(&["no"])),
            ProtectionReduction::CheckTurnedOff
        );
    }

    #[test]
    fn new_exclusions_and_lower_limits_weaken_protection() {
        assert!(change_weakens(
            "OnAccessExcludePath",
            &configured_values(&["/srv"]),
            &["/srv", "/home"]
        ));
        assert!(!change_weakens(
            "OnAccessExcludePath",
            &configured_values(&["/srv", "/home"]),
            &["/srv"]
        ));
        assert!(change_weakens(
            "OnAccessIncludePath",
            &configured_values(&["/home", "/tmp"]),
            &["/home"]
        ));
        assert!(change_weakens(
            "MaxFileSize",
            &configured_values(&["100M"]),
            &["25M"]
        ));
        assert!(!change_weakens(
            "MaxFileSize",
            &configured_values(&["25M"]),
            &["100M"]
        ));
        assert!(!change_weakens(
            "MaxThreads",
            &configured_values(&["12"]),
            &["2"]
        ));
    }

    #[test]
    fn unset_limits_compare_against_the_clamav_default() {
        assert!(change_weakens(
            "MaxFileSize",
            &ValuesInEffect::NotConfigured,
            &["25M"]
        ));
        assert!(!change_weakens(
            "MaxFileSize",
            &ValuesInEffect::NotConfigured,
            &["200M"]
        ));
        assert!(change_weakens(
            "SomeUnlistedSize",
            &ValuesInEffect::NotConfigured,
            &["1M"]
        ));
    }

    #[test]
    fn an_unreadable_config_never_makes_a_change_harmless() {
        let unreadable_config = unreadable_config();
        [
            ("OnAccessIncludePath", "/home"),
            ("OnAccessExcludePath", "/srv"),
            ("DetectPUA", "no"),
            ("OnAccessPrevention", "no"),
            ("MaxFileSize", "200M"),
        ]
        .into_iter()
        .for_each(|(setting_key, new_value)| {
            assert_eq!(
                protection_reduction(setting_key, &unreadable_config, &values(&[new_value])),
                ProtectionReduction::CurrentValuesUnknown,
                "{setting_key}"
            );
        });
        assert!(!change_weakens(
            "OnAccessPrevention",
            &unreadable_config,
            &["yes"]
        ));
        assert!(!change_weakens("MaxThreads", &unreadable_config, &["2"]));
    }

    #[test]
    fn every_reduction_survives_its_journal_field_value() {
        ALL_PROTECTION_REDUCTIONS
            .into_iter()
            .for_each(|protection_reduction| {
                assert_eq!(
                    ProtectionReduction::from_journal_field_value(
                        protection_reduction.journal_field_value()
                    ),
                    Some(protection_reduction)
                );
            });
        assert_eq!(
            ProtectionReduction::from_journal_field_value("surprise"),
            None
        );
    }
}
