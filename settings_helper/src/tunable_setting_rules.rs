use crate::protection_change_rules::{
    SettingValueKind, setting_value_kind, value_fits_setting_kind, value_has_only_safe_characters,
};

const PROTECTED_SETTINGS_LIST: &str = include_str!("../../data/protected-clamav-settings.txt");

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SettingRefusal {
    #[error("{setting_key} can never be changed at runtime")]
    ProtectedSetting { setting_key: String },
    #[error("{setting_key} is not in the list of settings allowed to change at runtime")]
    NotAllowlisted { setting_key: String },
    #[error("the value for {setting_key} is not valid")]
    InvalidValue { setting_key: String },
    #[error("no changes were given")]
    NoChanges,
}

pub fn setting_is_protected(setting_key: &str) -> bool {
    PROTECTED_SETTINGS_LIST
        .lines()
        .map(str::trim)
        .any(|protected_key| protected_key.eq_ignore_ascii_case(setting_key))
}

pub fn parse_tunable_settings(allowlist_text: &str) -> Vec<String> {
    allowlist_text
        .lines()
        .map(str::trim)
        .filter(|allowed_key| !allowed_key.is_empty())
        .filter(|allowed_key| !setting_is_protected(allowed_key))
        .map(str::to_owned)
        .collect()
}

fn value_kind_for_change(setting_key: &str) -> SettingValueKind {
    match setting_value_kind(setting_key) {
        SettingValueKind::UnknownSetting if setting_key.ends_with("Size") => {
            SettingValueKind::SizeSetting
        }
        SettingValueKind::UnknownSetting if setting_key.ends_with("Path") => {
            SettingValueKind::PathSetting
        }
        SettingValueKind::UnknownSetting => SettingValueKind::TextSetting,
        known_kind @ (SettingValueKind::BooleanSetting
        | SettingValueKind::CountSetting { .. }
        | SettingValueKind::SizeSetting
        | SettingValueKind::PathSetting
        | SettingValueKind::PathListSetting
        | SettingValueKind::TextSetting) => known_kind,
    }
}

pub fn check_setting_change(
    setting_key: &str,
    setting_value: &str,
    tunable_settings: &[String],
) -> Result<(), SettingRefusal> {
    if setting_is_protected(setting_key) {
        return Err(SettingRefusal::ProtectedSetting {
            setting_key: setting_key.to_owned(),
        });
    }
    if !tunable_settings
        .iter()
        .any(|allowed_key| allowed_key == setting_key)
    {
        return Err(SettingRefusal::NotAllowlisted {
            setting_key: setting_key.to_owned(),
        });
    }
    if value_has_only_safe_characters(setting_value)
        && value_fits_setting_kind(setting_value, value_kind_for_change(setting_key))
    {
        Ok(())
    } else {
        Err(SettingRefusal::InvalidValue {
            setting_key: setting_key.to_owned(),
        })
    }
}

#[cfg(test)]
mod tunable_setting_rules_tests {
    use super::*;

    fn allowed(setting_keys: &[&str]) -> Vec<String> {
        setting_keys
            .iter()
            .map(|setting_key| (*setting_key).to_owned())
            .collect()
    }

    #[test]
    fn protected_settings_are_refused_even_when_allowlisted() {
        [
            "VirusEvent",
            "virusevent",
            "OnUpdateExecute",
            "User",
            "LocalSocket",
        ]
        .into_iter()
        .for_each(|setting_key| {
            assert_eq!(
                check_setting_change(setting_key, "/bin/sh", &allowed(&[setting_key])),
                Err(SettingRefusal::ProtectedSetting {
                    setting_key: setting_key.to_owned()
                })
            );
        });
    }

    #[test]
    fn a_protected_key_in_the_allowlist_file_is_dropped_when_read() {
        assert_eq!(
            parse_tunable_settings("MaxFileSize\nVirusEvent\n\n  OnAccessPrevention \n"),
            allowed(&["MaxFileSize", "OnAccessPrevention"])
        );
    }

    #[test]
    fn settings_outside_the_allowlist_are_refused() {
        assert_eq!(
            check_setting_change("MaxFileSize", "100M", &allowed(&["OnAccessPrevention"])),
            Err(SettingRefusal::NotAllowlisted {
                setting_key: "MaxFileSize".to_owned()
            })
        );
    }

    #[test]
    fn newlines_cannot_inject_a_second_setting() {
        [
            "100M\nVirusEvent /bin/sh",
            "100M\rVirusEvent /bin/sh",
            "true\n",
            " true",
            "",
        ]
        .into_iter()
        .for_each(|injected_value| {
            assert!(matches!(
                check_setting_change(
                    "OnAccessMaxFileSize",
                    injected_value,
                    &allowed(&["OnAccessMaxFileSize"])
                ),
                Err(SettingRefusal::InvalidValue { .. })
            ));
        });
    }

    #[test]
    fn values_must_match_the_setting_kind() {
        let value_is_accepted = |setting_key: &str, setting_value: &str| {
            check_setting_change(setting_key, setting_value, &allowed(&[setting_key])).is_ok()
        };
        assert!(value_is_accepted("OnAccessPrevention", "true"));
        assert!(!value_is_accepted("OnAccessPrevention", "maybe"));
        assert!(value_is_accepted("DetectPUA", "yes"));
        assert!(!value_is_accepted("DetectPUA", "sometimes"));
        assert!(value_is_accepted("OnAccessMaxFileSize", "100M"));
        assert!(!value_is_accepted("OnAccessMaxFileSize", "lots"));
        assert!(value_is_accepted(
            "OnAccessIncludePath",
            "/home/user/Downloads"
        ));
        assert!(!value_is_accepted("OnAccessIncludePath", "relative/path"));
        assert!(!value_is_accepted("OnAccessIncludePath", "/home/../etc"));
        assert!(value_is_accepted("MaxThreads", "8"));
        assert!(!value_is_accepted("MaxThreads", "eight"));
        assert!(!value_is_accepted("MaxThreads", "100000"));
        assert!(!value_is_accepted("ScanSWF", "maybe"));
        assert!(value_is_accepted("NotARealClamdOption", "rejected"));
        assert!(value_is_accepted("SomeUnlistedSize", "2M"));
        assert!(!value_is_accepted("SomeUnlistedSize", "lots"));
        assert!(!value_is_accepted("ExcludePath", "relative"));
    }

    #[test]
    fn shell_and_config_metacharacters_are_refused_in_free_text() {
        ["$(reboot)", "`reboot`", "a;b", "a|b", "#comment"]
            .into_iter()
            .for_each(|unsafe_value| {
                assert!(
                    check_setting_change("LogTag", unsafe_value, &allowed(&["LogTag"])).is_err(),
                    "{unsafe_value}"
                );
            });
    }
}
