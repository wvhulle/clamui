use std::collections::BTreeSet;

use crate::{
    clamd_conf_format::{
        ClamdFormatError,
        config_lines::{ClamdConfigLine, ClamdConfigLines},
        deserializer::{UnknownSettingPolicy, from_config_lines},
        serializer::to_setting_lines,
    },
    tunable_allowlist::TunableAllowlist,
    tunable_record::{TunableSettings, tunable_setting_names},
};

pub fn tunable_settings_in(
    config_lines: &ClamdConfigLines,
) -> Result<TunableSettings, ClamdFormatError> {
    from_config_lines(
        config_lines,
        tunable_setting_names(),
        UnknownSettingPolicy::SkipUnknownSettings,
    )
}

pub fn requested_settings_in(
    config_lines: &ClamdConfigLines,
) -> Result<TunableSettings, ClamdFormatError> {
    from_config_lines(
        config_lines,
        tunable_setting_names(),
        UnknownSettingPolicy::RefuseUnknownSettings,
    )
}

pub fn merge_clamd_config(
    base_lines: &ClamdConfigLines,
    effective_overrides: &TunableSettings,
    tunable_allowlist: &TunableAllowlist,
) -> Result<ClamdConfigLines, ClamdFormatError> {
    let override_lines = to_setting_lines(effective_overrides)?
        .into_iter()
        .filter(|override_line| tunable_allowlist.allows(&override_line.setting_name))
        .collect::<Vec<_>>();
    let overridden_names = override_lines
        .iter()
        .map(|override_line| override_line.setting_name.clone())
        .collect::<BTreeSet<_>>();
    let kept_base_lines = base_lines
        .config_lines
        .iter()
        .filter(|base_line| match base_line {
            ClamdConfigLine::Setting(setting_line) => {
                !overridden_names.contains(&setting_line.setting_name)
            }
            ClamdConfigLine::BlankLine { .. } | ClamdConfigLine::CommentLine { .. } => true,
        })
        .cloned();
    Ok(ClamdConfigLines {
        config_lines: kept_base_lines
            .chain(override_lines.into_iter().map(ClamdConfigLine::Setting))
            .collect(),
    })
}

#[cfg(test)]
mod merged_clamd_config_tests {
    use bytesize::ByteSize;

    use super::*;
    use crate::{
        setting_values::{
            ClamdSize, ContainedPath, ContentCheck, SizeLimit, SwitchState, WatchedFolders,
        },
        tunable_record::ConfiguredValue,
    };

    const BASE_CONFIG: &str = "DatabaseDirectory /var/lib/clamav\nUser clamav\nOnAccessPrevention \
                               true\nOnAccessIncludePath /home/a\nOnAccessIncludePath \
                               /home/b\nOnAccessMaxFileSize 5M\nDetectPUA no\n";

    fn base_lines() -> ClamdConfigLines {
        BASE_CONFIG.parse().expect("parsed")
    }

    fn allowing(allowed_names: &str) -> TunableAllowlist {
        allowed_names.parse().expect("parsed")
    }

    #[test]
    fn the_base_config_reads_into_typed_values() {
        let base_settings = tunable_settings_in(&base_lines()).expect("typed");
        assert_eq!(
            base_settings.on_access_max_file_size,
            ConfiguredValue::Configured(SizeLimit(ClamdSize::LimitedTo(ByteSize::mib(5))))
        );
        assert_eq!(
            base_settings.detect_pua,
            ConfiguredValue::Configured(ContentCheck(SwitchState::SwitchedOff))
        );
        assert_eq!(
            base_settings.on_access_include_path,
            ConfiguredValue::Configured(WatchedFolders(vec![
                ContainedPath::try_from("/home/a".to_owned()).expect("path"),
                ContainedPath::try_from("/home/b".to_owned()).expect("path"),
            ]))
        );
    }

    #[test]
    fn a_bad_value_fails_at_deserialization() {
        let config_lines: ClamdConfigLines = "DetectPUA maybe\n".parse().expect("parsed");
        assert!(tunable_settings_in(&config_lines).is_err());
        let repeated_lines: ClamdConfigLines =
            "MaxThreads 4\nMaxThreads 5\n".parse().expect("parsed");
        assert!(tunable_settings_in(&repeated_lines).is_err());
    }

    #[test]
    fn requests_refuse_settings_that_cannot_change_at_runtime() {
        let request_lines: ClamdConfigLines = "VirusEvent /bin/sh\n".parse().expect("parsed");
        assert_eq!(
            requested_settings_in(&request_lines),
            Err(ClamdFormatError::UnknownSetting {
                setting_name: "VirusEvent".to_owned()
            })
        );
    }

    #[test]
    fn without_overrides_the_merged_config_equals_the_base_config() {
        let merged_lines = merge_clamd_config(
            &base_lines(),
            &TunableSettings::default(),
            &allowing("DetectPUA\n"),
        )
        .expect("merged");
        assert_eq!(merged_lines.to_string(), BASE_CONFIG);
    }

    #[test]
    fn overrides_replace_every_base_value_of_their_setting() {
        let effective_overrides = TunableSettings {
            on_access_include_path: ConfiguredValue::Configured(WatchedFolders(vec![
                ContainedPath::try_from("/home/c".to_owned()).expect("path"),
            ])),
            on_access_max_file_size: ConfiguredValue::Configured(SizeLimit(ClamdSize::LimitedTo(
                ByteSize::mib(200),
            ))),
            ..TunableSettings::default()
        };
        let merged_text = merge_clamd_config(
            &base_lines(),
            &effective_overrides,
            &allowing("OnAccessIncludePath\nOnAccessMaxFileSize\n"),
        )
        .expect("merged")
        .to_string();
        assert!(!merged_text.contains("/home/a"));
        assert!(!merged_text.contains("/home/b"));
        assert!(merged_text.contains("OnAccessIncludePath /home/c\n"));
        assert!(merged_text.contains("OnAccessMaxFileSize 200M\n"));
        assert!(merged_text.contains("User clamav\n"));
    }

    #[test]
    fn overrides_no_longer_allowlisted_are_ignored() {
        let effective_overrides = TunableSettings {
            detect_pua: ConfiguredValue::Configured(ContentCheck(SwitchState::SwitchedOn)),
            ..TunableSettings::default()
        };
        let merged_lines =
            merge_clamd_config(&base_lines(), &effective_overrides, &allowing("")).expect("merged");
        assert_eq!(merged_lines.to_string(), BASE_CONFIG);
    }
}
