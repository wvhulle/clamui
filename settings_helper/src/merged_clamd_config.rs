use std::{collections::BTreeSet, fs, io, os::unix::fs::PermissionsExt, path::Path};

use crate::tunable_setting_rules::check_setting_change;

const WORLD_READABLE_MODE: u32 = 0o644;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverrideSetting {
    pub setting_key: String,
    pub setting_value: String,
}

pub fn parse_override_settings(overrides_text: &str) -> Vec<OverrideSetting> {
    overrides_text
        .lines()
        .map(str::trim)
        .filter(|override_line| !override_line.is_empty() && !override_line.starts_with('#'))
        .filter_map(|override_line| override_line.split_once(' '))
        .map(|key_and_value| OverrideSetting {
            setting_key: key_and_value.0.to_owned(),
            setting_value: key_and_value.1.trim().to_owned(),
        })
        .collect()
}

pub fn render_override_settings(override_settings: &[OverrideSetting]) -> String {
    override_settings
        .iter()
        .map(|override_setting| {
            format!(
                "{} {}\n",
                override_setting.setting_key, override_setting.setting_value
            )
        })
        .collect()
}

pub fn merge_clamd_config(
    base_config: &str,
    overrides_text: &str,
    tunable_settings: &[String],
) -> String {
    let accepted_overrides = parse_override_settings(overrides_text)
        .into_iter()
        .filter(|override_setting| {
            check_setting_change(
                &override_setting.setting_key,
                &override_setting.setting_value,
                tunable_settings,
            )
            .is_ok()
        })
        .collect::<Vec<_>>();
    let overridden_keys = accepted_overrides
        .iter()
        .map(|override_setting| override_setting.setting_key.as_str())
        .collect::<BTreeSet<_>>();
    let kept_base_lines = base_config.lines().filter(|base_line| {
        base_line
            .split_whitespace()
            .next()
            .is_none_or(|base_key| !overridden_keys.contains(base_key))
    });
    let mut merged_config = kept_base_lines
        .map(|base_line| format!("{base_line}\n"))
        .collect::<String>();
    merged_config.push_str(&render_override_settings(&accepted_overrides));
    merged_config
}

pub fn write_file_atomically(target_path: &Path, file_text: &str) -> io::Result<()> {
    let temporary_path = target_path.with_extension("tmp");
    fs::write(&temporary_path, file_text)?;
    fs::set_permissions(
        &temporary_path,
        fs::Permissions::from_mode(WORLD_READABLE_MODE),
    )?;
    fs::rename(&temporary_path, target_path)
}

#[cfg(test)]
mod merged_clamd_config_tests {
    use super::*;

    const BASE_CONFIG: &str = "DatabaseDirectory /var/lib/clamav\nUser clamav\nOnAccessPrevention \
                               true\nOnAccessIncludePath /home/a\nOnAccessIncludePath /home/b\n";

    fn tunable(setting_keys: &[&str]) -> Vec<String> {
        setting_keys
            .iter()
            .map(|setting_key| (*setting_key).to_owned())
            .collect()
    }

    #[test]
    fn without_overrides_the_merged_config_equals_the_base_config() {
        let base_config = "LocalSocket /run/clamav/clamd.ctl\n# comment\n\nMaxThreads 12\n";
        assert_eq!(merge_clamd_config(base_config, "", &[]), base_config);
        assert_eq!(
            merge_clamd_config(base_config, "MaxThreads 4\n", &[]),
            base_config
        );
    }

    #[test]
    fn overrides_replace_every_base_value_of_their_key() {
        let merged_config = merge_clamd_config(
            BASE_CONFIG,
            "OnAccessIncludePath /home/c\n",
            &tunable(&["OnAccessIncludePath"]),
        );
        assert!(!merged_config.contains("/home/a"));
        assert!(!merged_config.contains("/home/b"));
        assert!(merged_config.contains("OnAccessIncludePath /home/c\n"));
        assert!(merged_config.contains("User clamav\n"));
    }

    #[test]
    fn a_planted_protected_key_never_reaches_the_merged_config() {
        let merged_config = merge_clamd_config(
            BASE_CONFIG,
            "VirusEvent /bin/sh\nUser root\nOnAccessPrevention false\n",
            &tunable(&["VirusEvent", "User", "OnAccessPrevention"]),
        );
        assert!(!merged_config.contains("VirusEvent"));
        assert!(!merged_config.contains("User root"));
        assert!(merged_config.contains("User clamav\n"));
        assert!(merged_config.contains("OnAccessPrevention false\n"));
    }

    #[test]
    fn overrides_no_longer_allowlisted_are_ignored() {
        assert_eq!(
            merge_clamd_config(BASE_CONFIG, "OnAccessPrevention false\n", &[]),
            BASE_CONFIG
        );
    }

    #[test]
    fn malformed_override_lines_are_skipped() {
        assert_eq!(
            merge_clamd_config(
                BASE_CONFIG,
                "OnAccessPrevention\n# OnAccessPrevention false\nOnAccessPrevention maybe\n",
                &tunable(&["OnAccessPrevention"]),
            ),
            BASE_CONFIG
        );
    }

    #[test]
    fn override_files_round_trip() {
        let override_settings = parse_override_settings("MaxThreads 8\nOnAccessIncludePath /a b\n");
        assert_eq!(
            render_override_settings(&override_settings),
            "MaxThreads 8\nOnAccessIncludePath /a b\n"
        );
    }

    #[test]
    fn atomic_writes_are_world_readable_and_leave_no_temporary_file() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let target_path = temporary_root.path().join("clamd.conf");
        write_file_atomically(&target_path, "User clamav\n").expect("written");
        assert_eq!(
            fs::read_to_string(&target_path).expect("read"),
            "User clamav\n"
        );
        assert_eq!(
            fs::metadata(&target_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            WORLD_READABLE_MODE
        );
        assert!(!target_path.with_extension("tmp").exists());
    }
}
