use std::{fs, path::Path};

const CLAMD_CONFIG_PATHS: [&str; 4] = [
    "/run/lazaret/clamd.conf",
    "/etc/clamav/clamd.conf",
    "/etc/clamd.d/scan.conf",
    "/etc/clamd.conf",
];
const FRESHCLAM_CONFIG_PATHS: [&str; 2] = ["/etc/clamav/freshclam.conf", "/etc/freshclam.conf"];
const ON_ACCESS_KEY_PREFIX: &str = "OnAccess";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigSetting {
    pub setting_key: String,
    pub setting_value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostConfigView {
    ConfigFound {
        config_path: String,
        config_settings: Vec<ConfigSetting>,
    },
    ConfigNotFound,
}

pub fn parse_config_settings(config_text: &str) -> Vec<ConfigSetting> {
    config_text
        .lines()
        .map(str::trim)
        .filter(|config_line| !config_line.is_empty() && !config_line.starts_with('#'))
        .map(
            |config_line| match config_line.split_once(char::is_whitespace) {
                Some((setting_key, setting_value)) => ConfigSetting {
                    setting_key: setting_key.to_owned(),
                    setting_value: setting_value.trim().to_owned(),
                },
                None => ConfigSetting {
                    setting_key: config_line.to_owned(),
                    setting_value: String::new(),
                },
            },
        )
        .collect()
}

fn read_first_config(config_paths: &[&str]) -> HostConfigView {
    config_paths
        .iter()
        .find_map(|config_path| {
            fs::read_to_string(Path::new(config_path))
                .ok()
                .map(|config_text| HostConfigView::ConfigFound {
                    config_path: (*config_path).to_owned(),
                    config_settings: parse_config_settings(&config_text),
                })
        })
        .unwrap_or(HostConfigView::ConfigNotFound)
}

pub fn read_clamd_config() -> HostConfigView {
    read_first_config(&CLAMD_CONFIG_PATHS)
}

pub fn read_freshclam_config() -> HostConfigView {
    read_first_config(&FRESHCLAM_CONFIG_PATHS)
}

pub fn is_on_access_setting(config_setting: &ConfigSetting) -> bool {
    config_setting.setting_key.starts_with(ON_ACCESS_KEY_PREFIX)
}

#[cfg(test)]
mod clamav_host_config_tests {
    use super::*;

    #[test]
    fn comments_are_skipped_and_values_keep_their_spaces() {
        assert_eq!(
            parse_config_settings(
                "# comment\n\nLogFile /var/log/clamd.log\n  VirusEvent  /bin/notify --a \
                 %v\nForeground\n"
            ),
            vec![
                ConfigSetting {
                    setting_key: "LogFile".to_owned(),
                    setting_value: "/var/log/clamd.log".to_owned(),
                },
                ConfigSetting {
                    setting_key: "VirusEvent".to_owned(),
                    setting_value: "/bin/notify --a %v".to_owned(),
                },
                ConfigSetting {
                    setting_key: "Foreground".to_owned(),
                    setting_value: String::new(),
                },
            ]
        );
    }

    #[test]
    fn on_access_settings_are_recognized_by_their_prefix() {
        assert!(is_on_access_setting(&ConfigSetting {
            setting_key: "OnAccessPrevention".to_owned(),
            setting_value: "yes".to_owned(),
        }));
        assert!(!is_on_access_setting(&ConfigSetting {
            setting_key: "LogFile".to_owned(),
            setting_value: String::new(),
        }));
    }
}
