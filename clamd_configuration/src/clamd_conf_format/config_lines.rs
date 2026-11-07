use std::{convert::Infallible, fmt, str::FromStr};

use crate::clamd_conf_format::ClamdFormatError;

const CLAMAV_MAX_OPTION_LINE_LENGTH: usize = 1024;
const FGETS_TERMINATOR_BYTES: usize = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingLine {
    pub setting_name: String,
    pub setting_value: String,
    pub line_text: String,
}

impl SettingLine {
    pub fn rendered(setting_name: &str, setting_value: &str) -> Result<Self, ClamdFormatError> {
        let line_text = format!("{setting_name} {setting_value}");
        if line_text.len() + FGETS_TERMINATOR_BYTES > CLAMAV_MAX_OPTION_LINE_LENGTH {
            return Err(ClamdFormatError::LineTooLong {
                setting_name: setting_name.to_owned(),
            });
        }
        Ok(Self {
            setting_name: setting_name.to_owned(),
            setting_value: setting_value.to_owned(),
            line_text,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamdConfigLine {
    BlankLine { line_text: String },
    CommentLine { line_text: String },
    Setting(SettingLine),
}

impl ClamdConfigLine {
    fn line_text(&self) -> &str {
        match self {
            Self::BlankLine { line_text } | Self::CommentLine { line_text } => line_text,
            Self::Setting(setting_line) => &setting_line.line_text,
        }
    }
}

impl From<&str> for ClamdConfigLine {
    fn from(line_text: &str) -> Self {
        let trimmed_line = line_text.trim();
        if trimmed_line.is_empty() {
            return Self::BlankLine {
                line_text: line_text.to_owned(),
            };
        }
        if trimmed_line.starts_with('#') {
            return Self::CommentLine {
                line_text: line_text.to_owned(),
            };
        }
        let (setting_name, setting_value) = trimmed_line
            .split_once(char::is_whitespace)
            .unwrap_or((trimmed_line, ""));
        Self::Setting(SettingLine {
            setting_name: setting_name.to_owned(),
            setting_value: setting_value.trim().to_owned(),
            line_text: line_text.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClamdConfigLines {
    pub config_lines: Vec<ClamdConfigLine>,
}

impl ClamdConfigLines {
    pub fn setting_lines(&self) -> impl Iterator<Item = &SettingLine> {
        self.config_lines
            .iter()
            .filter_map(|config_line| match config_line {
                ClamdConfigLine::Setting(setting_line) => Some(setting_line),
                ClamdConfigLine::BlankLine { .. } | ClamdConfigLine::CommentLine { .. } => None,
            })
    }

    pub fn values_of<'lines>(&'lines self, setting_name: &str) -> Vec<&'lines str> {
        self.setting_lines()
            .filter(|setting_line| setting_line.setting_name == setting_name)
            .map(|setting_line| setting_line.setting_value.as_str())
            .collect()
    }
}

impl FromStr for ClamdConfigLines {
    type Err = Infallible;

    fn from_str(config_text: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            config_lines: config_text.lines().map(ClamdConfigLine::from).collect(),
        })
    }
}

impl fmt::Display for ClamdConfigLines {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.config_lines
            .iter()
            .try_for_each(|config_line| writeln!(formatter, "{}", config_line.line_text()))
    }
}

#[cfg(test)]
mod config_lines_tests {
    use super::*;

    #[test]
    fn config_files_round_trip_byte_for_byte() {
        let config_text = "# managed by NixOS\n\nLocalSocket  /run/clamav/clamd.ctl\n  MaxThreads \
                           12\nForeground\n";
        let config_lines: ClamdConfigLines = config_text.parse().expect("parsed");
        assert_eq!(config_lines.to_string(), config_text);
        assert_eq!(
            config_lines.values_of("LocalSocket"),
            ["/run/clamav/clamd.ctl"]
        );
        assert_eq!(config_lines.values_of("MaxThreads"), ["12"]);
        assert_eq!(config_lines.values_of("Foreground"), [""]);
    }

    #[test]
    fn lines_clamd_would_split_are_never_rendered() {
        let longest_value =
            "a".repeat(CLAMAV_MAX_OPTION_LINE_LENGTH - FGETS_TERMINATOR_BYTES - "Name ".len());
        assert!(SettingLine::rendered("Name", &longest_value).is_ok());
        assert!(SettingLine::rendered("Name", &format!("{longest_value}a")).is_err());
    }
}
