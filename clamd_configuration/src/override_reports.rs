use jiff::Timestamp;

use crate::{
    clamd_conf_format::{config_lines::ClamdConfigLines, serializer::value_texts},
    live_overrides::{ReductionClock, SettingChanges},
    merged_clamd_config::{requested_settings_in, tunable_settings_in},
    protection_rules::{BaseValue, ProtectionReduction, TunableValue},
    tunable_record::{
        BaseSettings, ConfiguredValue, LiveOverrides, SettingOverride, SlotCombiner,
        TunableSettings,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverrideLifetime {
    Permanent,
    ExpiresAt { expires_at: Timestamp },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverrideReport {
    pub setting_name: &'static str,
    pub changed_values: Vec<String>,
    pub override_lifetime: OverrideLifetime,
    pub protection_reduction: ProtectionReduction,
}

struct OverrideReportCollector {
    now: Timestamp,
    override_reports: Vec<OverrideReport>,
}

impl SlotCombiner for OverrideReportCollector {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        base_value: &BaseValue<'_, Value>,
        _requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        let report_parts = match live_override {
            SettingOverride::Permanent { value } => Some((value, OverrideLifetime::Permanent)),
            SettingOverride::TemporaryReduction { value, expires_at } if *expires_at > self.now => {
                Some((
                    value,
                    OverrideLifetime::ExpiresAt {
                        expires_at: *expires_at,
                    },
                ))
            }
            SettingOverride::TemporaryReduction { .. } | SettingOverride::FromSystem => None,
        };
        if let Some((changed_value, override_lifetime)) = report_parts {
            self.override_reports.push(OverrideReport {
                setting_name,
                changed_values: value_texts(changed_value).unwrap_or_default(),
                override_lifetime,
                protection_reduction: Value::protection_change(base_value, changed_value),
            });
        }
        live_override.clone()
    }
}

struct DefaultTextCollector {
    wanted_name: String,
    default_texts: Vec<String>,
}

impl SlotCombiner for DefaultTextCollector {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        _base_value: &BaseValue<'_, Value>,
        _requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        if setting_name == self.wanted_name {
            self.default_texts = value_texts(&Value::unconfigured_default()).unwrap_or_default();
        }
        live_override.clone()
    }
}

impl LiveOverrides {
    pub fn override_reports(
        &self,
        base_settings: BaseSettings<'_>,
        now: Timestamp,
    ) -> Vec<OverrideReport> {
        let mut report_collector = OverrideReportCollector {
            now,
            override_reports: Vec::new(),
        };
        let _unchanged = self.combine_with(
            base_settings,
            &TunableSettings::default(),
            &mut report_collector,
        );
        report_collector.override_reports
    }
}

pub fn clamav_default_texts(setting_name: &str) -> Vec<String> {
    let mut default_collector = DefaultTextCollector {
        wanted_name: setting_name.to_owned(),
        default_texts: Vec::new(),
    };
    let _unchanged = LiveOverrides::default().combine_with(
        BaseSettings::UnreadableBase,
        &TunableSettings::default(),
        &mut default_collector,
    );
    default_collector.default_texts
}

pub fn change_reduction_from(
    current_lines: &ClamdConfigLines,
    requested_lines: &ClamdConfigLines,
    now: Timestamp,
) -> ProtectionReduction {
    let Ok(requested_settings) = requested_settings_in(requested_lines) else {
        return ProtectionReduction::CurrentValuesUnknown;
    };
    let current_settings = tunable_settings_in(current_lines).ok();
    let current_view = current_settings
        .as_ref()
        .map_or(BaseSettings::UnreadableBase, BaseSettings::ReadableBase);
    LiveOverrides::default()
        .with_changes(
            &SettingChanges::SetValues {
                setting_values: Box::new(requested_settings),
            },
            current_view,
            ReductionClock {
                now,
                reduction_lifetime: jiff::SignedDuration::ZERO,
            },
        )
        .protection_reduction
}

#[cfg(test)]
mod override_reports_tests {
    use super::*;

    fn lines(config_text: &str) -> ClamdConfigLines {
        config_text.parse().expect("parsed")
    }

    fn moment(unix_second: i64) -> Timestamp {
        Timestamp::from_second(unix_second).expect("timestamp")
    }

    #[test]
    fn clamav_defaults_render_in_clamd_spelling() {
        assert_eq!(clamav_default_texts("HeuristicAlerts"), ["yes"]);
        assert_eq!(clamav_default_texts("DetectPUA"), ["no"]);
        assert_eq!(clamav_default_texts("OnAccessMaxFileSize"), ["5M"]);
        assert!(clamav_default_texts("VirusEvent").is_empty());
    }

    #[test]
    fn changes_are_classified_against_the_current_values() {
        assert_eq!(
            change_reduction_from(
                &lines("OnAccessPrevention yes\n"),
                &lines("OnAccessPrevention no\n"),
                moment(0)
            ),
            ProtectionReduction::BlockingTurnedOff
        );
        assert_eq!(
            change_reduction_from(
                &lines("OnAccessMaxFileSize 10M\n"),
                &lines("OnAccessMaxFileSize 100M\n"),
                moment(0)
            ),
            ProtectionReduction::NoReduction
        );
        assert_eq!(
            change_reduction_from(&lines(""), &lines("OnAccessExcludePath /a\n"), moment(0)),
            ProtectionReduction::SkippedLocationAdded
        );
        assert_eq!(
            change_reduction_from(&lines(""), &lines("VirusEvent /bin/sh\n"), moment(0)),
            ProtectionReduction::CurrentValuesUnknown
        );
    }

    #[test]
    fn reports_list_active_overrides_with_their_reduction_and_lifetime() {
        let base_settings = tunable_settings_in(&lines("DetectPUA yes\n")).expect("typed");
        let live_overrides = LiveOverrides::from_toml_text(
            "[DetectPUA]\nstate = \"temporary-reduction\"\nvalue = false\nexpires_at = \
             \"1970-01-01T00:01:40Z\"\n\n[MaxThreads]\nstate = \"permanent\"\nvalue = 8\n",
        )
        .expect("parsed");
        let override_reports =
            live_overrides.override_reports(BaseSettings::ReadableBase(&base_settings), moment(0));
        assert_eq!(
            override_reports,
            [
                OverrideReport {
                    setting_name: "DetectPUA",
                    changed_values: vec!["no".to_owned()],
                    override_lifetime: OverrideLifetime::ExpiresAt {
                        expires_at: moment(100)
                    },
                    protection_reduction: ProtectionReduction::CheckTurnedOff,
                },
                OverrideReport {
                    setting_name: "MaxThreads",
                    changed_values: vec!["8".to_owned()],
                    override_lifetime: OverrideLifetime::Permanent,
                    protection_reduction: ProtectionReduction::NoReduction,
                },
            ]
        );
        assert_eq!(
            live_overrides
                .override_reports(BaseSettings::ReadableBase(&base_settings), moment(100))
                .len(),
            1
        );
    }
}
