use std::collections::BTreeSet;

use jiff::{SignedDuration, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{
    protection_rules::{BaseValue, ProtectionReduction, TunableValue, ValueInEffect},
    tunable_record::{
        BaseSettings, ConfiguredValue, LiveOverrides, SettingOverride, SettingSlot, SlotCombiner,
        TunableSettingName, TunableSettings,
    },
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SettingChanges {
    SetValues {
        setting_values: Box<TunableSettings>,
    },
    BackToSystem {
        setting_names: BTreeSet<TunableSettingName>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReductionClock {
    pub now: Timestamp,
    pub reduction_lifetime: SignedDuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReductionExpiry {
    NoExpiry,
    ExpiresAt { expires_at: Timestamp },
}

#[derive(Clone, Debug, PartialEq)]
pub struct OverridesChange {
    pub changed_overrides: LiveOverrides,
    pub protection_reduction: ProtectionReduction,
    pub reduction_expiry: ReductionExpiry,
    pub changed_names: Vec<&'static str>,
}

struct ValueRequestCombiner {
    reduction_clock: ReductionClock,
    protection_reduction: ProtectionReduction,
    reduction_expiry: ReductionExpiry,
    changed_names: Vec<&'static str>,
}

impl SlotCombiner for ValueRequestCombiner {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        base_value: &BaseValue<'_, Value>,
        requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        let ConfiguredValue::Configured(new_value) = requested_value else {
            return live_override.clone();
        };
        self.changed_names.push(setting_name);
        if base_value.is_configured_as(new_value) {
            return SettingOverride::FromSystem;
        }
        let reduction_from_base = Value::protection_change(base_value, new_value);
        self.protection_reduction = self.protection_reduction.or_else(reduction_from_base);
        if reduction_from_base.weakens_protection() {
            let expires_at = self.reduction_clock.now + self.reduction_clock.reduction_lifetime;
            self.reduction_expiry = ReductionExpiry::ExpiresAt { expires_at };
            SettingOverride::TemporaryReduction {
                value: new_value.clone(),
                expires_at,
            }
        } else {
            SettingOverride::Permanent {
                value: new_value.clone(),
            }
        }
    }
}

fn reduction_back_to_base<Value: TunableValue>(
    live_override: &SettingOverride<Value>,
    base_value: &BaseValue<'_, Value>,
    now: Timestamp,
) -> ProtectionReduction {
    let ConfiguredValue::Configured(overridden_value) = live_override.value_in_effect_at(now)
    else {
        return ProtectionReduction::NoReduction;
    };
    match base_value.value_in_effect() {
        ValueInEffect::KnownValue(base_in_effect) => Value::protection_change(
            &BaseValue::KnownBase(&ConfiguredValue::Configured(overridden_value)),
            &base_in_effect,
        ),
        ValueInEffect::UnknownValue => ProtectionReduction::CurrentValuesUnknown,
    }
}

struct ResetCombiner<'request> {
    reset_names: &'request BTreeSet<TunableSettingName>,
    now: Timestamp,
    protection_reduction: ProtectionReduction,
    changed_names: Vec<&'static str>,
}

impl SlotCombiner for ResetCombiner<'_> {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        base_value: &BaseValue<'_, Value>,
        _requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        let is_reset = self
            .reset_names
            .iter()
            .any(|reset_name| reset_name.as_str() == setting_name);
        if !is_reset || matches!(live_override, SettingOverride::FromSystem) {
            return live_override.clone();
        }
        self.changed_names.push(setting_name);
        self.protection_reduction = self.protection_reduction.or_else(reduction_back_to_base(
            live_override,
            base_value,
            self.now,
        ));
        SettingOverride::FromSystem
    }
}

struct ExpiryCombiner {
    now: Timestamp,
    expired_names: Vec<&'static str>,
}

impl SlotCombiner for ExpiryCombiner {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        _base_value: &BaseValue<'_, Value>,
        _requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        match live_override {
            SettingOverride::TemporaryReduction { expires_at, .. } if *expires_at <= self.now => {
                self.expired_names.push(setting_name);
                SettingOverride::FromSystem
            }
            SettingOverride::TemporaryReduction { .. }
            | SettingOverride::Permanent { .. }
            | SettingOverride::FromSystem => live_override.clone(),
        }
    }
}

struct PermanentAdoptionCombiner;

impl SlotCombiner for PermanentAdoptionCombiner {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        _setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        _base_value: &BaseValue<'_, Value>,
        requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        match requested_value {
            ConfiguredValue::Configured(adopted_value) => SettingOverride::Permanent {
                value: adopted_value.clone(),
            },
            ConfiguredValue::NotConfigured => live_override.clone(),
        }
    }
}

struct OverriddenNameCollector {
    now: Timestamp,
    overridden_names: Vec<&'static str>,
}

impl SlotCombiner for OverriddenNameCollector {
    fn combine_slot<Value: TunableValue>(
        &mut self,
        setting_name: &'static str,
        live_override: &SettingOverride<Value>,
        _base_value: &BaseValue<'_, Value>,
        _requested_value: &ConfiguredValue<Value>,
    ) -> SettingOverride<Value> {
        if !live_override.value_in_effect_at(self.now).is_unset() {
            self.overridden_names.push(setting_name);
        }
        live_override.clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ExpiryOutcome {
    pub remaining_overrides: LiveOverrides,
    pub expired_names: Vec<&'static str>,
}

impl LiveOverrides {
    pub fn with_changes(
        &self,
        setting_changes: &SettingChanges,
        base_settings: BaseSettings<'_>,
        reduction_clock: ReductionClock,
    ) -> OverridesChange {
        match setting_changes {
            SettingChanges::SetValues { setting_values } => {
                let mut value_combiner = ValueRequestCombiner {
                    reduction_clock,
                    protection_reduction: ProtectionReduction::NoReduction,
                    reduction_expiry: ReductionExpiry::NoExpiry,
                    changed_names: Vec::new(),
                };
                let changed_overrides =
                    self.combine_with(base_settings, setting_values, &mut value_combiner);
                OverridesChange {
                    changed_overrides,
                    protection_reduction: value_combiner.protection_reduction,
                    reduction_expiry: value_combiner.reduction_expiry,
                    changed_names: value_combiner.changed_names,
                }
            }
            SettingChanges::BackToSystem { setting_names } => {
                let mut reset_combiner = ResetCombiner {
                    reset_names: setting_names,
                    now: reduction_clock.now,
                    protection_reduction: ProtectionReduction::NoReduction,
                    changed_names: Vec::new(),
                };
                let changed_overrides = self.combine_with(
                    base_settings,
                    &TunableSettings::default(),
                    &mut reset_combiner,
                );
                OverridesChange {
                    changed_overrides,
                    protection_reduction: reset_combiner.protection_reduction,
                    reduction_expiry: ReductionExpiry::NoExpiry,
                    changed_names: reset_combiner.changed_names,
                }
            }
        }
    }

    pub fn without_expired(&self, now: Timestamp) -> ExpiryOutcome {
        let mut expiry_combiner = ExpiryCombiner {
            now,
            expired_names: Vec::new(),
        };
        let remaining_overrides = self.combine_with(
            BaseSettings::UnreadableBase,
            &TunableSettings::default(),
            &mut expiry_combiner,
        );
        ExpiryOutcome {
            remaining_overrides,
            expired_names: expiry_combiner.expired_names,
        }
    }

    pub fn adopted_as_permanent(adopted_settings: &TunableSettings) -> Self {
        Self::default().combine_with(
            BaseSettings::UnreadableBase,
            adopted_settings,
            &mut PermanentAdoptionCombiner,
        )
    }

    pub fn overridden_names_at(&self, now: Timestamp) -> Vec<&'static str> {
        let mut name_collector = OverriddenNameCollector {
            now,
            overridden_names: Vec::new(),
        };
        let _unchanged = self.combine_with(
            BaseSettings::UnreadableBase,
            &TunableSettings::default(),
            &mut name_collector,
        );
        name_collector.overridden_names
    }

    pub fn to_toml_text(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    pub fn from_toml_text(toml_text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_text)
    }
}

impl SettingChanges {
    pub fn to_toml_text(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    pub fn from_toml_text(toml_text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(toml_text)
    }
}

#[cfg(test)]
mod live_overrides_tests {
    use bytesize::ByteSize;

    use super::*;
    use crate::setting_values::{
        ClamdNumber, ClamdSize, ContentCheck, SizeLimit, SwitchState, ThreadCount,
    };

    fn moment(unix_second: i64) -> Timestamp {
        Timestamp::from_second(unix_second).expect("timestamp")
    }

    fn clock_at(unix_second: i64) -> ReductionClock {
        ReductionClock {
            now: moment(unix_second),
            reduction_lifetime: SignedDuration::from_hours(24),
        }
    }

    fn base_with_pua_and_size() -> TunableSettings {
        TunableSettings {
            detect_pua: ConfiguredValue::Configured(ContentCheck(SwitchState::SwitchedOn)),
            on_access_max_file_size: ConfiguredValue::Configured(SizeLimit(ClamdSize::LimitedTo(
                ByteSize::mib(100),
            ))),
            ..TunableSettings::default()
        }
    }

    #[test]
    fn a_reduction_from_the_base_expires_and_an_increase_stays() {
        let base_settings = base_with_pua_and_size();
        let requested_settings = TunableSettings {
            detect_pua: ConfiguredValue::Configured(ContentCheck(SwitchState::SwitchedOff)),
            on_access_max_file_size: ConfiguredValue::Configured(SizeLimit(ClamdSize::LimitedTo(
                ByteSize::mib(200),
            ))),
            ..TunableSettings::default()
        };
        let overrides_change = LiveOverrides::default().with_changes(
            &SettingChanges::SetValues {
                setting_values: Box::new(requested_settings),
            },
            BaseSettings::ReadableBase(&base_settings),
            clock_at(0),
        );
        assert_eq!(
            overrides_change.protection_reduction,
            ProtectionReduction::CheckTurnedOff
        );
        assert_eq!(
            overrides_change.reduction_expiry,
            ReductionExpiry::ExpiresAt {
                expires_at: moment(86_400)
            }
        );
        assert!(matches!(
            overrides_change.changed_overrides.detect_pua,
            SettingOverride::TemporaryReduction { .. }
        ));
        assert!(matches!(
            overrides_change.changed_overrides.on_access_max_file_size,
            SettingOverride::Permanent { .. }
        ));
    }

    #[test]
    fn setting_the_base_value_again_removes_the_override() {
        let base_settings = base_with_pua_and_size();
        let live_overrides = LiveOverrides {
            detect_pua: SettingOverride::TemporaryReduction {
                value: ContentCheck(SwitchState::SwitchedOff),
                expires_at: moment(100),
            },
            ..LiveOverrides::default()
        };
        let overrides_change = live_overrides.with_changes(
            &SettingChanges::SetValues {
                setting_values: Box::new(TunableSettings {
                    detect_pua: ConfiguredValue::Configured(ContentCheck(SwitchState::SwitchedOn)),
                    ..TunableSettings::default()
                }),
            },
            BaseSettings::ReadableBase(&base_settings),
            clock_at(0),
        );
        assert_eq!(overrides_change.changed_overrides, LiveOverrides::default());
    }

    #[test]
    fn going_back_to_the_system_value_reports_a_reduction_when_the_override_was_stronger() {
        let base_settings = base_with_pua_and_size();
        let live_overrides = LiveOverrides {
            on_access_max_file_size: SettingOverride::Permanent {
                value: SizeLimit(ClamdSize::LimitedTo(ByteSize::mib(400))),
            },
            max_threads: SettingOverride::Permanent {
                value: ThreadCount(ClamdNumber::clamav_default(8)),
            },
            ..LiveOverrides::default()
        };
        let reset_names = BTreeSet::from(["OnAccessMaxFileSize".parse().expect("name")]);
        let overrides_change = live_overrides.with_changes(
            &SettingChanges::BackToSystem {
                setting_names: reset_names,
            },
            BaseSettings::ReadableBase(&base_settings),
            clock_at(0),
        );
        assert_eq!(
            overrides_change.protection_reduction,
            ProtectionReduction::ScanLimitLowered
        );
        assert_eq!(
            overrides_change.changed_overrides,
            LiveOverrides {
                max_threads: SettingOverride::Permanent {
                    value: ThreadCount(ClamdNumber::clamav_default(8)),
                },
                ..LiveOverrides::default()
            }
        );
    }

    #[test]
    fn an_unreadable_base_treats_every_turned_off_check_as_a_reduction() {
        let overrides_change = LiveOverrides::default().with_changes(
            &SettingChanges::SetValues {
                setting_values: Box::new(TunableSettings {
                    scan_archive: ConfiguredValue::Configured(ContentCheck(
                        SwitchState::SwitchedOff,
                    )),
                    ..TunableSettings::default()
                }),
            },
            BaseSettings::UnreadableBase,
            clock_at(0),
        );
        assert_eq!(
            overrides_change.protection_reduction,
            ProtectionReduction::CurrentValuesUnknown
        );
    }

    #[test]
    fn expiry_drops_only_reductions_that_ran_out() {
        let live_overrides = LiveOverrides {
            detect_pua: SettingOverride::TemporaryReduction {
                value: ContentCheck(SwitchState::SwitchedOff),
                expires_at: moment(100),
            },
            heuristic_alerts: SettingOverride::TemporaryReduction {
                value: ContentCheck(SwitchState::SwitchedOff),
                expires_at: moment(300),
            },
            max_threads: SettingOverride::Permanent {
                value: ThreadCount(ClamdNumber::clamav_default(8)),
            },
            ..LiveOverrides::default()
        };
        let expiry_outcome = live_overrides.without_expired(moment(200));
        assert_eq!(expiry_outcome.expired_names, ["DetectPUA"]);
        assert_eq!(
            expiry_outcome
                .remaining_overrides
                .overridden_names_at(moment(200)),
            ["HeuristicAlerts", "MaxThreads"]
        );
    }

    #[test]
    fn live_overrides_round_trip_through_toml_with_typed_values() {
        let live_overrides = LiveOverrides {
            detect_pua: SettingOverride::TemporaryReduction {
                value: ContentCheck(SwitchState::SwitchedOff),
                expires_at: moment(1_762_603_200),
            },
            on_access_max_file_size: SettingOverride::Permanent {
                value: SizeLimit(ClamdSize::LimitedTo(ByteSize::mib(200))),
            },
            ..LiveOverrides::default()
        };
        let toml_text = live_overrides.to_toml_text().expect("serialized");
        assert!(toml_text.contains("[DetectPUA]"));
        assert!(toml_text.contains("state = \"temporary-reduction\""));
        assert!(toml_text.contains("value = false"));
        assert!(toml_text.contains("value = \"200M\""));
        assert_eq!(
            LiveOverrides::from_toml_text(&toml_text).expect("parsed"),
            live_overrides
        );
    }

    #[test]
    fn a_planted_protected_or_malformed_entry_refuses_the_whole_file() {
        assert!(
            LiveOverrides::from_toml_text(
                "[VirusEvent]\nstate = \"permanent\"\nvalue = \"/bin/sh\"\n"
            )
            .is_err()
        );
        assert!(
            LiveOverrides::from_toml_text(
                "[DetectPUA]\nstate = \"permanent\"\nvalue = \"maybe\"\n"
            )
            .is_err()
        );
        assert!(
            LiveOverrides::from_toml_text(
                "[OnAccessIncludePath]\nstate = \"permanent\"\nvalue = [\"relative\"]\n"
            )
            .is_err()
        );
    }

    #[test]
    fn setting_changes_round_trip_through_toml() {
        let setting_changes = SettingChanges::SetValues {
            setting_values: Box::new(TunableSettings {
                max_threads: ConfiguredValue::Configured(ThreadCount(ClamdNumber::clamav_default(
                    6,
                ))),
                ..TunableSettings::default()
            }),
        };
        let toml_text = setting_changes.to_toml_text().expect("serialized");
        assert_eq!(
            SettingChanges::from_toml_text(&toml_text).expect("parsed"),
            setting_changes
        );
    }
}
