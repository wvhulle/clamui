use std::fmt::Debug;

use serde::{Serialize, de::DeserializeOwned};

use crate::{
    setting_values::{
        BlockingSwitch, CLAMD_DEFAULT_MAX_THREADS, ClamdNumber, ClamdSize, ContentCheck,
        CountLimit, SizeLimit, SkipSwitch, SkippedPaths, SkippedPatterns, SwitchState, ThreadCount,
        WatchedFolders,
    },
    tunable_record::ConfiguredValue,
};

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

    pub fn from_journal_field_value(field_value: &str) -> Option<Self> {
        [
            Self::BlockingTurnedOff,
            Self::CheckTurnedOff,
            Self::WatchedFolderRemoved,
            Self::SkippedLocationAdded,
            Self::ScanLimitLowered,
            Self::CurrentValuesUnknown,
            Self::DetectionTrusted,
            Self::NoReduction,
        ]
        .into_iter()
        .find(|protection_reduction| protection_reduction.journal_field_value() == field_value)
    }

    #[must_use]
    pub const fn or_else(self, later_reduction: Self) -> Self {
        if self.weakens_protection() {
            self
        } else {
            later_reduction
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BaseValue<'base, Value> {
    KnownBase(&'base ConfiguredValue<Value>),
    UnknownBase,
}

impl<'base, Value> From<Option<&'base ConfiguredValue<Value>>> for BaseValue<'base, Value> {
    fn from(readable_value: Option<&'base ConfiguredValue<Value>>) -> Self {
        readable_value.map_or(Self::UnknownBase, Self::KnownBase)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValueInEffect<Value> {
    KnownValue(Value),
    UnknownValue,
}

impl<Value: TunableValue> BaseValue<'_, Value> {
    pub fn value_in_effect(&self) -> ValueInEffect<Value> {
        match self {
            Self::KnownBase(ConfiguredValue::Configured(configured_value)) => {
                ValueInEffect::KnownValue(configured_value.clone())
            }
            Self::KnownBase(ConfiguredValue::NotConfigured) => {
                ValueInEffect::KnownValue(Value::unconfigured_default())
            }
            Self::UnknownBase => ValueInEffect::UnknownValue,
        }
    }

    pub fn is_configured_as(&self, candidate_value: &Value) -> bool {
        matches!(
            self,
            Self::KnownBase(ConfiguredValue::Configured(configured_value))
                if configured_value == candidate_value
        )
    }
}

pub trait TunableValue: Clone + Debug + PartialEq + Serialize + DeserializeOwned {
    fn unconfigured_default() -> Self;

    fn protection_change(base_value: &BaseValue<'_, Self>, new_value: &Self)
    -> ProtectionReduction;
}

fn switch_turned_off(
    switch_in_effect: ValueInEffect<SwitchState>,
    new_state: SwitchState,
    turned_off_reduction: ProtectionReduction,
) -> ProtectionReduction {
    match (switch_in_effect, new_state) {
        (_, SwitchState::SwitchedOn)
        | (ValueInEffect::KnownValue(SwitchState::SwitchedOff), SwitchState::SwitchedOff) => {
            ProtectionReduction::NoReduction
        }
        (ValueInEffect::UnknownValue, SwitchState::SwitchedOff) => {
            ProtectionReduction::CurrentValuesUnknown
        }
        (ValueInEffect::KnownValue(SwitchState::SwitchedOn), SwitchState::SwitchedOff) => {
            turned_off_reduction
        }
    }
}

const fn switch_from_default(on_by_default: bool) -> SwitchState {
    if on_by_default {
        SwitchState::SwitchedOn
    } else {
        SwitchState::SwitchedOff
    }
}

fn mapped_in_effect<Value, Inner>(
    value_in_effect: ValueInEffect<Value>,
    inner_value: impl FnOnce(Value) -> Inner,
) -> ValueInEffect<Inner> {
    match value_in_effect {
        ValueInEffect::KnownValue(known_value) => {
            ValueInEffect::KnownValue(inner_value(known_value))
        }
        ValueInEffect::UnknownValue => ValueInEffect::UnknownValue,
    }
}

impl TunableValue for BlockingSwitch {
    fn unconfigured_default() -> Self {
        Self(SwitchState::SwitchedOff)
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        switch_turned_off(
            mapped_in_effect(base_value.value_in_effect(), |blocking_switch| {
                blocking_switch.0
            }),
            new_value.0,
            ProtectionReduction::BlockingTurnedOff,
        )
    }
}

impl<const ON_BY_DEFAULT: bool> TunableValue for ContentCheck<ON_BY_DEFAULT> {
    fn unconfigured_default() -> Self {
        Self(switch_from_default(ON_BY_DEFAULT))
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        switch_turned_off(
            mapped_in_effect(base_value.value_in_effect(), |content_check| {
                content_check.0
            }),
            new_value.0,
            ProtectionReduction::CheckTurnedOff,
        )
    }
}

impl TunableValue for SkipSwitch {
    fn unconfigured_default() -> Self {
        Self(SwitchState::SwitchedOff)
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        match (base_value.value_in_effect(), new_value.0) {
            (_, SwitchState::SwitchedOff)
            | (ValueInEffect::KnownValue(Self(SwitchState::SwitchedOn)), SwitchState::SwitchedOn) => {
                ProtectionReduction::NoReduction
            }
            (ValueInEffect::UnknownValue, SwitchState::SwitchedOn) => {
                ProtectionReduction::CurrentValuesUnknown
            }
            (
                ValueInEffect::KnownValue(Self(SwitchState::SwitchedOff)),
                SwitchState::SwitchedOn,
            ) => ProtectionReduction::SkippedLocationAdded,
        }
    }
}

fn limit_lowered<Limit: Ord>(
    limit_in_effect: ValueInEffect<Limit>,
    new_limit: &Limit,
) -> ProtectionReduction {
    match limit_in_effect {
        ValueInEffect::KnownValue(current_limit) if *new_limit >= current_limit => {
            ProtectionReduction::NoReduction
        }
        ValueInEffect::KnownValue(_higher_limit) => ProtectionReduction::ScanLimitLowered,
        ValueInEffect::UnknownValue => ProtectionReduction::CurrentValuesUnknown,
    }
}

impl<const CLAMAV_DEFAULT: i32> TunableValue for CountLimit<CLAMAV_DEFAULT> {
    fn unconfigured_default() -> Self {
        Self(ClamdNumber::clamav_default(CLAMAV_DEFAULT))
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        limit_lowered(base_value.value_in_effect(), new_value)
    }
}

impl<const CLAMAV_DEFAULT_BYTES: u64> TunableValue for SizeLimit<CLAMAV_DEFAULT_BYTES> {
    fn unconfigured_default() -> Self {
        Self(ClamdSize::LimitedTo(bytesize::ByteSize::b(
            CLAMAV_DEFAULT_BYTES,
        )))
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        limit_lowered(base_value.value_in_effect(), new_value)
    }
}

impl TunableValue for ThreadCount {
    fn unconfigured_default() -> Self {
        Self(ClamdNumber::clamav_default(CLAMD_DEFAULT_MAX_THREADS))
    }

    fn protection_change(
        _base_value: &BaseValue<'_, Self>,
        _new_value: &Self,
    ) -> ProtectionReduction {
        ProtectionReduction::NoReduction
    }
}

impl TunableValue for WatchedFolders {
    fn unconfigured_default() -> Self {
        Self(Vec::new())
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        match base_value.value_in_effect() {
            ValueInEffect::KnownValue(Self(watched_before))
                if watched_before
                    .iter()
                    .any(|watched_folder| !new_value.0.contains(watched_folder)) =>
            {
                ProtectionReduction::WatchedFolderRemoved
            }
            ValueInEffect::KnownValue(_still_watched) => ProtectionReduction::NoReduction,
            ValueInEffect::UnknownValue => ProtectionReduction::CurrentValuesUnknown,
        }
    }
}

fn skip_entries_added<Entry: PartialEq>(
    skipped_in_effect: ValueInEffect<Vec<Entry>>,
    new_entries: &[Entry],
) -> ProtectionReduction {
    match skipped_in_effect {
        ValueInEffect::UnknownValue if new_entries.is_empty() => ProtectionReduction::NoReduction,
        ValueInEffect::UnknownValue => ProtectionReduction::CurrentValuesUnknown,
        ValueInEffect::KnownValue(skipped_before)
            if new_entries
                .iter()
                .any(|new_entry| !skipped_before.contains(new_entry)) =>
        {
            ProtectionReduction::SkippedLocationAdded
        }
        ValueInEffect::KnownValue(_nothing_new) => ProtectionReduction::NoReduction,
    }
}

impl TunableValue for SkippedPaths {
    fn unconfigured_default() -> Self {
        Self(Vec::new())
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        skip_entries_added(
            mapped_in_effect(base_value.value_in_effect(), |skipped_paths| {
                skipped_paths.0
            }),
            &new_value.0,
        )
    }
}

impl TunableValue for SkippedPatterns {
    fn unconfigured_default() -> Self {
        Self(Vec::new())
    }

    fn protection_change(
        base_value: &BaseValue<'_, Self>,
        new_value: &Self,
    ) -> ProtectionReduction {
        skip_entries_added(
            mapped_in_effect(base_value.value_in_effect(), |skipped_patterns| {
                skipped_patterns.0
            }),
            &new_value.0,
        )
    }
}

#[cfg(test)]
mod protection_rules_tests {
    use bytesize::ByteSize;

    use super::*;
    use crate::setting_values::{CLAMAV_DEFAULT_MAX_FILE_SIZE, ContainedPath};

    fn configured<Value>(configured_value: Value) -> ConfiguredValue<Value> {
        ConfiguredValue::Configured(configured_value)
    }

    fn folders(folder_paths: &[&str]) -> Vec<ContainedPath> {
        folder_paths
            .iter()
            .map(|folder_path| ContainedPath::try_from((*folder_path).to_owned()).expect("path"))
            .collect()
    }

    #[test]
    fn turning_prevention_off_weakens_protection() {
        let prevention_on = configured(BlockingSwitch(SwitchState::SwitchedOn));
        assert_eq!(
            BlockingSwitch::protection_change(
                &BaseValue::KnownBase(&prevention_on),
                &BlockingSwitch(SwitchState::SwitchedOff)
            ),
            ProtectionReduction::BlockingTurnedOff
        );
        assert_eq!(
            BlockingSwitch::protection_change(
                &BaseValue::KnownBase(&ConfiguredValue::NotConfigured),
                &BlockingSwitch(SwitchState::SwitchedOff)
            ),
            ProtectionReduction::NoReduction
        );
    }

    #[test]
    fn unconfigured_checks_fall_back_to_the_clamd_default() {
        assert_eq!(
            ContentCheck::<true>::protection_change(
                &BaseValue::KnownBase(&ConfiguredValue::NotConfigured),
                &ContentCheck(SwitchState::SwitchedOff)
            ),
            ProtectionReduction::CheckTurnedOff
        );
        assert_eq!(
            ContentCheck::<false>::protection_change(
                &BaseValue::KnownBase(&ConfiguredValue::NotConfigured),
                &ContentCheck(SwitchState::SwitchedOff)
            ),
            ProtectionReduction::NoReduction
        );
    }

    #[test]
    fn an_unknown_base_makes_turning_off_a_possible_reduction() {
        assert_eq!(
            ContentCheck::<false>::protection_change(
                &BaseValue::UnknownBase,
                &ContentCheck(SwitchState::SwitchedOff)
            ),
            ProtectionReduction::CurrentValuesUnknown
        );
        assert_eq!(
            ContentCheck::<false>::protection_change(
                &BaseValue::UnknownBase,
                &ContentCheck(SwitchState::SwitchedOn)
            ),
            ProtectionReduction::NoReduction
        );
    }

    #[test]
    fn lowering_a_limit_weakens_protection() {
        type FileSizeLimit = SizeLimit<CLAMAV_DEFAULT_MAX_FILE_SIZE>;
        let current_limit = configured(SizeLimit(ClamdSize::LimitedTo(ByteSize::mib(100))));
        assert_eq!(
            FileSizeLimit::protection_change(
                &BaseValue::KnownBase(&current_limit),
                &SizeLimit(ClamdSize::LimitedTo(ByteSize::mib(10)))
            ),
            ProtectionReduction::ScanLimitLowered
        );
        assert_eq!(
            FileSizeLimit::protection_change(
                &BaseValue::KnownBase(&current_limit),
                &SizeLimit(ClamdSize::LimitedTo(ByteSize::kib(102_400)))
            ),
            ProtectionReduction::NoReduction
        );
        assert_eq!(
            FileSizeLimit::protection_change(
                &BaseValue::KnownBase(&ConfiguredValue::NotConfigured),
                &SizeLimit(ClamdSize::LimitedTo(ByteSize::mib(50)))
            ),
            ProtectionReduction::ScanLimitLowered
        );
        assert_eq!(
            FileSizeLimit::protection_change(
                &BaseValue::KnownBase(&current_limit),
                &SizeLimit(ClamdSize::Unlimited)
            ),
            ProtectionReduction::NoReduction
        );
    }

    #[test]
    fn removing_a_watched_folder_weakens_protection() {
        let watched_before = configured(WatchedFolders(folders(&["/a", "/b"])));
        assert_eq!(
            WatchedFolders::protection_change(
                &BaseValue::KnownBase(&watched_before),
                &WatchedFolders(folders(&["/a"]))
            ),
            ProtectionReduction::WatchedFolderRemoved
        );
        assert_eq!(
            WatchedFolders::protection_change(
                &BaseValue::KnownBase(&watched_before),
                &WatchedFolders(folders(&["/a", "/b", "/c"]))
            ),
            ProtectionReduction::NoReduction
        );
    }

    #[test]
    fn adding_an_exclusion_weakens_protection() {
        assert_eq!(
            SkippedPaths::protection_change(
                &BaseValue::KnownBase(&ConfiguredValue::NotConfigured),
                &SkippedPaths(folders(&["/a"]))
            ),
            ProtectionReduction::SkippedLocationAdded
        );
        assert_eq!(
            SkipSwitch::protection_change(
                &BaseValue::KnownBase(&ConfiguredValue::NotConfigured),
                &SkipSwitch(SwitchState::SwitchedOn)
            ),
            ProtectionReduction::SkippedLocationAdded
        );
        assert_eq!(
            SkipSwitch::protection_change(
                &BaseValue::KnownBase(&configured(SkipSwitch(SwitchState::SwitchedOn))),
                &SkipSwitch(SwitchState::SwitchedOff)
            ),
            ProtectionReduction::NoReduction
        );
    }

    #[test]
    fn journal_values_round_trip() {
        assert_eq!(
            ProtectionReduction::from_journal_field_value(
                ProtectionReduction::ScanLimitLowered.journal_field_value()
            ),
            Some(ProtectionReduction::ScanLimitLowered)
        );
    }
}
