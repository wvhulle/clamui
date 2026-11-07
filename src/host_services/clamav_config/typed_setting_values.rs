use crate::host_services::settings_helper::protection_change_rules::{
    SettingValueKind, limit_in_units, path_is_absolute_and_contained, setting_value_kind,
    value_fits_setting_kind, value_has_only_safe_characters, whole_number_in_text,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchPosition {
    SwitchedOn,
    SwitchedOff,
}

impl SwitchPosition {
    pub const fn from_switch_active(switch_active: bool) -> Self {
        if switch_active {
            Self::SwitchedOn
        } else {
            Self::SwitchedOff
        }
    }

    pub const fn is_switched_on(self) -> bool {
        matches!(self, Self::SwitchedOn)
    }

    pub const fn config_text(self) -> &'static str {
        match self {
            Self::SwitchedOn => "yes",
            Self::SwitchedOff => "no",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SizeUnit {
    PlainBytes,
    Kibibytes,
    Mebibytes,
}

pub const SIZE_UNITS: [SizeUnit; 3] = [
    SizeUnit::PlainBytes,
    SizeUnit::Kibibytes,
    SizeUnit::Mebibytes,
];

impl SizeUnit {
    pub const fn config_suffix(self) -> &'static str {
        match self {
            Self::PlainBytes => "",
            Self::Kibibytes => "K",
            Self::Mebibytes => "M",
        }
    }

    pub fn unit_position(self) -> u32 {
        match self {
            Self::PlainBytes => 0,
            Self::Kibibytes => 1,
            Self::Mebibytes => 2,
        }
    }

    pub fn unit_at_position(unit_position: u32) -> Option<Self> {
        SIZE_UNITS
            .into_iter()
            .find(|size_unit| size_unit.unit_position() == unit_position)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SizeAmount {
    pub unit_count: u64,
    pub size_unit: SizeUnit,
}

impl SizeAmount {
    pub fn config_text(self) -> String {
        format!("{}{}", self.unit_count, self.size_unit.config_suffix())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TypedSettingValue {
    BooleanValue(SwitchPosition),
    CountValue {
        count_value: u64,
        minimum: u64,
        maximum: u64,
    },
    SizeValue(SizeAmount),
    PathValue(String),
    TextValue(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingParseFailure {
    UnknownOption,
    NotYesOrNo,
    NotAWholeNumber,
    CountOutOfRange { minimum: u64, maximum: u64 },
    NotASize,
    PathNotAbsolute,
    EmptyText,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteRefusal {
    ValueNotParsed(SettingParseFailure),
    UnsafeCharacters,
}

fn parsed_size_amount(size_text: &str) -> Option<SizeAmount> {
    limit_in_units(size_text)?;
    let (digits, size_unit) = match size_text.chars().last()? {
        'k' | 'K' => (&size_text[..size_text.len() - 1], SizeUnit::Kibibytes),
        'm' | 'M' => (&size_text[..size_text.len() - 1], SizeUnit::Mebibytes),
        _no_suffix => (size_text, SizeUnit::PlainBytes),
    };
    Some(SizeAmount {
        unit_count: whole_number_in_text(digits)?,
        size_unit,
    })
}

pub fn parse_value_of_kind(
    setting_value: &str,
    value_kind: SettingValueKind,
) -> Result<TypedSettingValue, SettingParseFailure> {
    match value_kind {
        SettingValueKind::BooleanSetting => match setting_value {
            "yes" | "true" => Ok(TypedSettingValue::BooleanValue(SwitchPosition::SwitchedOn)),
            "no" | "false" => Ok(TypedSettingValue::BooleanValue(SwitchPosition::SwitchedOff)),
            _not_a_switch_value => Err(SettingParseFailure::NotYesOrNo),
        },
        SettingValueKind::CountSetting { minimum, maximum } => {
            let count_value =
                whole_number_in_text(setting_value).ok_or(SettingParseFailure::NotAWholeNumber)?;
            if (minimum..=maximum).contains(&count_value) {
                Ok(TypedSettingValue::CountValue {
                    count_value,
                    minimum,
                    maximum,
                })
            } else {
                Err(SettingParseFailure::CountOutOfRange { minimum, maximum })
            }
        }
        SettingValueKind::SizeSetting => parsed_size_amount(setting_value)
            .map(TypedSettingValue::SizeValue)
            .ok_or(SettingParseFailure::NotASize),
        SettingValueKind::PathSetting | SettingValueKind::PathListSetting => {
            if path_is_absolute_and_contained(setting_value) {
                Ok(TypedSettingValue::PathValue(setting_value.to_owned()))
            } else {
                Err(SettingParseFailure::PathNotAbsolute)
            }
        }
        SettingValueKind::TextSetting => {
            if setting_value.is_empty() {
                Err(SettingParseFailure::EmptyText)
            } else {
                Ok(TypedSettingValue::TextValue(setting_value.to_owned()))
            }
        }
        SettingValueKind::UnknownSetting => Err(SettingParseFailure::UnknownOption),
    }
}

pub fn parse_setting_value(
    setting_key: &str,
    setting_value: &str,
) -> Result<TypedSettingValue, SettingParseFailure> {
    parse_value_of_kind(setting_value, setting_value_kind(setting_key))
}

pub fn writable_setting_value(
    setting_key: &str,
    setting_value: &str,
) -> Result<String, WriteRefusal> {
    parse_setting_value(setting_key, setting_value).map_err(WriteRefusal::ValueNotParsed)?;
    if value_has_only_safe_characters(setting_value)
        && value_fits_setting_kind(setting_value, setting_value_kind(setting_key))
    {
        Ok(setting_value.to_owned())
    } else {
        Err(WriteRefusal::UnsafeCharacters)
    }
}

#[cfg(test)]
mod typed_setting_values_tests {
    use super::*;

    #[test]
    fn booleans_accept_yes_no_true_and_false() {
        assert_eq!(
            parse_setting_value("OnAccessExtraScanning", "true"),
            Ok(TypedSettingValue::BooleanValue(SwitchPosition::SwitchedOn))
        );
        assert_eq!(
            parse_setting_value("DetectPUA", "no"),
            Ok(TypedSettingValue::BooleanValue(SwitchPosition::SwitchedOff))
        );
        assert_eq!(
            parse_setting_value("OnAccessExtraScanning", "tru"),
            Err(SettingParseFailure::NotYesOrNo)
        );
    }

    #[test]
    fn counts_keep_to_their_range() {
        assert_eq!(
            parse_setting_value("MaxThreads", "8"),
            Ok(TypedSettingValue::CountValue {
                count_value: 8,
                minimum: 1,
                maximum: 256
            })
        );
        assert_eq!(
            parse_setting_value("MaxThreads", "eight"),
            Err(SettingParseFailure::NotAWholeNumber)
        );
        assert_eq!(
            parse_setting_value("MaxThreads", "0"),
            Err(SettingParseFailure::CountOutOfRange {
                minimum: 1,
                maximum: 256
            })
        );
    }

    #[test]
    fn sizes_keep_their_unit() {
        assert_eq!(
            parse_setting_value("MaxFileSize", "100M"),
            Ok(TypedSettingValue::SizeValue(SizeAmount {
                unit_count: 100,
                size_unit: SizeUnit::Mebibytes
            }))
        );
        assert_eq!(
            parse_setting_value("OnAccessMaxFileSize", "512k"),
            Ok(TypedSettingValue::SizeValue(SizeAmount {
                unit_count: 512,
                size_unit: SizeUnit::Kibibytes
            }))
        );
        assert_eq!(
            parse_setting_value("StreamMaxLength", "4096"),
            Ok(TypedSettingValue::SizeValue(SizeAmount {
                unit_count: 4096,
                size_unit: SizeUnit::PlainBytes
            }))
        );
        assert_eq!(
            parse_setting_value("MaxFileSize", "1G"),
            Err(SettingParseFailure::NotASize)
        );
        assert_eq!(
            SizeAmount {
                unit_count: 100,
                size_unit: SizeUnit::Mebibytes
            }
            .config_text(),
            "100M"
        );
    }

    #[test]
    fn paths_must_be_absolute_and_stay_inside() {
        assert_eq!(
            parse_setting_value("OnAccessIncludePath", "/home/user/Downloads"),
            Ok(TypedSettingValue::PathValue(
                "/home/user/Downloads".to_owned()
            ))
        );
        assert_eq!(
            parse_setting_value("LogFile", "clamd.log"),
            Err(SettingParseFailure::PathNotAbsolute)
        );
        assert_eq!(
            parse_setting_value("OnAccessExcludePath", "/srv/../etc"),
            Err(SettingParseFailure::PathNotAbsolute)
        );
    }

    #[test]
    fn options_outside_the_table_are_unknown() {
        assert_eq!(
            parse_setting_value("NotARealClamdOption", "rejected"),
            Err(SettingParseFailure::UnknownOption)
        );
        assert_eq!(
            parse_setting_value("DatabaseMirror", ""),
            Err(SettingParseFailure::EmptyText)
        );
    }

    #[test]
    fn parsing_agrees_with_what_the_helper_accepts() {
        [
            ("OnAccessPrevention", "yes"),
            ("OnAccessPrevention", "maybe"),
            ("MaxThreads", "8"),
            ("MaxThreads", "300"),
            ("MaxThreads", "+3"),
            ("MaxFileSize", "25M"),
            ("MaxFileSize", "lots"),
            ("OnAccessIncludePath", "/home"),
            ("OnAccessIncludePath", "home"),
            ("DatabaseMirror", "database.clamav.net"),
            ("NotARealClamdOption", "rejected"),
        ]
        .into_iter()
        .for_each(|(setting_key, setting_value)| {
            assert_eq!(
                parse_setting_value(setting_key, setting_value).is_ok(),
                value_fits_setting_kind(setting_value, setting_value_kind(setting_key)),
                "{setting_key} {setting_value}"
            );
        });
    }

    #[test]
    fn only_safe_parsed_values_can_be_written() {
        assert_eq!(
            writable_setting_value("DatabaseMirror", "mirror.example.org"),
            Ok("mirror.example.org".to_owned())
        );
        assert_eq!(
            writable_setting_value("DatabaseMirror", "a;reboot"),
            Err(WriteRefusal::UnsafeCharacters)
        );
        assert_eq!(
            writable_setting_value("MaxThreads", "many"),
            Err(WriteRefusal::ValueNotParsed(
                SettingParseFailure::NotAWholeNumber
            ))
        );
    }
}
