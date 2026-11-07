use std::{cmp::Ordering, fmt};

use bytesize::ByteSize;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

const KIBIBYTE: u64 = 1024;
const MEBIBYTE: u64 = KIBIBYTE * 1024;
const GIBIBYTE: u64 = MEBIBYTE * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchState {
    SwitchedOn,
    SwitchedOff,
}

impl SwitchState {
    pub const fn is_switched_on(self) -> bool {
        matches!(self, Self::SwitchedOn)
    }

    pub const fn clamd_text(self) -> &'static str {
        match self {
            Self::SwitchedOn => "yes",
            Self::SwitchedOff => "no",
        }
    }
}

impl std::str::FromStr for SwitchState {
    type Err = SettingValueRefusal;

    fn from_str(switch_text: &str) -> Result<Self, Self::Err> {
        match switch_text.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "on" => Ok(Self::SwitchedOn),
            "no" | "false" | "off" => Ok(Self::SwitchedOff),
            _other_text => Err(SettingValueRefusal::NotASwitch),
        }
    }
}

impl Serialize for SwitchState {
    fn serialize<SwitchSerializer: Serializer>(
        &self,
        serializer: SwitchSerializer,
    ) -> Result<SwitchSerializer::Ok, SwitchSerializer::Error> {
        serializer.serialize_bool(self.is_switched_on())
    }
}

struct SwitchStateVisitor;

impl de::Visitor<'_> for SwitchStateVisitor {
    type Value = SwitchState;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("yes, no, true or false")
    }

    fn visit_bool<VisitError: de::Error>(
        self,
        switched_on: bool,
    ) -> Result<SwitchState, VisitError> {
        Ok(if switched_on {
            SwitchState::SwitchedOn
        } else {
            SwitchState::SwitchedOff
        })
    }

    fn visit_str<VisitError: de::Error>(
        self,
        switch_text: &str,
    ) -> Result<SwitchState, VisitError> {
        switch_text.parse().map_err(VisitError::custom)
    }
}

impl<'de> Deserialize<'de> for SwitchState {
    fn deserialize<SwitchDeserializer: Deserializer<'de>>(
        deserializer: SwitchDeserializer,
    ) -> Result<Self, SwitchDeserializer::Error> {
        deserializer.deserialize_any(SwitchStateVisitor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SettingValueRefusal {
    #[error("the value is not yes or no")]
    NotASwitch,
    #[error("the value is not a size such as 100M, 512K, 2G or a number of bytes")]
    NotASize,
    #[error("the value is not a whole number that clamd can read")]
    NotAClamdNumber,
    #[error("the path must be absolute and must not contain ..")]
    PathNotContained,
    #[error("the text must be non-empty, trimmed and without control characters")]
    TextNotSafe,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct ClamdNumber(u32);

impl ClamdNumber {
    pub const fn count(self) -> u32 {
        self.0
    }

    pub const fn clamav_default(default_count: i32) -> Self {
        Self(default_count.unsigned_abs())
    }
}

impl TryFrom<i64> for ClamdNumber {
    type Error = SettingValueRefusal;

    fn try_from(number_value: i64) -> Result<Self, Self::Error> {
        i32::try_from(number_value)
            .ok()
            .and_then(|clamd_int| u32::try_from(clamd_int).ok())
            .map(Self)
            .ok_or(SettingValueRefusal::NotAClamdNumber)
    }
}

impl From<ClamdNumber> for i64 {
    fn from(clamd_number: ClamdNumber) -> Self {
        Self::from(clamd_number.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClamdSize {
    Unlimited,
    LimitedTo(ByteSize),
}

impl Ord for ClamdSize {
    fn cmp(&self, other_size: &Self) -> Ordering {
        match (self, other_size) {
            (Self::Unlimited, Self::Unlimited) => Ordering::Equal,
            (Self::Unlimited, Self::LimitedTo(_)) => Ordering::Greater,
            (Self::LimitedTo(_), Self::Unlimited) => Ordering::Less,
            (Self::LimitedTo(own_bytes), Self::LimitedTo(other_bytes)) => {
                own_bytes.cmp(other_bytes)
            }
        }
    }
}

impl PartialOrd for ClamdSize {
    fn partial_cmp(&self, other_size: &Self) -> Option<Ordering> {
        Some(self.cmp(other_size))
    }
}

impl std::str::FromStr for ClamdSize {
    type Err = SettingValueRefusal;

    fn from_str(size_text: &str) -> Result<Self, Self::Err> {
        let trimmed_text = size_text.trim();
        let (digit_text, unit_multiplier) = match trimmed_text.chars().last() {
            Some('k' | 'K') => (&trimmed_text[..trimmed_text.len() - 1], KIBIBYTE),
            Some('m' | 'M') => (&trimmed_text[..trimmed_text.len() - 1], MEBIBYTE),
            Some('g' | 'G') => (&trimmed_text[..trimmed_text.len() - 1], GIBIBYTE),
            Some(_digit) => (trimmed_text, 1),
            None => return Err(SettingValueRefusal::NotASize),
        };
        if digit_text.is_empty()
            || !digit_text
                .chars()
                .all(|digit_character| digit_character.is_ascii_digit())
        {
            return Err(SettingValueRefusal::NotASize);
        }
        let byte_count = digit_text
            .parse::<i64>()
            .ok()
            .and_then(|unit_count| u64::try_from(unit_count).ok())
            .and_then(|unit_count| unit_count.checked_mul(unit_multiplier))
            .filter(|byte_count| i64::try_from(*byte_count).is_ok())
            .ok_or(SettingValueRefusal::NotASize)?;
        Ok(if byte_count == 0 {
            Self::Unlimited
        } else {
            Self::LimitedTo(ByteSize::b(byte_count))
        })
    }
}

impl fmt::Display for ClamdSize {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self::LimitedTo(byte_size) = self else {
            return formatter.write_str("0");
        };
        let byte_count = byte_size.as_u64();
        match [(GIBIBYTE, "G"), (MEBIBYTE, "M"), (KIBIBYTE, "K")]
            .into_iter()
            .find(|(unit_bytes, _unit_suffix)| byte_count.is_multiple_of(*unit_bytes))
        {
            Some((unit_bytes, unit_suffix)) => {
                write!(formatter, "{}{unit_suffix}", byte_count / unit_bytes)
            }
            None => write!(formatter, "{byte_count}"),
        }
    }
}

impl Serialize for ClamdSize {
    fn serialize<SizeSerializer: Serializer>(
        &self,
        serializer: SizeSerializer,
    ) -> Result<SizeSerializer::Ok, SizeSerializer::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

struct ClamdSizeVisitor;

impl de::Visitor<'_> for ClamdSizeVisitor {
    type Value = ClamdSize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a size such as 100M, 512K, 2G or a number of bytes")
    }

    fn visit_i64<VisitError: de::Error>(self, byte_count: i64) -> Result<ClamdSize, VisitError> {
        byte_count.to_string().parse().map_err(VisitError::custom)
    }

    fn visit_u64<VisitError: de::Error>(self, byte_count: u64) -> Result<ClamdSize, VisitError> {
        byte_count.to_string().parse().map_err(VisitError::custom)
    }

    fn visit_str<VisitError: de::Error>(self, size_text: &str) -> Result<ClamdSize, VisitError> {
        size_text.parse().map_err(VisitError::custom)
    }
}

impl<'de> Deserialize<'de> for ClamdSize {
    fn deserialize<SizeDeserializer: Deserializer<'de>>(
        deserializer: SizeDeserializer,
    ) -> Result<Self, SizeDeserializer::Error> {
        deserializer.deserialize_any(ClamdSizeVisitor)
    }
}

fn text_is_safe(setting_text: &str) -> bool {
    !setting_text.is_empty()
        && setting_text == setting_text.trim()
        && !setting_text.chars().any(char::is_control)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SafeText(String);

impl SafeText {
    pub fn as_text(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SafeText {
    type Error = SettingValueRefusal;

    fn try_from(setting_text: String) -> Result<Self, Self::Error> {
        if text_is_safe(&setting_text) {
            Ok(Self(setting_text))
        } else {
            Err(SettingValueRefusal::TextNotSafe)
        }
    }
}

impl From<SafeText> for String {
    fn from(safe_text: SafeText) -> Self {
        safe_text.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainedPath(String);

impl ContainedPath {
    pub fn as_text(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ContainedPath {
    type Error = SettingValueRefusal;

    fn try_from(path_text: String) -> Result<Self, Self::Error> {
        let is_contained = path_text.starts_with('/')
            && !path_text
                .split('/')
                .any(|path_segment| path_segment == "..");
        if is_contained && text_is_safe(&path_text) {
            Ok(Self(path_text))
        } else {
            Err(SettingValueRefusal::PathNotContained)
        }
    }
}

impl From<ContainedPath> for String {
    fn from(contained_path: ContainedPath) -> Self {
        contained_path.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlockingSwitch(pub SwitchState);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContentCheck<const ON_BY_DEFAULT: bool>(pub SwitchState);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SkipSwitch(pub SwitchState);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CountLimit<const CLAMAV_DEFAULT: i32>(pub ClamdNumber);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SizeLimit<const CLAMAV_DEFAULT_BYTES: u64>(pub ClamdSize);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThreadCount(pub ClamdNumber);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WatchedFolders(pub Vec<ContainedPath>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SkippedPaths(pub Vec<ContainedPath>);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SkippedPatterns(pub Vec<SafeText>);

pub const fn mebibytes(mebibyte_count: u64) -> u64 {
    mebibyte_count * MEBIBYTE
}

pub const CLAMAV_DEFAULT_MAX_SCAN_TIME: i32 = 120_000;
pub const CLAMAV_DEFAULT_MAX_RECURSION: i32 = 17;
pub const CLAMAV_DEFAULT_MAX_FILES: i32 = 10_000;
pub const CLAMD_DEFAULT_MAX_DIRECTORY_RECURSION: i32 = 15;
pub const CLAMD_DEFAULT_MAX_THREADS: i32 = 10;
pub const CLAMAV_DEFAULT_MAX_EMBEDDED_PE: u64 = mebibytes(40);
pub const CLAMAV_DEFAULT_MAX_SCAN_SIZE: u64 = mebibytes(400);
pub const CLAMAV_DEFAULT_MAX_FILE_SIZE: u64 = mebibytes(100);
pub const CLAMD_DEFAULT_ON_ACCESS_MAX_FILE_SIZE: u64 = mebibytes(5);
pub const CLAMAV_DEFAULT_PCRE_MAX_FILE_SIZE: u64 = mebibytes(100);

#[cfg(test)]
mod setting_values_tests {
    use super::*;

    fn size_of(size_text: &str) -> Result<ClamdSize, SettingValueRefusal> {
        size_text.parse()
    }

    #[test]
    fn clamd_sizes_use_binary_units_and_zero_means_unlimited() {
        assert_eq!(
            size_of("200M"),
            Ok(ClamdSize::LimitedTo(ByteSize::mib(200)))
        );
        assert_eq!(
            size_of("512k"),
            Ok(ClamdSize::LimitedTo(ByteSize::kib(512)))
        );
        assert_eq!(size_of("2G"), Ok(ClamdSize::LimitedTo(ByteSize::gib(2))));
        assert_eq!(size_of("4096"), Ok(ClamdSize::LimitedTo(ByteSize::b(4096))));
        assert_eq!(size_of("0"), Ok(ClamdSize::Unlimited));
        assert_eq!(size_of("lots"), Err(SettingValueRefusal::NotASize));
        assert_eq!(size_of(""), Err(SettingValueRefusal::NotASize));
        assert_eq!(size_of("-5M"), Err(SettingValueRefusal::NotASize));
        assert_eq!(
            size_of("9223372036854775807G"),
            Err(SettingValueRefusal::NotASize)
        );
    }

    #[test]
    fn an_unlimited_size_is_larger_than_any_limit() {
        assert!(ClamdSize::Unlimited > ClamdSize::LimitedTo(ByteSize::gib(4)));
    }

    #[test]
    fn sizes_render_in_the_largest_exact_unit() {
        assert_eq!(ClamdSize::LimitedTo(ByteSize::mib(200)).to_string(), "200M");
        assert_eq!(ClamdSize::LimitedTo(ByteSize::gib(2)).to_string(), "2G");
        assert_eq!(
            ClamdSize::LimitedTo(ByteSize::kib(1536)).to_string(),
            "1536K"
        );
        assert_eq!(ClamdSize::LimitedTo(ByteSize::b(1000)).to_string(), "1000");
        assert_eq!(ClamdSize::Unlimited.to_string(), "0");
    }

    #[test]
    fn numbers_fit_the_c_int_that_clamd_parses_them_into() {
        assert!(ClamdNumber::try_from(i64::from(i32::MAX)).is_ok());
        assert!(ClamdNumber::try_from(i64::from(i32::MAX) + 1).is_err());
        assert!(ClamdNumber::try_from(-1).is_err());
    }

    #[test]
    fn switches_accept_every_clamd_spelling() {
        assert_eq!("yes".parse(), Ok(SwitchState::SwitchedOn));
        assert_eq!("True".parse(), Ok(SwitchState::SwitchedOn));
        assert_eq!("no".parse(), Ok(SwitchState::SwitchedOff));
        assert_eq!(
            "maybe".parse::<SwitchState>(),
            Err(SettingValueRefusal::NotASwitch)
        );
    }

    #[test]
    fn paths_must_stay_absolute_and_contained() {
        assert!(ContainedPath::try_from("/home/user/Downloads".to_owned()).is_ok());
        assert!(ContainedPath::try_from("home".to_owned()).is_err());
        assert!(ContainedPath::try_from("/home/../etc".to_owned()).is_err());
        assert!(ContainedPath::try_from("/home\nVirusEvent /bin/sh".to_owned()).is_err());
    }

    #[test]
    fn text_refuses_line_breaks_and_padding() {
        assert!(SafeText::try_from("^/proc/".to_owned()).is_ok());
        assert!(SafeText::try_from("a\nb".to_owned()).is_err());
        assert!(SafeText::try_from(" padded".to_owned()).is_err());
        assert!(SafeText::try_from(String::new()).is_err());
    }
}
