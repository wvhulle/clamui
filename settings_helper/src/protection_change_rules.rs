#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchRole {
    BlocksAccess,
    ChecksContent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectiveSwitch {
    pub setting_key: &'static str,
    pub on_by_default: bool,
    pub switch_role: SwitchRole,
}

const fn content_check(setting_key: &'static str, on_by_default: bool) -> ProtectiveSwitch {
    ProtectiveSwitch {
        setting_key,
        on_by_default,
        switch_role: SwitchRole::ChecksContent,
    }
}

const PROTECTIVE_SWITCHES: [ProtectiveSwitch; 21] = [
    ProtectiveSwitch {
        setting_key: "OnAccessPrevention",
        on_by_default: false,
        switch_role: SwitchRole::BlocksAccess,
    },
    content_check("OnAccessExtraScanning", false),
    content_check("ScanPE", true),
    content_check("ScanELF", true),
    content_check("ScanOLE2", true),
    content_check("ScanPDF", true),
    content_check("ScanHTML", true),
    content_check("ScanMail", true),
    content_check("ScanArchive", true),
    content_check("ScanSWF", true),
    content_check("ScanXMLDOCS", true),
    content_check("ScanHWP3", true),
    content_check("AlertBrokenExecutables", false),
    content_check("AlertEncrypted", false),
    content_check("AlertEncryptedArchive", false),
    content_check("AlertEncryptedDoc", false),
    content_check("AlertOLE2Macros", false),
    content_check("AlertExceedsMax", false),
    content_check("DetectPUA", false),
    content_check("HeuristicAlerts", true),
    content_check("Bytecode", true),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScanLimitDefault {
    setting_key: &'static str,
    default_limit: u64,
}

const MEBIBYTE: u64 = 1024 * 1024;

const SCAN_LIMIT_DEFAULTS: [ScanLimitDefault; 9] = [
    ScanLimitDefault {
        setting_key: "MaxScanTime",
        default_limit: 120_000,
    },
    ScanLimitDefault {
        setting_key: "MaxRecursion",
        default_limit: 17,
    },
    ScanLimitDefault {
        setting_key: "MaxFiles",
        default_limit: 10_000,
    },
    ScanLimitDefault {
        setting_key: "MaxDirectoryRecursion",
        default_limit: 15,
    },
    ScanLimitDefault {
        setting_key: "MaxEmbeddedPE",
        default_limit: 40 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "MaxScanSize",
        default_limit: 400 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "MaxFileSize",
        default_limit: 100 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "OnAccessMaxFileSize",
        default_limit: 5 * MEBIBYTE,
    },
    ScanLimitDefault {
        setting_key: "PCREMaxFileSize",
        default_limit: 100 * MEBIBYTE,
    },
];

const COUNT_CEILING: u64 = 4_294_967_295;
const MAXIMUM_VALUE_LENGTH: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingValueKind {
    BooleanSetting,
    CountSetting { minimum: u64, maximum: u64 },
    SizeSetting,
    PathSetting,
    PathListSetting,
    TextSetting,
    UnknownSetting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KnownSettingOption {
    setting_key: &'static str,
    value_kind: SettingValueKind,
}

const fn boolean_option(setting_key: &'static str) -> KnownSettingOption {
    KnownSettingOption {
        setting_key,
        value_kind: SettingValueKind::BooleanSetting,
    }
}

const fn count_option(setting_key: &'static str, minimum: u64, maximum: u64) -> KnownSettingOption {
    KnownSettingOption {
        setting_key,
        value_kind: SettingValueKind::CountSetting { minimum, maximum },
    }
}

const fn size_option(setting_key: &'static str) -> KnownSettingOption {
    KnownSettingOption {
        setting_key,
        value_kind: SettingValueKind::SizeSetting,
    }
}

const fn path_option(setting_key: &'static str) -> KnownSettingOption {
    KnownSettingOption {
        setting_key,
        value_kind: SettingValueKind::PathSetting,
    }
}

const fn path_list_option(setting_key: &'static str) -> KnownSettingOption {
    KnownSettingOption {
        setting_key,
        value_kind: SettingValueKind::PathListSetting,
    }
}

const fn text_option(setting_key: &'static str) -> KnownSettingOption {
    KnownSettingOption {
        setting_key,
        value_kind: SettingValueKind::TextSetting,
    }
}

const KNOWN_SETTING_OPTIONS: [KnownSettingOption; 121] = [
    boolean_option("LogFileUnlock"),
    boolean_option("LogTime"),
    boolean_option("LogClean"),
    boolean_option("LogSyslog"),
    boolean_option("LogVerbose"),
    boolean_option("LogRotate"),
    boolean_option("ExtendedDetectionInfo"),
    boolean_option("Foreground"),
    boolean_option("Debug"),
    boolean_option("LeaveTemporaryFiles"),
    boolean_option("GenerateMetadataJson"),
    boolean_option("AllowAllMatchScan"),
    boolean_option("FixStaleSocket"),
    boolean_option("ExitOnOOM"),
    boolean_option("ConcurrentDatabaseReload"),
    boolean_option("DisableCache"),
    boolean_option("CrossFilesystems"),
    boolean_option("FollowDirectorySymlinks"),
    boolean_option("FollowFileSymlinks"),
    boolean_option("AllowSupplementaryGroups"),
    boolean_option("ScanOneNote"),
    boolean_option("ScanPartialMessages"),
    boolean_option("PhishingSignatures"),
    boolean_option("PhishingScanURLs"),
    boolean_option("ScanImage"),
    boolean_option("ScanImageFuzzyHash"),
    boolean_option("BytecodeUnsigned"),
    boolean_option("ForceToDisk"),
    boolean_option("HeuristicScanPrecedence"),
    boolean_option("AlertBrokenMedia"),
    boolean_option("AlertPhishingSSLMismatch"),
    boolean_option("AlertPhishingCloak"),
    boolean_option("AlertPartitionIntersection"),
    boolean_option("StructuredDataDetection"),
    boolean_option("StructuredSSNFormatNormal"),
    boolean_option("StructuredSSNFormatStripped"),
    boolean_option("DisableCertCheck"),
    boolean_option("OnAccessDisableDDD"),
    boolean_option("OnAccessDenyOnError"),
    boolean_option("OnAccessExcludeRootUID"),
    boolean_option("ScriptedUpdates"),
    boolean_option("CompressLocalDatabase"),
    boolean_option("TestDatabases"),
    count_option("MaxThreads", 1, 256),
    count_option("MaxQueue", 1, 65_536),
    count_option("IdleTimeout", 0, 86_400),
    count_option("ReadTimeout", 0, 86_400),
    count_option("CommandReadTimeout", 0, 86_400),
    count_option("SendBufTimeout", 0, 86_400_000),
    count_option("MaxConnectionQueueLength", 1, 65_535),
    count_option("SelfCheck", 0, 604_800),
    count_option("MaxDirectoryRecursion", 0, 255),
    count_option("MaxScanTime", 0, 86_400_000),
    count_option("MaxRecursion", 0, 255),
    count_option("MaxFiles", 0, COUNT_CEILING),
    count_option("MaxPartitions", 0, COUNT_CEILING),
    count_option("MaxIconsPE", 0, COUNT_CEILING),
    count_option("MaxRecHWP3", 0, 255),
    count_option("PCREMatchLimit", 0, COUNT_CEILING),
    count_option("PCRERecMatchLimit", 0, COUNT_CEILING),
    count_option("BytecodeTimeout", 0, 86_400_000),
    count_option("StructuredMinCreditCardCount", 1, 10_000),
    count_option("StructuredMinSSNCount", 1, 10_000),
    count_option("OnAccessMaxThreads", 1, 256),
    count_option("OnAccessCurlTimeout", 0, 86_400_000),
    count_option("OnAccessRetryAttempts", 0, 100),
    count_option("OnAccessExcludeUID", 0, COUNT_CEILING),
    count_option("StreamMinPort", 1024, 65_535),
    count_option("StreamMaxPort", 1024, 65_535),
    count_option("TCPSocket", 1, 65_535),
    count_option("Checks", 0, 50),
    count_option("HTTPProxyPort", 1, 65_535),
    count_option("ConnectTimeout", 0, 3600),
    count_option("ReceiveTimeout", 0, 86_400),
    count_option("MaxAttempts", 1, 100),
    size_option("MaxScanSize"),
    size_option("MaxFileSize"),
    size_option("OnAccessMaxFileSize"),
    size_option("PCREMaxFileSize"),
    size_option("MaxEmbeddedPE"),
    size_option("MaxHTMLNormalize"),
    size_option("MaxHTMLNoTags"),
    size_option("MaxScriptNormalize"),
    size_option("MaxZipTypeRcg"),
    size_option("StreamMaxLength"),
    size_option("LogFileMaxSize"),
    path_option("LogFile"),
    path_option("PidFile"),
    path_option("TemporaryDirectory"),
    path_option("DatabaseDirectory"),
    path_option("LocalSocket"),
    path_option("UpdateLogFile"),
    path_option("NotifyClamd"),
    path_list_option("OnAccessIncludePath"),
    path_list_option("OnAccessExcludePath"),
    path_list_option("OnAccessMountPath"),
    text_option("LogFacility"),
    text_option("LocalSocketGroup"),
    text_option("LocalSocketMode"),
    text_option("TCPAddr"),
    text_option("User"),
    text_option("DatabaseOwner"),
    text_option("ExcludePUA"),
    text_option("IncludePUA"),
    text_option("OnAccessExcludeUname"),
    text_option("BytecodeSecurity"),
    text_option("DatabaseMirror"),
    text_option("PrivateMirror"),
    text_option("DNSDatabaseInfo"),
    text_option("DatabaseCustomURL"),
    text_option("ExtraDatabase"),
    text_option("ExcludeDatabase"),
    text_option("HTTPProxyServer"),
    text_option("HTTPProxyUsername"),
    text_option("HTTPProxyPassword"),
    text_option("HTTPUserAgent"),
    text_option("LocalIPAddress"),
    text_option("VirusEvent"),
    text_option("OnUpdateExecute"),
    text_option("OnErrorExecute"),
    text_option("OnOutdatedExecute"),
];

const SKIP_LIST_SETTINGS: [&str; 6] = [
    "OnAccessExcludePath",
    "OnAccessExcludeRootUID",
    "OnAccessExcludeUID",
    "OnAccessExcludeUname",
    "ExcludePath",
    "ExcludePUA",
];
const WATCHED_FOLDER_SETTING: &str = "OnAccessIncludePath";

#[derive(Debug)]
pub enum ValuesInEffect<ReadFailure> {
    NotConfigured,
    Configured { setting_values: Vec<String> },
    ConfigUnreadable(ReadFailure),
}

impl<ReadFailure> ValuesInEffect<ReadFailure> {
    pub fn from_config_values(setting_values: Vec<String>) -> Self {
        if setting_values.is_empty() {
            Self::NotConfigured
        } else {
            Self::Configured { setting_values }
        }
    }
}

pub fn protective_switch_named(setting_key: &str) -> Option<&'static ProtectiveSwitch> {
    PROTECTIVE_SWITCHES
        .iter()
        .find(|protective_switch| protective_switch.setting_key == setting_key)
}

fn default_scan_limit(setting_key: &str) -> Option<u64> {
    SCAN_LIMIT_DEFAULTS
        .iter()
        .find(|limit_default| limit_default.setting_key == setting_key)
        .map(|limit_default| limit_default.default_limit)
}

fn is_scan_limit(setting_key: &str) -> bool {
    setting_key.ends_with("Size") || default_scan_limit(setting_key).is_some()
}

fn switch_is_on(setting_value: &str) -> bool {
    matches!(setting_value, "true" | "yes")
}

pub fn limit_in_units(limit_text: &str) -> Option<u64> {
    let (digits, multiplier) = match limit_text.chars().last()? {
        'k' | 'K' => (&limit_text[..limit_text.len() - 1], 1024),
        'm' | 'M' => (&limit_text[..limit_text.len() - 1], 1024 * 1024),
        _no_suffix => (limit_text, 1),
    };
    whole_number_in_text(digits)?.checked_mul(multiplier)
}

pub fn setting_value_kind(setting_key: &str) -> SettingValueKind {
    if protective_switch_named(setting_key).is_some() {
        return SettingValueKind::BooleanSetting;
    }
    KNOWN_SETTING_OPTIONS
        .iter()
        .find(|known_option| known_option.setting_key == setting_key)
        .map_or(SettingValueKind::UnknownSetting, |known_option| {
            known_option.value_kind
        })
}

pub fn value_has_only_safe_characters(setting_value: &str) -> bool {
    !setting_value.is_empty()
        && setting_value.len() <= MAXIMUM_VALUE_LENGTH
        && setting_value == setting_value.trim()
        && setting_value.chars().all(|value_character| {
            value_character.is_alphanumeric() || " ._/:+@=,-".contains(value_character)
        })
}

pub fn whole_number_in_text(number_text: &str) -> Option<u64> {
    if number_text.is_empty()
        || !number_text
            .chars()
            .all(|number_character| number_character.is_ascii_digit())
    {
        return None;
    }
    number_text.parse::<u64>().ok()
}

pub fn path_is_absolute_and_contained(path_text: &str) -> bool {
    path_text.starts_with('/')
        && !path_text
            .split('/')
            .any(|path_segment| path_segment == "..")
}

pub fn value_fits_setting_kind(setting_value: &str, value_kind: SettingValueKind) -> bool {
    match value_kind {
        SettingValueKind::BooleanSetting => {
            matches!(setting_value, "true" | "false" | "yes" | "no")
        }
        SettingValueKind::CountSetting { minimum, maximum } => whole_number_in_text(setting_value)
            .is_some_and(|counted_value| (minimum..=maximum).contains(&counted_value)),
        SettingValueKind::SizeSetting => limit_in_units(setting_value).is_some(),
        SettingValueKind::PathSetting | SettingValueKind::PathListSetting => {
            path_is_absolute_and_contained(setting_value)
        }
        SettingValueKind::TextSetting => !setting_value.is_empty(),
        SettingValueKind::UnknownSetting => false,
    }
}

fn largest_limit(limit_values: &[String]) -> Option<u64> {
    limit_values
        .iter()
        .filter_map(|limit_value| limit_in_units(limit_value))
        .max()
}

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
}

const fn switch_reduction(protective_switch: &ProtectiveSwitch) -> ProtectionReduction {
    match protective_switch.switch_role {
        SwitchRole::BlocksAccess => ProtectionReduction::BlockingTurnedOff,
        SwitchRole::ChecksContent => ProtectionReduction::CheckTurnedOff,
    }
}

fn switch_change_reduction<ReadFailure>(
    protective_switch: &ProtectiveSwitch,
    values_in_effect: &ValuesInEffect<ReadFailure>,
    new_values: &[String],
) -> ProtectionReduction {
    if new_values.iter().any(|new_value| switch_is_on(new_value)) {
        return ProtectionReduction::NoReduction;
    }
    let was_on = match values_in_effect {
        ValuesInEffect::NotConfigured => protective_switch.on_by_default,
        ValuesInEffect::Configured { setting_values } => setting_values
            .iter()
            .any(|current_value| switch_is_on(current_value)),
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            return ProtectionReduction::CurrentValuesUnknown;
        }
    };
    if was_on {
        switch_reduction(protective_switch)
    } else {
        ProtectionReduction::NoReduction
    }
}

fn skip_list_reduction<ReadFailure>(
    values_in_effect: &ValuesInEffect<ReadFailure>,
    new_values: &[String],
) -> ProtectionReduction {
    let skipped_before: &[String] = match values_in_effect {
        ValuesInEffect::NotConfigured => &[],
        ValuesInEffect::Configured { setting_values } => setting_values,
        ValuesInEffect::ConfigUnreadable(_read_failure) if new_values.is_empty() => {
            return ProtectionReduction::NoReduction;
        }
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            return ProtectionReduction::CurrentValuesUnknown;
        }
    };
    if new_values
        .iter()
        .any(|new_value| !skipped_before.contains(new_value))
    {
        ProtectionReduction::SkippedLocationAdded
    } else {
        ProtectionReduction::NoReduction
    }
}

fn watched_folder_reduction<ReadFailure>(
    values_in_effect: &ValuesInEffect<ReadFailure>,
    new_values: &[String],
) -> ProtectionReduction {
    match values_in_effect {
        ValuesInEffect::NotConfigured => ProtectionReduction::NoReduction,
        ValuesInEffect::Configured { setting_values }
            if setting_values
                .iter()
                .any(|current_value| !new_values.contains(current_value)) =>
        {
            ProtectionReduction::WatchedFolderRemoved
        }
        ValuesInEffect::Configured { .. } => ProtectionReduction::NoReduction,
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            ProtectionReduction::CurrentValuesUnknown
        }
    }
}

fn scan_limit_reduction<ReadFailure>(
    setting_key: &str,
    values_in_effect: &ValuesInEffect<ReadFailure>,
    new_values: &[String],
) -> ProtectionReduction {
    let Some(new_limit) = largest_limit(new_values) else {
        return ProtectionReduction::NoReduction;
    };
    let current_limit = match values_in_effect {
        ValuesInEffect::NotConfigured => default_scan_limit(setting_key),
        ValuesInEffect::Configured { setting_values } => largest_limit(setting_values),
        ValuesInEffect::ConfigUnreadable(_read_failure) => {
            return ProtectionReduction::CurrentValuesUnknown;
        }
    };
    match current_limit {
        Some(current_limit) if new_limit >= current_limit => ProtectionReduction::NoReduction,
        Some(_) | None => ProtectionReduction::ScanLimitLowered,
    }
}

pub fn protection_reduction<ReadFailure>(
    setting_key: &str,
    values_in_effect: &ValuesInEffect<ReadFailure>,
    new_values: &[String],
) -> ProtectionReduction {
    if let Some(protective_switch) = protective_switch_named(setting_key) {
        return switch_change_reduction(protective_switch, values_in_effect, new_values);
    }
    if SKIP_LIST_SETTINGS.contains(&setting_key) {
        return skip_list_reduction(values_in_effect, new_values);
    }
    if setting_key == WATCHED_FOLDER_SETTING {
        return watched_folder_reduction(values_in_effect, new_values);
    }
    if is_scan_limit(setting_key) {
        return scan_limit_reduction(setting_key, values_in_effect, new_values);
    }
    ProtectionReduction::NoReduction
}

#[cfg(test)]
mod protection_change_rules_tests {
    use std::io;

    use super::*;

    type TestedValues = ValuesInEffect<io::ErrorKind>;

    fn configured_values(setting_values: &[&str]) -> TestedValues {
        TestedValues::from_config_values(values(setting_values))
    }

    fn values(setting_values: &[&str]) -> Vec<String> {
        setting_values
            .iter()
            .map(|setting_value| (*setting_value).to_owned())
            .collect()
    }

    fn unreadable_config() -> TestedValues {
        TestedValues::ConfigUnreadable(io::ErrorKind::PermissionDenied)
    }

    fn change_weakens(
        setting_key: &str,
        values_in_effect: &TestedValues,
        new_values: &[&str],
    ) -> bool {
        protection_reduction(setting_key, values_in_effect, &values(new_values))
            .weakens_protection()
    }

    #[test]
    fn every_protective_switch_and_scan_limit_has_a_value_kind() {
        PROTECTIVE_SWITCHES.iter().for_each(|protective_switch| {
            assert_eq!(
                setting_value_kind(protective_switch.setting_key),
                SettingValueKind::BooleanSetting,
                "{}",
                protective_switch.setting_key
            );
        });
        SCAN_LIMIT_DEFAULTS.iter().for_each(|limit_default| {
            assert!(
                matches!(
                    setting_value_kind(limit_default.setting_key),
                    SettingValueKind::CountSetting { .. } | SettingValueKind::SizeSetting
                ),
                "{}",
                limit_default.setting_key
            );
        });
    }

    #[test]
    fn every_known_option_is_listed_once() {
        KNOWN_SETTING_OPTIONS.iter().for_each(|known_option| {
            assert!(
                protective_switch_named(known_option.setting_key).is_none(),
                "{}",
                known_option.setting_key
            );
            assert_eq!(
                KNOWN_SETTING_OPTIONS
                    .iter()
                    .filter(|other_option| other_option.setting_key == known_option.setting_key)
                    .count(),
                1,
                "{}",
                known_option.setting_key
            );
        });
    }

    #[test]
    fn options_are_classified_by_their_value_type() {
        assert_eq!(
            setting_value_kind("OnAccessExtraScanning"),
            SettingValueKind::BooleanSetting
        );
        assert_eq!(
            setting_value_kind("MaxThreads"),
            SettingValueKind::CountSetting {
                minimum: 1,
                maximum: 256
            }
        );
        assert_eq!(
            setting_value_kind("OnAccessMaxFileSize"),
            SettingValueKind::SizeSetting
        );
        assert_eq!(setting_value_kind("LogFile"), SettingValueKind::PathSetting);
        assert_eq!(
            setting_value_kind("OnAccessIncludePath"),
            SettingValueKind::PathListSetting
        );
        assert_eq!(
            setting_value_kind("DatabaseMirror"),
            SettingValueKind::TextSetting
        );
        assert_eq!(
            setting_value_kind("NotARealClamdOption"),
            SettingValueKind::UnknownSetting
        );
    }

    #[test]
    fn values_are_checked_against_their_kind() {
        let fits_option = |setting_key: &str, setting_value: &str| {
            value_fits_setting_kind(setting_value, setting_value_kind(setting_key))
        };
        assert!(fits_option("OnAccessExtraScanning", "yes"));
        assert!(!fits_option("OnAccessExtraScanning", "tru"));
        assert!(fits_option("MaxThreads", "8"));
        assert!(!fits_option("MaxThreads", "0"));
        assert!(!fits_option("MaxThreads", "+8"));
        assert!(!fits_option("MaxThreads", "257"));
        assert!(fits_option("MaxFileSize", "25M"));
        assert!(!fits_option("MaxFileSize", "25G"));
        assert!(fits_option("OnAccessIncludePath", "/home/user"));
        assert!(!fits_option("OnAccessIncludePath", "home/user"));
        assert!(!fits_option("OnAccessIncludePath", "/home/../etc"));
        assert!(fits_option("DatabaseMirror", "database.clamav.net"));
        assert!(!fits_option("NotARealClamdOption", "anything"));
    }

    #[test]
    fn limit_suffixes_are_binary_multiples() {
        assert_eq!(limit_in_units("100M"), Some(104_857_600));
        assert_eq!(limit_in_units("102400k"), Some(104_857_600));
        assert_eq!(limit_in_units("512"), Some(512));
        assert_eq!(limit_in_units("lots"), None);
        assert_eq!(limit_in_units("+5M"), None);
    }

    #[test]
    fn switching_protection_off_weakens_it_and_switching_it_on_does_not() {
        assert!(change_weakens(
            "OnAccessPrevention",
            &configured_values(&["yes"]),
            &["no"]
        ));
        assert!(change_weakens(
            "ScanArchive",
            &TestedValues::NotConfigured,
            &["no"]
        ));
        assert!(!change_weakens(
            "DetectPUA",
            &configured_values(&["no"]),
            &["yes"]
        ));
    }

    #[test]
    fn switches_that_default_to_off_are_not_assumed_on() {
        ["OnAccessPrevention", "DetectPUA", "AlertOLE2Macros"]
            .into_iter()
            .for_each(|setting_key| {
                assert_eq!(
                    protection_reduction(
                        setting_key,
                        &TestedValues::NotConfigured,
                        &values(&["no"])
                    ),
                    ProtectionReduction::NoReduction,
                    "{setting_key}"
                );
            });
        assert_eq!(
            protection_reduction(
                "HeuristicAlerts",
                &TestedValues::NotConfigured,
                &values(&["no"])
            ),
            ProtectionReduction::CheckTurnedOff
        );
    }

    #[test]
    fn turning_off_prevention_is_reported_as_losing_blocking() {
        assert_eq!(
            protection_reduction(
                "OnAccessPrevention",
                &configured_values(&["yes"]),
                &values(&["no"])
            ),
            ProtectionReduction::BlockingTurnedOff
        );
        assert_eq!(
            protection_reduction("ScanPDF", &configured_values(&["yes"]), &values(&["no"])),
            ProtectionReduction::CheckTurnedOff
        );
    }

    #[test]
    fn new_exclusions_and_lower_limits_weaken_protection() {
        assert!(change_weakens(
            "OnAccessExcludePath",
            &configured_values(&["/srv"]),
            &["/srv", "/home"]
        ));
        assert!(!change_weakens(
            "OnAccessExcludePath",
            &configured_values(&["/srv", "/home"]),
            &["/srv"]
        ));
        assert!(change_weakens(
            "OnAccessIncludePath",
            &configured_values(&["/home", "/tmp"]),
            &["/home"]
        ));
        assert!(change_weakens(
            "MaxFileSize",
            &configured_values(&["100M"]),
            &["25M"]
        ));
        assert!(!change_weakens(
            "MaxFileSize",
            &configured_values(&["25M"]),
            &["100M"]
        ));
        assert!(!change_weakens(
            "MaxThreads",
            &configured_values(&["12"]),
            &["2"]
        ));
    }

    #[test]
    fn unset_limits_compare_against_the_clamav_default() {
        assert!(change_weakens(
            "MaxFileSize",
            &TestedValues::NotConfigured,
            &["25M"]
        ));
        assert!(!change_weakens(
            "MaxFileSize",
            &TestedValues::NotConfigured,
            &["200M"]
        ));
        assert!(change_weakens(
            "SomeUnlistedSize",
            &TestedValues::NotConfigured,
            &["1M"]
        ));
    }

    #[test]
    fn an_unreadable_config_never_makes_a_change_harmless() {
        let unreadable_config = unreadable_config();
        [
            ("OnAccessIncludePath", "/home"),
            ("OnAccessExcludePath", "/srv"),
            ("DetectPUA", "no"),
            ("OnAccessPrevention", "no"),
            ("MaxFileSize", "200M"),
        ]
        .into_iter()
        .for_each(|(setting_key, new_value)| {
            assert_eq!(
                protection_reduction(setting_key, &unreadable_config, &values(&[new_value])),
                ProtectionReduction::CurrentValuesUnknown,
                "{setting_key}"
            );
        });
        assert!(!change_weakens(
            "OnAccessPrevention",
            &unreadable_config,
            &["yes"]
        ));
        assert!(!change_weakens("MaxThreads", &unreadable_config, &["2"]));
    }
}
