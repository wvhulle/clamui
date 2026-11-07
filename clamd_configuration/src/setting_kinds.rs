use crate::setting_values::ClamdSize;

const CLAMD_NUMBER_CEILING: u64 = i32::MAX.unsigned_abs() as u64;

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

const KNOWN_SETTING_OPTIONS: [KnownSettingOption; 143] = [
    boolean_option("OnAccessPrevention"),
    boolean_option("OnAccessExtraScanning"),
    boolean_option("ScanPE"),
    boolean_option("ScanELF"),
    boolean_option("ScanOLE2"),
    boolean_option("ScanPDF"),
    boolean_option("ScanHTML"),
    boolean_option("ScanMail"),
    boolean_option("ScanArchive"),
    boolean_option("ScanSWF"),
    boolean_option("ScanXMLDOCS"),
    boolean_option("ScanHWP3"),
    boolean_option("AlertBrokenExecutables"),
    boolean_option("AlertEncrypted"),
    boolean_option("AlertEncryptedArchive"),
    boolean_option("AlertEncryptedDoc"),
    boolean_option("AlertOLE2Macros"),
    boolean_option("AlertExceedsMax"),
    boolean_option("DetectPUA"),
    boolean_option("HeuristicAlerts"),
    boolean_option("Bytecode"),
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
    count_option("MaxFiles", 0, CLAMD_NUMBER_CEILING),
    count_option("MaxPartitions", 0, CLAMD_NUMBER_CEILING),
    count_option("MaxIconsPE", 0, CLAMD_NUMBER_CEILING),
    count_option("MaxRecHWP3", 0, 255),
    count_option("PCREMatchLimit", 0, CLAMD_NUMBER_CEILING),
    count_option("PCRERecMatchLimit", 0, CLAMD_NUMBER_CEILING),
    count_option("BytecodeTimeout", 0, 86_400_000),
    count_option("StructuredMinCreditCardCount", 1, 10_000),
    count_option("StructuredMinSSNCount", 1, 10_000),
    count_option("OnAccessMaxThreads", 1, 256),
    count_option("OnAccessCurlTimeout", 0, 86_400_000),
    count_option("OnAccessRetryAttempts", 0, 100),
    count_option("OnAccessExcludeUID", 0, CLAMD_NUMBER_CEILING),
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
    text_option("ExcludePath"),
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

pub fn limit_in_units(limit_text: &str) -> Option<u64> {
    match limit_text.parse::<ClamdSize>().ok()? {
        ClamdSize::LimitedTo(byte_size) => Some(byte_size.as_u64()),
        ClamdSize::Unlimited => Some(0),
    }
}

pub fn setting_value_kind(setting_key: &str) -> SettingValueKind {
    KNOWN_SETTING_OPTIONS
        .iter()
        .find(|known_option| known_option.setting_key == setting_key)
        .map_or(SettingValueKind::UnknownSetting, |known_option| {
            known_option.value_kind
        })
}

pub fn value_has_only_safe_characters(setting_value: &str) -> bool {
    !setting_value.is_empty()
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

#[cfg(test)]
mod setting_kinds_tests {
    use super::*;

    #[test]
    fn every_tunable_setting_has_a_value_kind() {
        crate::tunable_record::tunable_setting_names()
            .iter()
            .for_each(|tunable_name| {
                assert_ne!(
                    setting_value_kind(tunable_name),
                    SettingValueKind::UnknownSetting,
                    "{tunable_name}"
                );
            });
    }

    #[test]
    fn every_known_option_is_listed_once() {
        KNOWN_SETTING_OPTIONS.iter().for_each(|known_option| {
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
        assert!(fits_option("MaxFileSize", "25G"));
        assert!(!fits_option("MaxFileSize", "25T"));
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
}
