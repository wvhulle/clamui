const PROTECTIVE_SWITCHES: [&str; 21] = [
    "OnAccessPrevention",
    "OnAccessExtraScanning",
    "ScanPE",
    "ScanELF",
    "ScanOLE2",
    "ScanPDF",
    "ScanHTML",
    "ScanMail",
    "ScanArchive",
    "ScanSWF",
    "ScanXMLDOCS",
    "ScanHWP3",
    "AlertBrokenExecutables",
    "AlertEncrypted",
    "AlertEncryptedArchive",
    "AlertEncryptedDoc",
    "AlertOLE2Macros",
    "AlertExceedsMax",
    "DetectPUA",
    "HeuristicAlerts",
    "Bytecode",
];
const SCAN_LIMIT_SETTINGS: [&str; 5] = [
    "MaxScanTime",
    "MaxRecursion",
    "MaxFiles",
    "MaxDirectoryRecursion",
    "MaxEmbeddedPE",
];
const SKIP_LIST_SETTINGS: [&str; 6] = [
    "OnAccessExcludePath",
    "OnAccessExcludeRootUID",
    "OnAccessExcludeUID",
    "OnAccessExcludeUname",
    "ExcludePath",
    "ExcludePUA",
];

fn switch_is_on(setting_value: &str) -> bool {
    matches!(setting_value, "true" | "yes")
}

fn limit_in_units(limit_text: &str) -> Option<u64> {
    let (digits, multiplier) = match limit_text.chars().last()? {
        'k' | 'K' => (&limit_text[..limit_text.len() - 1], 1024),
        'm' | 'M' => (&limit_text[..limit_text.len() - 1], 1024 * 1024),
        _no_suffix => (limit_text, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
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
    NoReduction,
}

const BLOCKING_SWITCHES: [&str; 1] = ["OnAccessPrevention"];

pub fn protection_reduction(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
) -> ProtectionReduction {
    if PROTECTIVE_SWITCHES.contains(&setting_key) {
        let was_on = current_values.is_empty()
            || current_values
                .iter()
                .any(|current_value| switch_is_on(current_value));
        let turned_off = was_on && !new_values.iter().any(|new_value| switch_is_on(new_value));
        return match turned_off {
            true if BLOCKING_SWITCHES.contains(&setting_key) => {
                ProtectionReduction::BlockingTurnedOff
            }
            true => ProtectionReduction::CheckTurnedOff,
            false => ProtectionReduction::NoReduction,
        };
    }
    if SKIP_LIST_SETTINGS.contains(&setting_key)
        && new_values
            .iter()
            .any(|new_value| !current_values.contains(new_value))
    {
        return ProtectionReduction::SkippedLocationAdded;
    }
    if setting_key == "OnAccessIncludePath"
        && current_values
            .iter()
            .any(|current_value| !new_values.contains(current_value))
    {
        return ProtectionReduction::WatchedFolderRemoved;
    }
    if setting_key.ends_with("Size") || SCAN_LIMIT_SETTINGS.contains(&setting_key) {
        let limit_lowered = match (largest_limit(current_values), largest_limit(new_values)) {
            (Some(current_limit), Some(new_limit)) => new_limit < current_limit,
            (_unknown_current, Some(_new_limit)) => true,
            (_any_current, None) => false,
        };
        if limit_lowered {
            return ProtectionReduction::ScanLimitLowered;
        }
    }
    ProtectionReduction::NoReduction
}

pub fn change_weakens_protection(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
) -> bool {
    protection_reduction(setting_key, current_values, new_values)
        != ProtectionReduction::NoReduction
}

#[cfg(test)]
mod protection_change_rules_tests {
    use super::*;

    fn values(setting_values: &[&str]) -> Vec<String> {
        setting_values
            .iter()
            .map(|setting_value| (*setting_value).to_owned())
            .collect()
    }

    #[test]
    fn switching_protection_off_weakens_it_and_switching_it_on_does_not() {
        assert!(change_weakens_protection(
            "OnAccessPrevention",
            &values(&["yes"]),
            &values(&["no"])
        ));
        assert!(change_weakens_protection(
            "ScanArchive",
            &[],
            &values(&["no"])
        ));
        assert!(!change_weakens_protection(
            "DetectPUA",
            &values(&["no"]),
            &values(&["yes"])
        ));
    }

    #[test]
    fn turning_off_prevention_is_reported_as_losing_blocking() {
        assert_eq!(
            protection_reduction("OnAccessPrevention", &values(&["yes"]), &values(&["no"])),
            ProtectionReduction::BlockingTurnedOff
        );
        assert_eq!(
            protection_reduction("ScanPDF", &values(&["yes"]), &values(&["no"])),
            ProtectionReduction::CheckTurnedOff
        );
    }

    #[test]
    fn new_exclusions_and_lower_limits_weaken_protection() {
        assert!(change_weakens_protection(
            "OnAccessExcludePath",
            &values(&["/srv"]),
            &values(&["/srv", "/home"])
        ));
        assert!(!change_weakens_protection(
            "OnAccessExcludePath",
            &values(&["/srv", "/home"]),
            &values(&["/srv"])
        ));
        assert!(change_weakens_protection(
            "OnAccessIncludePath",
            &values(&["/home", "/tmp"]),
            &values(&["/home"])
        ));
        assert!(change_weakens_protection(
            "MaxFileSize",
            &values(&["100M"]),
            &values(&["25M"])
        ));
        assert!(!change_weakens_protection(
            "MaxFileSize",
            &values(&["25M"]),
            &values(&["100M"])
        ));
        assert!(!change_weakens_protection(
            "MaxThreads",
            &values(&["12"]),
            &values(&["2"])
        ));
    }
}
