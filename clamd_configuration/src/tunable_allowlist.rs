use std::{collections::BTreeSet, convert::Infallible, str::FromStr};

use crate::tunable_record::TunableSettingName;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TunableAllowlist {
    pub allowed_names: BTreeSet<TunableSettingName>,
    pub refused_names: Vec<String>,
}

impl TunableAllowlist {
    pub fn allows(&self, setting_name: &str) -> bool {
        self.allowed_names
            .iter()
            .any(|allowed_name| allowed_name.as_str() == setting_name)
    }
}

impl FromStr for TunableAllowlist {
    type Err = Infallible;

    fn from_str(allowlist_text: &str) -> Result<Self, Self::Err> {
        let listed_names = allowlist_text
            .lines()
            .map(str::trim)
            .filter(|listed_name| !listed_name.is_empty() && !listed_name.starts_with('#'));
        Ok(
            listed_names.fold(Self::default(), |mut allowlist, listed_name| {
                match listed_name.parse::<TunableSettingName>() {
                    Ok(allowed_name) => {
                        allowlist.allowed_names.insert(allowed_name);
                    }
                    Err(_unknown_name) => allowlist.refused_names.push(listed_name.to_owned()),
                }
                allowlist
            }),
        )
    }
}

#[cfg(test)]
mod tunable_allowlist_tests {
    use super::*;

    #[test]
    fn protected_and_unknown_names_are_refused() {
        let allowlist: TunableAllowlist = "DetectPUA\nVirusEvent\n\nNoSuchSetting\nmaxthreads\n"
            .parse()
            .expect("parsed");
        assert!(allowlist.allows("DetectPUA"));
        assert!(allowlist.allows("MaxThreads"));
        assert!(!allowlist.allows("VirusEvent"));
        assert_eq!(allowlist.refused_names, ["VirusEvent", "NoSuchSetting"]);
    }
}
