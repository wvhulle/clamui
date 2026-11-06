use gettextrs::gettext;
use zbus::{Connection, proxy};

use crate::host_services::settings_helper::protection_change_rules::{
    ProtectionReduction, ValuesInEffect, protection_reduction,
};

#[proxy(
    interface = "page.codeberg.wvhulle.Lazaret.SettingsHelper",
    default_service = "page.codeberg.wvhulle.Lazaret.SettingsHelper",
    default_path = "/page/codeberg/wvhulle/Lazaret/SettingsHelper"
)]
trait SettingsHelper {
    fn get_tunable_settings(&self) -> zbus::Result<Vec<String>>;

    fn get_overrides(&self) -> zbus::Result<Vec<(String, String)>>;

    fn apply_changes(&self, changes: &[(&str, &str)]) -> zbus::Result<String>;
}

const APPLIED_ANSWER: &str = "applied";
const ROLLED_BACK_ANSWER: &str = "rolled-back";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverrideSetting {
    pub setting_key: String,
    pub setting_value: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LiveTuning {
    HelperUnavailable(zbus::Error),
    Available {
        tunable_settings: Vec<String>,
        active_overrides: Vec<OverrideSetting>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveChangeOutcome {
    SettingsApplied,
    PreviousRestored,
    NothingChanged { failure_text: String },
}

async fn helper_proxy() -> zbus::Result<SettingsHelperProxy<'static>> {
    SettingsHelperProxy::new(&Connection::system().await?).await
}

async fn read_live_tuning_from(
    settings_helper: &SettingsHelperProxy<'_>,
) -> zbus::Result<LiveTuning> {
    Ok(LiveTuning::Available {
        tunable_settings: settings_helper.get_tunable_settings().await?,
        active_overrides: settings_helper
            .get_overrides()
            .await?
            .into_iter()
            .map(|(setting_key, setting_value)| OverrideSetting {
                setting_key,
                setting_value,
            })
            .collect(),
    })
}

async fn live_tuning_on_bus(bus_connection: zbus::Result<Connection>) -> LiveTuning {
    let read_tuning = async {
        let settings_helper = SettingsHelperProxy::new(&bus_connection?).await?;
        read_live_tuning_from(&settings_helper).await
    };
    read_tuning
        .await
        .unwrap_or_else(LiveTuning::HelperUnavailable)
}

pub async fn read_live_tuning() -> LiveTuning {
    live_tuning_on_bus(Connection::system().await).await
}

pub fn outcome_from_helper_answer(helper_answer: &str) -> LiveChangeOutcome {
    match helper_answer {
        APPLIED_ANSWER => LiveChangeOutcome::SettingsApplied,
        ROLLED_BACK_ANSWER => LiveChangeOutcome::PreviousRestored,
        other_answer => LiveChangeOutcome::NothingChanged {
            failure_text: other_answer.to_owned(),
        },
    }
}

pub async fn apply_live_change(
    setting_key: String,
    setting_values: Vec<String>,
) -> LiveChangeOutcome {
    let changes = setting_values
        .iter()
        .map(|setting_value| (setting_key.as_str(), setting_value.as_str()))
        .collect::<Vec<_>>();
    let helper_answer = async { helper_proxy().await?.apply_changes(&changes).await };
    match helper_answer.await {
        Ok(helper_answer) => outcome_from_helper_answer(&helper_answer),
        Err(call_failure) => LiveChangeOutcome::NothingChanged {
            failure_text: call_failure.to_string(),
        },
    }
}

pub fn change_effect(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
) -> ProtectionReduction {
    protection_reduction(
        setting_key,
        &ValuesInEffect::from_config_values(current_values.to_vec()),
        new_values,
    )
}

fn reduction_headline(protection_reduction: ProtectionReduction) -> Option<String> {
    match protection_reduction {
        ProtectionReduction::BlockingTurnedOff => Some(gettext(
            "Detected files will no longer be blocked when opened. They are only reported.",
        )),
        ProtectionReduction::CheckTurnedOff => Some(gettext(
            "ClamAV will stop checking for this kind of file or threat on this computer.",
        )),
        ProtectionReduction::WatchedFolderRemoved => Some(gettext(
            "Files in the removed folder will no longer be checked when they are opened.",
        )),
        ProtectionReduction::SkippedLocationAdded => Some(gettext(
            "ClamAV will skip the new entry entirely, so malware there goes unnoticed.",
        )),
        ProtectionReduction::ScanLimitLowered => Some(gettext(
            "Files or archives above the new limit will be skipped without being checked.",
        )),
        ProtectionReduction::CurrentValuesUnknown => Some(gettext(
            "The current value could not be read, so this change may reduce protection.",
        )),
        ProtectionReduction::DetectionTrusted => {
            Some(gettext("ClamAV will no longer report what you trust here."))
        }
        ProtectionReduction::NoReduction => None,
    }
}

pub fn change_confirmation_text(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
    protection_reduction: ProtectionReduction,
) -> String {
    let change_lines = gettext("{key}\nNow: {current}\nNew: {new}")
        .replace("{key}", setting_key)
        .replace("{current}", &current_values.join(", "))
        .replace("{new}", &new_values.join(", "));
    match reduction_headline(protection_reduction) {
        Some(headline) => format!(
            "{headline}\n\n{change_lines}\n\n{}",
            gettext(
                "The system records that this change reduced protection, and the Protection page \
                 keeps showing it until you undo it.",
            )
        ),
        None => change_lines,
    }
}

#[cfg(test)]
mod live_settings_client_tests {
    use super::*;

    fn values(setting_values: &[&str]) -> Vec<String> {
        setting_values
            .iter()
            .map(|setting_value| (*setting_value).to_owned())
            .collect()
    }

    fn effect_of(setting_key: &str, current_values: &[&str], new_values: &[&str]) -> bool {
        change_effect(setting_key, &values(current_values), &values(new_values))
            != ProtectionReduction::NoReduction
    }

    #[test]
    fn turning_prevention_off_weakens_protection() {
        assert!(effect_of("OnAccessPrevention", &["true"], &["false"]));
        assert!(!effect_of("OnAccessPrevention", &["false"], &["true"]));
    }

    #[test]
    fn removing_a_watched_folder_weakens_protection() {
        assert!(effect_of("OnAccessIncludePath", &["/a", "/b"], &["/a"]));
        assert!(!effect_of("OnAccessIncludePath", &["/a"], &["/a", "/b"]));
    }

    #[test]
    fn adding_an_exclusion_weakens_protection() {
        assert!(effect_of("OnAccessExcludePath", &[], &["/a"]));
    }

    #[test]
    fn scanning_fewer_large_files_weakens_protection() {
        assert!(effect_of("OnAccessMaxFileSize", &["100M"], &["10M"]));
        assert!(!effect_of("OnAccessMaxFileSize", &["10M"], &["100M"]));
        assert!(!effect_of("OnAccessMaxFileSize", &["100M"], &["102400k"]));
    }

    #[test]
    fn a_size_that_cannot_be_compared_is_treated_as_weakening() {
        assert!(effect_of("MaxFileSize", &["lots"], &["10M"]));
    }

    #[test]
    fn the_confirmation_shows_both_values_and_warns_when_weakening() {
        let confirmation_text = change_confirmation_text(
            "OnAccessPrevention",
            &values(&["true"]),
            &values(&["false"]),
            ProtectionReduction::BlockingTurnedOff,
        );
        assert!(confirmation_text.starts_with("Detected files will no longer be blocked"));
        assert!(confirmation_text.contains("Now: true"));
        assert!(confirmation_text.contains("New: false"));
    }

    #[test]
    fn helper_answers_map_to_outcomes() {
        assert_eq!(
            outcome_from_helper_answer("applied"),
            LiveChangeOutcome::SettingsApplied
        );
        assert_eq!(
            outcome_from_helper_answer("rolled-back"),
            LiveChangeOutcome::PreviousRestored
        );
        assert!(matches!(
            outcome_from_helper_answer("surprise"),
            LiveChangeOutcome::NothingChanged { .. }
        ));
    }

    #[test]
    fn an_unreachable_helper_is_reported_as_unavailable() {
        let unreachable_bus = Err(zbus::Error::Address("no bus here".to_owned()));
        let live_tuning = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(live_tuning_on_bus(unreachable_bus));
        assert!(matches!(
            live_tuning,
            LiveTuning::HelperUnavailable(zbus::Error::Address(_))
        ));
    }
}
