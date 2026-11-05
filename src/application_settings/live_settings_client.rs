use std::fmt::Write as _;

use gettextrs::gettext;
use zbus::{Connection, proxy};

#[proxy(
    interface = "io.github.wvhulle.ClamUI.SettingsHelper",
    default_service = "io.github.wvhulle.ClamUI.SettingsHelper",
    default_path = "/io/github/wvhulle/ClamUI/SettingsHelper"
)]
trait SettingsHelper {
    fn get_tunable_settings(&self) -> zbus::Result<Vec<String>>;

    fn get_overrides(&self) -> zbus::Result<Vec<(String, String)>>;

    fn apply_changes(&self, changes: &[(&str, &str)]) -> zbus::Result<String>;
}

const APPLIED_ANSWER: &str = "applied";
const ROLLED_BACK_ANSWER: &str = "rolled-back";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiveTuningState {
    pub tunable_settings: Vec<String>,
    pub active_overrides: Vec<(String, String)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveChangeOutcome {
    SettingsApplied,
    PreviousRestored,
    NothingChanged { failure_text: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeEffect {
    KeepsProtection,
    WeakensProtection,
}

async fn helper_proxy() -> zbus::Result<SettingsHelperProxy<'static>> {
    SettingsHelperProxy::new(&Connection::system().await?).await
}

pub async fn read_live_tuning_state() -> LiveTuningState {
    let read_state = async {
        let settings_helper = helper_proxy().await?;
        Ok::<LiveTuningState, zbus::Error>(LiveTuningState {
            tunable_settings: settings_helper.get_tunable_settings().await?,
            active_overrides: settings_helper.get_overrides().await?,
        })
    };
    read_state.await.unwrap_or_default()
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

fn size_in_bytes(size_text: &str) -> Option<u64> {
    let (digits, multiplier) = match size_text.chars().last()? {
        'k' | 'K' => (&size_text[..size_text.len() - 1], 1024),
        'm' | 'M' => (&size_text[..size_text.len() - 1], 1024 * 1024),
        _no_suffix => (size_text, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(multiplier)
}

fn setting_is_on(setting_value: &str) -> bool {
    matches!(setting_value, "true" | "yes")
}

pub fn change_effect(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
) -> ChangeEffect {
    let weakens_protection = match setting_key {
        "OnAccessPrevention" | "OnAccessExtraScanning" => {
            current_values
                .iter()
                .any(|current_value| setting_is_on(current_value))
                && !new_values.iter().any(|new_value| setting_is_on(new_value))
        }
        "OnAccessIncludePath" => current_values
            .iter()
            .any(|current_value| !new_values.contains(current_value)),
        "OnAccessExcludePath" | "OnAccessExcludeRootUID" | "ExcludePath" => new_values
            .iter()
            .any(|new_value| !current_values.contains(new_value)),
        size_key if size_key.ends_with("Size") => {
            let largest_size = |size_values: &[String]| {
                size_values
                    .iter()
                    .filter_map(|size_value| size_in_bytes(size_value))
                    .max()
            };
            match (largest_size(current_values), largest_size(new_values)) {
                (Some(current_size), Some(new_size)) => new_size < current_size,
                _unknown_size => true,
            }
        }
        _other_setting => false,
    };
    if weakens_protection {
        ChangeEffect::WeakensProtection
    } else {
        ChangeEffect::KeepsProtection
    }
}

pub fn change_confirmation_text(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
    effect: ChangeEffect,
) -> String {
    let mut confirmation_text = gettext("{key}\nNow: {current}\nNew: {new}")
        .replace("{key}", setting_key)
        .replace("{current}", &current_values.join(", "))
        .replace("{new}", &new_values.join(", "));
    if effect == ChangeEffect::WeakensProtection {
        let _writing_to_string_succeeds = write!(
            confirmation_text,
            "\n\n{}",
            gettext("This reduces what ClamAV protects. Only continue if you mean to do that.")
        );
    }
    confirmation_text
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

    fn effect_of(setting_key: &str, current_values: &[&str], new_values: &[&str]) -> ChangeEffect {
        change_effect(setting_key, &values(current_values), &values(new_values))
    }

    #[test]
    fn turning_prevention_off_weakens_protection() {
        assert_eq!(
            effect_of("OnAccessPrevention", &["true"], &["false"]),
            ChangeEffect::WeakensProtection
        );
        assert_eq!(
            effect_of("OnAccessPrevention", &["false"], &["true"]),
            ChangeEffect::KeepsProtection
        );
    }

    #[test]
    fn removing_a_watched_folder_weakens_protection() {
        assert_eq!(
            effect_of("OnAccessIncludePath", &["/a", "/b"], &["/a"]),
            ChangeEffect::WeakensProtection
        );
        assert_eq!(
            effect_of("OnAccessIncludePath", &["/a"], &["/a", "/b"]),
            ChangeEffect::KeepsProtection
        );
    }

    #[test]
    fn adding_an_exclusion_weakens_protection() {
        assert_eq!(
            effect_of("OnAccessExcludePath", &[], &["/a"]),
            ChangeEffect::WeakensProtection
        );
    }

    #[test]
    fn scanning_fewer_large_files_weakens_protection() {
        assert_eq!(
            effect_of("OnAccessMaxFileSize", &["100M"], &["10M"]),
            ChangeEffect::WeakensProtection
        );
        assert_eq!(
            effect_of("OnAccessMaxFileSize", &["10M"], &["100M"]),
            ChangeEffect::KeepsProtection
        );
        assert_eq!(
            effect_of("OnAccessMaxFileSize", &["100M"], &["102400k"]),
            ChangeEffect::KeepsProtection
        );
    }

    #[test]
    fn a_size_that_cannot_be_compared_is_treated_as_weakening() {
        assert_eq!(
            effect_of("MaxFileSize", &["lots"], &["10M"]),
            ChangeEffect::WeakensProtection
        );
    }

    #[test]
    fn the_confirmation_shows_both_values_and_warns_when_weakening() {
        let confirmation_text = change_confirmation_text(
            "OnAccessPrevention",
            &values(&["true"]),
            &values(&["false"]),
            ChangeEffect::WeakensProtection,
        );
        assert!(confirmation_text.contains("Now: true"));
        assert!(confirmation_text.contains("New: false"));
        assert!(confirmation_text.contains("reduces what ClamAV protects"));
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
}
