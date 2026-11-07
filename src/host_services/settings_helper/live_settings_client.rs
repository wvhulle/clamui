use std::convert::Infallible;

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
const SERVICE_UNKNOWN_ERROR: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const ACCESS_DENIED_ERROR: &str = "org.freedesktop.DBus.Error.AccessDenied";

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

#[derive(Clone, Debug, PartialEq)]
pub enum LiveChangeOutcome {
    SettingsApplied,
    PreviousRestored,
    NothingChanged(LiveChangeFailure),
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum LiveChangeFailure {
    #[error("the settings helper answered with an unknown outcome: {helper_answer}")]
    UnknownHelperAnswer { helper_answer: String },
    #[error("administrator authorization was not given")]
    AuthorizationRefused,
    #[error("the settings helper is not installed")]
    HelperMissing,
    #[error("the settings helper reported: {helper_message}")]
    ReportedByHelper { helper_message: String },
    #[error(transparent)]
    HelperCallFailed(zbus::Error),
}

impl From<zbus::Error> for LiveChangeFailure {
    fn from(call_failure: zbus::Error) -> Self {
        match call_failure {
            zbus::Error::MethodError(error_name, _error_message, _reply)
                if error_name.as_str() == SERVICE_UNKNOWN_ERROR =>
            {
                Self::HelperMissing
            }
            zbus::Error::MethodError(error_name, _error_message, _reply)
                if error_name.as_str() == ACCESS_DENIED_ERROR =>
            {
                Self::AuthorizationRefused
            }
            zbus::Error::MethodError(_error_name, Some(helper_message), _reply) => {
                Self::ReportedByHelper { helper_message }
            }
            other_call_failure => Self::HelperCallFailed(other_call_failure),
        }
    }
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
        other_answer => LiveChangeOutcome::NothingChanged(LiveChangeFailure::UnknownHelperAnswer {
            helper_answer: other_answer.to_owned(),
        }),
    }
}

fn outcome_of_helper_call(helper_answer: zbus::Result<String>) -> LiveChangeOutcome {
    match helper_answer {
        Ok(helper_answer) => outcome_from_helper_answer(&helper_answer),
        Err(call_failure) => LiveChangeOutcome::NothingChanged(call_failure.into()),
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
    outcome_of_helper_call(helper_answer.await)
}

pub fn change_effect(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
) -> ProtectionReduction {
    protection_reduction(
        setting_key,
        &ValuesInEffect::<Infallible>::from_config_values(current_values.to_vec()),
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
                "The system records that this change reduced protection, and the sidebar keeps \
                 flagging the page of the changed setting until you undo it.",
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
        assert_eq!(
            outcome_from_helper_answer("surprise"),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::UnknownHelperAnswer {
                helper_answer: "surprise".to_owned(),
            })
        );
    }

    fn helper_method_error(error_name: &str, error_message: &str) -> zbus::Error {
        let request_message = zbus::message::Message::method_call("/", "ApplyChanges")
            .expect("method call")
            .destination("page.codeberg.wvhulle.Lazaret.SettingsHelper")
            .expect("destination")
            .build(&())
            .expect("request message");
        let error_reply = zbus::message::Message::error(&request_message.header(), error_name)
            .expect("error reply")
            .build(&(error_message,))
            .expect("error message");
        zbus::Error::from(error_reply)
    }

    #[test]
    fn helper_errors_are_classified_by_their_dbus_name() {
        assert_eq!(
            outcome_of_helper_call(Err(helper_method_error(
                ACCESS_DENIED_ERROR,
                "Failed with NotAuthorized somewhere"
            ))),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::AuthorizationRefused)
        );
        assert_eq!(
            outcome_of_helper_call(Err(helper_method_error(
                SERVICE_UNKNOWN_ERROR,
                "no such name"
            ))),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::HelperMissing)
        );
        assert_eq!(
            outcome_of_helper_call(Err(helper_method_error(
                "org.freedesktop.DBus.Error.Failed",
                "AccessDenied: the configuration files could not be updated"
            ))),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::ReportedByHelper {
                helper_message: "AccessDenied: the configuration files could not be updated"
                    .to_owned(),
            })
        );
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
