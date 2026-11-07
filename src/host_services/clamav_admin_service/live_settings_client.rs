use std::{collections::BTreeSet, fs, io, path::Path};

use clamd_configuration::{
    clamd_conf_format::config_lines::{ClamdConfigLines, SettingLine},
    live_overrides::SettingChanges,
    merged_clamd_config::{requested_settings_in, tunable_settings_in},
    override_reports::{OverrideLifetime, change_reduction_from},
    protection_rules::ProtectionReduction,
    tunable_record::{BaseSettings, LiveOverrides, TunableSettingName},
};
use gettextrs::gettext;
use jiff::Timestamp;
use zbus::{Connection, proxy};

use crate::host_services::desktop::flatpak_sandbox::readable_host_path;

#[proxy(
    interface = "page.codeberg.wvhulle.Lazaret.ClamavAdmin",
    default_service = "page.codeberg.wvhulle.Lazaret.ClamavAdmin",
    default_path = "/page/codeberg/wvhulle/Lazaret/ClamavAdmin"
)]
trait ClamavAdmin {
    fn get_tunable_settings(&self) -> zbus::Result<Vec<String>>;

    fn apply_changes(&self, change_document: &str) -> zbus::Result<String>;
}

const APPLIED_ANSWER: &str = "applied";
const ROLLED_BACK_ANSWER: &str = "rolled-back";
const SERVICE_UNKNOWN_ERROR: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
const ACCESS_DENIED_ERROR: &str = "org.freedesktop.DBus.Error.AccessDenied";
pub const LIVE_OVERRIDES_PATH: &str = "/var/lib/lazaret/live-overrides.toml";
pub const BASE_CLAMD_CONFIG_PATH: &str = "/etc/clamav/clamd.conf";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverrideSetting {
    pub setting_key: String,
    pub setting_value: String,
    pub override_lifetime: OverrideLifetime,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LiveTuning {
    AdminServiceNotInstalled,
    AdminServiceUnreachable(zbus::Error),
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
    #[error("the ClamAV admin service answered with an unknown outcome: {admin_service_answer}")]
    UnknownAdminServiceAnswer { admin_service_answer: String },
    #[error("administrator authorization was not given")]
    AuthorizationRefused,
    #[error("the ClamAV admin service is not installed")]
    AdminServiceMissing,
    #[error("the ClamAV admin service reported: {admin_service_message}")]
    ReportedByAdminService { admin_service_message: String },
    #[error("the requested value can't be used: {request_problem}")]
    InvalidRequest { request_problem: String },
    #[error(transparent)]
    AdminServiceCallFailed(zbus::Error),
}

impl From<zbus::Error> for LiveChangeFailure {
    fn from(call_failure: zbus::Error) -> Self {
        match call_failure {
            zbus::Error::MethodError(error_name, _error_message, _reply)
                if error_name.as_str() == SERVICE_UNKNOWN_ERROR =>
            {
                Self::AdminServiceMissing
            }
            zbus::Error::MethodError(error_name, _error_message, _reply)
                if error_name.as_str() == ACCESS_DENIED_ERROR =>
            {
                Self::AuthorizationRefused
            }
            zbus::Error::MethodError(_error_name, Some(admin_service_message), _reply) => {
                Self::ReportedByAdminService {
                    admin_service_message,
                }
            }
            other_call_failure => Self::AdminServiceCallFailed(other_call_failure),
        }
    }
}

async fn admin_service_proxy() -> zbus::Result<ClamavAdminProxy<'static>> {
    ClamavAdminProxy::new(&Connection::system().await?).await
}

fn config_lines_in(config_text: &str) -> ClamdConfigLines {
    match config_text.parse() {
        Ok(config_lines) => config_lines,
        Err(never_fails) => match never_fails {},
    }
}

pub fn read_stored_overrides(
    overrides_path: &Path,
) -> Result<LiveOverrides, StoredOverridesFailure> {
    match fs::read_to_string(overrides_path) {
        Ok(overrides_text) => LiveOverrides::from_toml_text(&overrides_text)
            .map_err(|_invalid_overrides| StoredOverridesFailure::OverridesFileInvalid),
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => {
            Ok(LiveOverrides::default())
        }
        Err(read_failure) => Err(StoredOverridesFailure::OverridesFileUnreadable {
            failure_kind: read_failure.kind(),
        }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StoredOverridesFailure {
    #[error("the runtime changes file could not be read: {failure_kind}")]
    OverridesFileUnreadable { failure_kind: io::ErrorKind },
    #[error("the runtime changes file is not in the expected format")]
    OverridesFileInvalid,
}

pub fn active_override_settings(
    live_overrides: &LiveOverrides,
    base_config_path: &Path,
) -> Vec<OverrideSetting> {
    let base_settings = fs::read_to_string(base_config_path)
        .ok()
        .and_then(|base_text| tunable_settings_in(&config_lines_in(&base_text)).ok());
    let base_view = base_settings
        .as_ref()
        .map_or(BaseSettings::UnreadableBase, BaseSettings::ReadableBase);
    live_overrides
        .override_reports(base_view, Timestamp::now())
        .into_iter()
        .flat_map(|override_report| {
            override_report
                .changed_values
                .into_iter()
                .map(move |setting_value| OverrideSetting {
                    setting_key: override_report.setting_name.to_owned(),
                    setting_value,
                    override_lifetime: override_report.override_lifetime,
                })
        })
        .collect()
}

fn live_tuning_from_answer(tunable_answer: zbus::Result<Vec<String>>) -> LiveTuning {
    match tunable_answer {
        Ok(tunable_settings) => LiveTuning::Available {
            tunable_settings,
            active_overrides: read_stored_overrides(&readable_host_path(LIVE_OVERRIDES_PATH))
                .map(|live_overrides| {
                    active_override_settings(
                        &live_overrides,
                        &readable_host_path(BASE_CLAMD_CONFIG_PATH),
                    )
                })
                .unwrap_or_default(),
        },
        Err(zbus::Error::MethodError(error_name, _error_message, _reply))
            if error_name.as_str() == SERVICE_UNKNOWN_ERROR =>
        {
            LiveTuning::AdminServiceNotInstalled
        }
        Err(call_failure) => LiveTuning::AdminServiceUnreachable(call_failure),
    }
}

async fn live_tuning_on_bus(bus_connection: zbus::Result<Connection>) -> LiveTuning {
    let tunable_answer = async {
        let clamav_admin_service = ClamavAdminProxy::new(&bus_connection?).await?;
        clamav_admin_service.get_tunable_settings().await
    };
    live_tuning_from_answer(tunable_answer.await)
}

pub async fn read_live_tuning() -> LiveTuning {
    live_tuning_on_bus(Connection::system().await).await
}

pub fn outcome_from_admin_service_answer(admin_service_answer: &str) -> LiveChangeOutcome {
    match admin_service_answer {
        APPLIED_ANSWER => LiveChangeOutcome::SettingsApplied,
        ROLLED_BACK_ANSWER => LiveChangeOutcome::PreviousRestored,
        other_answer => {
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::UnknownAdminServiceAnswer {
                admin_service_answer: other_answer.to_owned(),
            })
        }
    }
}

fn outcome_of_admin_service_call(admin_service_answer: zbus::Result<String>) -> LiveChangeOutcome {
    match admin_service_answer {
        Ok(admin_service_answer) => outcome_from_admin_service_answer(&admin_service_answer),
        Err(call_failure) => LiveChangeOutcome::NothingChanged(call_failure.into()),
    }
}

async fn send_setting_changes(setting_changes: &SettingChanges) -> LiveChangeOutcome {
    let change_document = match setting_changes.to_toml_text() {
        Ok(change_document) => change_document,
        Err(serialize_failure) => {
            return LiveChangeOutcome::NothingChanged(LiveChangeFailure::InvalidRequest {
                request_problem: serialize_failure.to_string(),
            });
        }
    };
    let admin_service_answer = async {
        admin_service_proxy()
            .await?
            .apply_changes(&change_document)
            .await
    };
    outcome_of_admin_service_call(admin_service_answer.await)
}

fn request_lines(setting_key: &str, setting_values: &[String]) -> Result<ClamdConfigLines, String> {
    setting_values
        .iter()
        .map(|setting_value| {
            SettingLine::rendered(setting_key, setting_value)
                .map(|setting_line| setting_line.line_text)
                .map_err(|line_problem| line_problem.to_string())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|line_texts| config_lines_in(&line_texts.join("\n")))
}

pub async fn reset_live_settings(setting_keys: Vec<String>) -> LiveChangeOutcome {
    let setting_names = setting_keys
        .iter()
        .map(|setting_key| setting_key.parse::<TunableSettingName>())
        .collect::<Result<BTreeSet<_>, _>>();
    match setting_names {
        Ok(setting_names) => {
            send_setting_changes(&SettingChanges::BackToSystem { setting_names }).await
        }
        Err(unknown_name) => LiveChangeOutcome::NothingChanged(LiveChangeFailure::InvalidRequest {
            request_problem: unknown_name.to_string(),
        }),
    }
}

pub async fn apply_live_change(
    setting_key: String,
    setting_values: Vec<String>,
) -> LiveChangeOutcome {
    let requested_settings =
        request_lines(&setting_key, &setting_values).and_then(|requested_lines| {
            requested_settings_in(&requested_lines)
                .map_err(|request_problem| request_problem.to_string())
        });
    match requested_settings {
        Ok(requested_settings) => {
            send_setting_changes(&SettingChanges::SetValues {
                setting_values: Box::new(requested_settings),
            })
            .await
        }
        Err(request_problem) => {
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::InvalidRequest { request_problem })
        }
    }
}

pub fn change_effect(
    setting_key: &str,
    current_values: &[String],
    new_values: &[String],
) -> ProtectionReduction {
    match (
        request_lines(setting_key, current_values),
        request_lines(setting_key, new_values),
    ) {
        (Ok(current_lines), Ok(requested_lines)) => {
            change_reduction_from(&current_lines, &requested_lines, Timestamp::now())
        }
        (Err(_unusable_current), Ok(requested_lines)) => change_reduction_from(
            &ClamdConfigLines::default(),
            &requested_lines,
            Timestamp::now(),
        )
        .or_else(ProtectionReduction::CurrentValuesUnknown),
        (_any_current, Err(_unusable_request)) => ProtectionReduction::CurrentValuesUnknown,
    }
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
    fn admin_service_answers_map_to_outcomes() {
        assert_eq!(
            outcome_from_admin_service_answer("applied"),
            LiveChangeOutcome::SettingsApplied
        );
        assert_eq!(
            outcome_from_admin_service_answer("rolled-back"),
            LiveChangeOutcome::PreviousRestored
        );
        assert_eq!(
            outcome_from_admin_service_answer("surprise"),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::UnknownAdminServiceAnswer {
                admin_service_answer: "surprise".to_owned(),
            })
        );
    }

    fn admin_service_method_error(error_name: &str, error_message: &str) -> zbus::Error {
        let request_message = zbus::message::Message::method_call("/", "ApplyChanges")
            .expect("method call")
            .destination("page.codeberg.wvhulle.Lazaret.ClamavAdmin")
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
    fn admin_service_errors_are_classified_by_their_dbus_name() {
        assert_eq!(
            outcome_of_admin_service_call(Err(admin_service_method_error(
                ACCESS_DENIED_ERROR,
                "Failed with NotAuthorized somewhere"
            ))),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::AuthorizationRefused)
        );
        assert_eq!(
            outcome_of_admin_service_call(Err(admin_service_method_error(
                SERVICE_UNKNOWN_ERROR,
                "no such name"
            ))),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::AdminServiceMissing)
        );
        assert_eq!(
            outcome_of_admin_service_call(Err(admin_service_method_error(
                "org.freedesktop.DBus.Error.Failed",
                "AccessDenied: the configuration files could not be updated"
            ))),
            LiveChangeOutcome::NothingChanged(LiveChangeFailure::ReportedByAdminService {
                admin_service_message: "AccessDenied: the configuration files could not be updated"
                    .to_owned(),
            })
        );
    }

    #[test]
    fn an_unreachable_admin_service_is_reported_as_unavailable() {
        let unreachable_bus = Err(zbus::Error::Address("no bus here".to_owned()));
        let live_tuning = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(live_tuning_on_bus(unreachable_bus));
        assert!(matches!(
            live_tuning,
            LiveTuning::AdminServiceUnreachable(zbus::Error::Address(_))
        ));
    }
}
