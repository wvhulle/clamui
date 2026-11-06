mod detection_trust_files;
mod helper_audit_journal;
mod merged_clamd_config;
mod protection_change_rules;
mod settings_application;
mod tunable_setting_rules;

use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use zbus::{blocking::connection::Builder, fdo, interface, message::Header, zvariant::Value};

use crate::{
    detection_trust_files::{
        TrustRequest, apply_trust_request, request_protection_reduction, request_summary,
        validated_request,
    },
    helper_audit_journal::{
        AuditOutcome, AuditedAction, HelperAuditRecord, RequestingUser, record_helper_action,
    },
    merged_clamd_config::OverrideSetting,
    protection_change_rules::{ProtectionReduction, ValuesInEffect, protection_reduction},
    settings_application::{
        ApplicationOutcome, SettingsPaths, SystemClamavServices, apply_setting_changes,
        clamd_reloads_signatures, config_values_in_effect, read_current_overrides,
        read_tunable_settings, write_merged_config,
    },
};

const HELPER_BUS_NAME: &str = "page.codeberg.wvhulle.Lazaret.SettingsHelper";
const HELPER_OBJECT_PATH: &str = "/page/codeberg/wvhulle/Lazaret/SettingsHelper";
const APPLY_ACTION_ID: &str = "page.codeberg.wvhulle.Lazaret.apply-settings";
const TRUST_ACTION_ID: &str = "page.codeberg.wvhulle.Lazaret.trust-detection";
const POLKIT_BUS_NAME: &str = "org.freedesktop.PolicyKit1";
const POLKIT_OBJECT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const ALLOW_USER_INTERACTION: u32 = 1;
const CHANGE_DETAIL_KEY: &str = "lazaret.change";
const TRUST_DETAIL_KEY: &str = "lazaret.trust";
const DEFAULT_LOCAL_SOCKET: &str = "/run/clamav/clamd.ctl";
const DEFAULT_DATABASE_DIRECTORY: &str = "/var/lib/clamav";
const APPLIED_ANSWER: &str = "applied";
const RELOAD_PENDING_ANSWER: &str = "applied-reload-pending";
const ROLLED_BACK_ANSWER: &str = "rolled-back";
const IDLE_EXIT_PAUSE: Duration = Duration::from_secs(60);

type PolkitSubject<'subject> = (&'subject str, HashMap<&'subject str, Value<'subject>>);

fn changes_for_prompt(requested_changes: &[OverrideSetting]) -> String {
    requested_changes
        .iter()
        .map(|requested_change| {
            format!(
                "{} {}",
                requested_change.setting_key, requested_change.setting_value
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

struct AuthorizationRequest<'request> {
    action_id: &'request str,
    detail_key: &'request str,
    detail_text: &'request str,
}

async fn requesting_user(caller_name: &str) -> RequestingUser {
    let looked_up_user = async {
        let bus_connection = zbus::Connection::system().await?;
        let bus_proxy = fdo::DBusProxy::new(&bus_connection).await?;
        let bus_name = zbus::names::BusName::try_from(caller_name)?;
        Ok::<u32, zbus::Error>(bus_proxy.get_connection_unix_user(bus_name).await?)
    };
    looked_up_user
        .await
        .map_or(RequestingUser::UnknownUser, |user_id| {
            RequestingUser::KnownUser { user_id }
        })
}

async fn caller_is_authorized(
    caller_name: &str,
    authorization_request: AuthorizationRequest<'_>,
) -> fdo::Result<bool> {
    let polkit_connection = zbus::Connection::system()
        .await
        .map_err(|bus_failure| fdo::Error::Failed(bus_failure.to_string()))?;
    let subject: PolkitSubject<'_> = (
        "system-bus-name",
        HashMap::from([("name", Value::from(caller_name))]),
    );
    let details = HashMap::from([(
        authorization_request.detail_key,
        authorization_request.detail_text,
    )]);
    let authorization_reply = polkit_connection
        .call_method(
            Some(POLKIT_BUS_NAME),
            POLKIT_OBJECT_PATH,
            Some(POLKIT_INTERFACE),
            "CheckAuthorization",
            &(
                subject,
                authorization_request.action_id,
                details,
                ALLOW_USER_INTERACTION,
                "",
            ),
        )
        .await
        .map_err(|polkit_failure| fdo::Error::Failed(polkit_failure.to_string()))?;
    let (is_authorized, _is_challenge, _result_details): (bool, bool, HashMap<String, String>) =
        authorization_reply
            .body()
            .deserialize()
            .map_err(|reply_failure| fdo::Error::Failed(reply_failure.to_string()))?;
    Ok(is_authorized)
}

fn configured_path(
    settings_paths: &SettingsPaths,
    setting_key: &str,
    default_path: &str,
) -> PathBuf {
    match config_values_in_effect(settings_paths, setting_key) {
        ValuesInEffect::Configured { setting_values } => setting_values
            .into_iter()
            .next()
            .filter(|configured_value| configured_value.starts_with('/'))
            .map_or_else(|| PathBuf::from(default_path), PathBuf::from),
        ValuesInEffect::NotConfigured | ValuesInEffect::ConfigUnreadable(_) => {
            PathBuf::from(default_path)
        }
    }
}

fn local_socket_in_config(settings_paths: &SettingsPaths) -> PathBuf {
    configured_path(settings_paths, "LocalSocket", DEFAULT_LOCAL_SOCKET)
}

fn database_directory_in_config(settings_paths: &SettingsPaths) -> PathBuf {
    configured_path(
        settings_paths,
        "DatabaseDirectory",
        DEFAULT_DATABASE_DIRECTORY,
    )
}

fn requested_changes_reduction(
    settings_paths: &SettingsPaths,
    requested_changes: &[OverrideSetting],
) -> ProtectionReduction {
    let new_values_by_key = requested_changes.iter().fold(
        BTreeMap::<&str, Vec<String>>::new(),
        |mut new_values_by_key, requested_change| {
            new_values_by_key
                .entry(requested_change.setting_key.as_str())
                .or_default()
                .push(requested_change.setting_value.clone());
            new_values_by_key
        },
    );
    new_values_by_key
        .iter()
        .map(|(setting_key, new_values)| {
            protection_reduction(
                setting_key,
                &config_values_in_effect(settings_paths, setting_key),
                new_values,
            )
        })
        .find(|change_reduction| change_reduction.weakens_protection())
        .unwrap_or(ProtectionReduction::NoReduction)
}

fn caller_of(message_header: &Header<'_>) -> fdo::Result<String> {
    message_header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| fdo::Error::Failed("the request has no sender".to_owned()))
}

#[derive(Default)]
struct HelperActivity {
    request_running: AtomicBool,
    request_finished_recently: AtomicBool,
}

struct SettingsHelperService {
    settings_paths: SettingsPaths,
    helper_activity: Arc<HelperActivity>,
}

struct FinishedRequestMarker {
    helper_activity: Arc<HelperActivity>,
}

impl Drop for FinishedRequestMarker {
    fn drop(&mut self) {
        self.helper_activity
            .request_finished_recently
            .store(true, Ordering::SeqCst);
        self.helper_activity
            .request_running
            .store(false, Ordering::SeqCst);
    }
}

#[interface(name = "page.codeberg.wvhulle.Lazaret.SettingsHelper")]
impl SettingsHelperService {
    fn get_tunable_settings(&self) -> fdo::Result<Vec<String>> {
        read_tunable_settings(&self.settings_paths)
            .map_err(|read_failure| fdo::Error::Failed(read_failure.to_string()))
    }

    fn get_overrides(&self) -> fdo::Result<Vec<(String, String)>> {
        read_current_overrides(&self.settings_paths)
            .map(|current_overrides| {
                current_overrides
                    .into_iter()
                    .map(|current_override| {
                        (current_override.setting_key, current_override.setting_value)
                    })
                    .collect()
            })
            .map_err(|read_failure| fdo::Error::Failed(read_failure.to_string()))
    }

    async fn apply_changes(
        &self,
        #[zbus(header)] message_header: Header<'_>,
        changes: Vec<(String, String)>,
    ) -> fdo::Result<String> {
        let finish_activity = self.start_request();
        let caller_name = caller_of(&message_header)?;
        let requested_changes = changes
            .into_iter()
            .map(|(setting_key, setting_value)| OverrideSetting {
                setting_key,
                setting_value,
            })
            .collect::<Vec<_>>();
        let change_summary = changes_for_prompt(&requested_changes);
        let protection_reduction =
            requested_changes_reduction(&self.settings_paths, &requested_changes);
        let requesting_user = requesting_user(&caller_name).await;
        let audit = |audit_outcome| {
            record_helper_action(&HelperAuditRecord {
                audited_action: AuditedAction::ChangeSettings,
                action_subject: &change_summary,
                requesting_user,
                audit_outcome,
                protection_reduction,
            });
        };
        let authorization_request = AuthorizationRequest {
            action_id: APPLY_ACTION_ID,
            detail_key: CHANGE_DETAIL_KEY,
            detail_text: &change_summary,
        };
        if !caller_is_authorized(&caller_name, authorization_request).await? {
            audit(AuditOutcome::AuthorizationRefused);
            return Err(fdo::Error::AccessDenied(
                "administrator authorization was not given".to_owned(),
            ));
        }
        let settings_paths = self.settings_paths.clone();
        let application_outcome = tokio::task::spawn_blocking(move || {
            let mut clamav_services = SystemClamavServices {
                local_socket: local_socket_in_config(&settings_paths),
            };
            apply_setting_changes(&settings_paths, &requested_changes, &mut clamav_services)
        })
        .await
        .map_err(|join_failure| fdo::Error::Failed(join_failure.to_string()))?;
        drop(finish_activity);
        match application_outcome {
            Ok(ApplicationOutcome::ChangesApplied) => {
                audit(AuditOutcome::ActionApplied);
                Ok(APPLIED_ANSWER.to_owned())
            }
            Ok(ApplicationOutcome::RolledBackAfterUnhealthyRestart) => {
                audit(AuditOutcome::ActionRolledBack);
                Ok(ROLLED_BACK_ANSWER.to_owned())
            }
            Err(application_failure) => {
                audit(AuditOutcome::ActionFailed);
                Err(fdo::Error::Failed(application_failure.to_string()))
            }
        }
    }

    async fn trust_file(
        &self,
        #[zbus(header)] message_header: Header<'_>,
        sha256_hex: String,
        file_size: u64,
    ) -> fdo::Result<String> {
        self.handle_trust_request(
            &message_header,
            TrustRequest::TrustFile {
                sha256_hex,
                file_size,
            },
        )
        .await
    }

    async fn ignore_signature(
        &self,
        #[zbus(header)] message_header: Header<'_>,
        signature_name: String,
    ) -> fdo::Result<String> {
        self.handle_trust_request(
            &message_header,
            TrustRequest::IgnoreSignature { signature_name },
        )
        .await
    }

    async fn forget_trusted_file(
        &self,
        #[zbus(header)] message_header: Header<'_>,
        sha256_hex: String,
    ) -> fdo::Result<String> {
        self.handle_trust_request(
            &message_header,
            TrustRequest::ForgetTrustedFile { sha256_hex },
        )
        .await
    }

    async fn stop_ignoring_signature(
        &self,
        #[zbus(header)] message_header: Header<'_>,
        signature_name: String,
    ) -> fdo::Result<String> {
        self.handle_trust_request(
            &message_header,
            TrustRequest::StopIgnoringSignature { signature_name },
        )
        .await
    }
}

impl SettingsHelperService {
    fn start_request(&self) -> FinishedRequestMarker {
        self.helper_activity
            .request_running
            .store(true, Ordering::SeqCst);
        FinishedRequestMarker {
            helper_activity: Arc::clone(&self.helper_activity),
        }
    }

    async fn handle_trust_request(
        &self,
        message_header: &Header<'_>,
        trust_request: TrustRequest,
    ) -> fdo::Result<String> {
        let finish_activity = self.start_request();
        let caller_name = caller_of(message_header)?;
        let trust_request = validated_request(trust_request)
            .map_err(|trust_refusal| fdo::Error::InvalidArgs(trust_refusal.to_string()))?;
        let trust_summary = request_summary(&trust_request);
        let requesting_user = requesting_user(&caller_name).await;
        let audit = |audit_outcome| {
            record_helper_action(&HelperAuditRecord {
                audited_action: AuditedAction::TrustChange(&trust_request),
                action_subject: &trust_summary,
                requesting_user,
                audit_outcome,
                protection_reduction: request_protection_reduction(&trust_request),
            });
        };
        let authorization_request = AuthorizationRequest {
            action_id: TRUST_ACTION_ID,
            detail_key: TRUST_DETAIL_KEY,
            detail_text: &trust_summary,
        };
        if !caller_is_authorized(&caller_name, authorization_request).await? {
            audit(AuditOutcome::AuthorizationRefused);
            return Err(fdo::Error::AccessDenied(
                "administrator authorization was not given".to_owned(),
            ));
        }
        let settings_paths = self.settings_paths.clone();
        let applied_request = trust_request.clone();
        let trust_outcome = tokio::task::spawn_blocking(move || {
            apply_trust_request(
                &database_directory_in_config(&settings_paths),
                &applied_request,
            )
            .map(|()| clamd_reloads_signatures(&local_socket_in_config(&settings_paths)))
        })
        .await
        .map_err(|join_failure| fdo::Error::Failed(join_failure.to_string()))?;
        drop(finish_activity);
        match trust_outcome {
            Ok(clamd_reloading) => {
                audit(AuditOutcome::ActionApplied);
                Ok(if clamd_reloading {
                    APPLIED_ANSWER
                } else {
                    RELOAD_PENDING_ANSWER
                }
                .to_owned())
            }
            Err(trust_refusal) => {
                audit(AuditOutcome::ActionFailed);
                Err(fdo::Error::Failed(trust_refusal.to_string()))
            }
        }
    }
}

fn serve_settings_helper() -> zbus::Result<()> {
    let helper_activity = Arc::new(HelperActivity::default());
    let _service_connection = Builder::system()?
        .name(HELPER_BUS_NAME)?
        .serve_at(
            HELPER_OBJECT_PATH,
            SettingsHelperService {
                settings_paths: SettingsPaths::on_this_host(),
                helper_activity: Arc::clone(&helper_activity),
            },
        )?
        .build()?;
    loop {
        thread::sleep(IDLE_EXIT_PAUSE);
        let finished_recently = helper_activity
            .request_finished_recently
            .swap(false, Ordering::SeqCst);
        if !finished_recently && !helper_activity.request_running.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum HelperModeFailure {
    #[error("the settings helper could not serve on the system bus: {0}")]
    ServingFailed(#[from] zbus::Error),
    #[error("the merged clamd configuration could not be written: {0}")]
    MergeFailed(#[from] std::io::Error),
    #[error("usage: lazaret-settings-helper serve|merge")]
    UnknownMode,
}

fn run_requested_mode(requested_mode: &str) -> Result<(), HelperModeFailure> {
    match requested_mode {
        "serve" => Ok(serve_settings_helper()?),
        "merge" => Ok(write_merged_config(&SettingsPaths::on_this_host())?),
        _unknown_mode => Err(HelperModeFailure::UnknownMode),
    }
}

fn main() -> ExitCode {
    let requested_mode = std::env::args().nth(1).unwrap_or_default();
    match run_requested_mode(&requested_mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(mode_failure) => {
            eprintln!("{mode_failure}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod settings_helper_tests {
    use super::*;

    #[test]
    fn a_request_stays_running_until_its_marker_is_dropped() {
        let helper_activity = Arc::new(HelperActivity::default());
        helper_activity
            .request_running
            .store(true, Ordering::SeqCst);
        let finish_activity = FinishedRequestMarker {
            helper_activity: Arc::clone(&helper_activity),
        };
        assert!(helper_activity.request_running.load(Ordering::SeqCst));
        drop(finish_activity);
        assert!(!helper_activity.request_running.load(Ordering::SeqCst));
        assert!(
            helper_activity
                .request_finished_recently
                .load(Ordering::SeqCst)
        );
    }

    #[test]
    fn the_prompt_shows_the_exact_change() {
        assert_eq!(
            changes_for_prompt(&[OverrideSetting {
                setting_key: "OnAccessPrevention".to_owned(),
                setting_value: "false".to_owned(),
            }]),
            "OnAccessPrevention false"
        );
    }

    #[test]
    fn both_actions_retain_no_authorization_and_show_the_exact_request() {
        let policy_text = include_str!("../../data/page.codeberg.wvhulle.Lazaret.policy");
        assert!(policy_text.contains(&format!("id=\"{APPLY_ACTION_ID}\"")));
        assert!(policy_text.contains(&format!("id=\"{TRUST_ACTION_ID}\"")));
        assert_eq!(
            policy_text
                .matches("<allow_active>auth_admin</allow_active>")
                .count(),
            2
        );
        assert!(!policy_text.contains("auth_admin_keep"));
        assert!(policy_text.contains(&format!("$({CHANGE_DETAIL_KEY})")));
        assert!(policy_text.contains(&format!("$({TRUST_DETAIL_KEY})")));
    }

    #[test]
    fn the_bus_configuration_names_this_service() {
        let bus_policy =
            include_str!("../../data/page.codeberg.wvhulle.Lazaret.SettingsHelper.conf");
        assert!(bus_policy.contains(&format!("own=\"{HELPER_BUS_NAME}\"")));
        assert!(bus_policy.contains(&format!("send_destination=\"{HELPER_BUS_NAME}\"")));
    }
}
