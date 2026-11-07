mod admin_audit_journal;
mod clamav_services;
mod detection_trust_files;
mod settings_application;

use std::{
    collections::HashMap,
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clamd_configuration::{
    clamd_conf_format::serializer::to_setting_lines,
    live_overrides::{ReductionExpiry, SettingChanges},
    protection_rules::ProtectionReduction,
};
use jiff::Timestamp;
use zbus::{connection::Builder, fdo, interface, message::Header, zvariant::Value};

use crate::{
    admin_audit_journal::{
        AdminAuditRecord, AuditOutcome, AuditedAction, RequestingUser, record_admin_action,
    },
    clamav_services::{
        ClamavServices, ServicesReadiness, SystemClamavServices, clamd_reloads_signatures,
    },
    detection_trust_files::{
        TrustRequest, apply_trust_request, request_protection_reduction, request_summary,
        validated_request,
    },
    settings_application::{
        ApplicationFailure, ApplicationOutcome, SettingsPaths, apply_setting_changes,
        expire_reductions, planned_overrides_change, read_lines_in_effect, read_tunable_allowlist,
        write_merged_config,
    },
};

const ADMIN_BUS_NAME: &str = "page.codeberg.wvhulle.Lazaret.ClamavAdmin";
const ADMIN_OBJECT_PATH: &str = "/page/codeberg/wvhulle/Lazaret/ClamavAdmin";
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
const ROOT_USER_ID: u32 = 0;

type PolkitSubject<'subject> = (&'subject str, HashMap<&'subject str, Value<'subject>>);

fn changes_for_prompt(setting_changes: &SettingChanges) -> String {
    match setting_changes {
        SettingChanges::SetValues { setting_values } => to_setting_lines(setting_values.as_ref())
            .map(|setting_lines| {
                setting_lines
                    .into_iter()
                    .map(|setting_line| setting_line.line_text)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
        SettingChanges::BackToSystem { setting_names } => format!(
            "back to the system configuration: {}",
            setting_names
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
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
    setting_name: &str,
    default_path: &str,
) -> PathBuf {
    read_lines_in_effect(settings_paths)
        .ok()
        .and_then(|lines_in_effect| {
            lines_in_effect
                .values_of(setting_name)
                .first()
                .filter(|configured_value| configured_value.starts_with('/'))
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from(default_path))
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

fn caller_of(message_header: &Header<'_>) -> fdo::Result<String> {
    message_header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| fdo::Error::Failed("the request has no sender".to_owned()))
}

#[derive(Default)]
struct AdminServiceActivity {
    request_running: AtomicBool,
    request_finished_recently: AtomicBool,
}

struct ClamavAdminService {
    settings_paths: SettingsPaths,
    admin_service_activity: Arc<AdminServiceActivity>,
}

struct FinishedRequestMarker {
    admin_service_activity: Arc<AdminServiceActivity>,
}

impl Drop for FinishedRequestMarker {
    fn drop(&mut self) {
        self.admin_service_activity
            .request_finished_recently
            .store(true, Ordering::SeqCst);
        self.admin_service_activity
            .request_running
            .store(false, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug)]
struct PlannedAudit {
    protection_reduction: ProtectionReduction,
    reduction_expiry: ReductionExpiry,
}

const UNPLANNED_AUDIT: PlannedAudit = PlannedAudit {
    protection_reduction: ProtectionReduction::NoReduction,
    reduction_expiry: ReductionExpiry::NoExpiry,
};

#[interface(name = "page.codeberg.wvhulle.Lazaret.ClamavAdmin")]
impl ClamavAdminService {
    fn get_tunable_settings(&self) -> fdo::Result<Vec<String>> {
        read_tunable_allowlist(&self.settings_paths)
            .map(|tunable_allowlist| {
                tunable_allowlist
                    .allowed_names
                    .iter()
                    .map(ToString::to_string)
                    .collect()
            })
            .map_err(|read_failure| fdo::Error::Failed(read_failure.to_string()))
    }

    async fn apply_changes(
        &self,
        #[zbus(header)] message_header: Header<'_>,
        change_document: String,
    ) -> fdo::Result<String> {
        let finish_activity = self.start_request();
        let caller_name = caller_of(&message_header)?;
        let setting_changes = SettingChanges::from_toml_text(&change_document)
            .map_err(|parse_failure| fdo::Error::InvalidArgs(parse_failure.to_string()))?;
        let change_summary = changes_for_prompt(&setting_changes);
        let requesting_user = requesting_user(&caller_name).await;
        let now = Timestamp::now();
        let audit = |audit_outcome, planned_audit: PlannedAudit| {
            record_admin_action(&AdminAuditRecord {
                audited_action: AuditedAction::ChangeSettings {
                    reduction_expiry: planned_audit.reduction_expiry,
                },
                action_subject: &change_summary,
                requesting_user,
                audit_outcome,
                protection_reduction: planned_audit.protection_reduction,
            });
        };
        let planned_audit =
            match planned_overrides_change(&self.settings_paths, &setting_changes, now) {
                Ok(overrides_change) => PlannedAudit {
                    protection_reduction: overrides_change.protection_reduction,
                    reduction_expiry: overrides_change.reduction_expiry,
                },
                Err(planning_failure) => {
                    audit(AuditOutcome::ActionFailed, UNPLANNED_AUDIT);
                    return Err(fdo::Error::Failed(planning_failure.to_string()));
                }
            };
        let authorization_request = AuthorizationRequest {
            action_id: APPLY_ACTION_ID,
            detail_key: CHANGE_DETAIL_KEY,
            detail_text: &change_summary,
        };
        if !caller_is_authorized(&caller_name, authorization_request).await? {
            audit(AuditOutcome::AuthorizationRefused, planned_audit);
            return Err(fdo::Error::AccessDenied(
                "administrator authorization was not given".to_owned(),
            ));
        }
        let local_socket = local_socket_in_config(&self.settings_paths);
        let mut clamav_services = SystemClamavServices {
            local_socket: &local_socket,
        };
        let application_outcome = apply_setting_changes(
            &self.settings_paths,
            &setting_changes,
            &mut clamav_services,
            now,
        )
        .await;
        drop(finish_activity);
        match application_outcome {
            Ok(ApplicationOutcome::ChangesApplied) => {
                audit(AuditOutcome::ActionApplied, planned_audit);
                Ok(APPLIED_ANSWER.to_owned())
            }
            Ok(ApplicationOutcome::RolledBackAfterFailedRestart) => {
                audit(AuditOutcome::ActionRolledBack, planned_audit);
                Ok(ROLLED_BACK_ANSWER.to_owned())
            }
            Err(application_failure) => {
                audit(AuditOutcome::ActionFailed, planned_audit);
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

impl ClamavAdminService {
    fn start_request(&self) -> FinishedRequestMarker {
        self.admin_service_activity
            .request_running
            .store(true, Ordering::SeqCst);
        FinishedRequestMarker {
            admin_service_activity: Arc::clone(&self.admin_service_activity),
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
            record_admin_action(&AdminAuditRecord {
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
        let trust_answer = match apply_trust_request(
            &database_directory_in_config(&self.settings_paths),
            &trust_request,
        ) {
            Ok(()) => {
                audit(AuditOutcome::ActionApplied);
                let clamd_reloading =
                    clamd_reloads_signatures(&local_socket_in_config(&self.settings_paths)).await;
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
        };
        drop(finish_activity);
        trust_answer
    }
}

async fn serve_clamav_admin_service() -> zbus::Result<()> {
    let admin_service_activity = Arc::new(AdminServiceActivity::default());
    let _service_connection = Builder::system()?
        .name(ADMIN_BUS_NAME)?
        .serve_at(
            ADMIN_OBJECT_PATH,
            ClamavAdminService {
                settings_paths: SettingsPaths::on_this_host(),
                admin_service_activity: Arc::clone(&admin_service_activity),
            },
        )?
        .build()
        .await?;
    loop {
        tokio::time::sleep(IDLE_EXIT_PAUSE).await;
        let finished_recently = admin_service_activity
            .request_finished_recently
            .swap(false, Ordering::SeqCst);
        if !finished_recently
            && !admin_service_activity
                .request_running
                .load(Ordering::SeqCst)
        {
            return Ok(());
        }
    }
}

async fn expire_and_restart(settings_paths: &SettingsPaths) -> Result<(), ApplicationFailure> {
    let expired_names = expire_reductions(settings_paths, Timestamp::now())?;
    if expired_names.is_empty() {
        return Ok(());
    }
    let local_socket = local_socket_in_config(settings_paths);
    let services_readiness = SystemClamavServices {
        local_socket: &local_socket,
    }
    .restart_until_ready()
    .await;
    record_admin_action(&AdminAuditRecord {
        audited_action: AuditedAction::ExpireReductions,
        action_subject: &format!("expired: {}", expired_names.join(", ")),
        requesting_user: RequestingUser::KnownUser {
            user_id: ROOT_USER_ID,
        },
        audit_outcome: match services_readiness {
            Ok(ServicesReadiness::ServicesReady) => AuditOutcome::ActionApplied,
            Ok(ServicesReadiness::ServiceNotReady { .. }) | Err(_) => AuditOutcome::ActionFailed,
        },
        protection_reduction: ProtectionReduction::NoReduction,
    });
    services_readiness
        .map(|_services_readiness| ())
        .map_err(ApplicationFailure::from)
}

#[derive(Debug, thiserror::Error)]
enum AdminModeFailure {
    #[error("the ClamAV admin service could not serve on the system bus: {0}")]
    ServingFailed(#[from] zbus::Error),
    #[error("the merged clamd configuration could not be written: {0}")]
    MergeFailed(#[from] std::io::Error),
    #[error("expired reductions could not be removed: {0}")]
    ExpiryFailed(#[from] ApplicationFailure),
    #[error("usage: lazaret-clamav-admin serve|merge|expire")]
    UnknownMode,
}

async fn run_requested_mode(requested_mode: &str) -> Result<(), AdminModeFailure> {
    let settings_paths = SettingsPaths::on_this_host();
    match requested_mode {
        "serve" => Ok(serve_clamav_admin_service().await?),
        "merge" => Ok(write_merged_config(&settings_paths, Timestamp::now())?),
        "expire" => Ok(expire_and_restart(&settings_paths).await?),
        _unknown_mode => Err(AdminModeFailure::UnknownMode),
    }
}

fn main() -> ExitCode {
    let requested_mode = std::env::args().nth(1).unwrap_or_default();
    let mode_outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(AdminModeFailure::from)
        .and_then(|admin_runtime| admin_runtime.block_on(run_requested_mode(&requested_mode)));
    match mode_outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(mode_failure) => {
            eprintln!("{mode_failure}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod clamav_admin_service_tests {
    use super::*;

    #[test]
    fn a_request_stays_running_until_its_marker_is_dropped() {
        let admin_service_activity = Arc::new(AdminServiceActivity::default());
        admin_service_activity
            .request_running
            .store(true, Ordering::SeqCst);
        let finish_activity = FinishedRequestMarker {
            admin_service_activity: Arc::clone(&admin_service_activity),
        };
        assert!(
            admin_service_activity
                .request_running
                .load(Ordering::SeqCst)
        );
        drop(finish_activity);
        assert!(
            !admin_service_activity
                .request_running
                .load(Ordering::SeqCst)
        );
        assert!(
            admin_service_activity
                .request_finished_recently
                .load(Ordering::SeqCst)
        );
    }

    #[test]
    fn the_prompt_shows_the_exact_change() {
        let setting_changes = SettingChanges::from_toml_text(
            "change = \"set-values\"\n\n[setting_values]\nOnAccessPrevention = \
             false\nOnAccessMaxFileSize = \"200M\"\n",
        )
        .expect("parsed");
        assert_eq!(
            changes_for_prompt(&setting_changes),
            "OnAccessPrevention no, OnAccessMaxFileSize 200M"
        );
    }

    #[test]
    fn both_actions_retain_no_authorization_and_show_the_exact_request() {
        let policy_text = include_str!("../system_files/page.codeberg.wvhulle.Lazaret.policy");
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
            include_str!("../system_files/page.codeberg.wvhulle.Lazaret.ClamavAdmin.conf");
        assert!(bus_policy.contains(&format!("own=\"{ADMIN_BUS_NAME}\"")));
        assert!(bus_policy.contains(&format!("send_destination=\"{ADMIN_BUS_NAME}\"")));
    }
}
