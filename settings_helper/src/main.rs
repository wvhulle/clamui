mod merged_clamd_config;
mod settings_application;
mod tunable_setting_rules;

use std::{
    collections::HashMap,
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
    merged_clamd_config::OverrideSetting,
    settings_application::{
        ApplicationOutcome, SettingsPaths, SystemClamavServices, apply_setting_changes,
        read_current_overrides, read_tunable_settings, write_merged_config,
    },
};

const HELPER_BUS_NAME: &str = "page.codeberg.wvhulle.Lazaret.SettingsHelper";
const HELPER_OBJECT_PATH: &str = "/page/codeberg/wvhulle/Lazaret/SettingsHelper";
const APPLY_ACTION_ID: &str = "page.codeberg.wvhulle.Lazaret.apply-settings";
const POLKIT_BUS_NAME: &str = "org.freedesktop.PolicyKit1";
const POLKIT_OBJECT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
const ALLOW_USER_INTERACTION: u32 = 1;
const CHANGE_DETAIL_KEY: &str = "lazaret.change";
const DEFAULT_LOCAL_SOCKET: &str = "/run/clamav/clamd.ctl";
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

async fn caller_is_authorized(caller_name: &str, change_summary: &str) -> fdo::Result<bool> {
    let polkit_connection = zbus::Connection::system()
        .await
        .map_err(|bus_failure| fdo::Error::Failed(bus_failure.to_string()))?;
    let subject: PolkitSubject<'_> = (
        "system-bus-name",
        HashMap::from([("name", Value::from(caller_name))]),
    );
    let details = HashMap::from([(CHANGE_DETAIL_KEY, change_summary)]);
    let authorization_reply = polkit_connection
        .call_method(
            Some(POLKIT_BUS_NAME),
            POLKIT_OBJECT_PATH,
            Some(POLKIT_INTERFACE),
            "CheckAuthorization",
            &(
                subject,
                APPLY_ACTION_ID,
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

fn local_socket_in_config(settings_paths: &SettingsPaths) -> PathBuf {
    std::fs::read_to_string(&settings_paths.base_config)
        .ok()
        .and_then(|base_config| {
            base_config.lines().find_map(|base_line| {
                base_line
                    .strip_prefix("LocalSocket ")
                    .map(|socket_path| PathBuf::from(socket_path.trim()))
            })
        })
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOCAL_SOCKET))
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
        self.helper_activity
            .request_running
            .store(true, Ordering::SeqCst);
        let finish_activity = FinishedRequestMarker {
            helper_activity: Arc::clone(&self.helper_activity),
        };
        let caller_name = message_header
            .sender()
            .ok_or_else(|| fdo::Error::Failed("the request has no sender".to_owned()))?
            .to_string();
        let requested_changes = changes
            .into_iter()
            .map(|(setting_key, setting_value)| OverrideSetting {
                setting_key,
                setting_value,
            })
            .collect::<Vec<_>>();
        let change_summary = changes_for_prompt(&requested_changes);
        if !caller_is_authorized(&caller_name, &change_summary).await? {
            println!("refused without authorization: {change_summary}");
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
                println!("applied: {change_summary}");
                Ok("applied".to_owned())
            }
            Ok(ApplicationOutcome::RolledBackAfterUnhealthyRestart) => {
                println!("rolled back after an unhealthy restart: {change_summary}");
                Ok("rolled-back".to_owned())
            }
            Err(application_failure) => {
                println!("failed: {change_summary}: {application_failure}");
                Err(fdo::Error::Failed(application_failure.to_string()))
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

fn main() -> ExitCode {
    let requested_mode = std::env::args().nth(1).unwrap_or_default();
    let mode_outcome = match requested_mode.as_str() {
        "serve" => serve_settings_helper().map_err(|bus_failure| bus_failure.to_string()),
        "merge" => write_merged_config(&SettingsPaths::on_this_host())
            .map_err(|merge_failure| merge_failure.to_string()),
        _unknown_mode => Err("usage: lazaret-settings-helper serve|merge".to_owned()),
    };
    match mode_outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure_text) => {
            eprintln!("{failure_text}");
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
    fn the_action_retains_no_authorization() {
        let policy_text = include_str!("../../data/page.codeberg.wvhulle.Lazaret.policy");
        assert!(policy_text.contains(&format!("id=\"{APPLY_ACTION_ID}\"")));
        assert!(policy_text.contains("<allow_active>auth_admin</allow_active>"));
        assert!(!policy_text.contains("auth_admin_keep"));
        assert!(policy_text.contains(&format!("$({CHANGE_DETAIL_KEY})")));
    }

    #[test]
    fn the_bus_configuration_names_this_service() {
        let bus_policy =
            include_str!("../../data/page.codeberg.wvhulle.Lazaret.SettingsHelper.conf");
        assert!(bus_policy.contains(&format!("own=\"{HELPER_BUS_NAME}\"")));
        assert!(bus_policy.contains(&format!("send_destination=\"{HELPER_BUS_NAME}\"")));
    }
}
