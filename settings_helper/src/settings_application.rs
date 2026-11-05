use std::{
    fs, io,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use crate::{
    merged_clamd_config::{
        OverrideSetting, merge_clamd_config, parse_override_settings, render_override_settings,
        write_file_atomically,
    },
    tunable_setting_rules::{SettingRefusal, check_setting_change, parse_tunable_settings},
};

const HEALTH_DEADLINE: Duration = Duration::from_secs(180);
const HEALTH_RECHECK_PAUSE: Duration = Duration::from_secs(2);
const SOCKET_ANSWER_TIMEOUT: Duration = Duration::from_secs(30);
const PING_REQUEST: &[u8] = b"zPING\0";
const PONG_ANSWER_PREFIX: &[u8] = b"PONG";
const RESTARTED_UNITS: [&str; 2] = ["clamav-daemon.service", "clamav-clamonacc.service"];

#[derive(Clone, Debug)]
pub struct SettingsPaths {
    pub base_config: PathBuf,
    pub overrides_file: PathBuf,
    pub allowlist_file: PathBuf,
    pub merged_config: PathBuf,
}

impl SettingsPaths {
    pub fn on_this_host() -> Self {
        Self {
            base_config: PathBuf::from("/etc/clamav/clamd.conf"),
            overrides_file: PathBuf::from("/var/lib/clamui/clamd-overrides.conf"),
            allowlist_file: PathBuf::from("/etc/clamui/tunable-settings"),
            merged_config: PathBuf::from("/run/clamui/clamd.conf"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApplicationFailure {
    #[error(transparent)]
    ChangeRefused(#[from] SettingRefusal),
    #[error("the configuration files could not be updated: {0}")]
    FilesUnavailable(#[from] io::Error),
    #[error("the services did not come back even after restoring the previous settings")]
    RollbackUnhealthy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationOutcome {
    ChangesApplied,
    RolledBackAfterUnhealthyRestart,
}

pub trait ClamavServices {
    fn restart_services(&mut self) -> io::Result<()>;
    fn services_are_healthy(&mut self) -> bool;
}

pub struct SystemClamavServices {
    pub local_socket: PathBuf,
}

fn clamd_answers_on_socket(local_socket: &PathBuf) -> bool {
    let answered = || -> io::Result<bool> {
        let mut socket_stream = UnixStream::connect(local_socket)?;
        socket_stream.set_read_timeout(Some(SOCKET_ANSWER_TIMEOUT))?;
        socket_stream.write_all(PING_REQUEST)?;
        let mut answer_bytes = [0_u8; 8];
        let answer_length = socket_stream.read(&mut answer_bytes)?;
        Ok(answer_bytes[..answer_length].starts_with(PONG_ANSWER_PREFIX))
    };
    answered().unwrap_or(false)
}

fn unit_is_failed(service_unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-failed", "--quiet", service_unit])
        .status()
        .is_ok_and(|unit_status| unit_status.success())
}

fn load_state_means_loaded(load_state: &str) -> bool {
    load_state.trim() == "loaded"
}

fn active_state_needs_restart(active_state: &str) -> bool {
    matches!(
        active_state.trim(),
        "active" | "activating" | "failed" | "reloading"
    )
}

fn unit_property(service_unit: &str, property_name: &str) -> Option<String> {
    Command::new("systemctl")
        .args([
            "show",
            &format!("--property={property_name}"),
            "--value",
            service_unit,
        ])
        .output()
        .ok()
        .map(|show_output| String::from_utf8_lossy(&show_output.stdout).into_owned())
}

impl ClamavServices for SystemClamavServices {
    fn restart_services(&mut self) -> io::Result<()> {
        RESTARTED_UNITS
            .iter()
            .filter(|service_unit| {
                unit_property(service_unit, "LoadState")
                    .is_some_and(|load_state| load_state_means_loaded(&load_state))
                    && unit_property(service_unit, "ActiveState")
                        .is_some_and(|active_state| active_state_needs_restart(&active_state))
            })
            .try_for_each(|service_unit| {
                let _nothing_to_reset = Command::new("systemctl")
                    .args(["reset-failed", service_unit])
                    .status()?;
                let restart_status = Command::new("systemctl")
                    .args(["restart", service_unit])
                    .status()?;
                if restart_status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!("{service_unit} did not restart")))
                }
            })
    }

    fn services_are_healthy(&mut self) -> bool {
        let started_waiting = Instant::now();
        while started_waiting.elapsed() < HEALTH_DEADLINE {
            if RESTARTED_UNITS
                .iter()
                .any(|service_unit| unit_is_failed(service_unit))
            {
                return false;
            }
            if clamd_answers_on_socket(&self.local_socket) {
                return true;
            }
            thread::sleep(HEALTH_RECHECK_PAUSE);
        }
        false
    }
}

fn read_text_or_empty(file_path: &PathBuf) -> io::Result<String> {
    match fs::read_to_string(file_path) {
        Ok(file_text) => Ok(file_text),
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(read_failure) => Err(read_failure),
    }
}

pub fn read_tunable_settings(settings_paths: &SettingsPaths) -> io::Result<Vec<String>> {
    Ok(parse_tunable_settings(&read_text_or_empty(
        &settings_paths.allowlist_file,
    )?))
}

pub fn read_current_overrides(settings_paths: &SettingsPaths) -> io::Result<Vec<OverrideSetting>> {
    Ok(parse_override_settings(&read_text_or_empty(
        &settings_paths.overrides_file,
    )?))
}

pub fn write_merged_config(settings_paths: &SettingsPaths) -> io::Result<()> {
    let base_config = fs::read_to_string(&settings_paths.base_config)?;
    let merged_config = match (
        read_text_or_empty(&settings_paths.overrides_file),
        read_tunable_settings(settings_paths),
    ) {
        (Ok(overrides_text), Ok(tunable_settings)) => {
            merge_clamd_config(&base_config, &overrides_text, &tunable_settings)
        }
        _unreadable_overrides => base_config,
    };
    write_file_atomically(&settings_paths.merged_config, &merged_config)
}

fn overrides_after_changes(
    current_overrides: Vec<OverrideSetting>,
    requested_changes: &[OverrideSetting],
) -> Vec<OverrideSetting> {
    current_overrides
        .into_iter()
        .filter(|current_override| {
            !requested_changes.iter().any(|requested_change| {
                requested_change.setting_key == current_override.setting_key
            })
        })
        .chain(requested_changes.iter().cloned())
        .collect()
}

pub fn apply_setting_changes(
    settings_paths: &SettingsPaths,
    requested_changes: &[OverrideSetting],
    clamav_services: &mut dyn ClamavServices,
) -> Result<ApplicationOutcome, ApplicationFailure> {
    if requested_changes.is_empty() {
        return Err(SettingRefusal::NoChanges.into());
    }
    let tunable_settings = read_tunable_settings(settings_paths)?;
    requested_changes.iter().try_for_each(|requested_change| {
        check_setting_change(
            &requested_change.setting_key,
            &requested_change.setting_value,
            &tunable_settings,
        )
    })?;
    let last_good_overrides = read_text_or_empty(&settings_paths.overrides_file)?;
    write_file_atomically(
        &settings_paths.overrides_file,
        &render_override_settings(&overrides_after_changes(
            parse_override_settings(&last_good_overrides),
            requested_changes,
        )),
    )?;
    write_merged_config(settings_paths)?;
    let restart_outcome = clamav_services.restart_services();
    if restart_outcome.is_ok() && clamav_services.services_are_healthy() {
        return Ok(ApplicationOutcome::ChangesApplied);
    }
    write_file_atomically(&settings_paths.overrides_file, &last_good_overrides)?;
    write_merged_config(settings_paths)?;
    clamav_services.restart_services()?;
    if clamav_services.services_are_healthy() {
        Ok(ApplicationOutcome::RolledBackAfterUnhealthyRestart)
    } else {
        Err(ApplicationFailure::RollbackUnhealthy)
    }
}

#[cfg(test)]
mod settings_application_tests {
    use super::*;

    struct ScriptedServices {
        health_answers: Vec<bool>,
        restart_count: usize,
    }

    impl ClamavServices for ScriptedServices {
        fn restart_services(&mut self) -> io::Result<()> {
            self.restart_count += 1;
            Ok(())
        }

        fn services_are_healthy(&mut self) -> bool {
            self.health_answers.remove(0)
        }
    }

    fn prepared_paths(temporary_root: &tempfile::TempDir) -> SettingsPaths {
        let settings_paths = SettingsPaths {
            base_config: temporary_root.path().join("base.conf"),
            overrides_file: temporary_root.path().join("overrides.conf"),
            allowlist_file: temporary_root.path().join("allowlist"),
            merged_config: temporary_root.path().join("merged.conf"),
        };
        fs::write(&settings_paths.base_config, "User clamav\nMaxThreads 4\n").expect("base");
        fs::write(&settings_paths.allowlist_file, "MaxThreads\n").expect("allowlist");
        settings_paths
    }

    fn change_of(setting_key: &str, setting_value: &str) -> OverrideSetting {
        OverrideSetting {
            setting_key: setting_key.to_owned(),
            setting_value: setting_value.to_owned(),
        }
    }

    #[test]
    fn a_failed_unit_is_restarted_but_one_stopped_on_purpose_is_left_alone() {
        assert!(active_state_needs_restart("active\n"));
        assert!(active_state_needs_restart("failed\n"));
        assert!(!active_state_needs_restart("inactive\n"));
    }

    #[test]
    fn only_loaded_units_are_restarted() {
        assert!(load_state_means_loaded(
            "loaded
"
        ));
        assert!(!load_state_means_loaded(
            "not-found
"
        ));
        assert!(!load_state_means_loaded(
            "masked
"
        ));
        assert!(!load_state_means_loaded(""));
    }

    #[test]
    fn a_healthy_restart_keeps_the_change() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            health_answers: vec![true],
            restart_count: 0,
        };
        assert_eq!(
            apply_setting_changes(
                &settings_paths,
                &[change_of("MaxThreads", "8")],
                &mut clamav_services
            )
            .expect("applied"),
            ApplicationOutcome::ChangesApplied
        );
        assert_eq!(clamav_services.restart_count, 1);
        let merged_config = fs::read_to_string(&settings_paths.merged_config).expect("merged");
        assert!(merged_config.contains("MaxThreads 8\n"));
        assert!(!merged_config.contains("MaxThreads 4"));
    }

    #[test]
    fn an_unhealthy_restart_restores_the_last_good_settings() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::write(&settings_paths.overrides_file, "MaxThreads 6\n").expect("previous");
        let mut clamav_services = ScriptedServices {
            health_answers: vec![false, true],
            restart_count: 0,
        };
        assert_eq!(
            apply_setting_changes(
                &settings_paths,
                &[change_of("MaxThreads", "8")],
                &mut clamav_services
            )
            .expect("rolled back"),
            ApplicationOutcome::RolledBackAfterUnhealthyRestart
        );
        assert_eq!(clamav_services.restart_count, 2);
        assert_eq!(
            fs::read_to_string(&settings_paths.overrides_file).expect("overrides"),
            "MaxThreads 6\n"
        );
        assert!(
            fs::read_to_string(&settings_paths.merged_config)
                .expect("merged")
                .contains("MaxThreads 6\n")
        );
    }

    #[test]
    fn a_failed_rollback_is_reported_rather_than_hidden() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            health_answers: vec![false, false],
            restart_count: 0,
        };
        assert!(matches!(
            apply_setting_changes(
                &settings_paths,
                &[change_of("MaxThreads", "8")],
                &mut clamav_services
            ),
            Err(ApplicationFailure::RollbackUnhealthy)
        ));
    }

    #[test]
    fn a_refused_change_touches_nothing() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            health_answers: Vec::new(),
            restart_count: 0,
        };
        assert!(matches!(
            apply_setting_changes(
                &settings_paths,
                &[change_of("VirusEvent", "/bin/sh")],
                &mut clamav_services
            ),
            Err(ApplicationFailure::ChangeRefused(_))
        ));
        assert_eq!(clamav_services.restart_count, 0);
        assert!(!settings_paths.overrides_file.exists());
    }

    #[test]
    fn one_bad_change_refuses_the_whole_request() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            health_answers: Vec::new(),
            restart_count: 0,
        };
        assert!(
            apply_setting_changes(
                &settings_paths,
                &[change_of("MaxThreads", "8"), change_of("User", "root")],
                &mut clamav_services
            )
            .is_err()
        );
        assert!(!settings_paths.overrides_file.exists());
    }

    #[test]
    fn repeated_keys_replace_the_earlier_override_for_that_key() {
        assert_eq!(
            overrides_after_changes(
                vec![change_of("MaxThreads", "4"), change_of("MaxFileSize", "1M")],
                &[change_of("MaxThreads", "8"), change_of("MaxThreads", "9")],
            ),
            vec![
                change_of("MaxFileSize", "1M"),
                change_of("MaxThreads", "8"),
                change_of("MaxThreads", "9"),
            ]
        );
    }

    #[test]
    fn merging_falls_back_to_the_base_when_the_allowlist_is_absent() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::remove_file(&settings_paths.allowlist_file).expect("removed");
        fs::write(&settings_paths.overrides_file, "MaxThreads 8\n").expect("overrides");
        write_merged_config(&settings_paths).expect("merged");
        assert_eq!(
            fs::read_to_string(&settings_paths.merged_config).expect("merged"),
            "User clamav\nMaxThreads 4\n"
        );
    }
}
