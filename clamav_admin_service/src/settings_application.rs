use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use clamd_configuration::{
    clamd_conf_format::config_lines::ClamdConfigLines,
    live_overrides::{OverridesChange, ReductionClock, SettingChanges},
    merged_clamd_config::{merge_clamd_config, tunable_settings_in},
    tunable_allowlist::TunableAllowlist,
    tunable_record::{BaseSettings, LiveOverrides},
};
use jiff::{SignedDuration, Timestamp};

use crate::clamav_services::{ClamavServices, ServicesReadiness};

const WORLD_READABLE_MODE: u32 = 0o644;
const DEFAULT_REDUCTION_LIFETIME: SignedDuration = SignedDuration::from_hours(24);
const MIGRATED_SUFFIX: &str = "migrated";

#[derive(Clone, Debug)]
pub struct SettingsPaths {
    pub base_config: PathBuf,
    pub live_overrides_file: PathBuf,
    pub previous_overrides_file: PathBuf,
    pub allowlist_file: PathBuf,
    pub reduction_lifetime_file: PathBuf,
    pub merged_config: PathBuf,
}

impl SettingsPaths {
    pub fn on_this_host() -> Self {
        Self {
            base_config: PathBuf::from("/etc/clamav/clamd.conf"),
            live_overrides_file: PathBuf::from("/var/lib/lazaret/live-overrides.toml"),
            previous_overrides_file: PathBuf::from("/var/lib/lazaret/clamd-overrides.conf"),
            allowlist_file: PathBuf::from("/etc/lazaret/tunable-settings"),
            reduction_lifetime_file: PathBuf::from("/etc/lazaret/reduction-lifetime"),
            merged_config: PathBuf::from("/run/lazaret/clamd.conf"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChangeRefusal {
    #[error("no changes were given")]
    NoChanges,
    #[error("{setting_name} is not in the list of settings allowed to change at runtime")]
    NotAllowlisted { setting_name: &'static str },
}

#[derive(Debug, thiserror::Error)]
pub enum ApplicationFailure {
    #[error(transparent)]
    ChangeRefused(#[from] ChangeRefusal),
    #[error("the configuration files could not be updated: {0}")]
    FilesUnavailable(#[from] io::Error),
    #[error("the stored runtime changes could not be read: {0}")]
    OverridesUnreadable(#[from] toml::de::Error),
    #[error("the runtime changes could not be stored: {0}")]
    OverridesUnwritable(#[from] toml::ser::Error),
    #[error("{unit_name} did not come back even after restoring the previous settings")]
    RollbackNotReady { unit_name: &'static str },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationOutcome {
    ChangesApplied,
    RolledBackAfterFailedRestart,
}

pub fn write_file_atomically(target_path: &Path, file_text: &str) -> io::Result<()> {
    let temporary_path = target_path.with_extension("tmp");
    fs::write(&temporary_path, file_text)?;
    fs::set_permissions(
        &temporary_path,
        fs::Permissions::from_mode(WORLD_READABLE_MODE),
    )?;
    fs::rename(&temporary_path, target_path)
}

fn read_text_or_empty(file_path: &Path) -> io::Result<String> {
    match fs::read_to_string(file_path) {
        Ok(file_text) => Ok(file_text),
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(read_failure) => Err(read_failure),
    }
}

fn config_lines_in(config_text: &str) -> ClamdConfigLines {
    match config_text.parse() {
        Ok(config_lines) => config_lines,
        Err(never_fails) => match never_fails {},
    }
}

pub fn read_base_lines(settings_paths: &SettingsPaths) -> io::Result<ClamdConfigLines> {
    fs::read_to_string(&settings_paths.base_config).map(|base_text| config_lines_in(&base_text))
}

pub fn read_lines_in_effect(settings_paths: &SettingsPaths) -> io::Result<ClamdConfigLines> {
    fs::read_to_string(&settings_paths.merged_config)
        .or_else(|_merged_unreadable| fs::read_to_string(&settings_paths.base_config))
        .map(|config_text| config_lines_in(&config_text))
}

pub fn read_tunable_allowlist(settings_paths: &SettingsPaths) -> io::Result<TunableAllowlist> {
    let allowlist_text = read_text_or_empty(&settings_paths.allowlist_file)?;
    Ok(match allowlist_text.parse() {
        Ok(tunable_allowlist) => tunable_allowlist,
        Err(never_fails) => match never_fails {},
    })
}

fn read_reduction_lifetime(settings_paths: &SettingsPaths) -> SignedDuration {
    read_text_or_empty(&settings_paths.reduction_lifetime_file)
        .ok()
        .and_then(|lifetime_text| lifetime_text.trim().parse::<i64>().ok())
        .filter(|lifetime_seconds| *lifetime_seconds > 0)
        .map_or(DEFAULT_REDUCTION_LIFETIME, SignedDuration::from_secs)
}

fn adopt_previous_overrides(settings_paths: &SettingsPaths) -> Result<(), ApplicationFailure> {
    if settings_paths.live_overrides_file.exists()
        || !settings_paths.previous_overrides_file.exists()
    {
        return Ok(());
    }
    let previous_lines = config_lines_in(&fs::read_to_string(
        &settings_paths.previous_overrides_file,
    )?);
    let adopted_overrides = tunable_settings_in(&previous_lines)
        .map(|previous_settings| LiveOverrides::adopted_as_permanent(&previous_settings))
        .unwrap_or_default();
    write_file_atomically(
        &settings_paths.live_overrides_file,
        &adopted_overrides.to_toml_text()?,
    )?;
    fs::rename(
        &settings_paths.previous_overrides_file,
        settings_paths
            .previous_overrides_file
            .with_extension(MIGRATED_SUFFIX),
    )?;
    Ok(())
}

pub fn read_live_overrides(
    settings_paths: &SettingsPaths,
) -> Result<LiveOverrides, ApplicationFailure> {
    adopt_previous_overrides(settings_paths)?;
    let overrides_text = read_text_or_empty(&settings_paths.live_overrides_file)?;
    Ok(LiveOverrides::from_toml_text(&overrides_text)?)
}

fn write_live_overrides(
    settings_paths: &SettingsPaths,
    live_overrides: &LiveOverrides,
) -> Result<(), ApplicationFailure> {
    write_file_atomically(
        &settings_paths.live_overrides_file,
        &live_overrides.to_toml_text()?,
    )?;
    Ok(())
}

pub fn write_merged_config(settings_paths: &SettingsPaths, now: Timestamp) -> io::Result<()> {
    let base_lines = read_base_lines(settings_paths)?;
    let settings_in_effect = read_live_overrides(settings_paths)
        .map(|live_overrides| live_overrides.settings_in_effect_at(now))
        .unwrap_or_default();
    let merged_lines = read_tunable_allowlist(settings_paths)
        .ok()
        .and_then(|tunable_allowlist| {
            merge_clamd_config(&base_lines, &settings_in_effect, &tunable_allowlist).ok()
        })
        .unwrap_or(base_lines);
    write_file_atomically(&settings_paths.merged_config, &merged_lines.to_string())
}

pub fn planned_overrides_change(
    settings_paths: &SettingsPaths,
    setting_changes: &SettingChanges,
    now: Timestamp,
) -> Result<OverridesChange, ApplicationFailure> {
    let current_overrides = read_live_overrides(settings_paths)?;
    let base_settings = read_base_lines(settings_paths)
        .ok()
        .and_then(|base_lines| tunable_settings_in(&base_lines).ok());
    let base_view = base_settings
        .as_ref()
        .map_or(BaseSettings::UnreadableBase, BaseSettings::ReadableBase);
    let overrides_change = current_overrides.with_changes(
        setting_changes,
        base_view,
        ReductionClock {
            now,
            reduction_lifetime: read_reduction_lifetime(settings_paths),
        },
    );
    if overrides_change.changed_names.is_empty() {
        return Err(ChangeRefusal::NoChanges.into());
    }
    if let SettingChanges::SetValues { .. } = setting_changes {
        let tunable_allowlist = read_tunable_allowlist(settings_paths)?;
        if let Some(setting_name) = overrides_change
            .changed_names
            .iter()
            .find(|changed_name| !tunable_allowlist.allows(changed_name))
        {
            return Err(ChangeRefusal::NotAllowlisted { setting_name }.into());
        }
    }
    Ok(overrides_change)
}

async fn switch_live_overrides(
    settings_paths: &SettingsPaths,
    previous_overrides: &LiveOverrides,
    updated_overrides: &LiveOverrides,
    clamav_services: &mut impl ClamavServices,
    now: Timestamp,
) -> Result<ApplicationOutcome, ApplicationFailure> {
    write_live_overrides(settings_paths, updated_overrides)?;
    write_merged_config(settings_paths, now)?;
    if clamav_services.restart_until_ready().await? == ServicesReadiness::ServicesReady {
        return Ok(ApplicationOutcome::ChangesApplied);
    }
    write_live_overrides(settings_paths, previous_overrides)?;
    write_merged_config(settings_paths, now)?;
    match clamav_services.restart_until_ready().await? {
        ServicesReadiness::ServicesReady => Ok(ApplicationOutcome::RolledBackAfterFailedRestart),
        ServicesReadiness::ServiceNotReady { unit_name } => {
            Err(ApplicationFailure::RollbackNotReady { unit_name })
        }
    }
}

pub async fn apply_setting_changes(
    settings_paths: &SettingsPaths,
    setting_changes: &SettingChanges,
    clamav_services: &mut impl ClamavServices,
    now: Timestamp,
) -> Result<ApplicationOutcome, ApplicationFailure> {
    let previous_overrides = read_live_overrides(settings_paths)?;
    let overrides_change = planned_overrides_change(settings_paths, setting_changes, now)?;
    switch_live_overrides(
        settings_paths,
        &previous_overrides,
        &overrides_change.changed_overrides,
        clamav_services,
        now,
    )
    .await
}

pub fn expire_reductions(
    settings_paths: &SettingsPaths,
    now: Timestamp,
) -> Result<Vec<&'static str>, ApplicationFailure> {
    let expiry_outcome = read_live_overrides(settings_paths)?.without_expired(now);
    if !expiry_outcome.expired_names.is_empty() {
        write_live_overrides(settings_paths, &expiry_outcome.remaining_overrides)?;
        write_merged_config(settings_paths, now)?;
    }
    Ok(expiry_outcome.expired_names)
}

#[cfg(test)]
mod settings_application_tests {
    use clamd_configuration::merged_clamd_config::requested_settings_in;

    use super::*;

    struct ScriptedServices {
        readiness_answers: Vec<ServicesReadiness>,
        restart_count: usize,
    }

    impl ClamavServices for ScriptedServices {
        async fn restart_until_ready(&mut self) -> io::Result<ServicesReadiness> {
            self.restart_count += 1;
            Ok(self.readiness_answers.remove(0))
        }
    }

    const NOT_READY: ServicesReadiness = ServicesReadiness::ServiceNotReady {
        unit_name: "clamav-daemon.service",
    };

    fn moment(unix_second: i64) -> Timestamp {
        Timestamp::from_second(unix_second).expect("timestamp")
    }

    fn prepared_paths(temporary_root: &tempfile::TempDir) -> SettingsPaths {
        let settings_paths = SettingsPaths {
            base_config: temporary_root.path().join("base.conf"),
            live_overrides_file: temporary_root.path().join("live-overrides.toml"),
            previous_overrides_file: temporary_root.path().join("clamd-overrides.conf"),
            allowlist_file: temporary_root.path().join("allowlist"),
            reduction_lifetime_file: temporary_root.path().join("reduction-lifetime"),
            merged_config: temporary_root.path().join("merged.conf"),
        };
        fs::write(
            &settings_paths.base_config,
            "User clamav\nMaxThreads 4\nDetectPUA yes\n",
        )
        .expect("base");
        fs::write(&settings_paths.allowlist_file, "MaxThreads\nDetectPUA\n").expect("allowlist");
        settings_paths
    }

    fn values_from(request_text: &str) -> SettingChanges {
        SettingChanges::SetValues {
            setting_values: Box::new(
                requested_settings_in(&config_lines_in(request_text)).expect("typed request"),
            ),
        }
    }

    fn applied(
        settings_paths: &SettingsPaths,
        setting_changes: &SettingChanges,
        clamav_services: &mut ScriptedServices,
    ) -> Result<ApplicationOutcome, ApplicationFailure> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(apply_setting_changes(
                settings_paths,
                setting_changes,
                clamav_services,
                moment(0),
            ))
    }

    fn merged_text(settings_paths: &SettingsPaths) -> String {
        fs::read_to_string(&settings_paths.merged_config).expect("merged")
    }

    #[test]
    fn a_ready_restart_keeps_the_change() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            readiness_answers: vec![ServicesReadiness::ServicesReady],
            restart_count: 0,
        };
        assert_eq!(
            applied(
                &settings_paths,
                &values_from("MaxThreads 8\n"),
                &mut clamav_services
            )
            .expect("applied"),
            ApplicationOutcome::ChangesApplied
        );
        assert_eq!(clamav_services.restart_count, 1);
        assert!(merged_text(&settings_paths).contains("MaxThreads 8\n"));
        assert!(!merged_text(&settings_paths).contains("MaxThreads 4"));
    }

    #[test]
    fn a_reduction_is_stored_with_its_expiry() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::write(&settings_paths.reduction_lifetime_file, "3600\n").expect("lifetime");
        let mut clamav_services = ScriptedServices {
            readiness_answers: vec![ServicesReadiness::ServicesReady],
            restart_count: 0,
        };
        applied(
            &settings_paths,
            &values_from("DetectPUA no\n"),
            &mut clamav_services,
        )
        .expect("applied");
        let stored_text = fs::read_to_string(&settings_paths.live_overrides_file).expect("stored");
        assert!(stored_text.contains("state = \"temporary-reduction\""));
        assert!(stored_text.contains("1970-01-01T01:00:00Z"));
    }

    #[test]
    fn a_failed_restart_restores_the_last_good_settings() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            readiness_answers: vec![ServicesReadiness::ServicesReady],
            restart_count: 0,
        };
        applied(
            &settings_paths,
            &values_from("MaxThreads 6\n"),
            &mut clamav_services,
        )
        .expect("first change");
        let mut failing_services = ScriptedServices {
            readiness_answers: vec![NOT_READY, ServicesReadiness::ServicesReady],
            restart_count: 0,
        };
        assert_eq!(
            applied(
                &settings_paths,
                &values_from("MaxThreads 8\n"),
                &mut failing_services
            )
            .expect("rolled back"),
            ApplicationOutcome::RolledBackAfterFailedRestart
        );
        assert_eq!(failing_services.restart_count, 2);
        assert!(merged_text(&settings_paths).contains("MaxThreads 6\n"));
    }

    #[test]
    fn a_failed_rollback_is_reported_rather_than_hidden() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            readiness_answers: vec![NOT_READY, NOT_READY],
            restart_count: 0,
        };
        assert!(matches!(
            applied(
                &settings_paths,
                &values_from("MaxThreads 8\n"),
                &mut clamav_services
            ),
            Err(ApplicationFailure::RollbackNotReady { .. })
        ));
    }

    #[test]
    fn a_setting_outside_the_allowlist_touches_nothing() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            readiness_answers: Vec::new(),
            restart_count: 0,
        };
        assert!(matches!(
            applied(
                &settings_paths,
                &values_from("ScanPDF no\n"),
                &mut clamav_services
            ),
            Err(ApplicationFailure::ChangeRefused(
                ChangeRefusal::NotAllowlisted { .. }
            ))
        ));
        assert_eq!(clamav_services.restart_count, 0);
        assert!(!settings_paths.live_overrides_file.exists());
    }

    #[test]
    fn going_back_to_the_system_value_leaves_the_base() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        let mut clamav_services = ScriptedServices {
            readiness_answers: vec![
                ServicesReadiness::ServicesReady,
                ServicesReadiness::ServicesReady,
            ],
            restart_count: 0,
        };
        applied(
            &settings_paths,
            &values_from("MaxThreads 8\n"),
            &mut clamav_services,
        )
        .expect("changed");
        applied(
            &settings_paths,
            &SettingChanges::BackToSystem {
                setting_names: ["MaxThreads".parse().expect("name")].into(),
            },
            &mut clamav_services,
        )
        .expect("reset");
        assert_eq!(
            merged_text(&settings_paths),
            "User clamav\nMaxThreads 4\nDetectPUA yes\n"
        );
    }

    #[test]
    fn expired_reductions_leave_the_merged_config() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::write(&settings_paths.reduction_lifetime_file, "60\n").expect("lifetime");
        let mut clamav_services = ScriptedServices {
            readiness_answers: vec![ServicesReadiness::ServicesReady],
            restart_count: 0,
        };
        applied(
            &settings_paths,
            &values_from("DetectPUA no\n"),
            &mut clamav_services,
        )
        .expect("applied");
        assert!(merged_text(&settings_paths).contains("DetectPUA no\n"));
        assert_eq!(
            expire_reductions(&settings_paths, moment(59)).expect("nothing expired"),
            Vec::<&str>::new()
        );
        assert_eq!(
            expire_reductions(&settings_paths, moment(60)).expect("expired"),
            ["DetectPUA"]
        );
        assert!(merged_text(&settings_paths).contains("DetectPUA yes\n"));
    }

    #[test]
    fn previous_override_lines_become_permanent_overrides() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::write(
            &settings_paths.previous_overrides_file,
            "MaxThreads 8\nVirusEvent /bin/sh\n",
        )
        .expect("previous overrides");
        write_merged_config(&settings_paths, moment(0)).expect("merged");
        assert!(merged_text(&settings_paths).contains("MaxThreads 8\n"));
        assert!(!merged_text(&settings_paths).contains("VirusEvent"));
        assert!(!settings_paths.previous_overrides_file.exists());
        assert!(
            settings_paths
                .previous_overrides_file
                .with_extension(MIGRATED_SUFFIX)
                .exists()
        );
    }

    #[test]
    fn merging_falls_back_to_the_base_when_the_allowlist_is_absent() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::remove_file(&settings_paths.allowlist_file).expect("removed");
        fs::write(
            &settings_paths.live_overrides_file,
            "[MaxThreads]\nstate = \"permanent\"\nvalue = 8\n",
        )
        .expect("overrides");
        write_merged_config(&settings_paths, moment(0)).expect("merged");
        assert_eq!(
            merged_text(&settings_paths),
            "User clamav\nMaxThreads 4\nDetectPUA yes\n"
        );
    }

    #[test]
    fn a_corrupt_state_file_falls_back_to_the_base() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let settings_paths = prepared_paths(&temporary_root);
        fs::write(
            &settings_paths.live_overrides_file,
            "[VirusEvent]\nstate = \"permanent\"\nvalue = \"/bin/sh\"\n",
        )
        .expect("planted");
        write_merged_config(&settings_paths, moment(0)).expect("merged");
        assert_eq!(
            merged_text(&settings_paths),
            "User clamav\nMaxThreads 4\nDetectPUA yes\n"
        );
    }
}
