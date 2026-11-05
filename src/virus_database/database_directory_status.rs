use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::systemd_bus::host_systemd_units::{UnitState, probe_unit_state};

const CONFIG_CANDIDATES: &[&str] = &[
    "/etc/clamav/freshclam.conf",
    "/etc/freshclam.conf",
    "/etc/clamav/clamd.conf",
    "/etc/clamd.d/scan.conf",
];
const DEFAULT_DATABASE_DIRECTORY: &str = "/var/lib/clamav";
const FRESHCLAM_SERVICE_UNITS: [&str; 2] = ["clamav-freshclam", "freshclam"];
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseDirectoryStatus {
    DefinitionsAvailable {
        database_directory: PathBuf,
        definition_file_count: u64,
        newest_definition_age_days: u64,
    },
    DefinitionsMissing {
        database_directory: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshclamServiceState {
    DaemonRunning { service_unit: &'static str },
    TimerScheduled { service_unit: &'static str },
    ServiceStopped { service_unit: &'static str },
    ServiceNotFound,
}

pub fn database_directory_in_config(config_text: &str) -> Option<PathBuf> {
    config_text.lines().map(str::trim).find_map(|config_line| {
        let directory_text = config_line.strip_prefix("DatabaseDirectory")?;
        directory_text
            .starts_with(char::is_whitespace)
            .then(|| PathBuf::from(directory_text.trim()))
    })
}

pub fn configured_database_directory() -> PathBuf {
    CONFIG_CANDIDATES
        .iter()
        .filter_map(|config_path| fs::read_to_string(config_path).ok())
        .find_map(|config_text| database_directory_in_config(&config_text))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DATABASE_DIRECTORY))
}

fn is_definition_file(file_path: &Path) -> bool {
    file_path
        .extension()
        .and_then(|file_extension| file_extension.to_str())
        .is_some_and(|file_extension| matches!(file_extension, "cvd" | "cld" | "cud"))
}

pub fn inspect_database_directory(
    database_directory: &Path,
    current_time: SystemTime,
) -> DatabaseDirectoryStatus {
    let definition_ages = fs::read_dir(database_directory)
        .map(|directory_entries| {
            directory_entries
                .filter_map(Result::ok)
                .filter(|directory_entry| is_definition_file(&directory_entry.path()))
                .filter_map(|directory_entry| directory_entry.metadata().ok())
                .filter_map(|file_metadata| file_metadata.modified().ok())
                .map(|modified_time| {
                    current_time
                        .duration_since(modified_time)
                        .unwrap_or_default()
                        .as_secs()
                        / SECONDS_PER_DAY
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    match definition_ages.iter().min() {
        Some(newest_definition_age_days) => DatabaseDirectoryStatus::DefinitionsAvailable {
            database_directory: database_directory.to_path_buf(),
            definition_file_count: definition_ages.len() as u64,
            newest_definition_age_days: *newest_definition_age_days,
        },
        None => DatabaseDirectoryStatus::DefinitionsMissing {
            database_directory: database_directory.to_path_buf(),
        },
    }
}

pub fn classify_service_state(
    service_unit: &'static str,
    service_state: UnitState,
    timer_state: UnitState,
) -> Option<FreshclamServiceState> {
    match service_state {
        UnitState::UnitActive => Some(FreshclamServiceState::DaemonRunning { service_unit }),
        UnitState::UnitInactive if timer_state == UnitState::UnitActive => {
            Some(FreshclamServiceState::TimerScheduled { service_unit })
        }
        UnitState::UnitInactive => Some(FreshclamServiceState::ServiceStopped { service_unit }),
        UnitState::UnitNotFound | UnitState::SystemdUnavailable => None,
    }
}

pub async fn detect_freshclam_service() -> FreshclamServiceState {
    let classified_units =
        futures::future::join_all(FRESHCLAM_SERVICE_UNITS.map(|service_unit| async move {
            classify_service_state(
                service_unit,
                probe_unit_state(&format!("{service_unit}.service")).await,
                probe_unit_state(&format!("{service_unit}.timer")).await,
            )
        }))
        .await;
    classified_units
        .into_iter()
        .flatten()
        .next()
        .unwrap_or(FreshclamServiceState::ServiceNotFound)
}

#[cfg(test)]
mod database_directory_status_tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn database_directory_directive_is_parsed_exactly() {
        assert_eq!(
            database_directory_in_config(
                "# comment\nDatabaseOwner clamav\nDatabaseDirectory /var/lib/clamav\n"
            ),
            Some(PathBuf::from("/var/lib/clamav"))
        );
        assert_eq!(
            database_directory_in_config("#DatabaseDirectory /old\n"),
            None
        );
        assert_eq!(
            database_directory_in_config("DatabaseDirectoryExtra /old\n"),
            None
        );
    }

    #[test]
    fn inventory_counts_definition_files_and_reports_the_newest_age() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let main_file = temporary_root.path().join("main.cvd");
        let daily_file = temporary_root.path().join("daily.cld");
        let ignored_file = temporary_root.path().join("ignored.CLD");
        let signature_file = temporary_root.path().join("daily.cvd.sign");
        [&main_file, &daily_file, &ignored_file, &signature_file]
            .iter()
            .for_each(|file_path| fs::write(file_path, b"fixture").expect("fixture file"));
        let reference_time = UNIX_EPOCH + Duration::from_secs(100 * SECONDS_PER_DAY);
        fs::File::open(&main_file)
            .expect("main file")
            .set_modified(UNIX_EPOCH + Duration::from_secs(90 * SECONDS_PER_DAY))
            .expect("main time");
        fs::File::open(&daily_file)
            .expect("daily file")
            .set_modified(UNIX_EPOCH + Duration::from_secs(97 * SECONDS_PER_DAY))
            .expect("daily time");
        assert_eq!(
            inspect_database_directory(temporary_root.path(), reference_time),
            DatabaseDirectoryStatus::DefinitionsAvailable {
                database_directory: temporary_root.path().to_path_buf(),
                definition_file_count: 2,
                newest_definition_age_days: 3,
            }
        );
    }

    #[test]
    fn missing_or_empty_directories_report_no_definitions() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        assert!(matches!(
            inspect_database_directory(temporary_root.path(), SystemTime::now()),
            DatabaseDirectoryStatus::DefinitionsMissing { .. }
        ));
        assert!(matches!(
            inspect_database_directory(Path::new("/nonexistent/clamav"), SystemTime::now()),
            DatabaseDirectoryStatus::DefinitionsMissing { .. }
        ));
    }

    #[test]
    fn service_state_distinguishes_daemon_timer_and_stopped_units() {
        assert_eq!(
            classify_service_state(
                "freshclam",
                UnitState::UnitNotFound,
                UnitState::UnitNotFound
            ),
            None
        );
        assert_eq!(
            classify_service_state("freshclam", UnitState::UnitActive, UnitState::UnitNotFound),
            Some(FreshclamServiceState::DaemonRunning {
                service_unit: "freshclam"
            })
        );
        assert_eq!(
            classify_service_state("freshclam", UnitState::UnitInactive, UnitState::UnitActive),
            Some(FreshclamServiceState::TimerScheduled {
                service_unit: "freshclam"
            })
        );
        assert_eq!(
            classify_service_state(
                "freshclam",
                UnitState::UnitInactive,
                UnitState::UnitNotFound
            ),
            Some(FreshclamServiceState::ServiceStopped {
                service_unit: "freshclam"
            })
        );
    }
}
