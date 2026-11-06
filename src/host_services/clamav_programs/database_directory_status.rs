use std::{
    fs, io,
    path::{Path, PathBuf},
    time::SystemTime,
};

use tokio::task::JoinError;

use crate::host_services::{
    desktop::flatpak_sandbox::readable_host_path,
    systemd_bus::host_systemd_units::{UnitActivity, UnitState, probe_unit_state},
};

const CONFIG_CANDIDATES: &[&str] = &[
    "/etc/clamav/freshclam.conf",
    "/etc/freshclam.conf",
    "/etc/clamav/clamd.conf",
    "/etc/clamd.d/scan.conf",
];
const DEFAULT_DATABASE_DIRECTORY: &str = "/var/lib/clamav";
const FRESHCLAM_SERVICE_UNITS: [&str; 2] = ["clamav-freshclam", "freshclam"];
const SECONDS_PER_DAY: u64 = 86_400;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DatabaseFolderReadFailure {
    #[error("the signature folder could not be read: {failure_kind}")]
    FolderUnreadable { failure_kind: io::ErrorKind },
    #[error("the task reading the signature folder stopped before it finished")]
    ReadingTaskInterrupted,
}

impl From<io::Error> for DatabaseFolderReadFailure {
    fn from(read_failure: io::Error) -> Self {
        Self::FolderUnreadable {
            failure_kind: read_failure.kind(),
        }
    }
}

impl From<JoinError> for DatabaseFolderReadFailure {
    fn from(_interrupted_task: JoinError) -> Self {
        Self::ReadingTaskInterrupted
    }
}

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
    DirectoryUnreadable {
        database_directory: PathBuf,
        read_failure: DatabaseFolderReadFailure,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshclamServiceState {
    DaemonRunning { service_unit: &'static str },
    TimerScheduled { service_unit: &'static str },
    ServiceStopped { service_unit: &'static str },
    ServiceNotFound,
    SystemdUnreachable,
}

impl FreshclamServiceState {
    const fn names_a_service_unit(self) -> bool {
        match self {
            Self::DaemonRunning { .. }
            | Self::TimerScheduled { .. }
            | Self::ServiceStopped { .. } => true,
            Self::ServiceNotFound | Self::SystemdUnreachable => false,
        }
    }
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
        .filter_map(|config_path| fs::read_to_string(readable_host_path(config_path)).ok())
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
    let directory_entries = match fs::read_dir(database_directory) {
        Ok(directory_entries) => directory_entries,
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => {
            return DatabaseDirectoryStatus::DefinitionsMissing {
                database_directory: database_directory.to_path_buf(),
            };
        }
        Err(read_failure) => {
            return DatabaseDirectoryStatus::DirectoryUnreadable {
                database_directory: database_directory.to_path_buf(),
                read_failure: read_failure.into(),
            };
        }
    };
    let definition_ages = directory_entries
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
        .collect::<Vec<_>>();
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
) -> FreshclamServiceState {
    match service_state {
        UnitState::UnitLoaded(UnitActivity::UnitActive) => {
            FreshclamServiceState::DaemonRunning { service_unit }
        }
        UnitState::UnitLoaded(UnitActivity::UnitInactive)
            if timer_state == UnitState::UnitLoaded(UnitActivity::UnitActive) =>
        {
            FreshclamServiceState::TimerScheduled { service_unit }
        }
        UnitState::UnitLoaded(UnitActivity::UnitInactive) => {
            FreshclamServiceState::ServiceStopped { service_unit }
        }
        UnitState::UnitNotFound => FreshclamServiceState::ServiceNotFound,
        UnitState::SystemdUnavailable => FreshclamServiceState::SystemdUnreachable,
    }
}

pub fn combined_service_state(classified_units: &[FreshclamServiceState]) -> FreshclamServiceState {
    let fallback_state = if classified_units.contains(&FreshclamServiceState::SystemdUnreachable) {
        FreshclamServiceState::SystemdUnreachable
    } else {
        FreshclamServiceState::ServiceNotFound
    };
    classified_units
        .iter()
        .copied()
        .find(|unit_state| unit_state.names_a_service_unit())
        .unwrap_or(fallback_state)
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
    combined_service_state(&classified_units)
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
    fn an_unreadable_directory_is_not_reported_as_missing_definitions() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let not_a_directory = temporary_root.path().join("daily.cvd");
        fs::write(&not_a_directory, b"fixture").expect("fixture file");
        assert!(matches!(
            inspect_database_directory(&not_a_directory, SystemTime::now()),
            DatabaseDirectoryStatus::DirectoryUnreadable {
                read_failure: DatabaseFolderReadFailure::FolderUnreadable { .. },
                ..
            }
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
            FreshclamServiceState::ServiceNotFound
        );
        assert_eq!(
            classify_service_state(
                "freshclam",
                UnitState::UnitLoaded(UnitActivity::UnitActive),
                UnitState::UnitNotFound
            ),
            FreshclamServiceState::DaemonRunning {
                service_unit: "freshclam"
            }
        );
        assert_eq!(
            classify_service_state(
                "freshclam",
                UnitState::UnitLoaded(UnitActivity::UnitInactive),
                UnitState::UnitLoaded(UnitActivity::UnitActive)
            ),
            FreshclamServiceState::TimerScheduled {
                service_unit: "freshclam"
            }
        );
        assert_eq!(
            classify_service_state(
                "freshclam",
                UnitState::UnitLoaded(UnitActivity::UnitInactive),
                UnitState::UnitNotFound
            ),
            FreshclamServiceState::ServiceStopped {
                service_unit: "freshclam"
            }
        );
    }

    #[test]
    fn an_unreachable_systemd_is_not_reported_as_a_missing_service() {
        assert_eq!(
            classify_service_state(
                "freshclam",
                UnitState::SystemdUnavailable,
                UnitState::SystemdUnavailable
            ),
            FreshclamServiceState::SystemdUnreachable
        );
        assert_eq!(
            combined_service_state(&[
                FreshclamServiceState::ServiceNotFound,
                FreshclamServiceState::SystemdUnreachable,
            ]),
            FreshclamServiceState::SystemdUnreachable
        );
        assert_eq!(
            combined_service_state(&[
                FreshclamServiceState::SystemdUnreachable,
                FreshclamServiceState::ServiceStopped {
                    service_unit: "clamav-freshclam"
                },
            ]),
            FreshclamServiceState::ServiceStopped {
                service_unit: "clamav-freshclam"
            }
        );
        assert_eq!(
            combined_service_state(&[FreshclamServiceState::ServiceNotFound]),
            FreshclamServiceState::ServiceNotFound
        );
    }
}
