use std::{fs, path::Path, time::SystemTime};

use futures::future::join_all;
use relm4::gtk::gio::prelude::SettingsExt;
use tokio::task::spawn_blocking;

use crate::{
    application_settings::{
        clamav_host_config::{ConfigSetting, HostConfigView, read_clamd_config},
        preferences_dialog::application_settings,
    },
    clamav_components::component_availability::{
        ProgramProbe, clamd_answers_ping, probe_program_version,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    protection_status::{
        clamav_engine_evidence::{
            DatabaseEvidence, inspect_database_evidence, newest_disk_signature_version,
        },
        service_run_journal::{ServiceRunHistory, newest_service_run},
    },
    systemd_bus::host_systemd_units::{
        ServiceLastResult, UnitState, UnitTimestamp, first_active_unit, probe_unit_state,
        service_unit_snapshot, timer_unit_snapshot,
    },
    virus_database::database_directory_status::configured_database_directory,
};

const CLAMDSCAN_PROGRAM: &str = "clamdscan";
const CLAMSCAN_PROGRAM: &str = "clamscan";
const DAEMON_SERVICE_UNITS: [&str; 3] = [
    "clamav-daemon.service",
    "clamd@scan.service",
    "clamd.service",
];
const ON_ACCESS_SERVICE_UNITS: [&str; 2] = ["clamav-clamonacc.service", "clamonacc.service"];
const SIGNATURE_UPDATER_UNITS: [SignatureUpdaterUnit; 3] = [
    SignatureUpdaterUnit {
        updater_name: "freshclam",
        service_unit: "clamav-freshclam.service",
    },
    SignatureUpdaterUnit {
        updater_name: "freshclam",
        service_unit: "freshclam.service",
    },
    SignatureUpdaterUnit {
        updater_name: "fangfrisch",
        service_unit: "clamav-fangfrisch.service",
    },
];
const SYSTEM_SCAN_UNITS: [SystemScanUnits; 1] = [SystemScanUnits {
    timer_unit: "clamdscan.timer",
    service_unit: "clamdscan.service",
}];
const THIRD_PARTY_SIGNATURE_EXTENSIONS: [&str; 7] =
    ["ndb", "hdb", "hsb", "ldb", "cdb", "ign2", "yara"];
const CLAMUI_SCHEDULE_KEY: &str = "schedule-enabled";
const SECONDS_PER_HOUR: u64 = 3_600;

pub const WATCHED_SERVICE_UNITS: [&str; 10] = [
    "clamav-daemon.service",
    "clamd@scan.service",
    "clamd.service",
    "clamav-clamonacc.service",
    "clamonacc.service",
    "clamav-freshclam.service",
    "freshclam.service",
    "clamav-fangfrisch.service",
    "clamdscan.service",
    "clamdscan.timer",
];

#[derive(Clone, Copy, Debug)]
struct SignatureUpdaterUnit {
    updater_name: &'static str,
    service_unit: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct SystemScanUnits {
    timer_unit: &'static str,
    service_unit: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineInstallation {
    EngineMissing,
    VersionUnverified { failure_text: String },
    VersionReported { version_banner: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdaterEvidence {
    pub updater_name: &'static str,
    pub service_unit: &'static str,
    pub last_result: ServiceLastResult,
    pub last_completed_run: ServiceRunHistory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThirdPartySignatureFile {
    pub file_name: String,
    pub age_hours: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEvidence {
    pub database_evidence: DatabaseEvidence,
    pub updater_evidence: Vec<UpdaterEvidence>,
    pub third_party_files: Vec<ThirdPartySignatureFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LoadedSignatures {
    MatchesDisk,
    BehindDisk {
        loaded_version: String,
        disk_version: String,
    },
    ComparisonUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonEvidence {
    ClamdAnswering { loaded_signatures: LoadedSignatures },
    UnitStopped { service_unit: &'static str },
    NeverSetUp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnAccessScanner {
    MonitorRunning,
    UnitStopped { service_unit: &'static str },
    NeverSetUp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnAccessSizeLimit {
    DefaultLimit,
    ConfiguredLimit { limit_text: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnAccessEvidence {
    pub on_access_scanner: OnAccessScanner,
    pub watched_paths: Vec<String>,
    pub prevention_enabled: bool,
    pub size_limit: OnAccessSizeLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScheduledScanEvidence {
    SystemTimer {
        service_unit: &'static str,
        timer_active: bool,
        next_run: UnitTimestamp,
        scan_targets: Vec<String>,
        last_result: ServiceLastResult,
        last_completed_run: ServiceRunHistory,
    },
    ClamuiSchedule,
    NoSchedule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionEvidence {
    pub engine_installation: EngineInstallation,
    pub signature_evidence: SignatureEvidence,
    pub daemon_evidence: DaemonEvidence,
    pub on_access_evidence: OnAccessEvidence,
    pub scheduled_scan_evidence: ScheduledScanEvidence,
}

pub fn scan_targets_from_arguments(program_arguments: &[String]) -> Vec<String> {
    program_arguments
        .iter()
        .skip(1)
        .filter(|program_argument| !program_argument.starts_with('-'))
        .map(|scan_target| sanitize_scanner_line(scan_target))
        .collect()
}

pub fn signature_version_in_banner(version_banner: &str) -> Option<&str> {
    version_banner.split('/').nth(1).map(str::trim)
}

pub fn compare_loaded_signatures(
    daemon_banner: &ProgramProbe,
    disk_version: Option<u64>,
) -> LoadedSignatures {
    let ProgramProbe::VersionReported {
        version_text: daemon_text,
    } = daemon_banner
    else {
        return LoadedSignatures::ComparisonUnavailable;
    };
    let loaded_version = signature_version_in_banner(daemon_text)
        .and_then(|version_text| version_text.parse::<u64>().ok());
    match (loaded_version, disk_version) {
        (Some(loaded_version), Some(disk_version)) if loaded_version >= disk_version => {
            LoadedSignatures::MatchesDisk
        }
        (Some(loaded_version), Some(disk_version)) => LoadedSignatures::BehindDisk {
            loaded_version: loaded_version.to_string(),
            disk_version: disk_version.to_string(),
        },
        _unknown_version => LoadedSignatures::ComparisonUnavailable,
    }
}

fn config_values<'config>(
    config_settings: &'config [ConfigSetting],
    setting_key: &'static str,
) -> impl Iterator<Item = &'config str> {
    config_settings
        .iter()
        .filter(move |config_setting| config_setting.setting_key == setting_key)
        .map(|config_setting| config_setting.setting_value.as_str())
}

fn setting_is_enabled(setting_value: &str) -> bool {
    matches!(
        setting_value.to_ascii_lowercase().as_str(),
        "true" | "yes" | "1"
    )
}

pub fn on_access_evidence_from_config(
    on_access_scanner: OnAccessScanner,
    config_settings: &[ConfigSetting],
) -> OnAccessEvidence {
    OnAccessEvidence {
        on_access_scanner,
        watched_paths: config_values(config_settings, "OnAccessIncludePath")
            .map(sanitize_scanner_line)
            .collect(),
        prevention_enabled: config_values(config_settings, "OnAccessPrevention")
            .any(setting_is_enabled),
        size_limit: config_values(config_settings, "OnAccessMaxFileSize")
            .next()
            .map_or(OnAccessSizeLimit::DefaultLimit, |limit_text| {
                OnAccessSizeLimit::ConfiguredLimit {
                    limit_text: sanitize_scanner_line(limit_text),
                }
            }),
    }
}

async fn inspect_engine_installation() -> EngineInstallation {
    match probe_program_version(Path::new(CLAMSCAN_PROGRAM)).await {
        ProgramProbe::NotFoundOnPath => EngineInstallation::EngineMissing,
        ProgramProbe::ProbeFailed { failure_text } => EngineInstallation::VersionUnverified {
            failure_text: sanitize_scanner_line(&failure_text),
        },
        ProgramProbe::VersionReported { version_text } => EngineInstallation::VersionReported {
            version_banner: sanitize_scanner_line(&version_text),
        },
    }
}

async fn inspect_updater_unit(updater_unit: SignatureUpdaterUnit) -> Option<UpdaterEvidence> {
    let service_snapshot = service_unit_snapshot(updater_unit.service_unit).await;
    if !matches!(
        service_snapshot.unit_state,
        UnitState::UnitActive | UnitState::UnitInactive
    ) {
        return None;
    }
    Some(UpdaterEvidence {
        updater_name: updater_unit.updater_name,
        service_unit: updater_unit.service_unit,
        last_result: service_snapshot.last_result,
        last_completed_run: newest_service_run(updater_unit.service_unit).await,
    })
}

fn third_party_signature_files(database_directory: &Path) -> Vec<ThirdPartySignatureFile> {
    let current_time = SystemTime::now();
    let mut signature_files = fs::read_dir(database_directory)
        .map(|directory_entries| {
            directory_entries
                .filter_map(Result::ok)
                .filter(|directory_entry| {
                    directory_entry
                        .path()
                        .extension()
                        .and_then(|file_extension| file_extension.to_str())
                        .is_some_and(|file_extension| {
                            THIRD_PARTY_SIGNATURE_EXTENSIONS.contains(&file_extension)
                        })
                })
                .filter_map(|directory_entry| {
                    let modified_time = directory_entry.metadata().ok()?.modified().ok()?;
                    Some(ThirdPartySignatureFile {
                        file_name: sanitize_scanner_line(
                            &directory_entry.file_name().to_string_lossy(),
                        ),
                        age_hours: current_time
                            .duration_since(modified_time)
                            .unwrap_or_default()
                            .as_secs()
                            / SECONDS_PER_HOUR,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    signature_files
        .sort_by(|first_file, second_file| first_file.file_name.cmp(&second_file.file_name));
    signature_files
}

async fn inspect_signature_evidence(engine_banner: &str) -> SignatureEvidence {
    let updater_evidence = join_all(SIGNATURE_UPDATER_UNITS.map(inspect_updater_unit))
        .await
        .into_iter()
        .flatten()
        .collect();
    SignatureEvidence {
        database_evidence: inspect_database_evidence(engine_banner).await,
        updater_evidence,
        third_party_files: spawn_blocking(|| {
            third_party_signature_files(&configured_database_directory())
        })
        .await
        .unwrap_or_default(),
    }
}

async fn inspect_daemon_evidence() -> DaemonEvidence {
    if clamd_answers_ping(Path::new(CLAMDSCAN_PROGRAM)).await {
        return DaemonEvidence::ClamdAnswering {
            loaded_signatures: compare_loaded_signatures(
                &probe_program_version(Path::new(CLAMDSCAN_PROGRAM)).await,
                spawn_blocking(newest_disk_signature_version)
                    .await
                    .ok()
                    .flatten(),
            ),
        };
    }
    let unit_states = join_all(DAEMON_SERVICE_UNITS.map(probe_unit_state)).await;
    DAEMON_SERVICE_UNITS
        .iter()
        .zip(unit_states)
        .find(|named_state| named_state.1 == UnitState::UnitInactive)
        .map_or(DaemonEvidence::NeverSetUp, |named_state| {
            DaemonEvidence::UnitStopped {
                service_unit: named_state.0,
            }
        })
}

async fn inspect_on_access_scanner() -> OnAccessScanner {
    if first_active_unit(&ON_ACCESS_SERVICE_UNITS).await.is_some() {
        return OnAccessScanner::MonitorRunning;
    }
    let unit_states = join_all(ON_ACCESS_SERVICE_UNITS.map(probe_unit_state)).await;
    ON_ACCESS_SERVICE_UNITS
        .iter()
        .zip(unit_states)
        .find(|named_state| named_state.1 == UnitState::UnitInactive)
        .map_or(OnAccessScanner::NeverSetUp, |named_state| {
            OnAccessScanner::UnitStopped {
                service_unit: named_state.0,
            }
        })
}

async fn inspect_on_access_evidence() -> OnAccessEvidence {
    let on_access_scanner = inspect_on_access_scanner().await;
    let config_settings = match spawn_blocking(read_clamd_config).await {
        Ok(HostConfigView::ConfigFound {
            config_settings, ..
        }) => config_settings,
        _no_config => Vec::new(),
    };
    on_access_evidence_from_config(on_access_scanner, &config_settings)
}

async fn inspect_scheduled_scan(clamui_schedule_enabled: bool) -> ScheduledScanEvidence {
    for system_scan_units in SYSTEM_SCAN_UNITS {
        let timer_snapshot = timer_unit_snapshot(system_scan_units.timer_unit).await;
        if matches!(
            timer_snapshot.unit_state,
            UnitState::UnitActive | UnitState::UnitInactive
        ) {
            let service_snapshot = service_unit_snapshot(system_scan_units.service_unit).await;
            return ScheduledScanEvidence::SystemTimer {
                service_unit: system_scan_units.service_unit,
                timer_active: timer_snapshot.unit_state == UnitState::UnitActive,
                next_run: timer_snapshot.next_run,
                scan_targets: scan_targets_from_arguments(&service_snapshot.program_arguments),
                last_result: service_snapshot.last_result,
                last_completed_run: newest_service_run(system_scan_units.service_unit).await,
            };
        }
    }
    if clamui_schedule_enabled {
        ScheduledScanEvidence::ClamuiSchedule
    } else {
        ScheduledScanEvidence::NoSchedule
    }
}

pub fn clamui_schedule_is_enabled() -> bool {
    application_settings().boolean(CLAMUI_SCHEDULE_KEY)
}

pub async fn gather_protection_evidence(clamui_schedule_enabled: bool) -> ProtectionEvidence {
    let engine_installation = inspect_engine_installation().await;
    let engine_banner = match &engine_installation {
        EngineInstallation::VersionReported { version_banner } => version_banner.clone(),
        EngineInstallation::EngineMissing | EngineInstallation::VersionUnverified { .. } => {
            String::new()
        }
    };
    ProtectionEvidence {
        engine_installation,
        signature_evidence: inspect_signature_evidence(&engine_banner).await,
        daemon_evidence: inspect_daemon_evidence().await,
        on_access_evidence: inspect_on_access_evidence().await,
        scheduled_scan_evidence: inspect_scheduled_scan(clamui_schedule_enabled).await,
    }
}

#[cfg(test)]
mod protection_evidence_tests {
    use super::*;

    fn config_setting(setting_key: &str, setting_value: &str) -> ConfigSetting {
        ConfigSetting {
            setting_key: setting_key.to_owned(),
            setting_value: setting_value.to_owned(),
        }
    }

    fn reported_banner(version_text: &str) -> ProgramProbe {
        ProgramProbe::VersionReported {
            version_text: version_text.to_owned(),
        }
    }

    #[test]
    fn scan_targets_skip_the_program_and_its_options_but_keep_spaces() {
        assert_eq!(
            scan_targets_from_arguments(&[
                "/bin/clamdscan".to_owned(),
                "--fdpass".to_owned(),
                "/home/my files".to_owned(),
                "/tmp".to_owned(),
            ]),
            vec!["/home/my files", "/tmp"]
        );
    }

    #[test]
    fn a_daemon_on_older_signatures_than_the_disk_is_reported() {
        let daemon_banner = reported_banner("ClamAV 1.5.4/28173/Tue Nov  3 07:27:52 2026");
        assert_eq!(
            compare_loaded_signatures(&daemon_banner, Some(28_174)),
            LoadedSignatures::BehindDisk {
                loaded_version: "28173".to_owned(),
                disk_version: "28174".to_owned(),
            }
        );
        assert_eq!(
            compare_loaded_signatures(&daemon_banner, Some(28_173)),
            LoadedSignatures::MatchesDisk
        );
    }

    #[test]
    fn a_banner_without_a_signature_version_cannot_be_compared() {
        assert_eq!(
            compare_loaded_signatures(&reported_banner("ClamAV 1.5.4"), Some(28_174)),
            LoadedSignatures::ComparisonUnavailable
        );
        assert_eq!(
            compare_loaded_signatures(&ProgramProbe::NotFoundOnPath, Some(28_174)),
            LoadedSignatures::ComparisonUnavailable
        );
    }

    #[test]
    fn on_access_settings_are_read_from_the_daemon_config() {
        assert_eq!(
            on_access_evidence_from_config(
                OnAccessScanner::MonitorRunning,
                &[
                    config_setting("OnAccessIncludePath", "/home/user/Downloads"),
                    config_setting("OnAccessIncludePath", "/srv/inbox"),
                    config_setting("OnAccessPrevention", "true"),
                    config_setting("OnAccessMaxFileSize", "100M"),
                ],
            ),
            OnAccessEvidence {
                on_access_scanner: OnAccessScanner::MonitorRunning,
                watched_paths: vec!["/home/user/Downloads".to_owned(), "/srv/inbox".to_owned()],
                prevention_enabled: true,
                size_limit: OnAccessSizeLimit::ConfiguredLimit {
                    limit_text: "100M".to_owned()
                },
            }
        );
    }

    #[test]
    fn absent_on_access_settings_do_not_claim_prevention() {
        let on_access_evidence = on_access_evidence_from_config(OnAccessScanner::NeverSetUp, &[]);
        assert!(!on_access_evidence.prevention_enabled);
        assert!(on_access_evidence.watched_paths.is_empty());
        assert_eq!(
            on_access_evidence.size_limit,
            OnAccessSizeLimit::DefaultLimit
        );
    }
}
