use std::{fs, path::Path};

use bytesize::ByteSize;
use futures::future::join_all;
use gettextrs::gettext;
use jiff::Timestamp;
use relm4::gtk::gio::prelude::SettingsExt;
use tokio::task::spawn_blocking;

use crate::{
    host_services::{
        clamav_config::clamav_host_config::{
            ConfigSetting, HostConfigView, parse_config_settings, read_clamd_config,
        },
        clamav_programs::{
            component_availability::{
                ProgramProbe, located_clamd_answers_ping, probe_located_program_version,
            },
            database_directory_status::configured_database_directory,
            trusted_program_lookup::{ClamavProgram, ProgramLocation, locate_trusted_program},
        },
        clamav_scanner::{
            scan_exclusion_rules::broad_exclusions, scanner_output_parser::sanitize_scanner_line,
        },
        desktop::{
            flatpak_sandbox::readable_host_path,
            stored_settings::{application_settings, read_exclusion_entries},
        },
        settings_helper::protection_change_rules::{
            ValuesInEffect, limit_in_units, protection_reduction,
        },
        systemd_bus::host_systemd_units::{
            ServiceFailureKind, ServiceLastResult, ServiceUnitSnapshot, TimerUnitSnapshot,
            UnitActivity, UnitState, UnitTimestamp, first_active_unit, probe_unit_state,
            probe_user_unit_state, service_unit_snapshot, timer_unit_snapshot,
        },
    },
    protection_page::{
        clamav_engine_evidence::{
            DatabaseEvidence, inspect_database_evidence_with_banner,
            inspect_database_evidence_without_banner, newest_disk_signature_version,
        },
        service_run_journal::{
            ScanRunHistory, UpdaterRunHistory, newest_scan_run, newest_update_run,
        },
        signature_update_run::updater_exit_status::{
            SignatureUpdaterProgram, UpdaterExitMeaning, classify_updater_exit_status,
        },
        trusted_detections_page::trust_list_contents::{
            TrustListReading, read_configured_trust_list,
        },
    },
    scan_page::scan_schedule_page::{
        scan_schedule_settings::StoredScheduleSettings,
        scan_schedule_units::changed_units_of_current_schedule,
    },
};

const CHECKED_CLAMAV_PROGRAMS: [ClamavProgram; 3] = [
    ClamavProgram::ClamdClient,
    ClamavProgram::StandaloneScanner,
    ClamavProgram::SignatureUpdater,
];
const DAEMON_SERVICE_UNITS: [&str; 3] = [
    "clamav-daemon.service",
    "clamd@scan.service",
    "clamd.service",
];
const ON_ACCESS_SERVICE_UNITS: [&str; 2] = ["clamav-clamonacc.service", "clamonacc.service"];
const SIGNATURE_UPDATER_UNITS: [SignatureUpdaterUnit; 3] = [
    SignatureUpdaterUnit {
        updater_program: SignatureUpdaterProgram::Freshclam,
        service_unit: "clamav-freshclam.service",
    },
    SignatureUpdaterUnit {
        updater_program: SignatureUpdaterProgram::Freshclam,
        service_unit: "freshclam.service",
    },
    SignatureUpdaterUnit {
        updater_program: SignatureUpdaterProgram::Fangfrisch,
        service_unit: "clamav-fangfrisch.service",
    },
];
const SYSTEM_SCAN_UNITS: [SystemScanUnits; 1] = [SystemScanUnits {
    timer_unit: "clamdscan.timer",
    service_unit: "clamdscan.service",
}];
const THIRD_PARTY_SIGNATURE_EXTENSIONS: [&str; 7] =
    ["ndb", "hdb", "hsb", "ldb", "cdb", "ign2", "yara"];
const LAZARET_SCHEDULE_KEY: &str = "schedule-enabled";
const NOTIFICATIONS_ENABLED_KEY: &str = "notifications-enabled";
const BACKGROUND_SERVICE_UNIT: &str = "lazaret.service";

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
    updater_program: SignatureUpdaterProgram,
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
pub enum ScanUnitResult {
    NothingFound,
    ThreatsFound,
    ScannerError { exit_status: i32 },
    ServiceFailed { failure_kind: ServiceFailureKind },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdaterUnitResult {
    UpdateSucceeded,
    UpdateAlreadyCurrent,
    UpdaterError { exit_status: i32 },
    ServiceFailed { failure_kind: ServiceFailureKind },
}

const SCANNER_CLEAN_STATUS: i32 = 0;
const SCANNER_FOUND_THREATS_STATUS: i32 = 1;

pub fn classify_scan_unit_result(last_result: ServiceLastResult) -> ScanUnitResult {
    match last_result {
        ServiceLastResult::ResultSucceeded
        | ServiceLastResult::ExitedWithStatus {
            exit_status: SCANNER_CLEAN_STATUS,
        } => ScanUnitResult::NothingFound,
        ServiceLastResult::ExitedWithStatus {
            exit_status: SCANNER_FOUND_THREATS_STATUS,
        } => ScanUnitResult::ThreatsFound,
        ServiceLastResult::ExitedWithStatus { exit_status } => {
            ScanUnitResult::ScannerError { exit_status }
        }
        ServiceLastResult::FailedWithResult { failure_kind } => {
            ScanUnitResult::ServiceFailed { failure_kind }
        }
    }
}

pub fn classify_updater_unit_result(
    updater_program: SignatureUpdaterProgram,
    last_result: ServiceLastResult,
) -> UpdaterUnitResult {
    match last_result {
        ServiceLastResult::ResultSucceeded => UpdaterUnitResult::UpdateSucceeded,
        ServiceLastResult::ExitedWithStatus { exit_status } => {
            match classify_updater_exit_status(updater_program, exit_status) {
                UpdaterExitMeaning::UpdateSucceeded => UpdaterUnitResult::UpdateSucceeded,
                UpdaterExitMeaning::UpdateAlreadyCurrent => UpdaterUnitResult::UpdateAlreadyCurrent,
                UpdaterExitMeaning::UpdaterError { exit_status } => {
                    UpdaterUnitResult::UpdaterError { exit_status }
                }
            }
        }
        ServiceLastResult::FailedWithResult { failure_kind } => {
            UpdaterUnitResult::ServiceFailed { failure_kind }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdaterEvidence {
    pub updater_program: SignatureUpdaterProgram,
    pub service_unit: &'static str,
    pub last_result: UpdaterUnitResult,
    pub last_completed_run: UpdaterRunHistory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThirdPartySignatureFile {
    pub file_name: String,
    pub modified_at: Timestamp,
    pub file_size: ByteSize,
    pub signature_count: u64,
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
    UnitActiveNotAnswering { service_unit: &'static str },
    UnitStopped { service_unit: &'static str },
    UnitStateUnknown,
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
    ConfiguredLimit { size_limit: ByteSize },
    UnreadableLimit { limit_text: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchedLocation {
    WatchedFolder { folder_path: String },
    WatchedMount { mount_path: String },
}

impl WatchedLocation {
    pub fn location_path(&self) -> &str {
        match self {
            Self::WatchedFolder { folder_path } => folder_path,
            Self::WatchedMount { mount_path } => mount_path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WatchScope {
    NothingWatched,
    WatchedLocations {
        first_location: WatchedLocation,
        other_locations: Vec<WatchedLocation>,
    },
}

impl WatchScope {
    fn from_locations(watched_locations: Vec<WatchedLocation>) -> Self {
        let mut location_iterator = watched_locations.into_iter();
        match location_iterator.next() {
            Some(first_location) => Self::WatchedLocations {
                first_location,
                other_locations: location_iterator.collect(),
            },
            None => Self::NothingWatched,
        }
    }

    pub fn watched_locations(&self) -> Vec<&WatchedLocation> {
        match self {
            Self::NothingWatched => Vec::new(),
            Self::WatchedLocations {
                first_location,
                other_locations,
            } => std::iter::once(first_location)
                .chain(other_locations)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnAccessResponse {
    BlockAccess,
    ReportOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClamdConfigReadFailure {
    #[error("no readable clamd.conf was found")]
    NoReadableConfig,
    #[error("the task reading clamd.conf stopped before it finished")]
    ReadingTaskAborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnAccessConfig {
    ConfigUnreadable(ClamdConfigReadFailure),
    ConfigRead {
        watch_scope: WatchScope,
        blocking_response: OnAccessResponse,
        size_limit: OnAccessSizeLimit,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnAccessEvidence {
    pub on_access_scanner: OnAccessScanner,
    pub on_access_config: OnAccessConfig,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScanServiceEvidence {
    ServiceConfigured {
        scan_targets: Vec<String>,
        last_result: ScanUnitResult,
    },
    ServiceMissing,
    ServiceUnreadable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimerState {
    TimerInactive,
    TimerActive { next_run: UnitTimestamp },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScheduledScanEvidence {
    SystemTimer {
        service_unit: &'static str,
        timer_state: TimerState,
        scan_service: ScanServiceEvidence,
        last_completed_run: ScanRunHistory,
    },
    LazaretSchedule,
    NoSchedule,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramTrustFinding {
    ReplaceableProgramIgnored {
        program_name: &'static str,
        trusted_path: String,
        ignored_paths: Vec<String>,
    },
    OnlyReplaceableProgram {
        program_name: &'static str,
        replaceable_paths: Vec<String>,
    },
}

const RUNTIME_OVERRIDES_PATH: &str = "/var/lib/lazaret/clamd-overrides.conf";
const BASE_CLAMD_CONFIG_PATH: &str = "/etc/clamav/clamd.conf";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReducedSetting {
    pub setting_key: String,
    pub base_value: String,
    pub changed_value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverriddenSetting {
    pub setting_key: String,
    pub changed_value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverridesChangeTime {
    ChangedAt { changed_at: Timestamp },
    ChangeTimeUnknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum RuntimeReductions {
    #[default]
    NothingReduced,
    SettingsReduced {
        change_time: OverridesChangeTime,
        reduced_settings: Vec<ReducedSetting>,
    },
    BaseConfigUnreadable {
        change_time: OverridesChangeTime,
        overridden_settings: Vec<OverriddenSetting>,
    },
}

fn values_for_key(config_settings: &[ConfigSetting], setting_key: &str) -> Vec<String> {
    config_settings
        .iter()
        .filter(|config_setting| config_setting.setting_key == setting_key)
        .map(|config_setting| config_setting.setting_value.clone())
        .collect()
}

pub fn reduced_settings(
    base_settings: &[ConfigSetting],
    override_settings: &[ConfigSetting],
) -> Vec<ReducedSetting> {
    let mut overridden_keys = override_settings
        .iter()
        .map(|override_setting| override_setting.setting_key.clone())
        .collect::<Vec<_>>();
    overridden_keys.dedup();
    overridden_keys
        .into_iter()
        .filter_map(|setting_key| {
            let base_values = values_for_key(base_settings, &setting_key);
            let changed_values = values_for_key(override_settings, &setting_key);
            protection_reduction(
                &setting_key,
                &ValuesInEffect::from_config_values(base_values.clone()),
                &changed_values,
            )
            .weakens_protection()
            .then(|| ReducedSetting {
                base_value: sanitize_scanner_line(&base_values.join(", ")),
                changed_value: sanitize_scanner_line(&changed_values.join(", ")),
                setting_key: sanitize_scanner_line(&setting_key),
            })
        })
        .collect()
}

fn overrides_change_time(overrides_path: &Path) -> OverridesChangeTime {
    fs::metadata(overrides_path)
        .and_then(|overrides_metadata| overrides_metadata.modified())
        .ok()
        .and_then(|modified_time| Timestamp::try_from(modified_time).ok())
        .map_or(OverridesChangeTime::ChangeTimeUnknown, |changed_at| {
            OverridesChangeTime::ChangedAt { changed_at }
        })
}

pub fn runtime_reductions_against_base(
    base_settings: &[ConfigSetting],
    override_settings: &[ConfigSetting],
    change_time: OverridesChangeTime,
) -> RuntimeReductions {
    let reduced_settings = reduced_settings(base_settings, override_settings);
    if reduced_settings.is_empty() {
        RuntimeReductions::NothingReduced
    } else {
        RuntimeReductions::SettingsReduced {
            change_time,
            reduced_settings,
        }
    }
}

pub fn runtime_reductions_without_base(
    override_settings: &[ConfigSetting],
    change_time: OverridesChangeTime,
) -> RuntimeReductions {
    if override_settings.is_empty() {
        return RuntimeReductions::NothingReduced;
    }
    RuntimeReductions::BaseConfigUnreadable {
        change_time,
        overridden_settings: override_settings
            .iter()
            .map(|override_setting| OverriddenSetting {
                setting_key: sanitize_scanner_line(&override_setting.setting_key),
                changed_value: sanitize_scanner_line(&override_setting.setting_value),
            })
            .collect(),
    }
}

fn inspect_runtime_reductions() -> RuntimeReductions {
    let overrides_path = readable_host_path(RUNTIME_OVERRIDES_PATH);
    let Ok(overrides_text) = fs::read_to_string(&overrides_path) else {
        return RuntimeReductions::NothingReduced;
    };
    let override_settings = parse_config_settings(&overrides_text);
    let change_time = overrides_change_time(&overrides_path);
    match fs::read_to_string(readable_host_path(BASE_CLAMD_CONFIG_PATH)) {
        Ok(base_text) => runtime_reductions_against_base(
            &parse_config_settings(&base_text),
            &override_settings,
            change_time,
        ),
        Err(_unreadable_base) => runtime_reductions_without_base(&override_settings, change_time),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountSettingFinding {
    BroadExclusion {
        exclusion_pattern: String,
        skipped_example: String,
    },
    ScheduleUnitChanged {
        unit_file_name: String,
    },
}

fn inspect_account_settings(lazaret_schedule_enabled: bool) -> Vec<AccountSettingFinding> {
    let stored_settings = application_settings();
    let exclusion_findings = broad_exclusions(
        &read_exclusion_entries(&stored_settings),
        &relm4::gtk::glib::home_dir(),
    )
    .into_iter()
    .map(|broad_exclusion| AccountSettingFinding::BroadExclusion {
        exclusion_pattern: sanitize_scanner_line(&broad_exclusion.exclusion_pattern),
        skipped_example: sanitize_scanner_line(&broad_exclusion.skipped_example.to_string_lossy()),
    });
    let schedule_findings = if lazaret_schedule_enabled {
        StoredScheduleSettings::read_from(&stored_settings)
            .scan_schedule()
            .map(|scan_schedule| changed_units_of_current_schedule(&scan_schedule))
            .unwrap_or_default()
    } else {
        Vec::new()
    }
    .into_iter()
    .map(|unit_file_name| AccountSettingFinding::ScheduleUnitChanged { unit_file_name });
    exclusion_findings.chain(schedule_findings).collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionEvidence {
    pub program_trust_findings: Vec<ProgramTrustFinding>,
    pub trust_list: TrustListReading,
    pub runtime_reductions: RuntimeReductions,
    pub account_setting_findings: Vec<AccountSettingFinding>,
    pub engine_installation: EngineInstallation,
    pub signature_evidence: SignatureEvidence,
    pub daemon_evidence: DaemonEvidence,
    pub on_access_evidence: OnAccessEvidence,
    pub scheduled_scan_evidence: ScheduledScanEvidence,
    pub background_service_state: UnitState,
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
    disk_version: u64,
) -> LoadedSignatures {
    let ProgramProbe::VersionReported {
        version_text: daemon_text,
    } = daemon_banner
    else {
        return LoadedSignatures::ComparisonUnavailable;
    };
    let Some(loaded_version) = signature_version_in_banner(daemon_text)
        .and_then(|version_text| version_text.parse::<u64>().ok())
    else {
        return LoadedSignatures::ComparisonUnavailable;
    };
    if loaded_version >= disk_version {
        LoadedSignatures::MatchesDisk
    } else {
        LoadedSignatures::BehindDisk {
            loaded_version: loaded_version.to_string(),
            disk_version: disk_version.to_string(),
        }
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

pub fn on_access_config_from_settings(config_settings: &[ConfigSetting]) -> OnAccessConfig {
    let watched_mounts = config_values(config_settings, "OnAccessMountPath").map(|mount_path| {
        WatchedLocation::WatchedMount {
            mount_path: sanitize_scanner_line(mount_path),
        }
    });
    let watched_folders =
        config_values(config_settings, "OnAccessIncludePath").map(|folder_path| {
            WatchedLocation::WatchedFolder {
                folder_path: sanitize_scanner_line(folder_path),
            }
        });
    OnAccessConfig::ConfigRead {
        watch_scope: WatchScope::from_locations(watched_mounts.chain(watched_folders).collect()),
        blocking_response: if config_values(config_settings, "OnAccessPrevention")
            .any(setting_is_enabled)
        {
            OnAccessResponse::BlockAccess
        } else {
            OnAccessResponse::ReportOnly
        },
        size_limit: config_values(config_settings, "OnAccessMaxFileSize")
            .next()
            .map_or(OnAccessSizeLimit::DefaultLimit, |limit_text| {
                limit_in_units(limit_text).map_or_else(
                    || OnAccessSizeLimit::UnreadableLimit {
                        limit_text: sanitize_scanner_line(limit_text),
                    },
                    |limit_units| OnAccessSizeLimit::ConfiguredLimit {
                        size_limit: ByteSize::b(limit_units),
                    },
                )
            }),
    }
}

pub fn on_access_config_from_view(config_view: HostConfigView) -> OnAccessConfig {
    match config_view {
        HostConfigView::ConfigFound {
            config_settings, ..
        } => on_access_config_from_settings(&config_settings),
        HostConfigView::ConfigNotFound => {
            OnAccessConfig::ConfigUnreadable(ClamdConfigReadFailure::NoReadableConfig)
        }
    }
}

fn sanitized_path_text(shown_path: &Path) -> String {
    sanitize_scanner_line(&shown_path.to_string_lossy())
}

fn program_trust_finding(
    clamav_program: ClamavProgram,
    program_location: &ProgramLocation,
) -> Option<ProgramTrustFinding> {
    let replaceable_paths = program_location
        .replaceable_candidates()
        .iter()
        .map(|replaceable_candidate| sanitized_path_text(&replaceable_candidate.candidate_path))
        .collect();
    match program_location {
        ProgramLocation::ShadowedTrustedProgram { program_path, .. } => {
            Some(ProgramTrustFinding::ReplaceableProgramIgnored {
                program_name: clamav_program.program_name(),
                trusted_path: sanitized_path_text(program_path),
                ignored_paths: replaceable_paths,
            })
        }
        ProgramLocation::OnlyReplaceableCandidates { .. } => {
            Some(ProgramTrustFinding::OnlyReplaceableProgram {
                program_name: clamav_program.program_name(),
                replaceable_paths,
            })
        }
        ProgramLocation::TrustedProgram { .. } | ProgramLocation::ProgramNotFound => None,
    }
}

fn inspect_program_trust() -> Vec<ProgramTrustFinding> {
    CHECKED_CLAMAV_PROGRAMS
        .into_iter()
        .filter_map(|clamav_program| {
            program_trust_finding(clamav_program, &locate_trusted_program(clamav_program))
        })
        .collect()
}

async fn inspect_engine_installation() -> EngineInstallation {
    let clamscan_location =
        spawn_blocking(|| locate_trusted_program(ClamavProgram::StandaloneScanner))
            .await
            .unwrap_or(ProgramLocation::ProgramNotFound);
    match probe_located_program_version(&clamscan_location).await {
        ProgramProbe::NotFoundOnPath => EngineInstallation::EngineMissing,
        ProgramProbe::ProgramRefused { candidate_path } => EngineInstallation::VersionUnverified {
            failure_text: gettext("refused {path}, because your account can replace it")
                .replace("{path}", &sanitized_path_text(&candidate_path)),
        },
        ProgramProbe::ProbeFailed { failure_text } => EngineInstallation::VersionUnverified {
            failure_text: sanitize_scanner_line(&failure_text),
        },
        ProgramProbe::VersionReported { version_text } => EngineInstallation::VersionReported {
            version_banner: sanitize_scanner_line(&version_text),
        },
    }
}

fn updater_last_result(
    updater_program: SignatureUpdaterProgram,
    service_snapshot: ServiceUnitSnapshot,
) -> Option<UpdaterUnitResult> {
    match service_snapshot {
        ServiceUnitSnapshot::LoadedService { last_result, .. } => {
            Some(classify_updater_unit_result(updater_program, last_result))
        }
        ServiceUnitSnapshot::ServiceNotFound | ServiceUnitSnapshot::SystemdUnreachable(_) => None,
    }
}

async fn inspect_updater_unit(updater_unit: SignatureUpdaterUnit) -> Option<UpdaterEvidence> {
    let last_result = updater_last_result(
        updater_unit.updater_program,
        service_unit_snapshot(updater_unit.service_unit).await,
    )?;
    Some(UpdaterEvidence {
        updater_program: updater_unit.updater_program,
        service_unit: updater_unit.service_unit,
        last_result,
        last_completed_run: newest_update_run(
            updater_unit.updater_program,
            updater_unit.service_unit,
        )
        .await,
    })
}

fn count_lines_with_content(file_bytes: &[u8]) -> u64 {
    file_bytes
        .split(|file_byte| *file_byte == b'\n')
        .filter(|file_line| !file_line.is_empty())
        .count() as u64
}

fn count_signature_lines(signature_file: &Path) -> u64 {
    fs::read(signature_file).map_or(0, |file_bytes| count_lines_with_content(&file_bytes))
}

fn third_party_signature_files(database_directory: &Path) -> Vec<ThirdPartySignatureFile> {
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
                    let file_metadata = directory_entry.metadata().ok()?;
                    let modified_at = Timestamp::try_from(file_metadata.modified().ok()?).ok()?;
                    Some(ThirdPartySignatureFile {
                        file_name: sanitize_scanner_line(
                            &directory_entry.file_name().to_string_lossy(),
                        ),
                        modified_at,
                        file_size: ByteSize::b(file_metadata.len()),
                        signature_count: count_signature_lines(&directory_entry.path()),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    signature_files
        .sort_by(|first_file, second_file| first_file.file_name.cmp(&second_file.file_name));
    signature_files
}

async fn inspect_signature_evidence(engine_installation: &EngineInstallation) -> SignatureEvidence {
    let updater_evidence = join_all(SIGNATURE_UPDATER_UNITS.map(inspect_updater_unit))
        .await
        .into_iter()
        .flatten()
        .collect();
    SignatureEvidence {
        database_evidence: match engine_installation {
            EngineInstallation::VersionReported { version_banner } => {
                inspect_database_evidence_with_banner(version_banner).await
            }
            EngineInstallation::EngineMissing | EngineInstallation::VersionUnverified { .. } => {
                inspect_database_evidence_without_banner().await
            }
        },
        updater_evidence,
        third_party_files: spawn_blocking(|| {
            third_party_signature_files(&configured_database_directory())
        })
        .await
        .unwrap_or_default(),
    }
}

async fn inspect_daemon_evidence() -> DaemonEvidence {
    let clamdscan_location = spawn_blocking(|| locate_trusted_program(ClamavProgram::ClamdClient))
        .await
        .unwrap_or(ProgramLocation::ProgramNotFound);
    if located_clamd_answers_ping(&clamdscan_location).await {
        let daemon_banner = probe_located_program_version(&clamdscan_location).await;
        return DaemonEvidence::ClamdAnswering {
            loaded_signatures: match spawn_blocking(newest_disk_signature_version)
                .await
                .ok()
                .flatten()
            {
                Some(disk_version) => compare_loaded_signatures(&daemon_banner, disk_version),
                None => LoadedSignatures::ComparisonUnavailable,
            },
        };
    }
    silent_daemon_evidence(&join_all(DAEMON_SERVICE_UNITS.map(probe_unit_state)).await)
}

fn first_unit_in_state(unit_states: &[UnitState], wanted_state: UnitState) -> Option<&'static str> {
    DAEMON_SERVICE_UNITS
        .iter()
        .zip(unit_states)
        .find(|named_state| *named_state.1 == wanted_state)
        .map(|named_state| *named_state.0)
}

pub fn silent_daemon_evidence(unit_states: &[UnitState]) -> DaemonEvidence {
    if let Some(service_unit) =
        first_unit_in_state(unit_states, UnitState::UnitLoaded(UnitActivity::UnitActive))
    {
        return DaemonEvidence::UnitActiveNotAnswering { service_unit };
    }
    if let Some(service_unit) = first_unit_in_state(
        unit_states,
        UnitState::UnitLoaded(UnitActivity::UnitInactive),
    ) {
        return DaemonEvidence::UnitStopped { service_unit };
    }
    if unit_states.contains(&UnitState::SystemdUnavailable) {
        DaemonEvidence::UnitStateUnknown
    } else {
        DaemonEvidence::NeverSetUp
    }
}

async fn inspect_on_access_scanner() -> OnAccessScanner {
    if first_active_unit(&ON_ACCESS_SERVICE_UNITS).await.is_some() {
        return OnAccessScanner::MonitorRunning;
    }
    let unit_states = join_all(ON_ACCESS_SERVICE_UNITS.map(probe_unit_state)).await;
    ON_ACCESS_SERVICE_UNITS
        .iter()
        .zip(unit_states)
        .find(|named_state| named_state.1 == UnitState::UnitLoaded(UnitActivity::UnitInactive))
        .map_or(OnAccessScanner::NeverSetUp, |named_state| {
            OnAccessScanner::UnitStopped {
                service_unit: named_state.0,
            }
        })
}

async fn inspect_on_access_evidence() -> OnAccessEvidence {
    let on_access_scanner = inspect_on_access_scanner().await;
    let on_access_config = spawn_blocking(read_clamd_config).await.map_or(
        OnAccessConfig::ConfigUnreadable(ClamdConfigReadFailure::ReadingTaskAborted),
        on_access_config_from_view,
    );
    OnAccessEvidence {
        on_access_scanner,
        on_access_config,
    }
}

pub fn scan_service_evidence(service_snapshot: ServiceUnitSnapshot) -> ScanServiceEvidence {
    match service_snapshot {
        ServiceUnitSnapshot::LoadedService {
            last_result,
            program_arguments,
            ..
        } => ScanServiceEvidence::ServiceConfigured {
            scan_targets: scan_targets_from_arguments(&program_arguments),
            last_result: classify_scan_unit_result(last_result),
        },
        ServiceUnitSnapshot::ServiceNotFound => ScanServiceEvidence::ServiceMissing,
        ServiceUnitSnapshot::SystemdUnreachable(_) => ScanServiceEvidence::ServiceUnreadable,
    }
}

async fn inspect_scheduled_scan(lazaret_schedule_enabled: bool) -> ScheduledScanEvidence {
    for system_scan_units in SYSTEM_SCAN_UNITS {
        let TimerUnitSnapshot::LoadedTimer {
            unit_activity,
            next_run,
            ..
        } = timer_unit_snapshot(system_scan_units.timer_unit).await
        else {
            continue;
        };
        let service_snapshot = service_unit_snapshot(system_scan_units.service_unit).await;
        return ScheduledScanEvidence::SystemTimer {
            service_unit: system_scan_units.service_unit,
            timer_state: match unit_activity {
                UnitActivity::UnitActive => TimerState::TimerActive { next_run },
                UnitActivity::UnitInactive => TimerState::TimerInactive,
            },
            scan_service: scan_service_evidence(service_snapshot),
            last_completed_run: newest_scan_run(system_scan_units.service_unit).await,
        };
    }
    if lazaret_schedule_enabled {
        ScheduledScanEvidence::LazaretSchedule
    } else {
        ScheduledScanEvidence::NoSchedule
    }
}

pub fn detection_notifications_are_enabled() -> bool {
    application_settings().boolean(NOTIFICATIONS_ENABLED_KEY)
}

pub fn lazaret_schedule_is_enabled() -> bool {
    application_settings().boolean(LAZARET_SCHEDULE_KEY)
}

pub async fn gather_protection_evidence(lazaret_schedule_enabled: bool) -> ProtectionEvidence {
    let engine_installation = inspect_engine_installation().await;
    let signature_evidence = inspect_signature_evidence(&engine_installation).await;
    ProtectionEvidence {
        program_trust_findings: spawn_blocking(inspect_program_trust)
            .await
            .unwrap_or_default(),
        trust_list: read_configured_trust_list().await,
        runtime_reductions: spawn_blocking(inspect_runtime_reductions)
            .await
            .unwrap_or_default(),
        account_setting_findings: inspect_account_settings(lazaret_schedule_enabled),
        engine_installation,
        signature_evidence,
        daemon_evidence: inspect_daemon_evidence().await,
        on_access_evidence: inspect_on_access_evidence().await,
        scheduled_scan_evidence: inspect_scheduled_scan(lazaret_schedule_enabled).await,
        background_service_state: probe_user_unit_state(BACKGROUND_SERVICE_UNIT).await,
    }
}

#[cfg(test)]
mod protection_evidence_tests {
    use super::*;
    use crate::host_services::systemd_bus::host_systemd_units::SystemdBusFailure;

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
    fn only_overrides_that_weaken_the_base_config_are_reduced_settings() {
        let base_settings = vec![
            config_setting("OnAccessPrevention", "yes"),
            config_setting("MaxThreads", "12"),
            config_setting("OnAccessIncludePath", "/home"),
        ];
        let override_settings = vec![
            config_setting("OnAccessPrevention", "no"),
            config_setting("MaxThreads", "2"),
            config_setting("OnAccessIncludePath", "/home"),
            config_setting("OnAccessIncludePath", "/srv"),
        ];
        assert_eq!(
            reduced_settings(&base_settings, &override_settings),
            vec![ReducedSetting {
                setting_key: "OnAccessPrevention".to_owned(),
                base_value: "yes".to_owned(),
                changed_value: "no".to_owned(),
            }]
        );
    }

    #[test]
    fn an_unreadable_or_missing_scan_service_never_reports_a_result() {
        assert_eq!(
            scan_service_evidence(ServiceUnitSnapshot::SystemdUnreachable(
                SystemdBusFailure::BusCallFailed(zbus::Error::InvalidReply)
            )),
            ScanServiceEvidence::ServiceUnreadable
        );
        assert_eq!(
            scan_service_evidence(ServiceUnitSnapshot::ServiceNotFound),
            ScanServiceEvidence::ServiceMissing
        );
        assert_eq!(
            scan_service_evidence(ServiceUnitSnapshot::LoadedService {
                unit_activity: UnitActivity::UnitInactive,
                last_result: ServiceLastResult::ResultSucceeded,
                program_arguments: vec!["/bin/clamdscan".to_owned(), "/home".to_owned()],
            }),
            ScanServiceEvidence::ServiceConfigured {
                scan_targets: vec!["/home".to_owned()],
                last_result: ScanUnitResult::NothingFound,
            }
        );
    }

    #[test]
    fn scan_unit_exit_statuses_follow_the_scanner_meaning() {
        assert_eq!(
            classify_scan_unit_result(ServiceLastResult::ResultSucceeded),
            ScanUnitResult::NothingFound
        );
        assert_eq!(
            classify_scan_unit_result(ServiceLastResult::ExitedWithStatus { exit_status: 1 }),
            ScanUnitResult::ThreatsFound
        );
        assert_eq!(
            classify_scan_unit_result(ServiceLastResult::ExitedWithStatus { exit_status: 2 }),
            ScanUnitResult::ScannerError { exit_status: 2 }
        );
        assert_eq!(
            classify_scan_unit_result(ServiceLastResult::FailedWithResult {
                failure_kind: ServiceFailureKind::TimedOut
            }),
            ScanUnitResult::ServiceFailed {
                failure_kind: ServiceFailureKind::TimedOut
            }
        );
    }

    #[test]
    fn freshclam_exit_one_is_already_current_but_fangfrisch_exit_one_is_an_error() {
        assert_eq!(
            classify_updater_unit_result(
                SignatureUpdaterProgram::Freshclam,
                ServiceLastResult::ResultSucceeded
            ),
            UpdaterUnitResult::UpdateSucceeded
        );
        assert_eq!(
            classify_updater_unit_result(
                SignatureUpdaterProgram::Freshclam,
                ServiceLastResult::ExitedWithStatus { exit_status: 1 }
            ),
            UpdaterUnitResult::UpdateAlreadyCurrent
        );
        assert_eq!(
            classify_updater_unit_result(
                SignatureUpdaterProgram::Fangfrisch,
                ServiceLastResult::ExitedWithStatus { exit_status: 1 }
            ),
            UpdaterUnitResult::UpdaterError { exit_status: 1 }
        );
        assert_eq!(
            classify_updater_unit_result(
                SignatureUpdaterProgram::Freshclam,
                ServiceLastResult::ExitedWithStatus { exit_status: 52 }
            ),
            UpdaterUnitResult::UpdaterError { exit_status: 52 }
        );
        assert_eq!(
            classify_updater_unit_result(
                SignatureUpdaterProgram::Freshclam,
                ServiceLastResult::FailedWithResult {
                    failure_kind: ServiceFailureKind::KilledBySignal
                }
            ),
            UpdaterUnitResult::ServiceFailed {
                failure_kind: ServiceFailureKind::KilledBySignal
            }
        );
    }

    #[test]
    fn a_missing_updater_unit_is_not_reported_as_succeeded() {
        assert_eq!(
            updater_last_result(
                SignatureUpdaterProgram::Freshclam,
                ServiceUnitSnapshot::ServiceNotFound
            ),
            None
        );
        assert_eq!(
            updater_last_result(
                SignatureUpdaterProgram::Freshclam,
                ServiceUnitSnapshot::SystemdUnreachable(SystemdBusFailure::UnrecognizedLoadState)
            ),
            None
        );
    }

    #[test]
    fn signature_counts_include_a_last_line_without_a_newline() {
        assert_eq!(count_lines_with_content(b"first\nsecond"), 2);
        assert_eq!(count_lines_with_content(b"first\nsecond\n"), 2);
        assert_eq!(count_lines_with_content(b""), 0);
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
            compare_loaded_signatures(&daemon_banner, 28_174),
            LoadedSignatures::BehindDisk {
                loaded_version: "28173".to_owned(),
                disk_version: "28174".to_owned(),
            }
        );
        assert_eq!(
            compare_loaded_signatures(&daemon_banner, 28_173),
            LoadedSignatures::MatchesDisk
        );
    }

    #[test]
    fn a_banner_without_a_signature_version_cannot_be_compared() {
        assert_eq!(
            compare_loaded_signatures(&reported_banner("ClamAV 1.5.4"), 28_174),
            LoadedSignatures::ComparisonUnavailable
        );
        assert_eq!(
            compare_loaded_signatures(&ProgramProbe::NotFoundOnPath, 28_174),
            LoadedSignatures::ComparisonUnavailable
        );
    }

    #[test]
    fn on_access_settings_are_read_from_the_daemon_config() {
        assert_eq!(
            on_access_config_from_settings(&[
                config_setting("OnAccessIncludePath", "/home/user/Downloads"),
                config_setting("OnAccessIncludePath", "/srv/inbox"),
                config_setting("OnAccessMountPath", "/media"),
                config_setting("OnAccessPrevention", "true"),
                config_setting("OnAccessMaxFileSize", "100M"),
            ]),
            OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedMount {
                        mount_path: "/media".to_owned()
                    },
                    other_locations: vec![
                        WatchedLocation::WatchedFolder {
                            folder_path: "/home/user/Downloads".to_owned()
                        },
                        WatchedLocation::WatchedFolder {
                            folder_path: "/srv/inbox".to_owned()
                        },
                    ],
                },
                blocking_response: OnAccessResponse::BlockAccess,
                size_limit: OnAccessSizeLimit::ConfiguredLimit {
                    size_limit: ByteSize::mib(100)
                },
            }
        );
    }

    #[test]
    fn a_watched_mount_alone_counts_as_watched() {
        let OnAccessConfig::ConfigRead { watch_scope, .. } =
            on_access_config_from_settings(&[config_setting("OnAccessMountPath", "/")])
        else {
            panic!("a read config was expected");
        };
        assert_ne!(watch_scope, WatchScope::NothingWatched);
    }

    #[test]
    fn absent_on_access_settings_do_not_claim_prevention() {
        assert_eq!(
            on_access_config_from_settings(&[]),
            OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::NothingWatched,
                blocking_response: OnAccessResponse::ReportOnly,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            }
        );
    }

    #[test]
    fn a_missing_daemon_config_claims_no_on_access_settings() {
        assert_eq!(
            on_access_config_from_view(HostConfigView::ConfigNotFound),
            OnAccessConfig::ConfigUnreadable(ClamdConfigReadFailure::NoReadableConfig)
        );
    }

    #[test]
    fn a_silent_daemon_is_classified_by_its_unit_states() {
        assert_eq!(
            silent_daemon_evidence(&[
                UnitState::UnitNotFound,
                UnitState::UnitLoaded(UnitActivity::UnitActive),
                UnitState::UnitNotFound,
            ]),
            DaemonEvidence::UnitActiveNotAnswering {
                service_unit: "clamd@scan.service"
            }
        );
        assert_eq!(
            silent_daemon_evidence(&[
                UnitState::UnitLoaded(UnitActivity::UnitInactive),
                UnitState::SystemdUnavailable,
                UnitState::UnitNotFound,
            ]),
            DaemonEvidence::UnitStopped {
                service_unit: "clamav-daemon.service"
            }
        );
        assert_eq!(
            silent_daemon_evidence(&[
                UnitState::SystemdUnavailable,
                UnitState::UnitNotFound,
                UnitState::UnitNotFound,
            ]),
            DaemonEvidence::UnitStateUnknown
        );
        assert_eq!(
            silent_daemon_evidence(&[UnitState::UnitNotFound; 3]),
            DaemonEvidence::NeverSetUp
        );
    }

    #[test]
    fn overrides_against_an_unreadable_base_are_not_called_harmless() {
        let override_settings = vec![config_setting("OnAccessPrevention", "no")];
        assert_eq!(
            runtime_reductions_without_base(
                &override_settings,
                OverridesChangeTime::ChangeTimeUnknown
            ),
            RuntimeReductions::BaseConfigUnreadable {
                change_time: OverridesChangeTime::ChangeTimeUnknown,
                overridden_settings: vec![OverriddenSetting {
                    setting_key: "OnAccessPrevention".to_owned(),
                    changed_value: "no".to_owned(),
                }],
            }
        );
        assert_eq!(
            runtime_reductions_without_base(&[], OverridesChangeTime::ChangeTimeUnknown),
            RuntimeReductions::NothingReduced
        );
    }

    #[test]
    fn a_reduction_keeps_an_unknown_change_time_unknown() {
        assert_eq!(
            runtime_reductions_against_base(
                &[config_setting("OnAccessPrevention", "yes")],
                &[config_setting("OnAccessPrevention", "no")],
                OverridesChangeTime::ChangeTimeUnknown,
            ),
            RuntimeReductions::SettingsReduced {
                change_time: OverridesChangeTime::ChangeTimeUnknown,
                reduced_settings: vec![ReducedSetting {
                    setting_key: "OnAccessPrevention".to_owned(),
                    base_value: "yes".to_owned(),
                    changed_value: "no".to_owned(),
                }],
            }
        );
    }
}
