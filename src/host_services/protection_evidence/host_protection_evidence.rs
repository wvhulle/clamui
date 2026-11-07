use std::{fs, io, path::Path};

use bytesize::ByteSize;
use clamd_configuration::{
    clamd_conf_format::config_lines::ClamdConfigLines,
    merged_clamd_config::tunable_settings_in,
    setting_kinds::limit_in_units,
    tunable_record::{BaseSettings, LiveOverrides},
};
use futures::future::join_all;
use jiff::Timestamp;
use relm4::gtk::gio::prelude::SettingsExt;
use tokio::task::spawn_blocking;

use crate::{
    findings::trusted_detections_page::trusted_detections_section::trust_list_contents::{
        TrustListReading, read_configured_trust_list,
    },
    host_services::{
        clamav_admin_service::live_settings_client::{
            BASE_CLAMD_CONFIG_PATH, LIVE_OVERRIDES_PATH, StoredOverridesFailure,
            read_stored_overrides,
        },
        clamav_config::clamav_host_config::{ConfigSetting, HostConfigView, read_clamd_config},
        clamav_programs::{
            component_availability::{
                ProbeFailure, ProgramProbe, located_clamd_answers_ping,
                probe_located_program_version,
            },
            database_directory_status::{DatabaseFolderReadFailure, configured_database_directory},
            trusted_program_lookup::{ClamavProgram, ProgramLocation, locate_trusted_program},
        },
        clamav_scanner::{
            scan_exclusion_rules::broad_exclusions, scanner_output_parser::sanitize_scanner_line,
        },
        desktop::{
            flatpak_sandbox::readable_host_path,
            stored_settings::{application_settings, read_exclusion_entries},
        },
        protection_evidence::{
            clamav_engine_evidence::{
                DatabaseEvidence, inspect_database_evidence_with_banner,
                inspect_database_evidence_without_banner, newest_disk_signature_version,
            },
            kernel_on_access_support::{
                InotifyWatchLimit, KernelBlockingSupport, KernelConfigReadFailure,
                WatchLimitReadFailure, inspect_inotify_watch_limit,
                inspect_kernel_blocking_support,
            },
            process_attach_scope::{ProcessAttachScope, inspect_process_attach_scope},
            service_run_journal::{
                ScanRunHistory, UpdaterRunHistory, newest_scan_run, newest_update_run,
            },
        },
        systemd_bus::host_systemd_units::{
            ServiceFailureKind, ServiceLastResult, ServiceUnitSnapshot, TimerUnitSnapshot,
            UnitActivity, UnitState, UnitTimestamp, probe_unit_state, probe_user_unit_state,
            service_unit_snapshot, timer_unit_snapshot,
        },
        threat_intel::service_key_status::{LookupKeyStatuses, read_lookup_key_statuses},
    },
    scans::scheduled_scans_page::{
        scan_schedule_settings::StoredScheduleSettings,
        scan_schedule_units::changed_units_of_current_schedule,
    },
    signatures::database_updates_page::signature_update_run::updater_exit_status::{
        SignatureUpdaterProgram, UpdaterExitMeaning, classify_updater_exit_status,
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
pub const ON_ACCESS_SERVICE_UNITS: [&str; 2] = ["clamav-clamonacc.service", "clamonacc.service"];
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
    ScannerRefused { refused_path: String },
    VersionUnverified(ProbeFailure),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureLineCount {
    LinesCounted { signature_count: u64 },
    FileUnreadable { failure_kind: io::ErrorKind },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThirdPartySignatureFile {
    pub file_name: String,
    pub modified_at: Timestamp,
    pub file_size: ByteSize,
    pub signature_lines: SignatureLineCount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ThirdPartySignatureListing {
    FilesListed(Vec<ThirdPartySignatureFile>),
    FolderUnreadable(DatabaseFolderReadFailure),
}

impl ThirdPartySignatureListing {
    pub fn listed_files(&self) -> &[ThirdPartySignatureFile] {
        match self {
            Self::FilesListed(signature_files) => signature_files,
            Self::FolderUnreadable(_) => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureEvidence {
    pub database_evidence: DatabaseEvidence,
    pub updater_evidence: Vec<UpdaterEvidence>,
    pub third_party_listing: ThirdPartySignatureListing,
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

pub const fn daemon_is_answering(daemon_evidence: &DaemonEvidence) -> bool {
    matches!(daemon_evidence, DaemonEvidence::ClamdAnswering { .. })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnAccessScanner {
    MonitorRunning,
    UnitStopped { service_unit: &'static str },
    UnitStateUnknown,
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
pub enum ConfiguredPrevention {
    PreventionRequested,
    PreventionOff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnAccessConflict {
    PreventionWithMountPath,
    IncludePathWithMountPath,
    ExcludePathWithMountPath,
    ExtraScanningWithMountPath,
}

impl OnAccessConflict {
    const ALL_CONFLICTS: [Self; 4] = [
        Self::PreventionWithMountPath,
        Self::IncludePathWithMountPath,
        Self::ExcludePathWithMountPath,
        Self::ExtraScanningWithMountPath,
    ];

    pub const fn conflicting_option(self) -> &'static str {
        match self {
            Self::PreventionWithMountPath => "OnAccessPrevention",
            Self::IncludePathWithMountPath => "OnAccessIncludePath",
            Self::ExcludePathWithMountPath => "OnAccessExcludePath",
            Self::ExtraScanningWithMountPath => "OnAccessExtraScanning",
        }
    }

    fn is_configured_in(self, config_settings: &[ConfigSetting]) -> bool {
        let mut option_values = config_values(config_settings, self.conflicting_option());
        match self {
            Self::PreventionWithMountPath | Self::ExtraScanningWithMountPath => {
                option_values.any(setting_is_enabled)
            }
            Self::IncludePathWithMountPath | Self::ExcludePathWithMountPath => {
                option_values.next().is_some()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClamdUserExclusion {
    ClamdUserExcluded,
    ClamdUserNotExcluded,
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
        configured_prevention: ConfiguredPrevention,
        setting_conflicts: Vec<OnAccessConflict>,
        clamd_user_exclusion: ClamdUserExclusion,
        size_limit: OnAccessSizeLimit,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnAccessEvidence {
    pub on_access_scanner: OnAccessScanner,
    pub on_access_config: OnAccessConfig,
    pub kernel_blocking_support: KernelBlockingSupport,
    pub inotify_watch_limit: InotifyWatchLimit,
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
pub enum ProgramTrustInspection {
    ProgramsChecked(Vec<ProgramTrustFinding>),
    CheckInterrupted,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OverridesReadFailure {
    #[error(transparent)]
    StoredOverridesUnusable(#[from] StoredOverridesFailure),
    #[error("the task reading the runtime overrides stopped before it finished")]
    ReadingTaskInterrupted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeReductions {
    NothingReduced,
    OverridesUnreadable(OverridesReadFailure),
    SettingsReduced {
        change_time: OverridesChangeTime,
        reduced_settings: Vec<ReducedSetting>,
    },
    BaseConfigUnreadable {
        change_time: OverridesChangeTime,
        overridden_settings: Vec<OverriddenSetting>,
    },
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

fn config_lines_in(config_text: &str) -> ClamdConfigLines {
    match config_text.parse() {
        Ok(config_lines) => config_lines,
        Err(never_fails) => match never_fails {},
    }
}

pub fn runtime_reductions_against(
    live_overrides: &LiveOverrides,
    base_text: io::Result<String>,
    change_time: OverridesChangeTime,
    now: Timestamp,
) -> RuntimeReductions {
    let base_lines = base_text.ok().map(|base_text| config_lines_in(&base_text));
    let base_settings = base_lines
        .as_ref()
        .and_then(|base_lines| tunable_settings_in(base_lines).ok());
    let weakening_reports = |base_view| {
        live_overrides
            .override_reports(base_view, now)
            .into_iter()
            .filter(|override_report| override_report.protection_reduction.weakens_protection())
            .collect::<Vec<_>>()
    };
    match (base_lines.as_ref(), base_settings.as_ref()) {
        (Some(base_lines), Some(base_settings)) => {
            let reduced_settings = weakening_reports(BaseSettings::ReadableBase(base_settings))
                .into_iter()
                .map(|override_report| ReducedSetting {
                    setting_key: sanitize_scanner_line(override_report.setting_name),
                    base_value: sanitize_scanner_line(
                        &base_lines
                            .values_of(override_report.setting_name)
                            .join(", "),
                    ),
                    changed_value: sanitize_scanner_line(
                        &override_report.changed_values.join(", "),
                    ),
                })
                .collect::<Vec<_>>();
            if reduced_settings.is_empty() {
                RuntimeReductions::NothingReduced
            } else {
                RuntimeReductions::SettingsReduced {
                    change_time,
                    reduced_settings,
                }
            }
        }
        (_unreadable_lines, _untyped_settings) => {
            let overridden_settings = weakening_reports(BaseSettings::UnreadableBase)
                .into_iter()
                .map(|override_report| OverriddenSetting {
                    setting_key: sanitize_scanner_line(override_report.setting_name),
                    changed_value: sanitize_scanner_line(
                        &override_report.changed_values.join(", "),
                    ),
                })
                .collect::<Vec<_>>();
            if overridden_settings.is_empty() {
                RuntimeReductions::NothingReduced
            } else {
                RuntimeReductions::BaseConfigUnreadable {
                    change_time,
                    overridden_settings,
                }
            }
        }
    }
}

pub fn runtime_reductions_in_files(
    overrides_path: &Path,
    base_config_path: &Path,
) -> RuntimeReductions {
    match read_stored_overrides(overrides_path) {
        Ok(live_overrides) => runtime_reductions_against(
            &live_overrides,
            fs::read_to_string(base_config_path),
            overrides_change_time(overrides_path),
            Timestamp::now(),
        ),
        Err(stored_failure) => RuntimeReductions::OverridesUnreadable(stored_failure.into()),
    }
}

fn inspect_runtime_reductions() -> RuntimeReductions {
    runtime_reductions_in_files(
        &readable_host_path(LIVE_OVERRIDES_PATH),
        &readable_host_path(BASE_CLAMD_CONFIG_PATH),
    )
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
    pub program_trust: ProgramTrustInspection,
    pub trust_list: TrustListReading,
    pub runtime_reductions: RuntimeReductions,
    pub account_setting_findings: Vec<AccountSettingFinding>,
    pub engine_installation: EngineInstallation,
    pub signature_evidence: SignatureEvidence,
    pub daemon_evidence: DaemonEvidence,
    pub on_access_evidence: OnAccessEvidence,
    pub scheduled_scan_evidence: ScheduledScanEvidence,
    pub background_service_state: UnitState,
    pub process_attach_scope: ProcessAttachScope,
    pub lookup_key_statuses: LookupKeyStatuses,
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
    let watched_locations = watched_mounts.chain(watched_folders).collect::<Vec<_>>();
    let mount_watched = watched_locations
        .iter()
        .any(|watched_location| matches!(watched_location, WatchedLocation::WatchedMount { .. }));
    OnAccessConfig::ConfigRead {
        watch_scope: WatchScope::from_locations(watched_locations),
        configured_prevention: if config_values(config_settings, "OnAccessPrevention")
            .any(setting_is_enabled)
        {
            ConfiguredPrevention::PreventionRequested
        } else {
            ConfiguredPrevention::PreventionOff
        },
        setting_conflicts: if mount_watched {
            OnAccessConflict::ALL_CONFLICTS
                .into_iter()
                .filter(|setting_conflict| setting_conflict.is_configured_in(config_settings))
                .collect()
        } else {
            Vec::new()
        },
        clamd_user_exclusion: if config_values(config_settings, "OnAccessExcludeUname")
            .chain(config_values(config_settings, "OnAccessExcludeUID"))
            .any(|excluded_user| !excluded_user.trim().is_empty())
        {
            ClamdUserExclusion::ClamdUserExcluded
        } else {
            ClamdUserExclusion::ClamdUserNotExcluded
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
        ProgramProbe::ProgramRefused { candidate_path } => EngineInstallation::ScannerRefused {
            refused_path: sanitized_path_text(&candidate_path),
        },
        ProgramProbe::ProbeFailed(probe_failure) => {
            EngineInstallation::VersionUnverified(probe_failure)
        }
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

fn count_signature_lines(signature_file: &Path) -> SignatureLineCount {
    match fs::read(signature_file) {
        Ok(file_bytes) => SignatureLineCount::LinesCounted {
            signature_count: count_lines_with_content(&file_bytes),
        },
        Err(read_failure) => SignatureLineCount::FileUnreadable {
            failure_kind: read_failure.kind(),
        },
    }
}

pub fn third_party_signature_files(database_directory: &Path) -> ThirdPartySignatureListing {
    let directory_entries = match fs::read_dir(database_directory) {
        Ok(directory_entries) => directory_entries,
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => {
            return ThirdPartySignatureListing::FilesListed(Vec::new());
        }
        Err(read_failure) => {
            return ThirdPartySignatureListing::FolderUnreadable(read_failure.into());
        }
    };
    let mut signature_files = directory_entries
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
                file_name: sanitize_scanner_line(&directory_entry.file_name().to_string_lossy()),
                modified_at,
                file_size: ByteSize::b(file_metadata.len()),
                signature_lines: count_signature_lines(&directory_entry.path()),
            })
        })
        .collect::<Vec<_>>();
    signature_files
        .sort_by(|first_file, second_file| first_file.file_name.cmp(&second_file.file_name));
    ThirdPartySignatureListing::FilesListed(signature_files)
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
            EngineInstallation::EngineMissing
            | EngineInstallation::ScannerRefused { .. }
            | EngineInstallation::VersionUnverified(_) => {
                inspect_database_evidence_without_banner().await
            }
        },
        updater_evidence,
        third_party_listing: spawn_blocking(|| {
            third_party_signature_files(&configured_database_directory())
        })
        .await
        .unwrap_or_else(|interrupted_listing| {
            ThirdPartySignatureListing::FolderUnreadable(interrupted_listing.into())
        }),
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
        .find(|(_unit_name, unit_state)| **unit_state == wanted_state)
        .map(|(unit_name, _unit_state)| *unit_name)
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

pub fn on_access_scanner_from_states(unit_states: &[UnitState]) -> OnAccessScanner {
    let unit_in_state = |wanted_state: UnitState| {
        ON_ACCESS_SERVICE_UNITS
            .iter()
            .zip(unit_states)
            .find(|(_unit_name, unit_state)| **unit_state == wanted_state)
            .map(|(unit_name, _unit_state)| *unit_name)
    };
    if unit_in_state(UnitState::UnitLoaded(UnitActivity::UnitActive)).is_some() {
        return OnAccessScanner::MonitorRunning;
    }
    if let Some(service_unit) = unit_in_state(UnitState::UnitLoaded(UnitActivity::UnitInactive)) {
        return OnAccessScanner::UnitStopped { service_unit };
    }
    if unit_states.contains(&UnitState::SystemdUnavailable) {
        OnAccessScanner::UnitStateUnknown
    } else {
        OnAccessScanner::NeverSetUp
    }
}

async fn inspect_on_access_scanner() -> OnAccessScanner {
    on_access_scanner_from_states(&join_all(ON_ACCESS_SERVICE_UNITS.map(probe_unit_state)).await)
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
        kernel_blocking_support: spawn_blocking(inspect_kernel_blocking_support)
            .await
            .unwrap_or(KernelBlockingSupport::KernelConfigUnreadable(
                KernelConfigReadFailure::ReadingTaskAborted,
            )),
        inotify_watch_limit: spawn_blocking(inspect_inotify_watch_limit).await.unwrap_or(
            InotifyWatchLimit::LimitUnreadable(WatchLimitReadFailure::ReadingTaskAborted),
        ),
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
        program_trust: spawn_blocking(inspect_program_trust).await.map_or(
            ProgramTrustInspection::CheckInterrupted,
            ProgramTrustInspection::ProgramsChecked,
        ),
        trust_list: read_configured_trust_list().await,
        runtime_reductions: spawn_blocking(inspect_runtime_reductions).await.unwrap_or(
            RuntimeReductions::OverridesUnreadable(OverridesReadFailure::ReadingTaskInterrupted),
        ),
        account_setting_findings: inspect_account_settings(lazaret_schedule_enabled),
        engine_installation,
        signature_evidence,
        daemon_evidence: inspect_daemon_evidence().await,
        on_access_evidence: inspect_on_access_evidence().await,
        scheduled_scan_evidence: inspect_scheduled_scan(lazaret_schedule_enabled).await,
        background_service_state: probe_user_unit_state(BACKGROUND_SERVICE_UNIT).await,
        process_attach_scope: inspect_process_attach_scope().await,
        lookup_key_statuses: read_lookup_key_statuses().await,
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

    fn stored_overrides(overrides_text: &str) -> LiveOverrides {
        LiveOverrides::from_toml_text(overrides_text).expect("stored overrides")
    }

    fn evidence_moment() -> Timestamp {
        Timestamp::from_second(0).expect("timestamp")
    }

    #[test]
    fn only_overrides_that_weaken_the_base_config_are_reduced_settings() {
        let live_overrides = stored_overrides(
            "[OnAccessPrevention]\nstate = \"temporary-reduction\"\nvalue = false\nexpires_at = \
             \"1970-01-02T00:00:00Z\"\n\n[MaxThreads]\nstate = \"permanent\"\nvalue = \
             2\n\n[OnAccessIncludePath]\nstate = \"permanent\"\nvalue = [\"/home\", \"/srv\"]\n",
        );
        assert_eq!(
            runtime_reductions_against(
                &live_overrides,
                Ok("OnAccessPrevention yes\nMaxThreads 12\nOnAccessIncludePath /home\n".to_owned()),
                OverridesChangeTime::ChangeTimeUnknown,
                evidence_moment(),
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
                config_setting("OnAccessPrevention", "true"),
                config_setting("OnAccessExcludeUname", "clamav"),
                config_setting("OnAccessMaxFileSize", "100M"),
            ]),
            OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedFolder {
                        folder_path: "/home/user/Downloads".to_owned()
                    },
                    other_locations: vec![WatchedLocation::WatchedFolder {
                        folder_path: "/srv/inbox".to_owned()
                    }],
                },
                configured_prevention: ConfiguredPrevention::PreventionRequested,
                setting_conflicts: Vec::new(),
                clamd_user_exclusion: ClamdUserExclusion::ClamdUserExcluded,
                size_limit: OnAccessSizeLimit::ConfiguredLimit {
                    size_limit: ByteSize::mib(100)
                },
            }
        );
    }

    #[test]
    fn a_watched_mount_with_prevention_records_the_conflicts_instead_of_blocking() {
        let OnAccessConfig::ConfigRead {
            watch_scope,
            setting_conflicts,
            ..
        } = on_access_config_from_settings(&[
            config_setting("OnAccessIncludePath", "/home/user/Downloads"),
            config_setting("OnAccessMountPath", "/media"),
            config_setting("OnAccessPrevention", "true"),
        ])
        else {
            panic!("a read config was expected");
        };
        assert_eq!(
            watch_scope.watched_locations()[0],
            &WatchedLocation::WatchedMount {
                mount_path: "/media".to_owned()
            }
        );
        assert_eq!(
            setting_conflicts,
            vec![
                OnAccessConflict::PreventionWithMountPath,
                OnAccessConflict::IncludePathWithMountPath,
            ]
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
                configured_prevention: ConfiguredPrevention::PreventionOff,
                setting_conflicts: Vec::new(),
                clamd_user_exclusion: ClamdUserExclusion::ClamdUserNotExcluded,
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
    fn an_unreadable_overrides_file_is_not_called_nothing_reduced() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let base_config = temporary_root.path().join("clamd.conf");
        fs::write(&base_config, "OnAccessPrevention yes\n").expect("base config");
        assert_eq!(
            runtime_reductions_in_files(&temporary_root.path().join("missing.toml"), &base_config),
            RuntimeReductions::NothingReduced
        );
        assert!(matches!(
            runtime_reductions_in_files(temporary_root.path(), &base_config),
            RuntimeReductions::OverridesUnreadable(OverridesReadFailure::StoredOverridesUnusable(
                StoredOverridesFailure::OverridesFileUnreadable { .. }
            ))
        ));
        let planted_overrides = temporary_root.path().join("planted.toml");
        fs::write(
            &planted_overrides,
            "[VirusEvent]\nstate = \"permanent\"\nvalue = \"/bin/sh\"\n",
        )
        .expect("planted");
        assert_eq!(
            runtime_reductions_in_files(&planted_overrides, &base_config),
            RuntimeReductions::OverridesUnreadable(OverridesReadFailure::StoredOverridesUnusable(
                StoredOverridesFailure::OverridesFileInvalid
            ))
        );
    }

    #[test]
    fn an_unreadable_signature_folder_is_not_an_empty_listing() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let not_a_folder = temporary_root.path().join("urlhaus.ndb");
        fs::write(&not_a_folder, "first\nsecond\n").expect("signature file");
        assert!(matches!(
            third_party_signature_files(&not_a_folder),
            ThirdPartySignatureListing::FolderUnreadable(
                DatabaseFolderReadFailure::FolderUnreadable { .. }
            )
        ));
        assert_eq!(
            third_party_signature_files(&temporary_root.path().join("missing")),
            ThirdPartySignatureListing::FilesListed(Vec::new())
        );
        let ThirdPartySignatureListing::FilesListed(listed_files) =
            third_party_signature_files(temporary_root.path())
        else {
            panic!("the folder is readable");
        };
        assert_eq!(
            listed_files
                .iter()
                .map(|listed_file| listed_file.signature_lines)
                .collect::<Vec<_>>(),
            vec![SignatureLineCount::LinesCounted { signature_count: 2 }]
        );
    }

    #[test]
    fn an_on_access_unit_systemd_could_not_report_is_not_never_set_up() {
        assert_eq!(
            on_access_scanner_from_states(&[
                UnitState::SystemdUnavailable,
                UnitState::UnitNotFound
            ]),
            OnAccessScanner::UnitStateUnknown
        );
        assert_eq!(
            on_access_scanner_from_states(&[UnitState::UnitNotFound; 2]),
            OnAccessScanner::NeverSetUp
        );
        assert_eq!(
            on_access_scanner_from_states(&[
                UnitState::SystemdUnavailable,
                UnitState::UnitLoaded(UnitActivity::UnitInactive)
            ]),
            OnAccessScanner::UnitStopped {
                service_unit: "clamonacc.service"
            }
        );
        assert_eq!(
            on_access_scanner_from_states(&[
                UnitState::UnitLoaded(UnitActivity::UnitInactive),
                UnitState::UnitLoaded(UnitActivity::UnitActive)
            ]),
            OnAccessScanner::MonitorRunning
        );
    }

    #[test]
    fn overrides_against_an_unreadable_base_are_not_called_harmless() {
        let live_overrides = stored_overrides(
            "[OnAccessPrevention]\nstate = \"permanent\"\nvalue = false\n\n[DetectPUA]\nstate = \
             \"permanent\"\nvalue = true\n\n[MaxThreads]\nstate = \"permanent\"\nvalue = 2\n",
        );
        let unreadable_base = || Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert_eq!(
            runtime_reductions_against(
                &live_overrides,
                unreadable_base(),
                OverridesChangeTime::ChangeTimeUnknown,
                evidence_moment(),
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
            runtime_reductions_against(
                &LiveOverrides::default(),
                unreadable_base(),
                OverridesChangeTime::ChangeTimeUnknown,
                evidence_moment(),
            ),
            RuntimeReductions::NothingReduced
        );
    }
}
