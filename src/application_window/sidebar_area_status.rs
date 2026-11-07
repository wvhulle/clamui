use std::collections::BTreeSet;

use gettextrs::{gettext, ngettext};
use jiff::Timestamp;

use crate::{
    findings::{
        detections_page::alert_delivery_presentation::{
            AlertReadiness, alerts_condition, process_attach_condition,
        },
        quarantine_page::quarantine_page_state::QuarantineEntryCount,
    },
    host_services::{
        clamav_programs::signature_provider_catalogue::{
            provider_of_signature_file, signature_file_source_name,
        },
        desktop::locale_formatting::MomentFormatters,
        detection_journal::detection_journal_follower::JournalAccess,
        protection_evidence::{
            clamav_engine_evidence::DatabaseEvidence,
            host_protection_evidence::{
                AccountSettingFinding, DaemonEvidence, EngineInstallation, LoadedSignatures,
                OnAccessConfig, OnAccessEvidence, OnAccessScanner, ProtectionEvidence,
                ScanServiceEvidence, ScheduledScanEvidence, SignatureEvidence,
                ThirdPartySignatureListing, TimerState, WatchScope, WatchedLocation,
                daemon_is_answering,
            },
            on_access_setup_review::{
                OnAccessBlocking, OnAccessSetupFinding, on_access_blocking,
                on_access_setup_findings,
            },
            process_attach_scope::ProcessAttachScope,
            service_run_journal::UpdaterRunHistory,
        },
        systemd_bus::host_systemd_units::UnitTimestamp,
    },
    protection_page::{
        protection_timeline_page::shown_coverage_text,
        protection_timeline_presentation::trust_list_condition,
    },
    scans::{
        on_access_page::on_access_presentation::on_access_condition,
        removable_drives_page::{
            removable_drives_presentation::auto_scan_state_text,
            removable_drives_state::{DeviceScanStatus, RemovableDrivesStatus},
        },
        scan_engine_page::scan_engine_presentation::{daemon_condition, engine_condition},
        scheduled_scans_page::scheduled_scans_presentation::scheduled_scan_condition,
    },
    shared_widgets::{
        scan_runs::scan_results_section::scan_results_state::ScanResultsStatus,
        step_timeline::{
            program_trust_steps::{TrustedProgramGroup, program_trust_condition},
            runtime_reduction_steps::{ReducedSettingGroup, runtime_reduction_condition},
            step_evidence_builders::CheckedCondition,
        },
    },
    sharing::analysis_page::trusted_detections_page::trust_list_contents::{
        LazaretListReading, TrustListReading,
    },
    signatures::database_updates_page::database_updates_presentation::{
        database_update_condition, third_party_source_condition, updater_failed,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidebarArea {
    SignatureSources,
    DatabaseUpdates,
    ScanEngine,
    OnAccessScanning,
    ScheduledScans,
    ManualScan,
    RemovableDrives,
    Detections,
    Quarantine,
    AnalysisAndFalsePositives,
    Submissions,
}

pub const ALL_SIDEBAR_AREAS: [SidebarArea; 11] = [
    SidebarArea::SignatureSources,
    SidebarArea::DatabaseUpdates,
    SidebarArea::ScanEngine,
    SidebarArea::OnAccessScanning,
    SidebarArea::ScheduledScans,
    SidebarArea::ManualScan,
    SidebarArea::RemovableDrives,
    SidebarArea::Detections,
    SidebarArea::Quarantine,
    SidebarArea::AnalysisAndFalsePositives,
    SidebarArea::Submissions,
];

impl SidebarArea {
    pub fn area_title(self) -> String {
        match self {
            Self::SignatureSources => gettext("Signature Sources"),
            Self::DatabaseUpdates => gettext("Database Updates"),
            Self::ScanEngine => gettext("Scan Engine"),
            Self::OnAccessScanning => gettext("On-Access Scanning"),
            Self::ScheduledScans => gettext("Scheduled Scans"),
            Self::ManualScan => gettext("Manual Scan"),
            Self::RemovableDrives => gettext("Removable Drives"),
            Self::Detections => gettext("Detections"),
            Self::Quarantine => gettext("Quarantine"),
            Self::AnalysisAndFalsePositives => gettext("Analysis & False Positives"),
            Self::Submissions => gettext("Submissions"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AreaStatus {
    AreaHealthy,
    AreaNeedsReview,
    AreaFailing,
    AreaUnknown,
    AreaWaiting,
}

impl AreaStatus {
    const fn severity_rank(self) -> u8 {
        match self {
            Self::AreaHealthy => 0,
            Self::AreaWaiting => 1,
            Self::AreaUnknown => 2,
            Self::AreaNeedsReview => 3,
            Self::AreaFailing => 4,
        }
    }

    const fn needs_attention(self) -> bool {
        match self {
            Self::AreaHealthy | Self::AreaWaiting => false,
            Self::AreaNeedsReview | Self::AreaFailing | Self::AreaUnknown => true,
        }
    }

    pub const fn status_indicator(self) -> StatusIndicator {
        match self {
            Self::AreaHealthy => StatusIndicator::IndicatorHidden,
            Self::AreaNeedsReview | Self::AreaUnknown | Self::AreaWaiting => {
                StatusIndicator::WarningIndicator
            }
            Self::AreaFailing => StatusIndicator::ErrorIndicator,
        }
    }
}

impl From<CheckedCondition> for AreaStatus {
    fn from(checked_condition: CheckedCondition) -> Self {
        match checked_condition {
            CheckedCondition::ConditionMet => Self::AreaHealthy,
            CheckedCondition::SetupSuggested | CheckedCondition::ReviewSuggested => {
                Self::AreaNeedsReview
            }
            CheckedCondition::EvidenceUnknown => Self::AreaUnknown,
            CheckedCondition::ConditionFailed => Self::AreaFailing,
            CheckedCondition::PrerequisiteMissing => Self::AreaWaiting,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusIndicator {
    IndicatorHidden,
    WarningIndicator,
    ErrorIndicator,
}

impl StatusIndicator {
    pub const fn is_shown(self) -> bool {
        match self {
            Self::IndicatorHidden => false,
            Self::WarningIndicator | Self::ErrorIndicator => true,
        }
    }

    pub const fn icon_name(self) -> &'static str {
        match self {
            Self::IndicatorHidden | Self::WarningIndicator => "dialog-warning-symbolic",
            Self::ErrorIndicator => "dialog-error-symbolic",
        }
    }

    pub const fn css_classes(self) -> &'static [&'static str] {
        match self {
            Self::IndicatorHidden => &[],
            Self::WarningIndicator => &["warning"],
            Self::ErrorIndicator => &["error"],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AreaSummary {
    pub area_status: AreaStatus,
    pub live_state_text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidebarAreaSummary {
    pub sidebar_area: SidebarArea,
    pub area_summary: AreaSummary,
}

#[derive(Clone)]
pub struct AreaSummaryContext {
    pub alert_readiness: AlertReadiness,
    pub unresolved_detections: usize,
    pub quarantine_entry_count: QuarantineEntryCount,
    pub removable_drives_status: RemovableDrivesStatus,
    pub home_directory: String,
    pub moment_formatters: &'static MomentFormatters,
    pub reference_moment: Timestamp,
}

const fn summary_of(area_status: AreaStatus, live_state_text: String) -> AreaSummary {
    AreaSummary {
        area_status,
        live_state_text,
    }
}

fn condition_summary(checked_condition: CheckedCondition, live_state_text: String) -> AreaSummary {
    summary_of(AreaStatus::from(checked_condition), live_state_text)
}

fn worst_summary(
    primary_summary: AreaSummary,
    other_summaries: impl IntoIterator<Item = Option<AreaSummary>>,
) -> AreaSummary {
    other_summaries.into_iter().flatten().fold(
        primary_summary,
        |kept_summary, candidate_summary| {
            if candidate_summary.area_status.severity_rank()
                > kept_summary.area_status.severity_rank()
            {
                candidate_summary
            } else {
                kept_summary
            }
        },
    )
}

fn relative_text(area_context: &AreaSummaryContext, moment: Timestamp) -> String {
    area_context
        .moment_formatters
        .relative_moment_text(moment, area_context.reference_moment)
}

fn count_as_u32(item_count: usize) -> u32 {
    u32::try_from(item_count).unwrap_or(u32::MAX)
}

fn third_party_provider_count(third_party_listing: &ThirdPartySignatureListing) -> usize {
    third_party_listing
        .listed_files()
        .iter()
        .map(|signature_file| {
            signature_file_source_name(provider_of_signature_file(&signature_file.file_name))
        })
        .collect::<BTreeSet<_>>()
        .len()
}

fn signature_sources_summary(
    signature_evidence: &SignatureEvidence,
    area_context: &AreaSummaryContext,
) -> AreaSummary {
    let source_condition = third_party_source_condition(
        &signature_evidence.third_party_listing,
        area_context.reference_moment,
    );
    let provider_count = third_party_provider_count(&signature_evidence.third_party_listing);
    let live_state_text = match &signature_evidence.third_party_listing {
        ThirdPartySignatureListing::FolderUnreadable(_) => gettext("Other sources unknown"),
        ThirdPartySignatureListing::FilesListed(_)
            if source_condition != CheckedCondition::ConditionMet =>
        {
            gettext("A source is out of date")
        }
        ThirdPartySignatureListing::FilesListed(_) if provider_count == 0 => {
            gettext("Official signatures only")
        }
        ThirdPartySignatureListing::FilesListed(_) => ngettext(
            "Official and {count} other source",
            "Official and {count} other sources",
            count_as_u32(provider_count),
        )
        .replace("{count}", &provider_count.to_string()),
    };
    condition_summary(source_condition, live_state_text)
}

fn latest_completed_update(signature_evidence: &SignatureEvidence) -> Option<Timestamp> {
    signature_evidence
        .updater_evidence
        .iter()
        .filter_map(
            |updater_evidence| match updater_evidence.last_completed_run {
                UpdaterRunHistory::CompletedUpdate { finished_at } => Some(finished_at),
                UpdaterRunHistory::NoCompletedUpdate | UpdaterRunHistory::JournalUnreadable(_) => {
                    None
                }
            },
        )
        .max()
}

fn database_updates_text(
    signature_evidence: &SignatureEvidence,
    area_context: &AreaSummaryContext,
) -> String {
    match signature_evidence.database_evidence {
        DatabaseEvidence::DatabaseMissing => gettext("No virus definitions"),
        DatabaseEvidence::AgeUndetermined | DatabaseEvidence::InspectionInterrupted => {
            gettext("Age of the definitions unknown")
        }
        DatabaseEvidence::BuiltAt { .. }
            if signature_evidence
                .updater_evidence
                .iter()
                .any(updater_failed) =>
        {
            gettext("Last update failed")
        }
        DatabaseEvidence::BuiltAt { built_at } if built_at > area_context.reference_moment => {
            gettext("Definitions dated in the future")
        }
        DatabaseEvidence::BuiltAt { built_at } => {
            match latest_completed_update(signature_evidence) {
                Some(finished_at) => gettext("Updated {when}")
                    .replace("{when}", &relative_text(area_context, finished_at)),
                None => gettext("Definitions from {when}")
                    .replace("{when}", &relative_text(area_context, built_at)),
            }
        }
    }
}

fn updater_trust_summary(protection_evidence: &ProtectionEvidence) -> Option<AreaSummary> {
    let trust_condition = program_trust_condition(
        &protection_evidence.program_trust,
        TrustedProgramGroup::UpdaterPrograms,
    );
    match trust_condition {
        CheckedCondition::ConditionMet => None,
        CheckedCondition::ConditionFailed => Some(gettext("freshclam is refused")),
        CheckedCondition::EvidenceUnknown => Some(gettext("Unknown whether freshclam is trusted")),
        CheckedCondition::SetupSuggested
        | CheckedCondition::ReviewSuggested
        | CheckedCondition::PrerequisiteMissing => {
            Some(gettext("A freshclam copy in your account is ignored"))
        }
    }
    .map(|live_state_text| condition_summary(trust_condition, live_state_text))
}

fn database_updates_summary(
    protection_evidence: &ProtectionEvidence,
    area_context: &AreaSummaryContext,
) -> AreaSummary {
    let signature_evidence = &protection_evidence.signature_evidence;
    worst_summary(
        condition_summary(
            database_update_condition(signature_evidence, area_context.reference_moment),
            database_updates_text(signature_evidence, area_context),
        ),
        [updater_trust_summary(protection_evidence)],
    )
}

fn daemon_text(daemon_evidence: &DaemonEvidence) -> String {
    match daemon_evidence {
        DaemonEvidence::ClamdAnswering {
            loaded_signatures: LoadedSignatures::BehindDisk { .. },
        } => gettext("clamd uses older signatures"),
        DaemonEvidence::ClamdAnswering {
            loaded_signatures:
                LoadedSignatures::MatchesDisk | LoadedSignatures::ComparisonUnavailable,
        } => gettext("clamd answering"),
        DaemonEvidence::UnitActiveNotAnswering { .. } => gettext("clamd not answering"),
        DaemonEvidence::UnitStateUnknown => gettext("clamd state unknown"),
        DaemonEvidence::UnitStopped { .. } => gettext("clamd not running"),
        DaemonEvidence::NeverSetUp => gettext("clamd not set up"),
    }
}

fn engine_installation_summary(engine_installation: &EngineInstallation) -> Option<AreaSummary> {
    match engine_installation {
        EngineInstallation::VersionReported { .. } => None,
        EngineInstallation::EngineMissing => Some(summary_of(
            AreaStatus::AreaFailing,
            gettext("ClamAV not installed"),
        )),
        EngineInstallation::ScannerRefused { .. } => Some(condition_summary(
            engine_condition(engine_installation),
            gettext("clamscan is refused"),
        )),
        EngineInstallation::VersionUnverified(_) => Some(condition_summary(
            engine_condition(engine_installation),
            gettext("ClamAV version unknown"),
        )),
    }
}

fn scanner_trust_summary(protection_evidence: &ProtectionEvidence) -> Option<AreaSummary> {
    let trust_condition = program_trust_condition(
        &protection_evidence.program_trust,
        TrustedProgramGroup::ScannerPrograms,
    );
    match trust_condition {
        CheckedCondition::ConditionMet => None,
        CheckedCondition::ConditionFailed => Some(gettext("A scanner program is refused")),
        CheckedCondition::EvidenceUnknown => {
            Some(gettext("Unknown whether the scanners are trusted"))
        }
        CheckedCondition::SetupSuggested
        | CheckedCondition::ReviewSuggested
        | CheckedCondition::PrerequisiteMissing => {
            Some(gettext("A scanner copy in your account is ignored"))
        }
    }
    .map(|live_state_text| condition_summary(trust_condition, live_state_text))
}

fn reduction_summary(
    protection_evidence: &ProtectionEvidence,
    setting_group: ReducedSettingGroup,
) -> Option<AreaSummary> {
    let reduction_condition =
        runtime_reduction_condition(&protection_evidence.runtime_reductions, setting_group);
    match reduction_condition {
        CheckedCondition::ConditionMet => None,
        CheckedCondition::EvidenceUnknown => Some(gettext("Runtime changes unknown")),
        CheckedCondition::SetupSuggested
        | CheckedCondition::ReviewSuggested
        | CheckedCondition::ConditionFailed
        | CheckedCondition::PrerequisiteMissing => Some(gettext("Settings reduced at runtime")),
    }
    .map(|live_state_text| condition_summary(reduction_condition, live_state_text))
}

fn scan_engine_summary(protection_evidence: &ProtectionEvidence) -> AreaSummary {
    let daemon_evidence = &protection_evidence.daemon_evidence;
    worst_summary(
        condition_summary(
            daemon_condition(daemon_evidence),
            daemon_text(daemon_evidence),
        ),
        [
            engine_installation_summary(&protection_evidence.engine_installation),
            scanner_trust_summary(protection_evidence),
            reduction_summary(protection_evidence, ReducedSettingGroup::EngineSettings),
        ],
    )
}

fn waiting_for_daemon_text() -> String {
    gettext("Waiting for clamd")
}

fn watched_paths_text(watch_scope: &WatchScope, home_directory: &str) -> String {
    shown_coverage_text(
        &watch_scope
            .watched_locations()
            .into_iter()
            .map(WatchedLocation::location_path)
            .collect::<Vec<_>>()
            .join(", "),
        home_directory,
    )
}

fn on_access_text(
    on_access_evidence: &OnAccessEvidence,
    daemon_answering: bool,
    home_directory: &str,
) -> String {
    match on_access_evidence.on_access_scanner {
        OnAccessScanner::UnitStateUnknown => gettext("State unknown"),
        OnAccessScanner::NeverSetUp => gettext("Not set up"),
        OnAccessScanner::UnitStopped { .. } | OnAccessScanner::MonitorRunning
            if !daemon_answering =>
        {
            waiting_for_daemon_text()
        }
        OnAccessScanner::UnitStopped { .. } => gettext("clamonacc not running"),
        OnAccessScanner::MonitorRunning => match &on_access_evidence.on_access_config {
            OnAccessConfig::ConfigUnreadable(_) => gettext("clamd.conf unreadable"),
            OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::NothingWatched,
                ..
            } => gettext("Nothing watched"),
            OnAccessConfig::ConfigRead {
                watch_scope: watch_scope @ WatchScope::WatchedLocations { .. },
                configured_prevention,
                setting_conflicts,
                ..
            } => match on_access_blocking(
                *configured_prevention,
                setting_conflicts,
                on_access_evidence.kernel_blocking_support,
            ) {
                OnAccessBlocking::PreventionOff
                | OnAccessBlocking::PreventionConflictsWithMounts => {
                    gettext("Checks files, doesn't block")
                }
                OnAccessBlocking::KernelCannotBlock => gettext("Checks files, kernel can't block"),
                OnAccessBlocking::KernelSupportUnknown(_) => {
                    gettext("Checks files, blocking unknown")
                }
                OnAccessBlocking::BlocksDetectedFiles => gettext("Blocking {paths}")
                    .replace("{paths}", &watched_paths_text(watch_scope, home_directory)),
            },
        },
    }
}

fn on_access_setup_summary(on_access_evidence: &OnAccessEvidence) -> Option<AreaSummary> {
    let setup_findings = on_access_setup_findings(on_access_evidence);
    let first_finding = setup_findings.first()?;
    Some(
        if setup_findings
            .iter()
            .all(OnAccessSetupFinding::evidence_is_missing)
        {
            condition_summary(
                CheckedCondition::EvidenceUnknown,
                gettext("Folder watch limit unknown"),
            )
        } else {
            condition_summary(
                CheckedCondition::ReviewSuggested,
                match first_finding {
                    OnAccessSetupFinding::MountWatchConflicts { .. } => {
                        gettext("Mount watching conflicts")
                    }
                    OnAccessSetupFinding::ClamdUserNotExcluded => gettext("clamd not excluded"),
                    OnAccessSetupFinding::WholeRootIncluded => gettext("Watches / directly"),
                    OnAccessSetupFinding::WatchLimitLow { .. }
                    | OnAccessSetupFinding::WatchLimitUnknown { .. } => {
                        gettext("Folder watch limit low")
                    }
                },
            )
        },
    )
}

fn on_access_summary(
    protection_evidence: &ProtectionEvidence,
    area_context: &AreaSummaryContext,
) -> AreaSummary {
    let daemon_answering = daemon_is_answering(&protection_evidence.daemon_evidence);
    let on_access_evidence = &protection_evidence.on_access_evidence;
    worst_summary(
        condition_summary(
            on_access_condition(on_access_evidence, daemon_answering),
            on_access_text(
                on_access_evidence,
                daemon_answering,
                &area_context.home_directory,
            ),
        ),
        [
            on_access_setup_summary(on_access_evidence),
            reduction_summary(protection_evidence, ReducedSettingGroup::OnAccessSettings),
        ],
    )
}

fn scheduled_scan_text(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    daemon_answering: bool,
    area_context: &AreaSummaryContext,
) -> String {
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer { .. } if !daemon_answering => waiting_for_daemon_text(),
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerInactive,
            ..
        } => gettext("Timer not active"),
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerActive { next_run },
            scan_service,
            ..
        } => match scan_service {
            ScanServiceEvidence::ServiceConfigured { .. }
                if scheduled_scan_condition(scheduled_scan_evidence, daemon_answering)
                    != CheckedCondition::ConditionMet =>
            {
                gettext("Last scan failed")
            }
            ScanServiceEvidence::ServiceConfigured { .. } => match next_run {
                UnitTimestamp::RecordedAt { recorded_at } => gettext("Next scan {when}")
                    .replace("{when}", &relative_text(area_context, *recorded_at)),
                UnitTimestamp::NeverRecorded => gettext("No next scan planned"),
            },
            ScanServiceEvidence::ServiceMissing => gettext("Scan service missing"),
            ScanServiceEvidence::ServiceUnreadable => gettext("Scan service unknown"),
        },
        ScheduledScanEvidence::LazaretSchedule => gettext("Scheduled by Lazaret"),
        ScheduledScanEvidence::NoSchedule => gettext("No scan scheduled"),
    }
}

fn account_finding_summary(
    account_findings: &[AccountSettingFinding],
    finding_matches: fn(&AccountSettingFinding) -> bool,
    live_state_text: String,
) -> Option<AreaSummary> {
    account_findings
        .iter()
        .any(finding_matches)
        .then(|| summary_of(AreaStatus::AreaNeedsReview, live_state_text))
}

const fn changes_schedule_unit(account_finding: &AccountSettingFinding) -> bool {
    match account_finding {
        AccountSettingFinding::ScheduleUnitChanged { .. } => true,
        AccountSettingFinding::BroadExclusion { .. } => false,
    }
}

const fn excludes_broadly(account_finding: &AccountSettingFinding) -> bool {
    match account_finding {
        AccountSettingFinding::BroadExclusion { .. } => true,
        AccountSettingFinding::ScheduleUnitChanged { .. } => false,
    }
}

fn scheduled_scans_summary(
    protection_evidence: &ProtectionEvidence,
    area_context: &AreaSummaryContext,
) -> AreaSummary {
    let daemon_answering = daemon_is_answering(&protection_evidence.daemon_evidence);
    let scheduled_scan_evidence = &protection_evidence.scheduled_scan_evidence;
    worst_summary(
        condition_summary(
            scheduled_scan_condition(scheduled_scan_evidence, daemon_answering),
            scheduled_scan_text(scheduled_scan_evidence, daemon_answering, area_context),
        ),
        [account_finding_summary(
            &protection_evidence.account_setting_findings,
            changes_schedule_unit,
            gettext("Schedule changed outside Lazaret"),
        )],
    )
}

fn manual_scan_summary(protection_evidence: &ProtectionEvidence) -> AreaSummary {
    let scanner_summary = match protection_evidence.engine_installation {
        EngineInstallation::EngineMissing => {
            summary_of(AreaStatus::AreaFailing, gettext("ClamAV not installed"))
        }
        EngineInstallation::VersionReported { .. }
        | EngineInstallation::ScannerRefused { .. }
        | EngineInstallation::VersionUnverified(_)
            if daemon_is_answering(&protection_evidence.daemon_evidence) =>
        {
            summary_of(AreaStatus::AreaHealthy, gettext("Ready to scan"))
        }
        EngineInstallation::VersionReported { .. }
        | EngineInstallation::ScannerRefused { .. }
        | EngineInstallation::VersionUnverified(_) => {
            summary_of(AreaStatus::AreaHealthy, gettext("Uses the slower clamscan"))
        }
    };
    worst_summary(
        scanner_summary,
        [account_finding_summary(
            &protection_evidence.account_setting_findings,
            excludes_broadly,
            gettext("An exclusion may skip malware"),
        )],
    )
}

fn removable_drives_summary(removable_drives_status: &RemovableDrivesStatus) -> AreaSummary {
    match &removable_drives_status.device_scan_status {
        DeviceScanStatus::DeviceScanRunning { drive_name } => summary_of(
            AreaStatus::AreaHealthy,
            gettext("Scanning {drive}").replace("{drive}", drive_name),
        ),
        DeviceScanStatus::DeviceScanEnded {
            drive_name,
            scan_result: ScanResultsStatus::ThreatsDetected,
        } => summary_of(
            AreaStatus::AreaNeedsReview,
            gettext("Threats found on {drive}").replace("{drive}", drive_name),
        ),
        DeviceScanStatus::NoDeviceScanYet
        | DeviceScanStatus::DeviceScanEnded {
            scan_result:
                ScanResultsStatus::NoThreatsDetected
                | ScanResultsStatus::FinishedWithProblems
                | ScanResultsStatus::ScanCancelled,
            ..
        } => summary_of(
            AreaStatus::AreaHealthy,
            auto_scan_state_text(removable_drives_status.auto_scan_settings),
        ),
    }
}

fn alerts_summary(
    protection_evidence: &ProtectionEvidence,
    alert_readiness: &AlertReadiness,
) -> Option<AreaSummary> {
    let alert_condition = alerts_condition(
        alert_readiness,
        protection_evidence.background_service_state,
    );
    if alert_condition == CheckedCondition::ConditionMet {
        return None;
    }
    let live_state_text = match alert_readiness.journal_access {
        JournalAccess::JournalUnreadable => gettext("Journal unreadable"),
        JournalAccess::FollowingFailed(_) => gettext("Following the journal stopped"),
        JournalAccess::FollowingJournal if !alert_readiness.notifications_enabled => {
            gettext("Notifications off")
        }
        JournalAccess::FollowingJournal => gettext("Alerts stop when Lazaret quits"),
    };
    Some(condition_summary(alert_condition, live_state_text))
}

fn process_attach_summary(process_attach_scope: ProcessAttachScope) -> Option<AreaSummary> {
    let attach_condition = process_attach_condition(process_attach_scope);
    match process_attach_scope {
        ProcessAttachScope::AttachRestricted => None,
        ProcessAttachScope::AnyProgramMayAttach | ProcessAttachScope::YamaNotLoaded => {
            Some(gettext("Other programs can attach to Lazaret"))
        }
        ProcessAttachScope::ScopeUnreadable(_) => {
            Some(gettext("Unknown whether programs can attach"))
        }
    }
    .map(|live_state_text| condition_summary(attach_condition, live_state_text))
}

fn detections_summary(
    protection_evidence: &ProtectionEvidence,
    area_context: &AreaSummaryContext,
) -> AreaSummary {
    let unresolved_detections = area_context.unresolved_detections;
    let decision_summary = if unresolved_detections == 0 {
        summary_of(AreaStatus::AreaHealthy, gettext("Nothing to decide"))
    } else {
        summary_of(
            AreaStatus::AreaNeedsReview,
            ngettext(
                "{count} needs a decision",
                "{count} need a decision",
                count_as_u32(unresolved_detections),
            )
            .replace("{count}", &unresolved_detections.to_string()),
        )
    };
    worst_summary(
        decision_summary,
        [
            alerts_summary(protection_evidence, &area_context.alert_readiness),
            process_attach_summary(protection_evidence.process_attach_scope),
        ],
    )
}

fn quarantine_summary(quarantine_entry_count: QuarantineEntryCount) -> AreaSummary {
    match quarantine_entry_count {
        QuarantineEntryCount::CountLoading => {
            summary_of(AreaStatus::AreaUnknown, gettext("Loading…"))
        }
        QuarantineEntryCount::EntriesCounted { entry_count: 0 } => {
            summary_of(AreaStatus::AreaHealthy, gettext("Empty"))
        }
        QuarantineEntryCount::EntriesCounted { entry_count } => summary_of(
            AreaStatus::AreaHealthy,
            ngettext("{count} item", "{count} items", count_as_u32(entry_count))
                .replace("{count}", &entry_count.to_string()),
        ),
        QuarantineEntryCount::CountUnavailable => summary_of(
            AreaStatus::AreaFailing,
            gettext("The quarantine can't be read"),
        ),
    }
}

fn trusted_entries_text(trusted_entries: usize) -> String {
    if trusted_entries == 0 {
        return gettext("Nothing trusted");
    }
    ngettext(
        "{count} item trusted",
        "{count} items trusted",
        count_as_u32(trusted_entries),
    )
    .replace("{count}", &trusted_entries.to_string())
}

fn analysis_summary(trust_list_reading: &TrustListReading) -> AreaSummary {
    let live_state_text = match trust_list_reading {
        TrustListReading::FolderUnreadable(_) => gettext("Signature folder unreadable"),
        TrustListReading::FolderMissing => trusted_entries_text(0),
        TrustListReading::ListsRead(trust_list) if !trust_list.foreign_allowlists.is_empty() => {
            gettext("Another allowlist silences ClamAV")
        }
        TrustListReading::ListsRead(trust_list) => {
            match (&trust_list.trusted_files, &trust_list.ignored_signatures) {
                (
                    LazaretListReading::ListRead(trusted_files),
                    LazaretListReading::ListRead(ignored_signatures),
                ) => trusted_entries_text(trusted_files.len() + ignored_signatures.len()),
                (LazaretListReading::ListUnreadable(_), _)
                | (LazaretListReading::ListRead(_), LazaretListReading::ListUnreadable(_)) => {
                    gettext("Lazaret's allowlist is unreadable")
                }
            }
        }
    };
    condition_summary(trust_list_condition(trust_list_reading), live_state_text)
}

pub fn area_summary(
    sidebar_area: SidebarArea,
    protection_evidence: &ProtectionEvidence,
    area_context: &AreaSummaryContext,
) -> AreaSummary {
    match sidebar_area {
        SidebarArea::SignatureSources => {
            signature_sources_summary(&protection_evidence.signature_evidence, area_context)
        }
        SidebarArea::DatabaseUpdates => database_updates_summary(protection_evidence, area_context),
        SidebarArea::ScanEngine => scan_engine_summary(protection_evidence),
        SidebarArea::OnAccessScanning => on_access_summary(protection_evidence, area_context),
        SidebarArea::ScheduledScans => scheduled_scans_summary(protection_evidence, area_context),
        SidebarArea::ManualScan => manual_scan_summary(protection_evidence),
        SidebarArea::RemovableDrives => {
            removable_drives_summary(&area_context.removable_drives_status)
        }
        SidebarArea::Detections => detections_summary(protection_evidence, area_context),
        SidebarArea::Quarantine => quarantine_summary(area_context.quarantine_entry_count),
        SidebarArea::AnalysisAndFalsePositives => analysis_summary(&protection_evidence.trust_list),
        SidebarArea::Submissions => {
            summary_of(AreaStatus::AreaHealthy, gettext("Nothing submitted"))
        }
    }
}

pub fn all_area_summaries(
    protection_evidence: &ProtectionEvidence,
    area_context: &AreaSummaryContext,
) -> Vec<SidebarAreaSummary> {
    ALL_SIDEBAR_AREAS
        .into_iter()
        .map(|sidebar_area| SidebarAreaSummary {
            sidebar_area,
            area_summary: area_summary(sidebar_area, protection_evidence, area_context),
        })
        .collect()
}

pub fn first_area_needing_attention(area_summaries: &[SidebarAreaSummary]) -> SidebarArea {
    area_summaries
        .iter()
        .find(|sidebar_summary| sidebar_summary.area_summary.area_status.needs_attention())
        .map_or(SidebarArea::Detections, |sidebar_summary| {
            sidebar_summary.sidebar_area
        })
}

pub fn worst_area_status(area_summaries: &[SidebarAreaSummary]) -> AreaStatus {
    area_summaries
        .iter()
        .map(|sidebar_summary| sidebar_summary.area_summary.area_status)
        .fold(AreaStatus::AreaHealthy, |kept_status, candidate_status| {
            if candidate_status.severity_rank() > kept_status.severity_rank() {
                candidate_status
            } else {
                kept_status
            }
        })
}

pub fn attention_summary_text(area_summaries: &[SidebarAreaSummary]) -> String {
    let attention_area = first_area_needing_attention(area_summaries);
    area_summaries
        .iter()
        .find(|sidebar_summary| sidebar_summary.sidebar_area == attention_area)
        .map_or_else(String::new, |sidebar_summary| {
            gettext("{area}: {state}")
                .replace("{area}", &sidebar_summary.sidebar_area.area_title())
                .replace("{state}", &sidebar_summary.area_summary.live_state_text)
        })
}

#[cfg(test)]
mod sidebar_area_status_tests {
    use super::*;
    use crate::{
        host_services::{
            clamav_programs::database_directory_status::DatabaseFolderReadFailure,
            protection_evidence::{
                host_protection_evidence::{
                    ClamdConfigReadFailure, ClamdUserExclusion, OverridesChangeTime,
                    OverridesReadFailure, ProgramTrustInspection, ReducedSetting,
                    RuntimeReductions, ScanUnitResult, UpdaterEvidence, UpdaterUnitResult,
                },
                kernel_on_access_support::{KernelBlockingSupport, KernelConfigReadFailure},
                protection_evidence_fixtures::{
                    REFERENCE_MOMENT, english_formatters, healthy_evidence,
                },
                service_run_journal::ScanRunHistory,
            },
        },
        scans::removable_drives_page::drive_mount_checks::DeviceAutoScanSettings,
        signatures::database_updates_page::signature_update_run::updater_exit_status::SignatureUpdaterProgram,
    };

    fn idle_context() -> AreaSummaryContext {
        AreaSummaryContext {
            alert_readiness: AlertReadiness {
                journal_access: JournalAccess::FollowingJournal,
                notifications_enabled: true,
            },
            unresolved_detections: 0,
            quarantine_entry_count: QuarantineEntryCount::EntriesCounted { entry_count: 0 },
            removable_drives_status: RemovableDrivesStatus {
                auto_scan_settings: DeviceAutoScanSettings {
                    auto_scan_enabled: true,
                    maximum_gigabytes: 32,
                    skip_on_battery: true,
                },
                device_scan_status: DeviceScanStatus::NoDeviceScanYet,
            },
            home_directory: "/home/user".to_owned(),
            moment_formatters: english_formatters(),
            reference_moment: REFERENCE_MOMENT,
        }
    }

    fn summary_for(
        sidebar_area: SidebarArea,
        protection_evidence: &ProtectionEvidence,
    ) -> AreaSummary {
        area_summary(sidebar_area, protection_evidence, &idle_context())
    }

    fn status_for(
        sidebar_area: SidebarArea,
        protection_evidence: &ProtectionEvidence,
    ) -> AreaStatus {
        summary_for(sidebar_area, protection_evidence).area_status
    }

    fn daemon_stopped_evidence() -> ProtectionEvidence {
        ProtectionEvidence {
            daemon_evidence: DaemonEvidence::UnitStopped {
                service_unit: "clamav-daemon.service",
            },
            ..healthy_evidence()
        }
    }

    #[test]
    fn a_healthy_host_is_healthy_in_every_area_with_its_live_state() {
        let protection_evidence = healthy_evidence();
        let area_summaries = all_area_summaries(&protection_evidence, &idle_context());
        assert!(area_summaries.iter().all(|sidebar_summary| {
            sidebar_summary.area_summary.area_status == AreaStatus::AreaHealthy
        }));
        let live_texts = area_summaries
            .iter()
            .map(|sidebar_summary| sidebar_summary.area_summary.live_state_text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            live_texts,
            vec![
                "Official signatures only",
                "Definitions from 5 hours ago",
                "clamd answering",
                "Blocking ~/Downloads",
                "Next scan in 6 hours",
                "Ready to scan",
                "Scans drives up to 32.0\u{a0}GB",
                "Nothing to decide",
                "Empty",
                "Nothing trusted",
                "Nothing submitted",
            ]
        );
        assert_eq!(
            first_area_needing_attention(&area_summaries),
            SidebarArea::Detections
        );
        assert_eq!(worst_area_status(&area_summaries), AreaStatus::AreaHealthy);
    }

    #[test]
    fn a_stopped_daemon_fails_the_engine_and_leaves_the_clamd_scans_waiting() {
        let protection_evidence = daemon_stopped_evidence();
        assert_eq!(
            summary_for(SidebarArea::ScanEngine, &protection_evidence),
            AreaSummary {
                area_status: AreaStatus::AreaFailing,
                live_state_text: "clamd not running".to_owned(),
            }
        );
        [SidebarArea::OnAccessScanning, SidebarArea::ScheduledScans]
            .into_iter()
            .for_each(|waiting_area| {
                assert_eq!(
                    summary_for(waiting_area, &protection_evidence),
                    AreaSummary {
                        area_status: AreaStatus::AreaWaiting,
                        live_state_text: "Waiting for clamd".to_owned(),
                    }
                );
            });
        assert_eq!(
            summary_for(SidebarArea::ManualScan, &protection_evidence).live_state_text,
            "Uses the slower clamscan"
        );
        let area_summaries = all_area_summaries(&protection_evidence, &idle_context());
        assert_eq!(
            first_area_needing_attention(&area_summaries),
            SidebarArea::ScanEngine
        );
        assert_eq!(worst_area_status(&area_summaries), AreaStatus::AreaFailing);
    }

    #[test]
    fn an_unreadable_clamd_config_leaves_on_access_unknown() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: OnAccessEvidence {
                on_access_config: OnAccessConfig::ConfigUnreadable(
                    ClamdConfigReadFailure::NoReadableConfig,
                ),
                ..healthy_evidence().on_access_evidence
            },
            ..healthy_evidence()
        };
        assert_eq!(
            summary_for(SidebarArea::OnAccessScanning, &protection_evidence),
            AreaSummary {
                area_status: AreaStatus::AreaUnknown,
                live_state_text: "clamd.conf unreadable".to_owned(),
            }
        );
    }

    #[test]
    fn a_failed_updater_needs_review_in_database_updates() {
        let protection_evidence = ProtectionEvidence {
            signature_evidence: SignatureEvidence {
                updater_evidence: vec![UpdaterEvidence {
                    updater_program: SignatureUpdaterProgram::Freshclam,
                    service_unit: "clamav-freshclam.service",
                    last_result: UpdaterUnitResult::UpdaterError { exit_status: 1 },
                    last_completed_run: UpdaterRunHistory::NoCompletedUpdate,
                }],
                ..healthy_evidence().signature_evidence
            },
            ..healthy_evidence()
        };
        assert_eq!(
            summary_for(SidebarArea::DatabaseUpdates, &protection_evidence),
            AreaSummary {
                area_status: AreaStatus::AreaNeedsReview,
                live_state_text: "Last update failed".to_owned(),
            }
        );
        assert_eq!(
            first_area_needing_attention(&all_area_summaries(
                &protection_evidence,
                &idle_context()
            )),
            SidebarArea::DatabaseUpdates
        );
    }

    #[test]
    fn a_completed_update_is_shown_as_the_update_time() {
        let protection_evidence = ProtectionEvidence {
            signature_evidence: SignatureEvidence {
                updater_evidence: vec![UpdaterEvidence {
                    updater_program: SignatureUpdaterProgram::Freshclam,
                    service_unit: "clamav-freshclam.service",
                    last_result: UpdaterUnitResult::UpdateSucceeded,
                    last_completed_run: UpdaterRunHistory::CompletedUpdate {
                        finished_at: REFERENCE_MOMENT - jiff::SignedDuration::from_hours(2),
                    },
                }],
                ..healthy_evidence().signature_evidence
            },
            ..healthy_evidence()
        };
        assert_eq!(
            summary_for(SidebarArea::DatabaseUpdates, &protection_evidence),
            AreaSummary {
                area_status: AreaStatus::AreaHealthy,
                live_state_text: "Updated 2 hours ago".to_owned(),
            }
        );
    }

    #[test]
    fn an_inactive_timer_fails_the_scheduled_scans() {
        let protection_evidence = ProtectionEvidence {
            scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                service_unit: "clamdscan.service",
                timer_state: TimerState::TimerInactive,
                scan_service: ScanServiceEvidence::ServiceConfigured {
                    scan_targets: vec!["/tmp".to_owned()],
                    last_result: ScanUnitResult::NothingFound,
                },
                last_completed_run: ScanRunHistory::NoCompletedScan,
            },
            ..healthy_evidence()
        };
        assert_eq!(
            summary_for(SidebarArea::ScheduledScans, &protection_evidence),
            AreaSummary {
                area_status: AreaStatus::AreaFailing,
                live_state_text: "Timer not active".to_owned(),
            }
        );
    }

    #[test]
    fn unreadable_evidence_is_never_reported_as_healthy() {
        let unknown_cases = [
            (
                SidebarArea::ScanEngine,
                ProtectionEvidence {
                    daemon_evidence: DaemonEvidence::UnitStateUnknown,
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::ScanEngine,
                ProtectionEvidence {
                    program_trust: ProgramTrustInspection::CheckInterrupted,
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::DatabaseUpdates,
                ProtectionEvidence {
                    program_trust: ProgramTrustInspection::CheckInterrupted,
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::DatabaseUpdates,
                ProtectionEvidence {
                    signature_evidence: SignatureEvidence {
                        database_evidence: DatabaseEvidence::InspectionInterrupted,
                        ..healthy_evidence().signature_evidence
                    },
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::SignatureSources,
                ProtectionEvidence {
                    signature_evidence: SignatureEvidence {
                        third_party_listing: ThirdPartySignatureListing::FolderUnreadable(
                            DatabaseFolderReadFailure::ReadingTaskInterrupted,
                        ),
                        ..healthy_evidence().signature_evidence
                    },
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::OnAccessScanning,
                ProtectionEvidence {
                    on_access_evidence: OnAccessEvidence {
                        on_access_scanner: OnAccessScanner::UnitStateUnknown,
                        ..healthy_evidence().on_access_evidence
                    },
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::OnAccessScanning,
                ProtectionEvidence {
                    runtime_reductions: RuntimeReductions::OverridesUnreadable(
                        OverridesReadFailure::ReadingTaskInterrupted,
                    ),
                    ..healthy_evidence()
                },
            ),
            (
                SidebarArea::ScheduledScans,
                ProtectionEvidence {
                    scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                        service_unit: "clamdscan.service",
                        timer_state: TimerState::TimerActive {
                            next_run: UnitTimestamp::NeverRecorded,
                        },
                        scan_service: ScanServiceEvidence::ServiceUnreadable,
                        last_completed_run: ScanRunHistory::NoCompletedScan,
                    },
                    ..healthy_evidence()
                },
            ),
        ];
        unknown_cases
            .iter()
            .for_each(|(sidebar_area, protection_evidence)| {
                assert_eq!(
                    status_for(*sidebar_area, protection_evidence),
                    AreaStatus::AreaUnknown,
                    "{sidebar_area:?}"
                );
            });
    }

    #[test]
    fn a_runtime_reduction_counts_against_the_area_of_its_setting() {
        let protection_evidence = ProtectionEvidence {
            runtime_reductions: RuntimeReductions::SettingsReduced {
                change_time: OverridesChangeTime::ChangeTimeUnknown,
                reduced_settings: vec![ReducedSetting {
                    setting_key: "OnAccessPrevention".to_owned(),
                    base_value: "yes".to_owned(),
                    changed_value: "no".to_owned(),
                }],
            },
            ..healthy_evidence()
        };
        assert_eq!(
            summary_for(SidebarArea::OnAccessScanning, &protection_evidence),
            AreaSummary {
                area_status: AreaStatus::AreaNeedsReview,
                live_state_text: "Settings reduced at runtime".to_owned(),
            }
        );
        assert_eq!(
            status_for(SidebarArea::ScanEngine, &protection_evidence),
            AreaStatus::AreaHealthy
        );
    }

    #[test]
    fn detections_and_quarantine_follow_their_counts() {
        let area_context = AreaSummaryContext {
            unresolved_detections: 2,
            quarantine_entry_count: QuarantineEntryCount::EntriesCounted { entry_count: 1 },
            ..idle_context()
        };
        let protection_evidence = healthy_evidence();
        assert_eq!(
            area_summary(SidebarArea::Detections, &protection_evidence, &area_context),
            AreaSummary {
                area_status: AreaStatus::AreaNeedsReview,
                live_state_text: "2 need a decision".to_owned(),
            }
        );
        assert_eq!(
            area_summary(SidebarArea::Quarantine, &protection_evidence, &area_context),
            AreaSummary {
                area_status: AreaStatus::AreaHealthy,
                live_state_text: "1 item".to_owned(),
            }
        );
        let unreadable_journal = AreaSummaryContext {
            alert_readiness: AlertReadiness {
                journal_access: JournalAccess::JournalUnreadable,
                notifications_enabled: true,
            },
            ..area_context
        };
        assert_eq!(
            area_summary(
                SidebarArea::Detections,
                &protection_evidence,
                &unreadable_journal
            )
            .area_status,
            AreaStatus::AreaFailing
        );
    }

    #[test]
    fn the_process_attach_check_counts_toward_detections() {
        let attach_open = ProtectionEvidence {
            process_attach_scope: ProcessAttachScope::AnyProgramMayAttach,
            ..healthy_evidence()
        };
        assert_eq!(
            summary_for(SidebarArea::Detections, &attach_open),
            AreaSummary {
                area_status: AreaStatus::AreaNeedsReview,
                live_state_text: "Other programs can attach to Lazaret".to_owned(),
            }
        );
        let attach_unreadable = ProtectionEvidence {
            process_attach_scope: ProcessAttachScope::ScopeUnreadable(
                crate::host_services::protection_evidence::process_attach_scope::ProcessAttachReadFailure::ReadingTaskInterrupted,
            ),
            ..healthy_evidence()
        };
        assert_eq!(
            status_for(SidebarArea::Detections, &attach_unreadable),
            AreaStatus::AreaUnknown
        );
        assert_eq!(
            status_for(SidebarArea::Detections, &healthy_evidence()),
            AreaStatus::AreaHealthy
        );
    }

    fn summary_list(area_statuses: &[(SidebarArea, AreaStatus)]) -> Vec<SidebarAreaSummary> {
        area_statuses
            .iter()
            .map(|(sidebar_area, area_status)| SidebarAreaSummary {
                sidebar_area: *sidebar_area,
                area_summary: summary_of(*area_status, String::new()),
            })
            .collect()
    }

    #[test]
    fn the_first_area_needing_attention_follows_the_sidebar_order() {
        assert_eq!(
            first_area_needing_attention(&summary_list(&[
                (SidebarArea::DatabaseUpdates, AreaStatus::AreaHealthy),
                (SidebarArea::OnAccessScanning, AreaStatus::AreaUnknown),
                (SidebarArea::Quarantine, AreaStatus::AreaFailing),
            ])),
            SidebarArea::OnAccessScanning
        );
        assert_eq!(
            first_area_needing_attention(&summary_list(&[
                (SidebarArea::ScheduledScans, AreaStatus::AreaWaiting),
                (SidebarArea::Quarantine, AreaStatus::AreaHealthy),
            ])),
            SidebarArea::Detections
        );
        assert_eq!(first_area_needing_attention(&[]), SidebarArea::Detections);
    }

    #[test]
    fn the_protection_row_shows_the_worst_status() {
        let area_summaries = summary_list(&[
            (SidebarArea::ScanEngine, AreaStatus::AreaUnknown),
            (SidebarArea::ScheduledScans, AreaStatus::AreaNeedsReview),
        ]);
        assert_eq!(
            worst_area_status(&area_summaries).status_indicator(),
            StatusIndicator::WarningIndicator
        );
        assert_eq!(
            AreaStatus::AreaFailing.status_indicator(),
            StatusIndicator::ErrorIndicator
        );
        assert!(!AreaStatus::AreaHealthy.status_indicator().is_shown());
    }

    #[test]
    fn on_access_follows_the_kernel_and_the_setup_review() {
        let with_on_access = |on_access_evidence| ProtectionEvidence {
            on_access_evidence,
            ..healthy_evidence()
        };
        let unknown_kernel = summary_for(
            SidebarArea::OnAccessScanning,
            &with_on_access(OnAccessEvidence {
                kernel_blocking_support: KernelBlockingSupport::KernelConfigUnreadable(
                    KernelConfigReadFailure::NoKernelConfigFound,
                ),
                ..healthy_evidence().on_access_evidence
            }),
        );
        assert_eq!(unknown_kernel.area_status, AreaStatus::AreaUnknown);
        assert_eq!(
            unknown_kernel.live_state_text,
            "Checks files, blocking unknown"
        );
        let notify_only = summary_for(
            SidebarArea::OnAccessScanning,
            &with_on_access(OnAccessEvidence {
                kernel_blocking_support: KernelBlockingSupport::NotifyOnly,
                ..healthy_evidence().on_access_evidence
            }),
        );
        assert_eq!(notify_only.area_status, AreaStatus::AreaNeedsReview);
        assert_eq!(
            notify_only.live_state_text,
            "Checks files, kernel can't block"
        );
        let OnAccessConfig::ConfigRead {
            watch_scope,
            configured_prevention,
            size_limit,
            ..
        } = healthy_evidence().on_access_evidence.on_access_config
        else {
            panic!("the healthy fixture reads its config");
        };
        let not_excluded = summary_for(
            SidebarArea::OnAccessScanning,
            &with_on_access(OnAccessEvidence {
                on_access_config: OnAccessConfig::ConfigRead {
                    watch_scope,
                    configured_prevention,
                    setting_conflicts: Vec::new(),
                    clamd_user_exclusion: ClamdUserExclusion::ClamdUserNotExcluded,
                    size_limit,
                },
                ..healthy_evidence().on_access_evidence
            }),
        );
        assert_eq!(not_excluded.area_status, AreaStatus::AreaNeedsReview);
        assert_eq!(not_excluded.live_state_text, "clamd not excluded");
    }

    fn removable_drives_summary_with(
        auto_scan_settings: DeviceAutoScanSettings,
        device_scan_status: DeviceScanStatus,
    ) -> AreaSummary {
        area_summary(
            SidebarArea::RemovableDrives,
            &healthy_evidence(),
            &AreaSummaryContext {
                removable_drives_status: RemovableDrivesStatus {
                    auto_scan_settings,
                    device_scan_status,
                },
                ..idle_context()
            },
        )
    }

    #[test]
    fn removable_drives_show_the_auto_scan_choice_and_the_running_drive() {
        let enabled_settings = idle_context().removable_drives_status.auto_scan_settings;
        assert_eq!(
            removable_drives_summary_with(
                DeviceAutoScanSettings {
                    auto_scan_enabled: false,
                    ..enabled_settings
                },
                DeviceScanStatus::NoDeviceScanYet
            ),
            AreaSummary {
                area_status: AreaStatus::AreaHealthy,
                live_state_text: "Off".to_owned(),
            }
        );
        assert_eq!(
            removable_drives_summary_with(
                DeviceAutoScanSettings {
                    maximum_gigabytes: 0,
                    ..enabled_settings
                },
                DeviceScanStatus::DeviceScanEnded {
                    drive_name: "USB STICK".to_owned(),
                    scan_result: ScanResultsStatus::NoThreatsDetected,
                }
            )
            .live_state_text,
            "Scans every drive"
        );
        assert_eq!(
            removable_drives_summary_with(
                enabled_settings,
                DeviceScanStatus::DeviceScanRunning {
                    drive_name: "USB STICK".to_owned()
                }
            ),
            AreaSummary {
                area_status: AreaStatus::AreaHealthy,
                live_state_text: "Scanning USB STICK".to_owned(),
            }
        );
    }

    #[test]
    fn a_device_scan_that_found_threats_needs_review() {
        assert_eq!(
            removable_drives_summary_with(
                idle_context().removable_drives_status.auto_scan_settings,
                DeviceScanStatus::DeviceScanEnded {
                    drive_name: "CAMERA".to_owned(),
                    scan_result: ScanResultsStatus::ThreatsDetected,
                }
            ),
            AreaSummary {
                area_status: AreaStatus::AreaNeedsReview,
                live_state_text: "Threats found on CAMERA".to_owned(),
            }
        );
    }
}
