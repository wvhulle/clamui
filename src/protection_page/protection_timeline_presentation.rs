use bytesize::ByteSize;
use gettextrs::{gettext, ngettext};

use crate::{
    application_window::settings_navigation::SettingsSubpage,
    hardening_page::suggested_audit_commands::{SuggestedRemedy, suggested_command},
    host_services::{
        clamav_programs::distribution_install_guides::{DistributionFamily, engine_install_guides},
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        detection_journal::detection_journal_follower::JournalAccess,
        systemd_bus::host_systemd_units::{ServiceLastResult, UnitState, UnitTimestamp},
    },
    logs_page::activity_entry_row::formatted_local_time,
    protection_page::{
        clamav_engine_evidence::DatabaseEvidence,
        protection_evidence::{
            AccountSettingFinding, DaemonEvidence, EngineInstallation, LoadedSignatures,
            OnAccessEvidence, OnAccessScanner, OnAccessSizeLimit, ProgramTrustFinding,
            ProtectionEvidence, RuntimeReductions, ScheduledScanEvidence, SignatureEvidence,
            UpdaterEvidence,
        },
        service_run_journal::ServiceRunHistory,
        trusted_detections_page::trust_list_contents::TrustListContents,
    },
    shared_widgets::step_timeline::timeline_step_contents::{
        StepActionSlot, StepEvidenceRow, StepNodeState, TimelineStep, TimelineStepAction,
    },
    signatures_page::signature_provider_catalogue::provider_of_signature_file,
};

const DATABASE_FRESH_DAYS: u64 = 3;
const DATABASE_STALE_DAYS: u64 = 7;
const THIRD_PARTY_STALE_HOURS: u64 = 48;
const SCANNER_ERROR_STATUS: i32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertReadiness {
    pub journal_access: JournalAccess,
    pub notifications_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionTimeline {
    pub coverage_summary: String,
    pub timeline_steps: Vec<TimelineStep>,
}

fn evidence_row(evidence_name: String, evidence_value: String) -> StepEvidenceRow {
    StepEvidenceRow {
        evidence_name,
        evidence_value,
    }
}

fn no_guidance_step(
    step_title: String,
    mechanism_details: String,
    node_state: StepNodeState,
    status_text: String,
) -> TimelineStep {
    TimelineStep {
        step_title,
        mechanism_details,
        node_state,
        status_text,
        evidence_rows: Vec::new(),
        guidance_commands: Vec::new(),
        choice_rows: Vec::new(),
        action_slot: StepActionSlot::NoAction,
    }
}

fn remedy_commands(
    suggested_remedy: SuggestedRemedy,
    distribution_family: DistributionFamily,
) -> Vec<String> {
    suggested_command(suggested_remedy, distribution_family)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn engine_step(
    engine_installation: &EngineInstallation,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let step_title = gettext("ClamAV installed");
    let mechanism_details = gettext(
        "ClamAV is the engine that recognizes malware. Lazaret uses the copy installed on this \
         computer and never bundles its own.",
    );
    match engine_installation {
        EngineInstallation::VersionReported { version_banner } => no_guidance_step(
            step_title,
            mechanism_details,
            StepNodeState::Completed,
            version_banner.clone(),
        ),
        EngineInstallation::VersionUnverified { failure_text } => no_guidance_step(
            step_title,
            mechanism_details,
            StepNodeState::NeedsReview,
            failure_text.clone(),
        ),
        EngineInstallation::EngineMissing => TimelineStep {
            guidance_commands: engine_install_guides()
                .iter()
                .filter(|install_guide| install_guide.distribution_family == distribution_family)
                .map(|install_guide| install_guide.install_command.to_owned())
                .collect(),
            ..no_guidance_step(
                step_title,
                mechanism_details,
                StepNodeState::ActNext,
                gettext("ClamAV was not found on this computer"),
            )
        },
    }
}

fn program_trust_rows(program_trust_finding: &ProgramTrustFinding) -> Vec<StepEvidenceRow> {
    match program_trust_finding {
        ProgramTrustFinding::ReplaceableProgramIgnored {
            program_name,
            trusted_path,
            ignored_paths,
        } => std::iter::once(evidence_row(
            gettext("{program} in use").replace("{program}", program_name),
            trusted_path.clone(),
        ))
        .chain(ignored_paths.iter().map(|ignored_path| {
            evidence_row(
                gettext("Ignored {program}").replace("{program}", program_name),
                ignored_path.clone(),
            )
        }))
        .collect(),
        ProgramTrustFinding::OnlyReplaceableProgram {
            program_name,
            replaceable_paths,
        } => replaceable_paths
            .iter()
            .map(|replaceable_path| {
                evidence_row(
                    gettext("Refused {program}").replace("{program}", program_name),
                    replaceable_path.clone(),
                )
            })
            .collect(),
    }
}

fn program_trust_step(program_trust_findings: &[ProgramTrustFinding]) -> Option<TimelineStep> {
    if program_trust_findings.is_empty() {
        return None;
    }
    let any_program_refused = program_trust_findings.iter().any(|program_trust_finding| {
        matches!(
            program_trust_finding,
            ProgramTrustFinding::OnlyReplaceableProgram { .. }
        )
    });
    let (node_state, status_text) = if any_program_refused {
        (
            StepNodeState::HasFailed,
            gettext(
                "A ClamAV program can be replaced by your account, so Lazaret refuses to run it",
            ),
        )
    } else {
        (
            StepNodeState::NeedsReview,
            gettext(
                "A ClamAV program in your account shadows the system copy. Lazaret ignores it, \
                 but check where it came from",
            ),
        )
    };
    Some(TimelineStep {
        evidence_rows: program_trust_findings
            .iter()
            .flat_map(program_trust_rows)
            .collect(),
        ..no_guidance_step(
            gettext("Scanner programs can be trusted"),
            gettext(
                "Malware running as you could put a fake clamdscan earlier on your search path \
                 that reports every file as clean. Lazaret only runs ClamAV programs that your \
                 account can't replace, such as the ones installed for the whole system.",
            ),
            node_state,
            status_text,
        )
    })
}

fn runtime_reduction_step(runtime_reductions: &RuntimeReductions) -> Option<TimelineStep> {
    let RuntimeReductions::ReducedSince {
        changed_unix_seconds,
        reduced_settings,
    } = runtime_reductions
    else {
        return None;
    };
    Some(TimelineStep {
        evidence_rows: reduced_settings
            .iter()
            .map(|reduced_setting| {
                evidence_row(
                    reduced_setting.setting_key.clone(),
                    gettext("{base} in your configuration, {changed} now")
                        .replace("{base}", &reduced_setting.base_value)
                        .replace("{changed}", &reduced_setting.changed_value),
                )
            })
            .collect(),
        action_slot: StepActionSlot::ActionOffered {
            action_label: gettext("Review"),
            chosen_action: TimelineStepAction::OpenSettingsSubpage(SettingsSubpage::ScannerEngine),
            action_suggested: false,
        },
        ..no_guidance_step(
            gettext("Protection reduced on purpose"),
            gettext(
                "Someone with the administrator password changed ClamAV settings at runtime in a \
                 way that checks less than your configuration does. The System Changes tab on the \
                 Logs page shows who and when.",
            ),
            StepNodeState::NeedsReview,
            ngettext(
                "{count} setting checks less than configured since {time}",
                "{count} settings check less than configured since {time}",
                u32::try_from(reduced_settings.len()).unwrap_or(u32::MAX),
            )
            .replace("{count}", &reduced_settings.len().to_string())
            .replace("{time}", &formatted_local_time(*changed_unix_seconds)),
        )
    })
}

fn account_settings_step(account_findings: &[AccountSettingFinding]) -> Option<TimelineStep> {
    if account_findings.is_empty() {
        return None;
    }
    let exclusion_found = account_findings.iter().any(|account_finding| {
        matches!(
            account_finding,
            AccountSettingFinding::BroadExclusion { .. }
        )
    });
    Some(TimelineStep {
        evidence_rows: account_findings
            .iter()
            .map(|account_finding| match account_finding {
                AccountSettingFinding::BroadExclusion {
                    exclusion_pattern,
                    skipped_example,
                } => evidence_row(
                    gettext("Exclusion {pattern}").replace("{pattern}", exclusion_pattern),
                    gettext("Skips files such as {path}").replace("{path}", skipped_example),
                ),
                AccountSettingFinding::ScheduleUnitChanged { unit_file_name } => {
                    evidence_row(gettext("Changed outside Lazaret"), unit_file_name.clone())
                }
            })
            .collect(),
        action_slot: StepActionSlot::ActionOffered {
            action_label: gettext("Review"),
            chosen_action: TimelineStepAction::OpenSettingsSubpage(if exclusion_found {
                SettingsSubpage::ScanExclusions
            } else {
                SettingsSubpage::ScanSchedule
            }),
            action_suggested: true,
        },
        ..no_guidance_step(
            gettext("Scan settings in your account"),
            gettext(
                "Exclusions and the scan schedule are stored in your account, so any program \
                 running as you can change them. Lazaret warns when an exclusion skips places \
                 where malware usually lands, or when the schedule's unit files differ from what \
                 Lazaret wrote, for example after an update or because something else changed \
                 them. Applying the schedule again rewrites them.",
            ),
            StepNodeState::NeedsReview,
            gettext("Your scan settings may skip malware"),
        )
    })
}

fn trust_list_step(trust_list: &TrustListContents) -> Option<TimelineStep> {
    if trust_list.is_empty() {
        return None;
    }
    let lazaret_entries = trust_list.lazaret_entry_count();
    let (node_state, status_text) = if trust_list.foreign_allowlists.is_empty() {
        (
            StepNodeState::Completed,
            ngettext(
                "{count} file or detection is never reported",
                "{count} files or detections are never reported",
                u32::try_from(lazaret_entries).unwrap_or(u32::MAX),
            )
            .replace("{count}", &lazaret_entries.to_string()),
        )
    } else {
        (
            StepNodeState::NeedsReview,
            gettext("An allowlist that Lazaret didn't write tells ClamAV to stay silent"),
        )
    };
    Some(TimelineStep {
        evidence_rows: trust_list
            .foreign_allowlists
            .iter()
            .map(|foreign_allowlist| {
                evidence_row(
                    gettext("Other allowlist"),
                    foreign_allowlist.file_name.clone(),
                )
            })
            .collect(),
        action_slot: StepActionSlot::ActionOffered {
            action_label: gettext("Review"),
            chosen_action: TimelineStepAction::OpenSettingsSubpage(
                SettingsSubpage::TrustedDetections,
            ),
            action_suggested: node_state == StepNodeState::NeedsReview,
        },
        ..no_guidance_step(
            gettext("Trusted detections"),
            gettext(
                "Files and detection names on ClamAV's allowlists are never reported, by any \
                 scan. Malware that gets administrator rights could hide itself this way, so \
                 check that every entry was added on purpose.",
            ),
            node_state,
            status_text,
        )
    })
}

fn database_state(database_evidence: &DatabaseEvidence) -> StepNodeState {
    match database_evidence {
        DatabaseEvidence::BuiltDaysAgo { age_days, .. } if *age_days <= DATABASE_FRESH_DAYS => {
            StepNodeState::Completed
        }
        DatabaseEvidence::BuiltDaysAgo { age_days, .. } if *age_days <= DATABASE_STALE_DAYS => {
            StepNodeState::NeedsReview
        }
        DatabaseEvidence::BuiltDaysAgo { .. } | DatabaseEvidence::DatabaseMissing => {
            StepNodeState::HasFailed
        }
        DatabaseEvidence::AgeUndetermined => StepNodeState::NeedsReview,
    }
}

fn database_status_text(database_evidence: &DatabaseEvidence) -> String {
    match database_evidence {
        DatabaseEvidence::BuiltDaysAgo {
            age_days,
            build_date,
        } => gettext("Definitions built {date}, {days} days ago")
            .replace("{days}", &age_days.to_string())
            .replace("{date}", build_date),
        DatabaseEvidence::AgeUndetermined => {
            gettext("Definitions exist, but their age could not be determined")
        }
        DatabaseEvidence::DatabaseMissing => gettext("No virus definitions were found"),
    }
}

fn updater_failed(updater_evidence: &UpdaterEvidence) -> bool {
    updater_evidence.last_result != ServiceLastResult::ResultSucceeded
}

fn updater_status_text(updater_evidence: &UpdaterEvidence) -> String {
    if updater_failed(updater_evidence) {
        return gettext("Its last update failed");
    }
    match updater_evidence.last_completed_run {
        ServiceRunHistory::CompletedRun(service_run) => gettext("Last updated {time}").replace(
            "{time}",
            &formatted_local_time(service_run.finished_at_unix),
        ),
        ServiceRunHistory::NoCompletedRun => gettext("No completed update recorded yet"),
    }
}

fn signature_step(
    signature_evidence: &SignatureEvidence,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let any_updater_failed = signature_evidence
        .updater_evidence
        .iter()
        .any(updater_failed);
    let any_source_stale = signature_evidence
        .third_party_files
        .iter()
        .any(|signature_file| signature_file.age_hours > THIRD_PARTY_STALE_HOURS);
    let base_state = database_state(&signature_evidence.database_evidence);
    let node_state =
        if base_state == StepNodeState::Completed && (any_updater_failed || any_source_stale) {
            StepNodeState::NeedsReview
        } else {
            base_state
        };
    let updater_rows = signature_evidence
        .updater_evidence
        .iter()
        .map(|updater_evidence| {
            evidence_row(
                updater_evidence.updater_name.to_owned(),
                updater_status_text(updater_evidence),
            )
        });
    let file_rows = signature_evidence
        .third_party_files
        .iter()
        .map(|signature_file| {
            evidence_row(
                provider_of_signature_file(&signature_file.file_name).to_owned(),
                ngettext(
                    "{count} signature, {size}, updated {hours} hours ago ({file})",
                    "{count} signatures, {size}, updated {hours} hours ago ({file})",
                    u32::try_from(signature_file.signature_count).unwrap_or(u32::MAX),
                )
                .replace("{count}", &signature_file.signature_count.to_string())
                .replace(
                    "{size}",
                    &ByteSize::b(signature_file.file_size_bytes).to_string(),
                )
                .replace("{hours}", &signature_file.age_hours.to_string())
                .replace("{file}", &signature_file.file_name),
            )
        });
    TimelineStep {
        evidence_rows: updater_rows.chain(file_rows).collect(),
        guidance_commands: if signature_evidence.updater_evidence.is_empty() {
            remedy_commands(SuggestedRemedy::FreshclamUpdatesEnable, distribution_family)
        } else {
            Vec::new()
        },
        action_slot: StepActionSlot::ActionOffered {
            action_label: gettext("Update Now"),
            chosen_action: TimelineStepAction::UpdateSignatures,
            action_suggested: node_state != StepNodeState::Completed,
        },
        ..no_guidance_step(
            gettext("Signatures current"),
            gettext(
                "Signatures describe known malware, and new ones are published constantly. Old \
                 signatures miss recent threats even when everything else is running.",
            ),
            node_state,
            database_status_text(&signature_evidence.database_evidence),
        )
    }
}

fn daemon_step(
    daemon_evidence: &DaemonEvidence,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let step_title = gettext("Daemon running");
    let mechanism_details = gettext(
        "clamd keeps the signatures loaded in memory. On-access blocking and scheduled scans both \
         send their files to it.",
    );
    match daemon_evidence {
        DaemonEvidence::ClamdAnswering {
            loaded_signatures:
                LoadedSignatures::BehindDisk {
                    loaded_version,
                    disk_version,
                },
        } => no_guidance_step(
            step_title,
            mechanism_details,
            StepNodeState::NeedsReview,
            gettext("clamd still uses signatures {loaded}, but {disk} is on disk")
                .replace("{loaded}", loaded_version)
                .replace("{disk}", disk_version),
        ),
        DaemonEvidence::ClamdAnswering { .. } => no_guidance_step(
            step_title,
            mechanism_details,
            StepNodeState::Completed,
            gettext("clamd is answering"),
        ),
        DaemonEvidence::UnitStopped { service_unit } => TimelineStep {
            guidance_commands: remedy_commands(
                SuggestedRemedy::ClamavDaemonStart,
                distribution_family,
            ),
            ..no_guidance_step(
                step_title,
                mechanism_details,
                StepNodeState::HasFailed,
                gettext("{unit} is not running").replace("{unit}", service_unit),
            )
        },
        DaemonEvidence::NeverSetUp => TimelineStep {
            guidance_commands: remedy_commands(
                SuggestedRemedy::ClamavDaemonStart,
                distribution_family,
            ),
            ..no_guidance_step(
                step_title,
                mechanism_details,
                StepNodeState::ActNext,
                gettext("clamd is not set up, so scans fall back to the slower clamscan"),
            )
        },
    }
}

fn daemon_is_answering(daemon_evidence: &DaemonEvidence) -> bool {
    matches!(daemon_evidence, DaemonEvidence::ClamdAnswering { .. })
}

fn on_access_rows(on_access_evidence: &OnAccessEvidence) -> Vec<StepEvidenceRow> {
    let watched_row = evidence_row(
        gettext("Watched folders"),
        if on_access_evidence.watched_paths.is_empty() {
            gettext("None configured")
        } else {
            on_access_evidence.watched_paths.join("\n")
        },
    );
    let size_row = match &on_access_evidence.size_limit {
        OnAccessSizeLimit::DefaultLimit => evidence_row(
            gettext("Largest file scanned"),
            gettext("The ClamAV default"),
        ),
        OnAccessSizeLimit::ConfiguredLimit { limit_text } => {
            evidence_row(gettext("Largest file scanned"), limit_text.clone())
        }
    };
    vec![watched_row, size_row]
}

fn on_access_step(
    on_access_evidence: &OnAccessEvidence,
    daemon_answering: bool,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let step_title = gettext("On-access blocking");
    let mechanism_details = gettext(
        "clamonacc checks files in the watched folders as they are opened. With prevention on, \
         the kernel refuses access to a detected file, which is why such a file can't be opened \
         even though it is still there.",
    );
    let (node_state, status_text) = match on_access_evidence.on_access_scanner {
        OnAccessScanner::NeverSetUp => (
            StepNodeState::NeedsReview,
            gettext("On-access scanning is not set up"),
        ),
        _configured_scanner if !daemon_answering => (
            StepNodeState::AwaitingEarlier,
            gettext("Waiting for the daemon"),
        ),
        OnAccessScanner::UnitStopped { service_unit } => (
            StepNodeState::HasFailed,
            gettext("{unit} is not running").replace("{unit}", service_unit),
        ),
        OnAccessScanner::MonitorRunning if !on_access_evidence.prevention_enabled => (
            StepNodeState::NeedsReview,
            gettext("Files are checked, but detected files are not blocked"),
        ),
        OnAccessScanner::MonitorRunning if on_access_evidence.watched_paths.is_empty() => (
            StepNodeState::NeedsReview,
            gettext("Running, but no watched folders could be read"),
        ),
        OnAccessScanner::MonitorRunning => (
            StepNodeState::Completed,
            gettext("Detected files are blocked"),
        ),
    };
    TimelineStep {
        evidence_rows: on_access_rows(on_access_evidence),
        guidance_commands: if node_state == StepNodeState::Completed {
            Vec::new()
        } else {
            remedy_commands(
                if on_access_evidence.on_access_scanner == OnAccessScanner::MonitorRunning {
                    SuggestedRemedy::OnAccessPreventionEnable
                } else {
                    SuggestedRemedy::OnAccessScanningEnable
                },
                distribution_family,
            )
        },
        ..no_guidance_step(step_title, mechanism_details, node_state, status_text)
    }
}

fn next_run_text(next_run: UnitTimestamp) -> String {
    match next_run {
        UnitTimestamp::RecordedAt { unix_seconds } => formatted_local_time(unix_seconds),
        UnitTimestamp::NeverRecorded => gettext("Not scheduled"),
    }
}

fn last_run_text(last_completed_run: ServiceRunHistory) -> String {
    match last_completed_run {
        ServiceRunHistory::CompletedRun(service_run) if service_run.threats_found => {
            gettext("{time}, threats found").replace(
                "{time}",
                &formatted_local_time(service_run.finished_at_unix),
            )
        }
        ServiceRunHistory::CompletedRun(service_run) => gettext("{time}, nothing found").replace(
            "{time}",
            &formatted_local_time(service_run.finished_at_unix),
        ),
        ServiceRunHistory::NoCompletedRun => gettext("Not run yet"),
    }
}

fn scan_result_failed(last_result: &ServiceLastResult) -> bool {
    match last_result {
        ServiceLastResult::ResultSucceeded => false,
        ServiceLastResult::ExitedWithStatus { exit_status } => *exit_status >= SCANNER_ERROR_STATUS,
        ServiceLastResult::FailedWithResult { .. } => true,
    }
}

fn scheduled_scan_step(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    daemon_answering: bool,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let step_title = gettext("Scheduled scan");
    let mechanism_details = gettext(
        "A scheduled scan catches files that were not opened, or that only became detectable \
         after a signature update.",
    );
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            service_unit,
            timer_active,
            next_run,
            scan_targets,
            last_result,
            last_completed_run,
        } => {
            let (node_state, status_text) = if !daemon_answering {
                (
                    StepNodeState::AwaitingEarlier,
                    gettext("Waiting for the daemon"),
                )
            } else if !timer_active {
                (
                    StepNodeState::HasFailed,
                    gettext("The system timer is not active"),
                )
            } else if scan_result_failed(last_result) {
                (
                    StepNodeState::NeedsReview,
                    gettext("The last scan ended with an error"),
                )
            } else {
                (
                    StepNodeState::Completed,
                    gettext("Next scan: {time}").replace("{time}", &next_run_text(*next_run)),
                )
            };
            TimelineStep {
                evidence_rows: vec![
                    evidence_row(gettext("Last scan"), last_run_text(*last_completed_run)),
                    evidence_row(gettext("Folders scanned"), scan_targets.join("\n")),
                ],
                action_slot: StepActionSlot::ActionOffered {
                    action_label: gettext("Run Now"),
                    chosen_action: TimelineStepAction::RunScheduledScan { service_unit },
                    action_suggested: false,
                },
                ..no_guidance_step(step_title, mechanism_details, node_state, status_text)
            }
        }
        ScheduledScanEvidence::LazaretSchedule => no_guidance_step(
            step_title,
            mechanism_details,
            StepNodeState::Completed,
            gettext("Scheduled by Lazaret"),
        ),
        ScheduledScanEvidence::NoSchedule => TimelineStep {
            guidance_commands: remedy_commands(
                SuggestedRemedy::ScheduledScanEnable,
                distribution_family,
            ),
            action_slot: StepActionSlot::ActionOffered {
                action_label: gettext("Set Up"),
                chosen_action: TimelineStepAction::OpenSettingsSubpage(
                    SettingsSubpage::ScanSchedule,
                ),
                action_suggested: true,
            },
            ..no_guidance_step(
                step_title,
                mechanism_details,
                StepNodeState::NeedsReview,
                gettext("No scan is scheduled"),
            )
        },
    }
}

fn alerts_step(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let step_title = gettext("Alerts");
    let mechanism_details = gettext(
        "Lazaret follows the system journal and notifies you when something is detected. It can \
         only do that while it is running, so it should run in the background.",
    );
    let (node_state, status_text) = match &alert_readiness.journal_access {
        JournalAccess::JournalUnreadable => (
            StepNodeState::HasFailed,
            gettext(
                "The system journal can't be read. Add your user to the systemd-journal group.",
            ),
        ),
        JournalAccess::FollowingFailed { failure_text } => (
            StepNodeState::HasFailed,
            gettext("Reading the system journal stopped: {error}")
                .replace("{error}", &sanitize_scanner_line(failure_text)),
        ),
        JournalAccess::FollowingJournal if !alert_readiness.notifications_enabled => (
            StepNodeState::NeedsReview,
            gettext("Notifications are turned off in the preferences"),
        ),
        JournalAccess::FollowingJournal if background_service_state != UnitState::UnitActive => (
            StepNodeState::NeedsReview,
            gettext(
                "Alerts stop when you quit Lazaret, because it isn't set up to run in the \
                 background",
            ),
        ),
        JournalAccess::FollowingJournal => (
            StepNodeState::Completed,
            gettext("Running in the background and following the journal"),
        ),
    };
    TimelineStep {
        guidance_commands: if alert_readiness.journal_access == JournalAccess::FollowingJournal
            && alert_readiness.notifications_enabled
            && background_service_state != UnitState::UnitActive
        {
            remedy_commands(SuggestedRemedy::BackgroundAlertsEnable, distribution_family)
        } else {
            Vec::new()
        },
        ..no_guidance_step(step_title, mechanism_details, node_state, status_text)
    }
}

fn on_access_coverage(on_access_evidence: &OnAccessEvidence) -> Option<String> {
    if on_access_evidence.on_access_scanner != OnAccessScanner::MonitorRunning
        || on_access_evidence.watched_paths.is_empty()
    {
        return None;
    }
    let watched_folders = on_access_evidence.watched_paths.join(", ");
    Some(if on_access_evidence.prevention_enabled {
        gettext("{paths} blocked on access").replace("{paths}", &watched_folders)
    } else {
        gettext("{paths} checked on access, not blocked").replace("{paths}", &watched_folders)
    })
}

fn scheduled_coverage(scheduled_scan_evidence: &ScheduledScanEvidence) -> Option<String> {
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            timer_active: true,
            scan_targets,
            ..
        } if !scan_targets.is_empty() => Some(
            gettext("{paths} scanned on a schedule").replace("{paths}", &scan_targets.join(", ")),
        ),
        ScheduledScanEvidence::LazaretSchedule => {
            Some(gettext("Scheduled scans set up in Lazaret"))
        }
        ScheduledScanEvidence::SystemTimer { .. } | ScheduledScanEvidence::NoSchedule => None,
    }
}

pub fn coverage_summary(protection_evidence: &ProtectionEvidence) -> String {
    if protection_evidence.engine_installation == EngineInstallation::EngineMissing {
        return gettext("ClamAV is not installed, so nothing is being checked");
    }
    let coverage_parts = if daemon_is_answering(&protection_evidence.daemon_evidence) {
        on_access_coverage(&protection_evidence.on_access_evidence)
            .into_iter()
            .chain(scheduled_coverage(
                &protection_evidence.scheduled_scan_evidence,
            ))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if coverage_parts.is_empty() {
        gettext("Files are only checked when you scan them")
    } else {
        coverage_parts.join("\n")
    }
}

pub fn protection_timeline(
    protection_evidence: &ProtectionEvidence,
    alert_readiness: &AlertReadiness,
    distribution_family: DistributionFamily,
) -> ProtectionTimeline {
    let daemon_answering = daemon_is_answering(&protection_evidence.daemon_evidence);
    let engine_problem = Some(engine_step(
        &protection_evidence.engine_installation,
        distribution_family,
    ))
    .filter(|installation_step| installation_step.node_state != StepNodeState::Completed);
    ProtectionTimeline {
        coverage_summary: coverage_summary(protection_evidence),
        timeline_steps: program_trust_step(&protection_evidence.program_trust_findings)
            .into_iter()
            .chain(engine_problem)
            .chain([
                signature_step(&protection_evidence.signature_evidence, distribution_family),
                daemon_step(&protection_evidence.daemon_evidence, distribution_family),
                on_access_step(
                    &protection_evidence.on_access_evidence,
                    daemon_answering,
                    distribution_family,
                ),
                scheduled_scan_step(
                    &protection_evidence.scheduled_scan_evidence,
                    daemon_answering,
                    distribution_family,
                ),
                alerts_step(
                    alert_readiness,
                    protection_evidence.background_service_state,
                    distribution_family,
                ),
            ])
            .chain(runtime_reduction_step(
                &protection_evidence.runtime_reductions,
            ))
            .chain(account_settings_step(
                &protection_evidence.account_setting_findings,
            ))
            .chain(trust_list_step(&protection_evidence.trust_list))
            .collect(),
    }
}

#[cfg(test)]
mod protection_timeline_presentation_tests {
    use super::*;

    const ON_ACCESS_POSITION: usize = 2;
    const SCHEDULED_POSITION: usize = 3;
    const SIGNATURE_POSITION: usize = 0;

    fn healthy_evidence() -> ProtectionEvidence {
        ProtectionEvidence {
            program_trust_findings: Vec::new(),
            trust_list: TrustListContents::default(),
            runtime_reductions: RuntimeReductions::NothingReduced,
            account_setting_findings: Vec::new(),
            engine_installation: EngineInstallation::VersionReported {
                version_banner: "ClamAV 1.5.4/28174".to_owned(),
            },
            signature_evidence: SignatureEvidence {
                database_evidence: DatabaseEvidence::BuiltDaysAgo {
                    age_days: 0,
                    build_date: "2026-11-05".to_owned(),
                },
                updater_evidence: Vec::new(),
                third_party_files: Vec::new(),
            },
            daemon_evidence: DaemonEvidence::ClamdAnswering {
                loaded_signatures: LoadedSignatures::MatchesDisk,
            },
            on_access_evidence: OnAccessEvidence {
                on_access_scanner: OnAccessScanner::MonitorRunning,
                watched_paths: vec!["/home/user/Downloads".to_owned()],
                prevention_enabled: true,
                size_limit: OnAccessSizeLimit::ConfiguredLimit {
                    limit_text: "100M".to_owned(),
                },
            },
            scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                service_unit: "clamdscan.service",
                timer_active: true,
                next_run: UnitTimestamp::RecordedAt {
                    unix_seconds: 1_794_223_800,
                },
                scan_targets: vec!["/tmp".to_owned(), "/var/tmp".to_owned()],
                last_result: ServiceLastResult::ResultSucceeded,
                last_completed_run: ServiceRunHistory::NoCompletedRun,
            },
            background_service_state: UnitState::UnitActive,
        }
    }

    fn ready_alerts() -> AlertReadiness {
        AlertReadiness {
            journal_access: JournalAccess::FollowingJournal,
            notifications_enabled: true,
        }
    }

    fn step_states(protection_evidence: &ProtectionEvidence) -> Vec<StepNodeState> {
        protection_timeline(
            protection_evidence,
            &ready_alerts(),
            DistributionFamily::NixosFamily,
        )
        .timeline_steps
        .iter()
        .map(|timeline_step| timeline_step.node_state)
        .collect()
    }

    #[tokio::test]
    #[ignore = "reads the real host"]
    async fn host_timeline_reports_the_real_backend() {
        let host_timeline = protection_timeline(
            &crate::protection_page::protection_evidence::gather_protection_evidence(false).await,
            &ready_alerts(),
            crate::host_services::clamav_programs::distribution_install_guides::detect_distribution_family(),
        );
        println!("{}", host_timeline.coverage_summary);
        host_timeline
            .timeline_steps
            .iter()
            .for_each(|timeline_step| {
                println!(
                    "{:?} | {} | {}",
                    timeline_step.node_state, timeline_step.step_title, timeline_step.status_text
                );
                timeline_step
                    .evidence_rows
                    .iter()
                    .for_each(|step_evidence| {
                        println!(
                            "    {}: {}",
                            step_evidence.evidence_name, step_evidence.evidence_value
                        );
                    });
            });
    }

    #[test]
    fn a_healthy_host_completes_every_step_and_names_its_coverage() {
        let protection_evidence = healthy_evidence();
        assert!(
            step_states(&protection_evidence)
                .iter()
                .all(|node_state| *node_state == StepNodeState::Completed)
        );
        assert_eq!(
            coverage_summary(&protection_evidence),
            "/home/user/Downloads blocked on access\n/tmp, /var/tmp scanned on a schedule"
        );
    }

    #[test]
    fn the_installation_step_only_appears_when_clamav_is_missing() {
        let installed_steps = protection_timeline(
            &healthy_evidence(),
            &ready_alerts(),
            DistributionFamily::NixosFamily,
        )
        .timeline_steps;
        assert_eq!(installed_steps[0].step_title, "Signatures current");
    }

    #[test]
    fn a_stopped_daemon_fails_once_and_leaves_its_dependents_pending() {
        let protection_evidence = ProtectionEvidence {
            daemon_evidence: DaemonEvidence::UnitStopped {
                service_unit: "clamav-daemon.service",
            },
            ..healthy_evidence()
        };
        assert_eq!(
            step_states(&protection_evidence),
            vec![
                StepNodeState::Completed,
                StepNodeState::HasFailed,
                StepNodeState::AwaitingEarlier,
                StepNodeState::AwaitingEarlier,
                StepNodeState::Completed,
            ]
        );
        assert_eq!(
            coverage_summary(&protection_evidence),
            "Files are only checked when you scan them"
        );
    }

    #[test]
    fn on_access_and_scheduled_scans_can_need_attention_together() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: OnAccessEvidence {
                on_access_scanner: OnAccessScanner::UnitStopped {
                    service_unit: "clamav-clamonacc.service",
                },
                ..healthy_evidence().on_access_evidence
            },
            scheduled_scan_evidence: ScheduledScanEvidence::NoSchedule,
            ..healthy_evidence()
        };
        let node_states = step_states(&protection_evidence);
        assert_eq!(node_states[ON_ACCESS_POSITION], StepNodeState::HasFailed);
        assert_eq!(node_states[SCHEDULED_POSITION], StepNodeState::NeedsReview);
    }

    #[test]
    fn a_replaceable_scanner_program_fails_before_every_other_step() {
        let protection_evidence = ProtectionEvidence {
            program_trust_findings: vec![ProgramTrustFinding::OnlyReplaceableProgram {
                program_name: "clamdscan",
                replaceable_paths: vec!["/home/user/.local/bin/clamdscan".to_owned()],
            }],
            ..healthy_evidence()
        };
        let node_states = step_states(&protection_evidence);
        assert_eq!(node_states[0], StepNodeState::HasFailed);
        assert_eq!(
            node_states.len(),
            step_states(&healthy_evidence()).len() + 1
        );
    }

    #[test]
    fn a_foreign_allowlist_needs_review_after_every_other_step() {
        let protection_evidence = ProtectionEvidence {
            trust_list: TrustListContents {
                foreign_allowlists: vec![
                    crate::protection_page::trusted_detections_page::trust_list_contents::ForeignAllowlistFile {
                        file_name: "local.ign2".to_owned(),
                        entry_count: 3,
                    },
                ],
                ..TrustListContents::default()
            },
            ..healthy_evidence()
        };
        let node_states = step_states(&protection_evidence);
        assert_eq!(node_states.last(), Some(&StepNodeState::NeedsReview));
        assert_eq!(
            node_states.len(),
            step_states(&healthy_evidence()).len() + 1
        );
    }

    #[test]
    fn a_runtime_reduction_stays_visible_as_needing_review() {
        let protection_evidence = ProtectionEvidence {
            runtime_reductions: RuntimeReductions::ReducedSince {
                changed_unix_seconds: 1_794_223_800,
                reduced_settings: vec![
                    crate::protection_page::protection_evidence::ReducedSetting {
                        setting_key: "OnAccessPrevention".to_owned(),
                        base_value: "yes".to_owned(),
                        changed_value: "no".to_owned(),
                    },
                ],
            },
            ..healthy_evidence()
        };
        let node_states = step_states(&protection_evidence);
        assert_eq!(node_states.last(), Some(&StepNodeState::NeedsReview));
        assert_eq!(
            node_states.len(),
            step_states(&healthy_evidence()).len() + 1
        );
    }

    #[test]
    fn a_broad_exclusion_needs_review_and_opens_the_exclusions() {
        let protection_evidence = ProtectionEvidence {
            account_setting_findings: vec![AccountSettingFinding::BroadExclusion {
                exclusion_pattern: "*".to_owned(),
                skipped_example: "/home/alex/Downloads/invoice.pdf.exe".to_owned(),
            }],
            ..healthy_evidence()
        };
        let timeline = protection_timeline(
            &protection_evidence,
            &ready_alerts(),
            DistributionFamily::NixosFamily,
        );
        let account_step = timeline.timeline_steps.last().unwrap();
        assert_eq!(account_step.node_state, StepNodeState::NeedsReview);
        assert!(matches!(
            account_step.action_slot,
            StepActionSlot::ActionOffered {
                chosen_action: TimelineStepAction::OpenSettingsSubpage(
                    SettingsSubpage::ScanExclusions
                ),
                ..
            }
        ));
    }

    #[test]
    fn an_ignored_shadowing_program_only_needs_review() {
        let protection_evidence = ProtectionEvidence {
            program_trust_findings: vec![ProgramTrustFinding::ReplaceableProgramIgnored {
                program_name: "clamscan",
                trusted_path: "/usr/bin/clamscan".to_owned(),
                ignored_paths: vec!["/home/user/.local/bin/clamscan".to_owned()],
            }],
            ..healthy_evidence()
        };
        assert_eq!(
            step_states(&protection_evidence)[0],
            StepNodeState::NeedsReview
        );
    }

    #[test]
    fn running_without_prevention_is_never_reported_as_blocking() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: OnAccessEvidence {
                prevention_enabled: false,
                ..healthy_evidence().on_access_evidence
            },
            ..healthy_evidence()
        };
        assert_eq!(
            step_states(&protection_evidence)[ON_ACCESS_POSITION],
            StepNodeState::NeedsReview
        );
        assert!(coverage_summary(&protection_evidence).contains("not blocked"));
    }

    #[test]
    fn finding_threats_is_not_a_scan_failure_but_a_scanner_error_is() {
        assert!(!scan_result_failed(&ServiceLastResult::ExitedWithStatus {
            exit_status: 1
        }));
        assert!(scan_result_failed(&ServiceLastResult::ExitedWithStatus {
            exit_status: 2
        }));
        assert!(scan_result_failed(&ServiceLastResult::FailedWithResult {
            result_name: "timeout".to_owned()
        }));
    }

    #[test]
    fn a_failed_updater_or_stale_source_warns_even_with_fresh_definitions() {
        let failed_updater = ProtectionEvidence {
            signature_evidence: SignatureEvidence {
                updater_evidence: vec![UpdaterEvidence {
                    updater_name: "fangfrisch",
                    service_unit: "clamav-fangfrisch.service",
                    last_result: ServiceLastResult::ExitedWithStatus { exit_status: 1 },
                    last_completed_run: ServiceRunHistory::NoCompletedRun,
                }],
                ..healthy_evidence().signature_evidence
            },
            ..healthy_evidence()
        };
        assert_eq!(
            step_states(&failed_updater)[SIGNATURE_POSITION],
            StepNodeState::NeedsReview
        );
    }

    fn alert_step_state(
        alert_readiness: &AlertReadiness,
        background_service_state: UnitState,
    ) -> StepNodeState {
        alerts_step(
            alert_readiness,
            background_service_state,
            DistributionFamily::NixosFamily,
        )
        .node_state
    }

    #[test]
    fn alerts_are_only_complete_when_they_will_actually_fire() {
        assert_eq!(
            alert_step_state(&ready_alerts(), UnitState::UnitActive),
            StepNodeState::Completed
        );
        assert_eq!(
            alert_step_state(&ready_alerts(), UnitState::UnitNotFound),
            StepNodeState::NeedsReview
        );
        assert_eq!(
            alert_step_state(
                &AlertReadiness {
                    notifications_enabled: false,
                    ..ready_alerts()
                },
                UnitState::UnitActive
            ),
            StepNodeState::NeedsReview
        );
        assert_eq!(
            alert_step_state(
                &AlertReadiness {
                    journal_access: JournalAccess::JournalUnreadable,
                    ..ready_alerts()
                },
                UnitState::UnitActive
            ),
            StepNodeState::HasFailed
        );
    }

    #[test]
    fn a_missing_engine_says_nothing_is_being_checked() {
        let protection_evidence = ProtectionEvidence {
            engine_installation: EngineInstallation::EngineMissing,
            ..healthy_evidence()
        };
        assert_eq!(step_states(&protection_evidence)[0], StepNodeState::ActNext);
        assert!(coverage_summary(&protection_evidence).contains("nothing is being checked"));
    }
}
