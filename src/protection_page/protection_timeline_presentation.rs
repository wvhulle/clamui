use gettextrs::{gettext, ngettext};
use jiff::{SignedDuration, Timestamp};

use crate::{
    application_window::settings_navigation::SettingsSubpage,
    hardening_page::suggested_audit_commands::{SuggestedRemedy, suggested_command},
    host_services::{
        clamav_programs::distribution_install_guides::{DistributionFamily, engine_install_guides},
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::{MomentFormatters, byte_size_text, exact_local_time_text},
        detection_journal::detection_journal_follower::JournalAccess,
        systemd_bus::host_systemd_units::{UnitActivity, UnitState, UnitTimestamp},
    },
    protection_page::{
        clamav_engine_evidence::DatabaseEvidence,
        protection_evidence::{
            AccountSettingFinding, DaemonEvidence, EngineInstallation, LoadedSignatures,
            OnAccessEvidence, OnAccessScanner, OnAccessSizeLimit, ProgramTrustFinding,
            ProtectionEvidence, RuntimeReductions, ScanServiceEvidence, ScanUnitResult,
            ScheduledScanEvidence, SignatureEvidence, ThirdPartySignatureFile, UpdaterEvidence,
            UpdaterUnitResult,
        },
        service_run_journal::{ScanRunFindings, ScanRunHistory, UpdaterRunHistory},
        signature_update_run::signature_update_session::{
            LastManualUpdate, SignatureUpdateProgress, SignatureUpdateView,
        },
        trusted_detections_page::trust_list_contents::TrustListContents,
    },
    shared_widgets::step_timeline::timeline_step_contents::{
        EvidenceMoment, StepActionSlot, StepEvidenceRow, StepNodeState, TimelineStep,
        TimelineStepAction, moment_value_text,
    },
    signatures_page::signature_provider_catalogue::provider_of_signature_file,
};

const DATABASE_FRESH_LIMIT: SignedDuration = SignedDuration::from_hours(4 * 24);
const DATABASE_STALE_LIMIT: SignedDuration = SignedDuration::from_hours(8 * 24);
const THIRD_PARTY_STALE_LIMIT: SignedDuration = SignedDuration::from_hours(48);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertReadiness {
    pub journal_access: JournalAccess,
    pub notifications_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionTimeline {
    pub coverage_summary: String,
    pub protection_steps: Vec<TimelineStep>,
    pub engine_steps: Vec<TimelineStep>,
    pub review_steps: Vec<TimelineStep>,
}

#[derive(Clone)]
pub struct ProtectionActivity {
    pub signature_update: SignatureUpdateView,
    pub scheduled_scan_starting: bool,
    pub observed_at: Timestamp,
    pub moment_formatters: &'static MomentFormatters,
}

impl ProtectionActivity {
    const fn moment_context(&self) -> MomentContext {
        MomentContext {
            moment_formatters: self.moment_formatters,
            reference_moment: self.observed_at,
        }
    }
}

fn evidence_row(evidence_name: String, evidence_value: String) -> StepEvidenceRow {
    StepEvidenceRow::current_fact(evidence_name, evidence_value)
}

#[derive(Clone, Copy)]
struct MomentContext {
    moment_formatters: &'static MomentFormatters,
    reference_moment: Timestamp,
}

fn timed_evidence_row(
    evidence_name: String,
    evidence_moment: EvidenceMoment,
    moment_details: String,
    moment_context: MomentContext,
) -> StepEvidenceRow {
    StepEvidenceRow {
        evidence_moment,
        ..evidence_row(
            evidence_name,
            moment_value_text(
                moment_context.moment_formatters,
                evidence_moment,
                moment_details,
                moment_context.reference_moment,
            ),
        )
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
        changed_at,
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
            .replace("{time}", &exact_local_time_text(*changed_at)),
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

fn database_state(
    database_evidence: &DatabaseEvidence,
    reference_moment: Timestamp,
) -> StepNodeState {
    match database_evidence {
        DatabaseEvidence::BuiltAt { built_at } if *built_at > reference_moment => {
            StepNodeState::NeedsReview
        }
        DatabaseEvidence::BuiltAt { built_at }
            if reference_moment.duration_since(*built_at) < DATABASE_FRESH_LIMIT =>
        {
            StepNodeState::Completed
        }
        DatabaseEvidence::BuiltAt { built_at }
            if reference_moment.duration_since(*built_at) < DATABASE_STALE_LIMIT =>
        {
            StepNodeState::NeedsReview
        }
        DatabaseEvidence::BuiltAt { .. } | DatabaseEvidence::DatabaseMissing => {
            StepNodeState::HasFailed
        }
        DatabaseEvidence::AgeUndetermined => StepNodeState::NeedsReview,
    }
}

fn database_status_text(
    database_evidence: &DatabaseEvidence,
    moment_context: MomentContext,
) -> String {
    match database_evidence {
        DatabaseEvidence::BuiltAt { built_at } if *built_at <= moment_context.reference_moment => {
            gettext("Definitions built {when} ({date})")
                .replace(
                    "{when}",
                    &moment_context
                        .moment_formatters
                        .relative_moment_text(*built_at, moment_context.reference_moment),
                )
                .replace(
                    "{date}",
                    &moment_context
                        .moment_formatters
                        .calendar_date_text(*built_at),
                )
        }
        DatabaseEvidence::BuiltAt { .. } | DatabaseEvidence::AgeUndetermined => {
            gettext("Definitions exist, but their age could not be determined")
        }
        DatabaseEvidence::DatabaseMissing => gettext("No virus definitions were found"),
    }
}

fn updater_failed(updater_evidence: &UpdaterEvidence) -> bool {
    match updater_evidence.last_result {
        UpdaterUnitResult::UpdateSucceeded | UpdaterUnitResult::UpdateAlreadyCurrent => false,
        UpdaterUnitResult::UpdaterError { .. } | UpdaterUnitResult::ServiceFailed { .. } => true,
    }
}

impl From<ScanRunHistory> for EvidenceMoment {
    fn from(run_history: ScanRunHistory) -> Self {
        match run_history {
            ScanRunHistory::CompletedScan { finished_at, .. } => Self::PastEvent {
                happened_at: finished_at,
            },
            ScanRunHistory::NoCompletedScan => Self::NeverHappened,
        }
    }
}

impl From<UpdaterRunHistory> for EvidenceMoment {
    fn from(run_history: UpdaterRunHistory) -> Self {
        match run_history {
            UpdaterRunHistory::CompletedUpdate { finished_at } => Self::PastEvent {
                happened_at: finished_at,
            },
            UpdaterRunHistory::NoCompletedUpdate => Self::NeverHappened,
        }
    }
}

impl From<UnitTimestamp> for EvidenceMoment {
    fn from(unit_timestamp: UnitTimestamp) -> Self {
        match unit_timestamp {
            UnitTimestamp::RecordedAt { recorded_at } => Self::UpcomingEvent {
                due_at: recorded_at,
            },
            UnitTimestamp::NeverRecorded => Self::NothingUpcoming,
        }
    }
}

fn updater_row(
    updater_evidence: &UpdaterEvidence,
    moment_context: MomentContext,
) -> StepEvidenceRow {
    let evidence_moment = EvidenceMoment::from(updater_evidence.last_completed_run);
    let evidence_value = if updater_failed(updater_evidence) {
        gettext("Its last update failed")
    } else if evidence_moment == EvidenceMoment::NeverHappened {
        gettext("No completed update recorded yet")
    } else {
        String::new()
    };
    timed_evidence_row(
        gettext("{updater} updated")
            .replace("{updater}", updater_evidence.updater_program.program_name()),
        evidence_moment,
        evidence_value,
        moment_context,
    )
}

fn third_party_file_row(
    signature_file: &ThirdPartySignatureFile,
    moment_context: MomentContext,
) -> StepEvidenceRow {
    timed_evidence_row(
        gettext("{provider} fetched").replace(
            "{provider}",
            provider_of_signature_file(&signature_file.file_name),
        ),
        EvidenceMoment::PastEvent {
            happened_at: signature_file.modified_at,
        },
        ngettext(
            "{count} signature, {size} ({file})",
            "{count} signatures, {size} ({file})",
            u32::try_from(signature_file.signature_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &signature_file.signature_count.to_string())
        .replace("{size}", &byte_size_text(signature_file.file_size))
        .replace("{file}", &signature_file.file_name),
        moment_context,
    )
}

fn update_progress_of(signature_update: &SignatureUpdateView) -> SignatureUpdateProgress {
    match signature_update {
        SignatureUpdateView::HostStatusLoading => SignatureUpdateProgress::UpdateUnavailable,
        SignatureUpdateView::HostStatusKnown(known_host) => known_host.update_progress.clone(),
    }
}

fn update_now_row(
    signature_update: &SignatureUpdateView,
    update_progress: &SignatureUpdateProgress,
    suggest_update: bool,
    moment_context: MomentContext,
) -> StepEvidenceRow {
    let last_manual_update = match signature_update {
        SignatureUpdateView::HostStatusLoading => &LastManualUpdate::NotRunThisSession,
        SignatureUpdateView::HostStatusKnown(known_host) => &known_host.last_manual_update,
    };
    let (evidence_moment, evidence_value) = match last_manual_update {
        LastManualUpdate::FinishedAt {
            summary_line,
            finished_at,
        } => (
            EvidenceMoment::PastEvent {
                happened_at: *finished_at,
            },
            summary_line.clone(),
        ),
        LastManualUpdate::NotRunThisSession => (
            EvidenceMoment::CurrentFact,
            gettext("Fetch the newest signatures from every updater now"),
        ),
    };
    let row_action = match update_progress {
        SignatureUpdateProgress::ReadyToUpdate => StepActionSlot::ActionOffered {
            action_label: gettext("Update Now"),
            chosen_action: TimelineStepAction::UpdateSignatures,
            action_suggested: suggest_update,
        },
        SignatureUpdateProgress::CancellableUpdateRunning { .. } => StepActionSlot::ActionOffered {
            action_label: gettext("Cancel"),
            chosen_action: TimelineStepAction::CancelSignatureUpdate,
            action_suggested: false,
        },
        SignatureUpdateProgress::UncancellableUpdateRunning { .. }
        | SignatureUpdateProgress::UpdateCancelling
        | SignatureUpdateProgress::UpdateUnavailable => StepActionSlot::NoAction,
    };
    StepEvidenceRow {
        row_action,
        ..timed_evidence_row(
            gettext("Manual update"),
            evidence_moment,
            evidence_value,
            moment_context,
        )
    }
}

fn update_host_rows(signature_update: &SignatureUpdateView) -> Vec<StepEvidenceRow> {
    match signature_update {
        SignatureUpdateView::HostStatusLoading => Vec::new(),
        SignatureUpdateView::HostStatusKnown(known_host) => vec![
            evidence_row(
                gettext("Update service"),
                known_host.update_service_text.clone(),
            ),
            evidence_row(
                gettext("Database folder"),
                known_host.database_folder_text.clone(),
            ),
        ],
    }
}

fn updater_output_rows(update_progress: &SignatureUpdateProgress) -> Vec<StepEvidenceRow> {
    match update_progress {
        SignatureUpdateProgress::CancellableUpdateRunning { latest_output_line }
        | SignatureUpdateProgress::UncancellableUpdateRunning { latest_output_line } => {
            vec![StepEvidenceRow {
                evidence_moment: EvidenceMoment::HappeningNow,
                ..evidence_row(gettext("Updater output"), latest_output_line.clone())
            }]
        }
        SignatureUpdateProgress::UpdateCancelling
        | SignatureUpdateProgress::ReadyToUpdate
        | SignatureUpdateProgress::UpdateUnavailable => Vec::new(),
    }
}

fn signature_step(
    signature_evidence: &SignatureEvidence,
    signature_update: &SignatureUpdateView,
    moment_context: MomentContext,
    distribution_family: DistributionFamily,
) -> TimelineStep {
    let any_updater_failed = signature_evidence
        .updater_evidence
        .iter()
        .any(updater_failed);
    let any_source_stale = signature_evidence
        .third_party_files
        .iter()
        .any(|signature_file| {
            moment_context
                .reference_moment
                .duration_since(signature_file.modified_at)
                > THIRD_PARTY_STALE_LIMIT
        });
    let base_state = database_state(
        &signature_evidence.database_evidence,
        moment_context.reference_moment,
    );
    let evidence_state =
        if base_state == StepNodeState::Completed && (any_updater_failed || any_source_stale) {
            StepNodeState::NeedsReview
        } else {
            base_state
        };
    let update_progress = update_progress_of(signature_update);
    let (node_state, status_text) = match &update_progress {
        SignatureUpdateProgress::CancellableUpdateRunning { .. }
        | SignatureUpdateProgress::UncancellableUpdateRunning { .. } => {
            (StepNodeState::InProgress, gettext("Updating signatures…"))
        }
        SignatureUpdateProgress::UpdateCancelling => {
            (StepNodeState::InProgress, gettext("Cancelling the update…"))
        }
        SignatureUpdateProgress::ReadyToUpdate | SignatureUpdateProgress::UpdateUnavailable => (
            evidence_state,
            database_status_text(&signature_evidence.database_evidence, moment_context),
        ),
    };
    let evidence_rows = std::iter::once(update_now_row(
        signature_update,
        &update_progress,
        evidence_state != StepNodeState::Completed,
        moment_context,
    ))
    .chain(updater_output_rows(&update_progress))
    .chain(
        signature_evidence
            .updater_evidence
            .iter()
            .map(|updater_evidence| updater_row(updater_evidence, moment_context)),
    )
    .chain(
        signature_evidence
            .third_party_files
            .iter()
            .map(|signature_file| third_party_file_row(signature_file, moment_context)),
    )
    .chain(update_host_rows(signature_update))
    .collect();
    TimelineStep {
        evidence_rows,
        guidance_commands: if signature_evidence.updater_evidence.is_empty() {
            remedy_commands(SuggestedRemedy::FreshclamUpdatesEnable, distribution_family)
        } else {
            Vec::new()
        },
        ..no_guidance_step(
            gettext("Signatures current"),
            gettext(
                "Signatures describe known malware, and new ones are published constantly. Old \
                 signatures miss recent threats even when everything else is running.",
            ),
            node_state,
            status_text,
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

fn on_access_setting_row(evidence_name: String, evidence_value: String) -> StepEvidenceRow {
    StepEvidenceRow {
        evidence_moment: EvidenceMoment::ChangeableSetting {
            settings_subpage: SettingsSubpage::OnAccessScanning,
        },
        ..evidence_row(evidence_name, evidence_value)
    }
}

fn on_access_rows(on_access_evidence: &OnAccessEvidence) -> Vec<StepEvidenceRow> {
    let watched_row = on_access_setting_row(
        gettext("Watched folders"),
        if on_access_evidence.watched_paths.is_empty() {
            gettext("None configured")
        } else {
            on_access_evidence.watched_paths.join("\n")
        },
    );
    let size_row = on_access_setting_row(
        gettext("Largest file scanned"),
        match &on_access_evidence.size_limit {
            OnAccessSizeLimit::DefaultLimit => gettext("The ClamAV default"),
            OnAccessSizeLimit::ConfiguredLimit { size_limit } => byte_size_text(*size_limit),
            OnAccessSizeLimit::UnreadableLimit { limit_text } => limit_text.clone(),
        },
    );
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
        _configured_scanner if !daemon_answering => {
            (StepNodeState::AwaitingPrerequisite, daemon_awaited_text())
        }
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

fn daemon_awaited_text() -> String {
    gettext("Needs the daemon, see Engine below")
}

fn next_run_text(next_run: UnitTimestamp) -> String {
    match next_run {
        UnitTimestamp::RecordedAt { recorded_at } => exact_local_time_text(recorded_at),
        UnitTimestamp::NeverRecorded => gettext("Not scheduled"),
    }
}

fn next_run_row(next_run: UnitTimestamp, moment_context: MomentContext) -> StepEvidenceRow {
    let evidence_value = match next_run {
        UnitTimestamp::RecordedAt { .. } => String::new(),
        UnitTimestamp::NeverRecorded => gettext("Not scheduled"),
    };
    timed_evidence_row(
        gettext("Next scan"),
        EvidenceMoment::from(next_run),
        evidence_value,
        moment_context,
    )
}

fn last_run_row(
    last_completed_run: ScanRunHistory,
    row_action: StepActionSlot,
    moment_context: MomentContext,
) -> StepEvidenceRow {
    let evidence_value = match last_completed_run {
        ScanRunHistory::CompletedScan {
            scan_findings: ScanRunFindings::ThreatsFound,
            ..
        } => gettext("threats found"),
        ScanRunHistory::CompletedScan {
            scan_findings: ScanRunFindings::NothingFound,
            ..
        } => gettext("nothing found"),
        ScanRunHistory::NoCompletedScan => gettext("Not run yet"),
    };
    StepEvidenceRow {
        row_action,
        ..timed_evidence_row(
            gettext("Last scan"),
            EvidenceMoment::from(last_completed_run),
            evidence_value,
            moment_context,
        )
    }
}

fn scan_result_failed(last_result: &ScanUnitResult) -> bool {
    match last_result {
        ScanUnitResult::NothingFound | ScanUnitResult::ThreatsFound => false,
        ScanUnitResult::ScannerError { .. } | ScanUnitResult::ServiceFailed { .. } => true,
    }
}

fn scanned_folders_text(scan_service: &ScanServiceEvidence) -> String {
    match scan_service {
        ScanServiceEvidence::ServiceConfigured { scan_targets, .. } => scan_targets.join("\n"),
        ScanServiceEvidence::ServiceMissing | ScanServiceEvidence::ServiceUnreadable => {
            gettext("Unknown")
        }
    }
}

fn scheduled_scan_step(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    scheduled_scan_starting: bool,
    daemon_answering: bool,
    moment_context: MomentContext,
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
            scan_service,
            last_completed_run,
        } => {
            let (node_state, status_text) = if !daemon_answering {
                (StepNodeState::AwaitingPrerequisite, daemon_awaited_text())
            } else if !timer_active {
                (
                    StepNodeState::HasFailed,
                    gettext("The system timer is not active"),
                )
            } else if scheduled_scan_starting {
                (StepNodeState::InProgress, gettext("Starting the scan…"))
            } else {
                match scan_service {
                    ScanServiceEvidence::ServiceConfigured { last_result, .. }
                        if scan_result_failed(last_result) =>
                    {
                        (
                            StepNodeState::NeedsReview,
                            gettext("The last scan ended with an error"),
                        )
                    }
                    ScanServiceEvidence::ServiceConfigured { .. } => (
                        StepNodeState::Completed,
                        gettext("Next scan: {time}").replace("{time}", &next_run_text(*next_run)),
                    ),
                    ScanServiceEvidence::ServiceMissing => (
                        StepNodeState::NeedsReview,
                        gettext("The timer starts a scan service that is not installed"),
                    ),
                    ScanServiceEvidence::ServiceUnreadable => (
                        StepNodeState::NeedsReview,
                        gettext("The scan service could not be read from systemd"),
                    ),
                }
            };
            let run_action = if scheduled_scan_starting || !daemon_answering {
                StepActionSlot::NoAction
            } else {
                StepActionSlot::ActionOffered {
                    action_label: gettext("Run Now"),
                    chosen_action: TimelineStepAction::RunScheduledScan { service_unit },
                    action_suggested: false,
                }
            };
            TimelineStep {
                evidence_rows: vec![
                    next_run_row(*next_run, moment_context),
                    last_run_row(*last_completed_run, run_action, moment_context),
                    StepEvidenceRow {
                        evidence_moment: EvidenceMoment::FixedSetting,
                        ..evidence_row(
                            gettext("Folders scanned"),
                            scanned_folders_text(scan_service),
                        )
                    },
                ],
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
        JournalAccess::FollowingJournal
            if background_service_state != UnitState::UnitLoaded(UnitActivity::UnitActive) =>
        {
            (
                StepNodeState::NeedsReview,
                gettext(
                    "Alerts stop when you quit Lazaret, because it isn't set up to run in the \
                     background",
                ),
            )
        }
        JournalAccess::FollowingJournal => (
            StepNodeState::Completed,
            gettext("Running in the background and following the journal"),
        ),
    };
    TimelineStep {
        guidance_commands: if alert_readiness.journal_access == JournalAccess::FollowingJournal
            && alert_readiness.notifications_enabled
            && background_service_state != UnitState::UnitLoaded(UnitActivity::UnitActive)
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
            scan_service: ScanServiceEvidence::ServiceConfigured { scan_targets, .. },
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
    protection_activity: &ProtectionActivity,
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
        protection_steps: vec![
            on_access_step(
                &protection_evidence.on_access_evidence,
                daemon_answering,
                distribution_family,
            ),
            scheduled_scan_step(
                &protection_evidence.scheduled_scan_evidence,
                protection_activity.scheduled_scan_starting,
                daemon_answering,
                protection_activity.moment_context(),
                distribution_family,
            ),
            alerts_step(
                alert_readiness,
                protection_evidence.background_service_state,
                distribution_family,
            ),
        ],
        engine_steps: engine_problem
            .into_iter()
            .chain(program_trust_step(
                &protection_evidence.program_trust_findings,
            ))
            .chain([
                signature_step(
                    &protection_evidence.signature_evidence,
                    &protection_activity.signature_update,
                    protection_activity.moment_context(),
                    distribution_family,
                ),
                daemon_step(&protection_evidence.daemon_evidence, distribution_family),
            ])
            .collect(),
        review_steps: runtime_reduction_step(&protection_evidence.runtime_reductions)
            .into_iter()
            .chain(account_settings_step(
                &protection_evidence.account_setting_findings,
            ))
            .chain(trust_list_step(&protection_evidence.trust_list))
            .collect(),
    }
}

#[cfg(test)]
mod protection_timeline_presentation_tests {
    use bytesize::ByteSize;

    use super::*;
    use crate::{
        host_services::systemd_bus::host_systemd_units::ServiceFailureKind,
        protection_page::signature_update_run::updater_exit_status::SignatureUpdaterProgram,
    };

    const REFERENCE_MOMENT: Timestamp = Timestamp::constant(1_794_200_000, 0);

    fn english_formatters() -> &'static MomentFormatters {
        static ENGLISH_FORMATTERS: std::sync::OnceLock<MomentFormatters> =
            std::sync::OnceLock::new();
        ENGLISH_FORMATTERS.get_or_init(|| {
            MomentFormatters::try_for_locales(
                &icu::locale::locale!("en"),
                &icu::locale::locale!("en"),
            )
            .unwrap()
        })
    }

    fn known_update_host(update_progress: SignatureUpdateProgress) -> SignatureUpdateView {
        SignatureUpdateView::HostStatusKnown(
            crate::protection_page::signature_update_run::signature_update_session::KnownUpdateHost {
                update_progress,
                last_manual_update: LastManualUpdate::NotRunThisSession,
                update_service_text: "Active".to_owned(),
                database_folder_text: "/var/lib/clamav".to_owned(),
            },
        )
    }

    fn idle_activity() -> ProtectionActivity {
        ProtectionActivity {
            signature_update: known_update_host(SignatureUpdateProgress::ReadyToUpdate),
            scheduled_scan_starting: false,
            observed_at: REFERENCE_MOMENT,
            moment_formatters: english_formatters(),
        }
    }

    fn timeline_with(
        protection_evidence: &ProtectionEvidence,
        protection_activity: &ProtectionActivity,
    ) -> ProtectionTimeline {
        protection_timeline(
            protection_evidence,
            &ready_alerts(),
            protection_activity,
            DistributionFamily::NixosFamily,
        )
    }

    fn idle_timeline(protection_evidence: &ProtectionEvidence) -> ProtectionTimeline {
        timeline_with(protection_evidence, &idle_activity())
    }

    fn step_titled<'timeline>(
        timeline_steps: &'timeline [TimelineStep],
        step_title: &str,
    ) -> &'timeline TimelineStep {
        timeline_steps
            .iter()
            .find(|timeline_step| timeline_step.step_title == step_title)
            .unwrap()
    }

    fn step_titles(timeline_steps: &[TimelineStep]) -> Vec<&str> {
        timeline_steps
            .iter()
            .map(|timeline_step| timeline_step.step_title.as_str())
            .collect()
    }

    fn row_named<'step>(
        timeline_step: &'step TimelineStep,
        evidence_name: &str,
    ) -> &'step StepEvidenceRow {
        timeline_step
            .evidence_rows
            .iter()
            .find(|step_evidence| step_evidence.evidence_name == evidence_name)
            .unwrap()
    }

    fn all_steps(protection_timeline: ProtectionTimeline) -> Vec<TimelineStep> {
        protection_timeline
            .protection_steps
            .into_iter()
            .chain(protection_timeline.engine_steps)
            .chain(protection_timeline.review_steps)
            .collect()
    }

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
                database_evidence: DatabaseEvidence::BuiltAt {
                    built_at: REFERENCE_MOMENT - SignedDuration::from_hours(5),
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
                    size_limit: ByteSize::mib(100),
                },
            },
            scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                service_unit: "clamdscan.service",
                timer_active: true,
                next_run: UnitTimestamp::RecordedAt {
                    recorded_at: REFERENCE_MOMENT + SignedDuration::from_hours(6),
                },
                scan_service: ScanServiceEvidence::ServiceConfigured {
                    scan_targets: vec!["/tmp".to_owned(), "/var/tmp".to_owned()],
                    last_result: ScanUnitResult::NothingFound,
                },
                last_completed_run: ScanRunHistory::NoCompletedScan,
            },
            background_service_state: UnitState::UnitLoaded(UnitActivity::UnitActive),
        }
    }

    fn ready_alerts() -> AlertReadiness {
        AlertReadiness {
            journal_access: JournalAccess::FollowingJournal,
            notifications_enabled: true,
        }
    }

    fn step_states(protection_evidence: &ProtectionEvidence) -> Vec<StepNodeState> {
        all_steps(idle_timeline(protection_evidence))
            .iter()
            .map(|timeline_step| timeline_step.node_state)
            .collect()
    }

    fn state_of(protection_evidence: &ProtectionEvidence, step_title: &str) -> StepNodeState {
        step_titled(&all_steps(idle_timeline(protection_evidence)), step_title).node_state
    }

    #[tokio::test]
    #[ignore = "reads the real host"]
    async fn host_timeline_reports_the_real_backend() {
        let host_timeline = protection_timeline(
            &crate::protection_page::protection_evidence::gather_protection_evidence(false).await,
            &ready_alerts(),
            &idle_activity(),
            crate::host_services::clamav_programs::distribution_install_guides::detect_distribution_family(),
        );
        println!("{}", host_timeline.coverage_summary);
        all_steps(host_timeline).iter().for_each(|timeline_step| {
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
    fn panes_follow_a_file_and_the_engine_comes_after() {
        let healthy_timeline = idle_timeline(&healthy_evidence());
        assert_eq!(
            step_titles(&healthy_timeline.protection_steps),
            vec!["On-access blocking", "Scheduled scan", "Alerts"]
        );
        assert_eq!(
            step_titles(&healthy_timeline.engine_steps),
            vec!["Signatures current", "Daemon running"]
        );
        assert!(healthy_timeline.review_steps.is_empty());
    }

    #[test]
    fn the_installation_step_only_appears_when_clamav_is_missing() {
        let missing_timeline = idle_timeline(&ProtectionEvidence {
            engine_installation: EngineInstallation::EngineMissing,
            ..healthy_evidence()
        });
        assert_eq!(
            missing_timeline.engine_steps[0].step_title,
            "ClamAV installed"
        );
        assert_eq!(
            idle_timeline(&healthy_evidence()).engine_steps[0].step_title,
            "Signatures current"
        );
    }

    #[test]
    fn each_row_says_whether_it_is_past_upcoming_or_a_setting() {
        let healthy_steps = all_steps(idle_timeline(&ProtectionEvidence {
            scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                service_unit: "clamdscan.service",
                timer_active: true,
                next_run: UnitTimestamp::RecordedAt {
                    recorded_at: REFERENCE_MOMENT
                        + SignedDuration::from_hours(72)
                        + SignedDuration::from_mins(1),
                },
                scan_service: ScanServiceEvidence::ServiceConfigured {
                    scan_targets: vec!["/tmp".to_owned()],
                    last_result: ScanUnitResult::NothingFound,
                },
                last_completed_run: ScanRunHistory::CompletedScan {
                    finished_at: REFERENCE_MOMENT - SignedDuration::from_hours(2),
                    scan_findings: ScanRunFindings::NothingFound,
                },
            },
            ..healthy_evidence()
        }));
        let scheduled_step = step_titled(&healthy_steps, "Scheduled scan");
        assert_eq!(
            row_named(scheduled_step, "Next scan").evidence_value,
            "in 3 days"
        );
        let last_scan_row = row_named(scheduled_step, "Last scan");
        assert_eq!(last_scan_row.evidence_value, "2 hours ago · nothing found");
        assert!(matches!(
            last_scan_row.row_action,
            StepActionSlot::ActionOffered {
                chosen_action: TimelineStepAction::RunScheduledScan { .. },
                ..
            }
        ));
        assert_eq!(scheduled_step.action_slot, StepActionSlot::NoAction);
        assert_eq!(
            row_named(
                step_titled(&healthy_steps, "On-access blocking"),
                "Watched folders"
            )
            .evidence_moment,
            EvidenceMoment::ChangeableSetting {
                settings_subpage: SettingsSubpage::OnAccessScanning
            }
        );
        let signature_step = step_titled(&healthy_steps, "Signatures current");
        assert_eq!(signature_step.action_slot, StepActionSlot::NoAction);
        assert!(matches!(
            row_named(signature_step, "Manual update").row_action,
            StepActionSlot::ActionOffered {
                chosen_action: TimelineStepAction::UpdateSignatures,
                ..
            }
        ));
        assert!(
            signature_step
                .status_text
                .starts_with("Definitions built 5 hours ago (")
        );
    }

    #[test]
    fn a_running_update_shows_its_progress_and_can_be_cancelled() {
        let running_activity = ProtectionActivity {
            signature_update: known_update_host(
                SignatureUpdateProgress::CancellableUpdateRunning {
                    latest_output_line: "daily.cld updated".to_owned(),
                },
            ),
            ..idle_activity()
        };
        let running_timeline = timeline_with(&healthy_evidence(), &running_activity);
        let signature_step = step_titled(&running_timeline.engine_steps, "Signatures current");
        assert_eq!(signature_step.node_state, StepNodeState::InProgress);
        let output_row = row_named(signature_step, "Updater output");
        assert_eq!(output_row.evidence_moment, EvidenceMoment::HappeningNow);
        assert_eq!(output_row.evidence_value, "daily.cld updated");
        assert!(matches!(
            row_named(signature_step, "Manual update").row_action,
            StepActionSlot::ActionOffered {
                chosen_action: TimelineStepAction::CancelSignatureUpdate,
                ..
            }
        ));
    }

    #[test]
    fn a_starting_scan_is_in_progress_and_cannot_be_started_twice() {
        let starting_timeline = timeline_with(
            &healthy_evidence(),
            &ProtectionActivity {
                scheduled_scan_starting: true,
                ..idle_activity()
            },
        );
        let scheduled_step = step_titled(&starting_timeline.protection_steps, "Scheduled scan");
        assert_eq!(scheduled_step.node_state, StepNodeState::InProgress);
        assert_eq!(
            row_named(scheduled_step, "Last scan").row_action,
            StepActionSlot::NoAction
        );
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
                StepNodeState::AwaitingPrerequisite,
                StepNodeState::AwaitingPrerequisite,
                StepNodeState::Completed,
                StepNodeState::Completed,
                StepNodeState::HasFailed,
            ]
        );
        assert_eq!(
            coverage_summary(&protection_evidence),
            "Files are only checked when you scan them"
        );
    }

    fn system_timer_with(scan_service: ScanServiceEvidence) -> ProtectionEvidence {
        ProtectionEvidence {
            scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                service_unit: "clamdscan.service",
                timer_active: true,
                next_run: UnitTimestamp::RecordedAt {
                    recorded_at: REFERENCE_MOMENT + SignedDuration::from_hours(6),
                },
                scan_service,
                last_completed_run: ScanRunHistory::NoCompletedScan,
            },
            ..healthy_evidence()
        }
    }

    #[test]
    fn an_unreadable_scan_service_after_a_readable_timer_needs_review() {
        let unreadable_service = system_timer_with(ScanServiceEvidence::ServiceUnreadable);
        let scheduled_steps = all_steps(idle_timeline(&unreadable_service));
        let scheduled_step = step_titled(&scheduled_steps, "Scheduled scan");
        assert_eq!(scheduled_step.node_state, StepNodeState::NeedsReview);
        assert_eq!(
            scheduled_step.status_text,
            "The scan service could not be read from systemd"
        );
        assert!(!coverage_summary(&unreadable_service).contains("scanned on a schedule"));
    }

    #[test]
    fn a_missing_scan_service_is_not_reported_as_completed() {
        assert_eq!(
            state_of(
                &system_timer_with(ScanServiceEvidence::ServiceMissing),
                "Scheduled scan"
            ),
            StepNodeState::NeedsReview
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
        assert_eq!(
            state_of(&protection_evidence, "On-access blocking"),
            StepNodeState::HasFailed
        );
        assert_eq!(
            state_of(&protection_evidence, "Scheduled scan"),
            StepNodeState::NeedsReview
        );
    }

    #[test]
    fn a_replaceable_scanner_program_fails_first_among_the_engine_steps() {
        let protection_evidence = ProtectionEvidence {
            program_trust_findings: vec![ProgramTrustFinding::OnlyReplaceableProgram {
                program_name: "clamdscan",
                replaceable_paths: vec!["/home/user/.local/bin/clamdscan".to_owned()],
            }],
            ..healthy_evidence()
        };
        let engine_steps = idle_timeline(&protection_evidence).engine_steps;
        assert_eq!(engine_steps[0].node_state, StepNodeState::HasFailed);
        assert_eq!(engine_steps.len(), 3);
    }

    #[test]
    fn a_foreign_allowlist_appears_under_needs_review() {
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
        let review_steps = idle_timeline(&protection_evidence).review_steps;
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state, StepNodeState::NeedsReview);
    }

    #[test]
    fn a_runtime_reduction_stays_visible_as_needing_review() {
        let protection_evidence = ProtectionEvidence {
            runtime_reductions: RuntimeReductions::ReducedSince {
                changed_at: REFERENCE_MOMENT,
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
        let review_steps = idle_timeline(&protection_evidence).review_steps;
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state, StepNodeState::NeedsReview);
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
        let review_steps = idle_timeline(&protection_evidence).review_steps;
        let account_step = review_steps.last().unwrap();
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
            idle_timeline(&protection_evidence).engine_steps[0].node_state,
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
            state_of(&protection_evidence, "On-access blocking"),
            StepNodeState::NeedsReview
        );
        assert!(coverage_summary(&protection_evidence).contains("not blocked"));
    }

    #[test]
    fn finding_threats_is_not_a_scan_failure_but_a_scanner_error_is() {
        assert!(!scan_result_failed(&ScanUnitResult::ThreatsFound));
        assert!(scan_result_failed(&ScanUnitResult::ScannerError {
            exit_status: 2
        }));
        assert!(scan_result_failed(&ScanUnitResult::ServiceFailed {
            failure_kind: ServiceFailureKind::TimedOut
        }));
    }

    #[test]
    fn a_failed_updater_or_stale_source_warns_even_with_fresh_definitions() {
        let failed_updater = ProtectionEvidence {
            signature_evidence: SignatureEvidence {
                updater_evidence: vec![UpdaterEvidence {
                    updater_program: SignatureUpdaterProgram::Fangfrisch,
                    service_unit: "clamav-fangfrisch.service",
                    last_result: UpdaterUnitResult::UpdaterError { exit_status: 1 },
                    last_completed_run: UpdaterRunHistory::NoCompletedUpdate,
                }],
                ..healthy_evidence().signature_evidence
            },
            ..healthy_evidence()
        };
        assert_eq!(
            state_of(&failed_updater, "Signatures current"),
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
            alert_step_state(
                &ready_alerts(),
                UnitState::UnitLoaded(UnitActivity::UnitActive)
            ),
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
                UnitState::UnitLoaded(UnitActivity::UnitActive)
            ),
            StepNodeState::NeedsReview
        );
        assert_eq!(
            alert_step_state(
                &AlertReadiness {
                    journal_access: JournalAccess::JournalUnreadable,
                    ..ready_alerts()
                },
                UnitState::UnitLoaded(UnitActivity::UnitActive)
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
        assert_eq!(
            idle_timeline(&protection_evidence).engine_steps[0].node_state,
            StepNodeState::ActNext
        );
        assert!(coverage_summary(&protection_evidence).contains("nothing is being checked"));
    }
}
