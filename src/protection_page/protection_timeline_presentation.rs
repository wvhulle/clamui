use gettextrs::{gettext, ngettext};
use jiff::{SignedDuration, Timestamp};

use crate::{
    application_window::settings_navigation::SettingsSubpage,
    hardening_page::suggested_audit_commands::{SuggestedRemedy, suggested_command},
    host_services::{
        clamav_programs::{
            component_availability::ProbeFailure,
            distribution_install_guides::{DistributionFamily, engine_install_guides},
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::{MomentFormatters, byte_size_text, exact_local_time_text},
        detection_journal::detection_journal_follower::JournalAccess,
        systemd_bus::host_systemd_units::{UnitActivity, UnitState, UnitTimestamp},
    },
    protection_page::{
        clamav_engine_evidence::DatabaseEvidence,
        protection_evidence::{
            AccountSettingFinding, ClamdConfigReadFailure, DaemonEvidence, EngineInstallation,
            LoadedSignatures, OnAccessConfig, OnAccessEvidence, OnAccessResponse, OnAccessScanner,
            OnAccessSizeLimit, OverridesChangeTime, ProgramTrustFinding, ProtectionEvidence,
            ReducedSetting, RuntimeReductions, ScanServiceEvidence, ScanUnitResult,
            ScheduledScanEvidence, SignatureEvidence, ThirdPartySignatureFile, TimerState,
            UpdaterEvidence, UpdaterUnitResult, WatchScope, WatchedLocation,
        },
        service_run_journal::{ScanRunFindings, ScanRunHistory, UpdaterRunHistory},
        signature_update_run::signature_update_session::{
            LastManualUpdate, SignatureUpdateProgress, SignatureUpdateView,
        },
        trusted_detections_page::{
            trust_list_contents::{
                AllowlistEntries, ForeignAllowlistFile, LazaretListReading, TrustListContents,
                TrustListReading,
            },
            trusted_detections_component::trust_list_failure_text,
        },
    },
    shared_widgets::{
        journal_follow_failure_text::journal_follow_failure_text,
        step_timeline::timeline_step_contents::{
            ActionConsequence, ActionableEvidenceRow, CancelSlot, EvidenceMoment,
            EvidenceRowControl, OfferedAction, RunningStep, SettledNodeState, SettledStep,
            StepActionButton, StepActionSlot, StepEvidenceRow, StepNodeState, TimelineStep,
            moment_value_text,
        },
    },
    signatures_page::signature_provider_catalogue::provider_of_signature_file,
};

const DATABASE_FRESH_LIMIT: SignedDuration = SignedDuration::from_hours(4 * 24);
const DATABASE_STALE_LIMIT: SignedDuration = SignedDuration::from_hours(8 * 24);
const THIRD_PARTY_STALE_LIMIT: SignedDuration = SignedDuration::from_hours(48);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionStepAction {
    UpdateSignatures,
    CancelSignatureUpdate,
    RunScheduledScan { service_unit: &'static str },
    ReviewSettingsSubpage(SettingsSubpage),
    SetUpSettingsSubpage(SettingsSubpage),
}

impl StepActionButton for ProtectionStepAction {
    fn button_label(&self) -> String {
        match self {
            Self::UpdateSignatures => gettext("Update Now"),
            Self::CancelSignatureUpdate => gettext("Cancel"),
            Self::RunScheduledScan { .. } => gettext("Run Now"),
            Self::ReviewSettingsSubpage(_) => gettext("Review"),
            Self::SetUpSettingsSubpage(_) => gettext("Set Up"),
        }
    }

    fn action_consequence(&self) -> ActionConsequence {
        match self {
            Self::UpdateSignatures
            | Self::CancelSignatureUpdate
            | Self::RunScheduledScan { .. }
            | Self::ReviewSettingsSubpage(_)
            | Self::SetUpSettingsSubpage(_) => ActionConsequence::OrdinaryAction,
        }
    }
}

pub type ProtectionStep = TimelineStep<ProtectionStepAction>;
type ProtectionEvidenceRow = ActionableEvidenceRow<ProtectionStepAction>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertReadiness {
    pub journal_access: JournalAccess,
    pub notifications_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionTimeline {
    pub coverage_summary: String,
    pub protection_steps: Vec<ProtectionStep>,
    pub engine_steps: Vec<ProtectionStep>,
    pub review_steps: Vec<ProtectionStep>,
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
    node_state: SettledNodeState,
    status_text: String,
) -> ProtectionStep {
    TimelineStep::settled(
        step_title,
        mechanism_details,
        status_text,
        SettledStep::without_offers(node_state),
    )
}

fn plain_rows(
    evidence_rows: impl IntoIterator<Item = StepEvidenceRow>,
) -> Vec<ProtectionEvidenceRow> {
    evidence_rows.into_iter().map(Into::into).collect()
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

fn probe_failure_text(probe_failure: &ProbeFailure) -> String {
    match probe_failure {
        ProbeFailure::ProgramPrintedFailure { program_stderr } => {
            sanitize_scanner_line(program_stderr)
        }
        ProbeFailure::ProgramStartFailed { start_failure_kind } => {
            gettext("clamscan could not be started: {error}")
                .replace("{error}", &start_failure_kind.to_string())
        }
        ProbeFailure::ProbeTimedOut => gettext("clamscan did not answer in time"),
    }
}

fn engine_step(
    engine_installation: &EngineInstallation,
    distribution_family: DistributionFamily,
) -> ProtectionStep {
    let step_title = gettext("ClamAV installed");
    let mechanism_details = gettext(
        "ClamAV is the engine that recognizes malware. Lazaret uses the copy installed on this \
         computer and never bundles its own.",
    );
    match engine_installation {
        EngineInstallation::VersionReported { version_banner } => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::Completed,
            version_banner.clone(),
        ),
        EngineInstallation::ScannerRefused { refused_path } => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::NeedsReview,
            gettext("refused {path}, because your account can replace it")
                .replace("{path}", refused_path),
        ),
        EngineInstallation::VersionUnverified(probe_failure) => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::NeedsReview,
            probe_failure_text(probe_failure),
        ),
        EngineInstallation::EngineMissing => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::ActNext,
            gettext("ClamAV was not found on this computer"),
        )
        .with_guidance_commands(
            engine_install_guides()
                .iter()
                .filter(|install_guide| install_guide.distribution_family == distribution_family)
                .map(|install_guide| install_guide.install_command.to_owned())
                .collect(),
        ),
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

fn program_trust_step(program_trust_findings: &[ProgramTrustFinding]) -> Option<ProtectionStep> {
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
            SettledNodeState::HasFailed,
            gettext(
                "A ClamAV program can be replaced by your account, so Lazaret refuses to run it",
            ),
        )
    } else {
        (
            SettledNodeState::NeedsReview,
            gettext(
                "A ClamAV program in your account shadows the system copy. Lazaret ignores it, \
                 but check where it came from",
            ),
        )
    };
    Some(TimelineStep::settled(
        gettext("Scanner programs can be trusted"),
        gettext(
            "Malware running as you could put a fake clamdscan earlier on your search path that \
             reports every file as clean. Lazaret only runs ClamAV programs that your account \
             can't replace, such as the ones installed for the whole system.",
        ),
        status_text,
        SettledStep {
            evidence_rows: plain_rows(program_trust_findings.iter().flat_map(program_trust_rows)),
            ..SettledStep::without_offers(node_state)
        },
    ))
}

fn reduced_settings_status(
    reduced_settings: &[ReducedSetting],
    change_time: OverridesChangeTime,
) -> String {
    let setting_count = u32::try_from(reduced_settings.len()).unwrap_or(u32::MAX);
    match change_time {
        OverridesChangeTime::ChangedAt { changed_at } => ngettext(
            "{count} setting checks less than configured since {time}",
            "{count} settings check less than configured since {time}",
            setting_count,
        )
        .replace("{time}", &exact_local_time_text(changed_at)),
        OverridesChangeTime::ChangeTimeUnknown => ngettext(
            "{count} setting checks less than configured, since a time that could not be read",
            "{count} settings check less than configured, since a time that could not be read",
            setting_count,
        ),
    }
    .replace("{count}", &reduced_settings.len().to_string())
}

fn override_change_time_row(change_time: OverridesChangeTime) -> StepEvidenceRow {
    evidence_row(
        gettext("Changed"),
        match change_time {
            OverridesChangeTime::ChangedAt { changed_at } => exact_local_time_text(changed_at),
            OverridesChangeTime::ChangeTimeUnknown => gettext("Unknown"),
        },
    )
}

fn runtime_review_action() -> StepActionSlot<ProtectionStepAction> {
    StepActionSlot::ActionOffered(OfferedAction::plain(
        ProtectionStepAction::ReviewSettingsSubpage(SettingsSubpage::ScannerEngine),
    ))
}

fn runtime_reduction_step(runtime_reductions: &RuntimeReductions) -> Option<ProtectionStep> {
    match runtime_reductions {
        RuntimeReductions::NothingReduced => None,
        RuntimeReductions::SettingsReduced {
            change_time,
            reduced_settings,
        } => Some(TimelineStep::settled(
            gettext("Protection reduced on purpose"),
            gettext(
                "Someone with the administrator password changed ClamAV settings at runtime in a \
                 way that checks less than your configuration does. The System Changes tab on the \
                 Logs page shows who and when.",
            ),
            reduced_settings_status(reduced_settings, *change_time),
            SettledStep {
                evidence_rows: plain_rows(reduced_settings.iter().map(|reduced_setting| {
                    evidence_row(
                        reduced_setting.setting_key.clone(),
                        gettext("{base} in your configuration, {changed} now")
                            .replace("{base}", &reduced_setting.base_value)
                            .replace("{changed}", &reduced_setting.changed_value),
                    )
                })),
                header_action: runtime_review_action(),
                ..SettledStep::without_offers(SettledNodeState::NeedsReview)
            },
        )),
        RuntimeReductions::BaseConfigUnreadable {
            change_time,
            overridden_settings,
        } => Some(TimelineStep::settled(
            gettext("Settings changed at runtime"),
            gettext(
                "Someone with the administrator password changed ClamAV settings at runtime. Your \
                 clamd.conf could not be read, so Lazaret can't tell whether these changes check \
                 less than your configuration does. The System Changes tab on the Logs page shows \
                 who and when.",
            ),
            gettext(
                "Settings were changed at runtime, but clamd.conf could not be read to compare \
                 them",
            ),
            SettledStep {
                evidence_rows: plain_rows(
                    overridden_settings
                        .iter()
                        .map(|overridden_setting| {
                            evidence_row(
                                overridden_setting.setting_key.clone(),
                                gettext("{changed} now")
                                    .replace("{changed}", &overridden_setting.changed_value),
                            )
                        })
                        .chain(std::iter::once(override_change_time_row(*change_time))),
                ),
                header_action: runtime_review_action(),
                ..SettledStep::without_offers(SettledNodeState::NeedsReview)
            },
        )),
    }
}

fn account_settings_step(account_findings: &[AccountSettingFinding]) -> Option<ProtectionStep> {
    if account_findings.is_empty() {
        return None;
    }
    let exclusion_found = account_findings.iter().any(|account_finding| {
        matches!(
            account_finding,
            AccountSettingFinding::BroadExclusion { .. }
        )
    });
    let evidence_rows =
        plain_rows(
            account_findings
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
                }),
        );
    Some(TimelineStep::settled(
        gettext("Scan settings in your account"),
        gettext(
            "Exclusions and the scan schedule are stored in your account, so any program running \
             as you can change them. Lazaret warns when an exclusion skips places where malware \
             usually lands, or when the schedule's unit files differ from what Lazaret wrote, for \
             example after an update or because something else changed them. Applying the \
             schedule again rewrites them.",
        ),
        gettext("Your scan settings may skip malware"),
        SettledStep {
            evidence_rows,
            header_action: StepActionSlot::ActionOffered(OfferedAction::suggested(
                ProtectionStepAction::ReviewSettingsSubpage(if exclusion_found {
                    SettingsSubpage::ScanExclusions
                } else {
                    SettingsSubpage::ScanSchedule
                }),
            )),
            ..SettledStep::without_offers(SettledNodeState::NeedsReview)
        },
    ))
}

struct TrustListVerdict {
    node_state: SettledNodeState,
    status_text: String,
    evidence_rows: Vec<StepEvidenceRow>,
}

fn lazaret_list_failure_row<ListEntry>(
    list_label: String,
    list_reading: &LazaretListReading<ListEntry>,
) -> Option<StepEvidenceRow> {
    match list_reading {
        LazaretListReading::ListRead(_) => None,
        LazaretListReading::ListUnreadable(read_failure) => Some(evidence_row(
            list_label,
            trust_list_failure_text(read_failure),
        )),
    }
}

fn foreign_allowlist_evidence_row(foreign_allowlist: &ForeignAllowlistFile) -> StepEvidenceRow {
    match &foreign_allowlist.allowlist_entries {
        AllowlistEntries::EntriesCounted { .. } => evidence_row(
            gettext("Other allowlist"),
            foreign_allowlist.file_name.clone(),
        ),
        AllowlistEntries::FileUnreadable(read_failure) => evidence_row(
            gettext("Other allowlist"),
            gettext("{file}: {reason}")
                .replace("{file}", &foreign_allowlist.file_name)
                .replace("{reason}", &trust_list_failure_text(read_failure)),
        ),
    }
}

fn trust_list_contents_verdict(trust_list: &TrustListContents) -> Option<TrustListVerdict> {
    let evidence_rows = [
        lazaret_list_failure_row(gettext("Trusted files"), &trust_list.trusted_files),
        lazaret_list_failure_row(
            gettext("Ignored detections"),
            &trust_list.ignored_signatures,
        ),
    ]
    .into_iter()
    .flatten()
    .chain(
        trust_list
            .foreign_allowlists
            .iter()
            .map(foreign_allowlist_evidence_row),
    )
    .collect();
    if !trust_list.foreign_allowlists.is_empty() {
        return Some(TrustListVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext(
                "An allowlist that Lazaret didn't write tells ClamAV to stay silent",
            ),
            evidence_rows,
        });
    }
    match (&trust_list.trusted_files, &trust_list.ignored_signatures) {
        (
            LazaretListReading::ListRead(trusted_files),
            LazaretListReading::ListRead(ignored_signatures),
        ) => {
            let lazaret_entries = trusted_files.len() + ignored_signatures.len();
            (lazaret_entries > 0).then(|| TrustListVerdict {
                node_state: SettledNodeState::Completed,
                status_text: ngettext(
                    "{count} file or detection is never reported",
                    "{count} files or detections are never reported",
                    u32::try_from(lazaret_entries).unwrap_or(u32::MAX),
                )
                .replace("{count}", &lazaret_entries.to_string()),
                evidence_rows,
            })
        }
        (LazaretListReading::ListUnreadable(_), _)
        | (LazaretListReading::ListRead(_), LazaretListReading::ListUnreadable(_)) => {
            Some(TrustListVerdict {
                node_state: SettledNodeState::NeedsReview,
                status_text: gettext(
                    "Lazaret can't read its own allowlist, so it can't tell what ClamAV stays \
                     silent about",
                ),
                evidence_rows,
            })
        }
    }
}

fn trust_list_verdict(trust_list_reading: &TrustListReading) -> Option<TrustListVerdict> {
    match trust_list_reading {
        TrustListReading::ListsRead(trust_list) => trust_list_contents_verdict(trust_list),
        TrustListReading::FolderMissing => None,
        TrustListReading::FolderUnreadable(read_failure) => Some(TrustListVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext(
                "Lazaret can't read the signature folder, so it can't tell what ClamAV stays \
                 silent about",
            ),
            evidence_rows: vec![evidence_row(
                gettext("Signature folder"),
                trust_list_failure_text(read_failure),
            )],
        }),
    }
}

fn trust_list_step(trust_list_reading: &TrustListReading) -> Option<ProtectionStep> {
    let TrustListVerdict {
        node_state,
        status_text,
        evidence_rows,
    } = trust_list_verdict(trust_list_reading)?;
    let review_action =
        ProtectionStepAction::ReviewSettingsSubpage(SettingsSubpage::TrustedDetections);
    Some(TimelineStep::settled(
        gettext("Trusted detections"),
        gettext(
            "Files and detection names on ClamAV's allowlists are never reported, by any scan. \
             Malware that gets administrator rights could hide itself this way, so check that \
             every entry was added on purpose.",
        ),
        status_text,
        SettledStep {
            evidence_rows: plain_rows(evidence_rows),
            header_action: StepActionSlot::ActionOffered(
                if node_state == SettledNodeState::NeedsReview {
                    OfferedAction::suggested(review_action)
                } else {
                    OfferedAction::plain(review_action)
                },
            ),
            ..SettledStep::without_offers(node_state)
        },
    ))
}

fn database_state(
    database_evidence: &DatabaseEvidence,
    reference_moment: Timestamp,
) -> SettledNodeState {
    match database_evidence {
        DatabaseEvidence::BuiltAt { built_at } if *built_at > reference_moment => {
            SettledNodeState::NeedsReview
        }
        DatabaseEvidence::BuiltAt { built_at }
            if reference_moment.duration_since(*built_at) < DATABASE_FRESH_LIMIT =>
        {
            SettledNodeState::Completed
        }
        DatabaseEvidence::BuiltAt { built_at }
            if reference_moment.duration_since(*built_at) < DATABASE_STALE_LIMIT =>
        {
            SettledNodeState::NeedsReview
        }
        DatabaseEvidence::BuiltAt { .. } | DatabaseEvidence::DatabaseMissing => {
            SettledNodeState::HasFailed
        }
        DatabaseEvidence::AgeUndetermined => SettledNodeState::NeedsReview,
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

fn manual_update_row(
    signature_update: &SignatureUpdateView,
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
    timed_evidence_row(
        gettext("Manual update"),
        evidence_moment,
        evidence_value,
        moment_context,
    )
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
) -> ProtectionStep {
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
        if base_state == SettledNodeState::Completed && (any_updater_failed || any_source_stale) {
            SettledNodeState::NeedsReview
        } else {
            base_state
        };
    let update_progress = update_progress_of(signature_update);
    let manual_row = manual_update_row(signature_update, moment_context);
    let other_rows = updater_output_rows(&update_progress)
        .into_iter()
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
        .collect::<Vec<_>>();
    let step_title = gettext("Signatures current");
    let mechanism_details = gettext(
        "Signatures describe known malware, and new ones are published constantly. Old signatures \
         miss recent threats even when everything else is running.",
    );
    let running_signature_step = |status_text: String, cancel_slot| {
        TimelineStep::running(
            step_title.clone(),
            mechanism_details.clone(),
            status_text,
            RunningStep {
                evidence_rows: std::iter::once(manual_row.clone())
                    .chain(other_rows.clone())
                    .collect(),
                cancel_slot,
            },
        )
    };
    let settled_signature_step = |manual_control| {
        TimelineStep::settled(
            step_title.clone(),
            mechanism_details.clone(),
            database_status_text(&signature_evidence.database_evidence, moment_context),
            SettledStep {
                evidence_rows: std::iter::once(ActionableEvidenceRow {
                    shown_evidence: manual_row.clone(),
                    row_control: manual_control,
                })
                .chain(plain_rows(other_rows.clone()))
                .collect(),
                ..SettledStep::without_offers(evidence_state)
            },
        )
    };
    let signature_step = match &update_progress {
        SignatureUpdateProgress::CancellableUpdateRunning { .. } => running_signature_step(
            gettext("Updating signatures…"),
            CancelSlot::Cancellable {
                cancel_action: ProtectionStepAction::CancelSignatureUpdate,
            },
        ),
        SignatureUpdateProgress::UncancellableUpdateRunning { .. } => {
            running_signature_step(gettext("Updating signatures…"), CancelSlot::NotCancellable)
        }
        SignatureUpdateProgress::UpdateCancelling => running_signature_step(
            gettext("Cancelling the update…"),
            CancelSlot::NotCancellable,
        ),
        SignatureUpdateProgress::ReadyToUpdate => settled_signature_step(
            EvidenceRowControl::RowButton(if evidence_state == SettledNodeState::Completed {
                OfferedAction::plain(ProtectionStepAction::UpdateSignatures)
            } else {
                OfferedAction::suggested(ProtectionStepAction::UpdateSignatures)
            }),
        ),
        SignatureUpdateProgress::UpdateUnavailable => {
            settled_signature_step(EvidenceRowControl::NoRowControl)
        }
    };
    signature_step.with_guidance_commands(if signature_evidence.updater_evidence.is_empty() {
        remedy_commands(SuggestedRemedy::FreshclamUpdatesEnable, distribution_family)
    } else {
        Vec::new()
    })
}

fn daemon_step(
    daemon_evidence: &DaemonEvidence,
    distribution_family: DistributionFamily,
) -> ProtectionStep {
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
            SettledNodeState::NeedsReview,
            gettext("clamd still uses signatures {loaded}, but {disk} is on disk")
                .replace("{loaded}", loaded_version)
                .replace("{disk}", disk_version),
        ),
        DaemonEvidence::ClamdAnswering { .. } => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::Completed,
            gettext("clamd is answering"),
        ),
        DaemonEvidence::UnitActiveNotAnswering { service_unit } => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::HasFailed,
            gettext(
                "{unit} is running, but clamd does not answer. It may still be loading signatures.",
            )
            .replace("{unit}", service_unit),
        )
        .with_guidance_commands(remedy_commands(
            SuggestedRemedy::ClamavDaemonRestart,
            distribution_family,
        )),
        DaemonEvidence::UnitStateUnknown => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::NeedsReview,
            gettext("clamd does not answer, and systemd could not report its state"),
        ),
        DaemonEvidence::UnitStopped { service_unit } => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::HasFailed,
            gettext("{unit} is not running").replace("{unit}", service_unit),
        )
        .with_guidance_commands(remedy_commands(
            SuggestedRemedy::ClamavDaemonStart,
            distribution_family,
        )),
        DaemonEvidence::NeverSetUp => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::ActNext,
            gettext("clamd is not set up, so scans fall back to the slower clamscan"),
        )
        .with_guidance_commands(remedy_commands(
            SuggestedRemedy::ClamavDaemonStart,
            distribution_family,
        )),
    }
}

fn daemon_is_answering(daemon_evidence: &DaemonEvidence) -> bool {
    matches!(daemon_evidence, DaemonEvidence::ClamdAnswering { .. })
}

fn on_access_setting_row(evidence_name: String, evidence_value: String) -> ProtectionEvidenceRow {
    ActionableEvidenceRow {
        shown_evidence: StepEvidenceRow {
            evidence_moment: EvidenceMoment::SettingValue,
            ..evidence_row(evidence_name, evidence_value)
        },
        row_control: EvidenceRowControl::SettingsLink {
            settings_action: ProtectionStepAction::ReviewSettingsSubpage(
                SettingsSubpage::OnAccessScanning,
            ),
        },
    }
}

fn clamd_config_failure_text(config_failure: ClamdConfigReadFailure) -> String {
    match config_failure {
        ClamdConfigReadFailure::NoReadableConfig => gettext("No readable clamd.conf was found"),
        ClamdConfigReadFailure::ReadingTaskAborted => {
            gettext("Reading clamd.conf stopped before it finished")
        }
    }
}

fn watched_location_text(watched_location: &WatchedLocation) -> String {
    match watched_location {
        WatchedLocation::WatchedFolder { folder_path } => folder_path.clone(),
        WatchedLocation::WatchedMount { mount_path } => {
            gettext("{path} (whole mount)").replace("{path}", mount_path)
        }
    }
}

fn watch_scope_text(watch_scope: &WatchScope) -> String {
    match watch_scope {
        WatchScope::NothingWatched => gettext("None configured"),
        WatchScope::WatchedLocations { .. } => watch_scope
            .watched_locations()
            .into_iter()
            .map(watched_location_text)
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn size_limit_text(size_limit: &OnAccessSizeLimit) -> String {
    match size_limit {
        OnAccessSizeLimit::DefaultLimit => gettext("The ClamAV default"),
        OnAccessSizeLimit::ConfiguredLimit { size_limit } => byte_size_text(*size_limit),
        OnAccessSizeLimit::UnreadableLimit { limit_text } => limit_text.clone(),
    }
}

fn on_access_rows(on_access_config: &OnAccessConfig) -> Vec<ProtectionEvidenceRow> {
    match on_access_config {
        OnAccessConfig::ConfigUnreadable(config_failure) => vec![on_access_setting_row(
            gettext("Configuration"),
            clamd_config_failure_text(*config_failure),
        )],
        OnAccessConfig::ConfigRead {
            watch_scope,
            size_limit,
            ..
        } => vec![
            on_access_setting_row(gettext("Watched folders"), watch_scope_text(watch_scope)),
            on_access_setting_row(gettext("Largest file scanned"), size_limit_text(size_limit)),
        ],
    }
}

struct OnAccessVerdict {
    node_state: SettledNodeState,
    status_text: String,
    suggested_remedies: Vec<SuggestedRemedy>,
}

fn running_monitor_verdict(on_access_config: &OnAccessConfig) -> OnAccessVerdict {
    match on_access_config {
        OnAccessConfig::ConfigUnreadable(_) => OnAccessVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext(
                "Running, but clamd.conf could not be read, so what is checked and whether \
                 detected files are blocked is unknown",
            ),
            suggested_remedies: Vec::new(),
        },
        OnAccessConfig::ConfigRead {
            watch_scope: WatchScope::NothingWatched,
            blocking_response: OnAccessResponse::BlockAccess,
            ..
        } => OnAccessVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext("Running, but no folders or mounts are watched"),
            suggested_remedies: vec![SuggestedRemedy::OnAccessWatchedPathAdd],
        },
        OnAccessConfig::ConfigRead {
            watch_scope: WatchScope::NothingWatched,
            blocking_response: OnAccessResponse::ReportOnly,
            ..
        } => OnAccessVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext(
                "Running, but no folders or mounts are watched, and detected files would not be \
                 blocked",
            ),
            suggested_remedies: vec![
                SuggestedRemedy::OnAccessWatchedPathAdd,
                SuggestedRemedy::OnAccessPreventionEnable,
            ],
        },
        OnAccessConfig::ConfigRead {
            watch_scope: WatchScope::WatchedLocations { .. },
            blocking_response: OnAccessResponse::ReportOnly,
            ..
        } => OnAccessVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext("Files are checked, but detected files are not blocked"),
            suggested_remedies: vec![SuggestedRemedy::OnAccessPreventionEnable],
        },
        OnAccessConfig::ConfigRead {
            watch_scope: WatchScope::WatchedLocations { .. },
            blocking_response: OnAccessResponse::BlockAccess,
            ..
        } => OnAccessVerdict {
            node_state: SettledNodeState::Completed,
            status_text: gettext("Detected files are blocked"),
            suggested_remedies: Vec::new(),
        },
    }
}

fn on_access_verdict(
    on_access_evidence: &OnAccessEvidence,
    daemon_answering: bool,
) -> OnAccessVerdict {
    match on_access_evidence.on_access_scanner {
        OnAccessScanner::NeverSetUp => OnAccessVerdict {
            node_state: SettledNodeState::NeedsReview,
            status_text: gettext("On-access scanning is not set up"),
            suggested_remedies: vec![SuggestedRemedy::OnAccessScanningEnable],
        },
        OnAccessScanner::UnitStopped { .. } if !daemon_answering => OnAccessVerdict {
            node_state: SettledNodeState::AwaitingPrerequisite,
            status_text: daemon_awaited_text(),
            suggested_remedies: vec![SuggestedRemedy::OnAccessScanningEnable],
        },
        OnAccessScanner::UnitStopped { service_unit } => OnAccessVerdict {
            node_state: SettledNodeState::HasFailed,
            status_text: gettext("{unit} is not running").replace("{unit}", service_unit),
            suggested_remedies: vec![SuggestedRemedy::OnAccessScanningEnable],
        },
        OnAccessScanner::MonitorRunning if !daemon_answering => OnAccessVerdict {
            node_state: SettledNodeState::AwaitingPrerequisite,
            status_text: daemon_awaited_text(),
            suggested_remedies: Vec::new(),
        },
        OnAccessScanner::MonitorRunning => {
            running_monitor_verdict(&on_access_evidence.on_access_config)
        }
    }
}

fn on_access_step(
    on_access_evidence: &OnAccessEvidence,
    daemon_answering: bool,
    distribution_family: DistributionFamily,
) -> ProtectionStep {
    let step_title = gettext("On-access blocking");
    let mechanism_details = gettext(
        "clamonacc checks files in the watched folders as they are opened. With prevention on, \
         the kernel refuses access to a detected file, which is why such a file can't be opened \
         even though it is still there.",
    );
    let on_access_verdict = on_access_verdict(on_access_evidence, daemon_answering);
    TimelineStep::settled(
        step_title,
        mechanism_details,
        on_access_verdict.status_text,
        SettledStep {
            evidence_rows: on_access_rows(&on_access_evidence.on_access_config),
            ..SettledStep::without_offers(on_access_verdict.node_state)
        },
    )
    .with_guidance_commands(
        on_access_verdict
            .suggested_remedies
            .into_iter()
            .flat_map(|suggested_remedy| remedy_commands(suggested_remedy, distribution_family))
            .collect(),
    )
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
    timed_evidence_row(
        gettext("Last scan"),
        EvidenceMoment::from(last_completed_run),
        evidence_value,
        moment_context,
    )
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
) -> ProtectionStep {
    let step_title = gettext("Scheduled scan");
    let mechanism_details = gettext(
        "A scheduled scan catches files that were not opened, or that only became detectable \
         after a signature update.",
    );
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            service_unit,
            timer_state,
            scan_service,
            last_completed_run,
        } => {
            let next_scan_row = match timer_state {
                TimerState::TimerActive { next_run } => next_run_row(*next_run, moment_context),
                TimerState::TimerInactive => evidence_row(
                    gettext("Next scan"),
                    gettext("Not scheduled, because the timer is not active"),
                ),
            };
            let folders_row = StepEvidenceRow {
                evidence_moment: EvidenceMoment::SettingValue,
                ..evidence_row(
                    gettext("Folders scanned"),
                    scanned_folders_text(scan_service),
                )
            };
            let scan_rows = |last_scan_control| {
                vec![
                    next_scan_row.clone().into(),
                    ActionableEvidenceRow {
                        shown_evidence: last_run_row(*last_completed_run, moment_context),
                        row_control: last_scan_control,
                    },
                    folders_row.clone().into(),
                ]
            };
            let run_now_control = EvidenceRowControl::RowButton(OfferedAction::plain(
                ProtectionStepAction::RunScheduledScan { service_unit },
            ));
            let settled_scan_step = |node_state, status_text, last_scan_control| {
                TimelineStep::settled(
                    step_title.clone(),
                    mechanism_details.clone(),
                    status_text,
                    SettledStep {
                        evidence_rows: scan_rows(last_scan_control),
                        ..SettledStep::without_offers(node_state)
                    },
                )
            };
            match timer_state {
                TimerState::TimerInactive | TimerState::TimerActive { .. } if !daemon_answering => {
                    settled_scan_step(
                        SettledNodeState::AwaitingPrerequisite,
                        daemon_awaited_text(),
                        EvidenceRowControl::NoRowControl,
                    )
                }
                TimerState::TimerInactive => settled_scan_step(
                    SettledNodeState::HasFailed,
                    gettext("The system timer is not active"),
                    run_now_control,
                ),
                TimerState::TimerActive { .. } if scheduled_scan_starting => TimelineStep::running(
                    step_title.clone(),
                    mechanism_details.clone(),
                    gettext("Starting the scan…"),
                    RunningStep {
                        evidence_rows: vec![
                            next_scan_row.clone(),
                            last_run_row(*last_completed_run, moment_context),
                            folders_row.clone(),
                        ],
                        cancel_slot: CancelSlot::NotCancellable,
                    },
                ),
                TimerState::TimerActive { next_run } => match scan_service {
                    ScanServiceEvidence::ServiceConfigured { last_result, .. }
                        if scan_result_failed(last_result) =>
                    {
                        settled_scan_step(
                            SettledNodeState::NeedsReview,
                            gettext("The last scan ended with an error"),
                            run_now_control,
                        )
                    }
                    ScanServiceEvidence::ServiceConfigured { .. } => settled_scan_step(
                        SettledNodeState::Completed,
                        gettext("Next scan: {time}").replace("{time}", &next_run_text(*next_run)),
                        run_now_control,
                    ),
                    ScanServiceEvidence::ServiceMissing => settled_scan_step(
                        SettledNodeState::NeedsReview,
                        gettext("The timer starts a scan service that is not installed"),
                        run_now_control,
                    ),
                    ScanServiceEvidence::ServiceUnreadable => settled_scan_step(
                        SettledNodeState::NeedsReview,
                        gettext("The scan service could not be read from systemd"),
                        run_now_control,
                    ),
                },
            }
        }
        ScheduledScanEvidence::LazaretSchedule => no_guidance_step(
            step_title,
            mechanism_details,
            SettledNodeState::Completed,
            gettext("Scheduled by Lazaret"),
        ),
        ScheduledScanEvidence::NoSchedule => TimelineStep::settled(
            step_title,
            mechanism_details,
            gettext("No scan is scheduled"),
            SettledStep {
                header_action: StepActionSlot::ActionOffered(OfferedAction::suggested(
                    ProtectionStepAction::SetUpSettingsSubpage(SettingsSubpage::ScanSchedule),
                )),
                ..SettledStep::without_offers(SettledNodeState::NeedsReview)
            },
        )
        .with_guidance_commands(remedy_commands(
            SuggestedRemedy::ScheduledScanEnable,
            distribution_family,
        )),
    }
}

fn alerts_step(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
    distribution_family: DistributionFamily,
) -> ProtectionStep {
    let step_title = gettext("Alerts");
    let mechanism_details = gettext(
        "Lazaret follows the system journal and notifies you when something is detected. It can \
         only do that while it is running, so it should run in the background.",
    );
    let (node_state, status_text) = match &alert_readiness.journal_access {
        JournalAccess::JournalUnreadable => (
            SettledNodeState::HasFailed,
            gettext(
                "The system journal can't be read. Add your user to the systemd-journal group.",
            ),
        ),
        JournalAccess::FollowingFailed(follow_failure) => (
            SettledNodeState::HasFailed,
            journal_follow_failure_text(follow_failure),
        ),
        JournalAccess::FollowingJournal if !alert_readiness.notifications_enabled => (
            SettledNodeState::NeedsReview,
            gettext("Notifications are turned off in the preferences"),
        ),
        JournalAccess::FollowingJournal
            if background_service_state != UnitState::UnitLoaded(UnitActivity::UnitActive) =>
        {
            (
                SettledNodeState::NeedsReview,
                gettext(
                    "Alerts stop when you quit Lazaret, because it isn't set up to run in the \
                     background",
                ),
            )
        }
        JournalAccess::FollowingJournal => (
            SettledNodeState::Completed,
            gettext("Running in the background and following the journal"),
        ),
    };
    no_guidance_step(step_title, mechanism_details, node_state, status_text).with_guidance_commands(
        if alert_readiness.journal_access == JournalAccess::FollowingJournal
            && alert_readiness.notifications_enabled
            && background_service_state != UnitState::UnitLoaded(UnitActivity::UnitActive)
        {
            remedy_commands(SuggestedRemedy::BackgroundAlertsEnable, distribution_family)
        } else {
            Vec::new()
        },
    )
}

fn on_access_coverage(on_access_evidence: &OnAccessEvidence) -> Option<String> {
    let OnAccessEvidence {
        on_access_scanner: OnAccessScanner::MonitorRunning,
        on_access_config:
            OnAccessConfig::ConfigRead {
                watch_scope: watch_scope @ WatchScope::WatchedLocations { .. },
                blocking_response,
                ..
            },
    } = on_access_evidence
    else {
        return None;
    };
    let watched_paths = watch_scope
        .watched_locations()
        .into_iter()
        .map(WatchedLocation::location_path)
        .collect::<Vec<_>>()
        .join(", ");
    Some(match blocking_response {
        OnAccessResponse::BlockAccess => {
            gettext("{paths} blocked on access").replace("{paths}", &watched_paths)
        }
        OnAccessResponse::ReportOnly => {
            gettext("{paths} checked on access, not blocked").replace("{paths}", &watched_paths)
        }
    })
}

fn scheduled_coverage(scheduled_scan_evidence: &ScheduledScanEvidence) -> Option<String> {
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerActive { .. },
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
    .filter(|installation_step| installation_step.node_state() != StepNodeState::Completed);
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
        protection_page::{
            signature_update_run::updater_exit_status::SignatureUpdaterProgram,
            trusted_detections_page::trust_list_contents::TrustListReadFailure,
        },
        shared_widgets::step_timeline::timeline_step_contents::StepPhase,
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
        timeline_steps: &'timeline [ProtectionStep],
        step_title: &str,
    ) -> &'timeline ProtectionStep {
        timeline_steps
            .iter()
            .find(|timeline_step| timeline_step.step_title == step_title)
            .unwrap()
    }

    fn step_titles(timeline_steps: &[ProtectionStep]) -> Vec<&str> {
        timeline_steps
            .iter()
            .map(|timeline_step| timeline_step.step_title.as_str())
            .collect()
    }

    fn row_named<'step>(
        timeline_step: &'step ProtectionStep,
        evidence_name: &str,
    ) -> &'step StepEvidenceRow {
        timeline_step
            .shown_evidence_rows()
            .into_iter()
            .find(|step_evidence| step_evidence.evidence_name == evidence_name)
            .unwrap()
    }

    fn settled_part(timeline_step: &ProtectionStep) -> &SettledStep<ProtectionStepAction> {
        match &timeline_step.step_phase {
            StepPhase::StepSettled(settled_step) => settled_step,
            StepPhase::StepRunning(_) => panic!("{} is running", timeline_step.step_title),
        }
    }

    fn row_control_named<'step>(
        timeline_step: &'step ProtectionStep,
        evidence_name: &str,
    ) -> &'step EvidenceRowControl<ProtectionStepAction> {
        &settled_part(timeline_step)
            .evidence_rows
            .iter()
            .find(|actionable_row| actionable_row.shown_evidence.evidence_name == evidence_name)
            .unwrap()
            .row_control
    }

    fn all_steps(protection_timeline: ProtectionTimeline) -> Vec<ProtectionStep> {
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
            trust_list: TrustListReading::ListsRead(empty_trust_list()),
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
                on_access_config: OnAccessConfig::ConfigRead {
                    watch_scope: WatchScope::WatchedLocations {
                        first_location: WatchedLocation::WatchedFolder {
                            folder_path: "/home/user/Downloads".to_owned(),
                        },
                        other_locations: Vec::new(),
                    },
                    blocking_response: OnAccessResponse::BlockAccess,
                    size_limit: OnAccessSizeLimit::ConfiguredLimit {
                        size_limit: ByteSize::mib(100),
                    },
                },
            },
            scheduled_scan_evidence: ScheduledScanEvidence::SystemTimer {
                service_unit: "clamdscan.service",
                timer_state: TimerState::TimerActive {
                    next_run: UnitTimestamp::RecordedAt {
                        recorded_at: REFERENCE_MOMENT + SignedDuration::from_hours(6),
                    },
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
            .map(|timeline_step| timeline_step.node_state())
            .collect()
    }

    fn state_of(protection_evidence: &ProtectionEvidence, step_title: &str) -> StepNodeState {
        step_titled(&all_steps(idle_timeline(protection_evidence)), step_title).node_state()
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
                timeline_step.node_state(),
                timeline_step.step_title,
                timeline_step.status_text
            );
            timeline_step
                .shown_evidence_rows()
                .into_iter()
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
                timer_state: TimerState::TimerActive {
                    next_run: UnitTimestamp::RecordedAt {
                        recorded_at: REFERENCE_MOMENT
                            + SignedDuration::from_hours(72)
                            + SignedDuration::from_mins(1),
                    },
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
            row_control_named(scheduled_step, "Last scan"),
            EvidenceRowControl::RowButton(OfferedAction {
                offered_action: ProtectionStepAction::RunScheduledScan { .. },
                ..
            })
        ));
        assert_eq!(scheduled_step.header_offer(), None);
        let on_access_step = step_titled(&healthy_steps, "On-access blocking");
        assert_eq!(
            row_named(on_access_step, "Watched folders").evidence_moment,
            EvidenceMoment::SettingValue
        );
        assert_eq!(
            row_control_named(on_access_step, "Watched folders"),
            &EvidenceRowControl::SettingsLink {
                settings_action: ProtectionStepAction::ReviewSettingsSubpage(
                    SettingsSubpage::OnAccessScanning
                )
            }
        );
        let signature_step = step_titled(&healthy_steps, "Signatures current");
        assert_eq!(signature_step.header_offer(), None);
        assert!(matches!(
            row_control_named(signature_step, "Manual update"),
            EvidenceRowControl::RowButton(OfferedAction {
                offered_action: ProtectionStepAction::UpdateSignatures,
                ..
            })
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
        assert_eq!(signature_step.node_state(), StepNodeState::InProgress);
        let output_row = row_named(signature_step, "Updater output");
        assert_eq!(output_row.evidence_moment, EvidenceMoment::HappeningNow);
        assert_eq!(output_row.evidence_value, "daily.cld updated");
        assert_eq!(
            signature_step.offered_actions(),
            vec![OfferedAction::plain(
                ProtectionStepAction::CancelSignatureUpdate
            )]
        );
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
        assert_eq!(scheduled_step.node_state(), StepNodeState::InProgress);
        assert_eq!(scheduled_step.offered_actions(), Vec::new());
        assert_eq!(
            row_named(scheduled_step, "Last scan").evidence_value,
            "Not run yet"
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
                timer_state: TimerState::TimerActive {
                    next_run: UnitTimestamp::RecordedAt {
                        recorded_at: REFERENCE_MOMENT + SignedDuration::from_hours(6),
                    },
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
        assert_eq!(scheduled_step.node_state(), StepNodeState::NeedsReview);
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
        assert_eq!(engine_steps[0].node_state(), StepNodeState::HasFailed);
        assert_eq!(engine_steps.len(), 3);
    }

    fn empty_trust_list() -> TrustListContents {
        TrustListContents {
            trusted_files: LazaretListReading::ListRead(Vec::new()),
            ignored_signatures: LazaretListReading::ListRead(Vec::new()),
            foreign_allowlists: Vec::new(),
        }
    }

    fn trust_review_steps(trust_list_reading: TrustListReading) -> Vec<ProtectionStep> {
        let protection_evidence = ProtectionEvidence {
            trust_list: trust_list_reading,
            ..healthy_evidence()
        };
        idle_timeline(&protection_evidence).review_steps
    }

    #[test]
    fn a_foreign_allowlist_appears_under_needs_review() {
        let review_steps = trust_review_steps(TrustListReading::ListsRead(TrustListContents {
            foreign_allowlists: vec![ForeignAllowlistFile {
                file_name: "local.ign2".to_owned(),
                allowlist_entries: AllowlistEntries::EntriesCounted { entry_count: 3 },
            }],
            ..empty_trust_list()
        }));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
    }

    #[test]
    fn an_unreadable_foreign_allowlist_keeps_its_warning() {
        let review_steps = trust_review_steps(TrustListReading::ListsRead(TrustListContents {
            foreign_allowlists: vec![ForeignAllowlistFile {
                file_name: "local.ign2".to_owned(),
                allowlist_entries: AllowlistEntries::FileUnreadable(
                    TrustListReadFailure::AccessDenied,
                ),
            }],
            ..empty_trust_list()
        }));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            review_steps[0].status_text,
            "An allowlist that Lazaret didn't write tells ClamAV to stay silent"
        );
    }

    #[test]
    fn an_unreadable_signature_folder_is_not_shown_as_nothing_trusted() {
        let review_steps = trust_review_steps(TrustListReading::FolderUnreadable(
            TrustListReadFailure::AccessDenied,
        ));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
    }

    #[test]
    fn an_unreadable_lazaret_list_needs_review() {
        let review_steps = trust_review_steps(TrustListReading::ListsRead(TrustListContents {
            ignored_signatures: LazaretListReading::ListUnreadable(
                TrustListReadFailure::AccessDenied,
            ),
            ..empty_trust_list()
        }));
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
    }

    #[test]
    fn empty_readable_trust_lists_add_no_step() {
        assert!(trust_review_steps(TrustListReading::ListsRead(empty_trust_list())).is_empty());
        assert!(trust_review_steps(TrustListReading::FolderMissing).is_empty());
    }

    #[test]
    fn a_runtime_reduction_stays_visible_as_needing_review() {
        let protection_evidence = ProtectionEvidence {
            runtime_reductions: RuntimeReductions::SettingsReduced {
                change_time: OverridesChangeTime::ChangedAt {
                    changed_at: REFERENCE_MOMENT,
                },
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
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
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
        assert_eq!(account_step.node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            account_step.header_offer(),
            Some(OfferedAction::suggested(
                ProtectionStepAction::ReviewSettingsSubpage(SettingsSubpage::ScanExclusions)
            ))
        );
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
            idle_timeline(&protection_evidence).engine_steps[0].node_state(),
            StepNodeState::NeedsReview
        );
    }

    #[test]
    fn running_without_prevention_is_never_reported_as_blocking() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: on_access_with(OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedFolder {
                        folder_path: "/home/user/Downloads".to_owned(),
                    },
                    other_locations: Vec::new(),
                },
                blocking_response: OnAccessResponse::ReportOnly,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            }),
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
        .node_state()
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
            idle_timeline(&protection_evidence).engine_steps[0].node_state(),
            StepNodeState::ActNext
        );
        assert!(coverage_summary(&protection_evidence).contains("nothing is being checked"));
    }

    fn on_access_with(on_access_config: OnAccessConfig) -> OnAccessEvidence {
        OnAccessEvidence {
            on_access_scanner: OnAccessScanner::MonitorRunning,
            on_access_config,
        }
    }

    fn on_access_step_of(protection_evidence: &ProtectionEvidence) -> ProtectionStep {
        step_titled(
            &idle_timeline(protection_evidence).protection_steps,
            "On-access blocking",
        )
        .clone()
    }

    #[test]
    fn an_unreadable_daemon_config_claims_neither_coverage_nor_missing_blocking() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: on_access_with(OnAccessConfig::ConfigUnreadable(
                ClamdConfigReadFailure::NoReadableConfig,
            )),
            ..healthy_evidence()
        };
        let on_access_step = on_access_step_of(&protection_evidence);
        assert_eq!(on_access_step.node_state(), StepNodeState::NeedsReview);
        assert!(
            on_access_step
                .status_text
                .contains("clamd.conf could not be read")
        );
        assert!(!on_access_step.status_text.contains("not blocked"));
        assert!(on_access_step.guidance_commands.is_empty());
        assert_eq!(
            row_named(&on_access_step, "Configuration").evidence_value,
            "No readable clamd.conf was found"
        );
        let coverage_text = coverage_summary(&protection_evidence);
        assert!(!coverage_text.contains("on access"));
    }

    #[test]
    fn prevention_without_watched_locations_suggests_adding_a_watched_folder() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: on_access_with(OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::NothingWatched,
                blocking_response: OnAccessResponse::BlockAccess,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            }),
            ..healthy_evidence()
        };
        let on_access_step = on_access_step_of(&protection_evidence);
        assert_eq!(on_access_step.node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            on_access_step.status_text,
            "Running, but no folders or mounts are watched"
        );
        assert_eq!(
            on_access_step.guidance_commands,
            remedy_commands(
                SuggestedRemedy::OnAccessWatchedPathAdd,
                DistributionFamily::NixosFamily
            )
        );
        assert!(!coverage_summary(&protection_evidence).contains("on access"));
    }

    #[test]
    fn a_watched_mount_is_shown_as_a_whole_mount_and_counts_as_coverage() {
        let protection_evidence = ProtectionEvidence {
            on_access_evidence: on_access_with(OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedMount {
                        mount_path: "/".to_owned(),
                    },
                    other_locations: Vec::new(),
                },
                blocking_response: OnAccessResponse::BlockAccess,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            }),
            ..healthy_evidence()
        };
        let on_access_step = on_access_step_of(&protection_evidence);
        assert_eq!(on_access_step.node_state(), StepNodeState::Completed);
        assert_eq!(
            row_named(&on_access_step, "Watched folders").evidence_value,
            "/ (whole mount)"
        );
        assert!(coverage_summary(&protection_evidence).starts_with("/ blocked on access"));
    }

    #[test]
    fn an_active_daemon_that_does_not_answer_suggests_a_restart() {
        let protection_evidence = ProtectionEvidence {
            daemon_evidence: DaemonEvidence::UnitActiveNotAnswering {
                service_unit: "clamav-daemon.service",
            },
            ..healthy_evidence()
        };
        let daemon_step = daemon_step(
            &protection_evidence.daemon_evidence,
            DistributionFamily::DebianFamily,
        );
        assert_eq!(daemon_step.node_state(), StepNodeState::HasFailed);
        assert!(
            daemon_step
                .status_text
                .starts_with("clamav-daemon.service is running, but clamd does not answer")
        );
        assert_eq!(
            daemon_step.guidance_commands,
            vec!["sudo systemctl restart clamav-daemon".to_owned()]
        );
        assert_eq!(
            state_of(&protection_evidence, "On-access blocking"),
            StepNodeState::AwaitingPrerequisite
        );
        assert_eq!(
            daemon_step_state(DaemonEvidence::UnitStateUnknown),
            StepNodeState::NeedsReview
        );
    }

    fn daemon_step_state(daemon_evidence: DaemonEvidence) -> StepNodeState {
        daemon_step(&daemon_evidence, DistributionFamily::NixosFamily).node_state()
    }

    #[test]
    fn a_reduction_with_an_unknown_change_time_never_shows_a_date() {
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
        let review_steps = idle_timeline(&protection_evidence).review_steps;
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            review_steps[0].status_text,
            "1 setting checks less than configured, since a time that could not be read"
        );
        assert!(!review_steps[0].status_text.contains("1970"));
    }

    #[test]
    fn an_inactive_timer_fails_and_claims_no_scheduled_coverage() {
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
        let protection_steps = idle_timeline(&protection_evidence).protection_steps;
        let scheduled_step = step_titled(&protection_steps, "Scheduled scan");
        assert_eq!(scheduled_step.node_state(), StepNodeState::HasFailed);
        assert_eq!(
            row_named(scheduled_step, "Next scan").evidence_value,
            "Not scheduled, because the timer is not active"
        );
        assert!(!coverage_summary(&protection_evidence).contains("scanned on a schedule"));
    }
}
