use gettextrs::gettext;
use jiff::Timestamp;

use crate::{
    findings::detections_page::alert_delivery_presentation::{
        AlertReadiness, alerts_condition, alerts_status_step,
    },
    host_services::{
        clamav_programs::distribution_install_guides::DistributionFamily,
        desktop::locale_formatting::MomentFormatters,
        protection_evidence::{
            host_protection_evidence::{
                AccountSettingFinding, EngineInstallation, OnAccessConfig, OnAccessEvidence,
                OnAccessScanner, ProtectionEvidence, ScanServiceEvidence, ScheduledScanEvidence,
                SignatureEvidence, TimerState, WatchScope, WatchedLocation, daemon_is_answering,
            },
            on_access_setup_review::{OnAccessBlocking, on_access_blocking},
        },
        systemd_bus::host_systemd_units::UnitState,
    },
    scans::{
        on_access_page::on_access_presentation::{on_access_condition, on_access_step},
        scan_engine_page::scan_engine_presentation::{
            daemon_condition, daemon_step, engine_condition, engine_step,
        },
        scheduled_scans_page::scheduled_scans_presentation::{
            last_scheduled_run_failed, scheduled_scan_condition, scheduled_scan_step,
        },
    },
    shared_widgets::step_timeline::{
        program_trust_steps::{TrustedProgramGroup, program_trust_step},
        runtime_reduction_steps::{ReducedSettingGroup, runtime_reduction_step},
        step_evidence_builders::{CheckedCondition, MomentContext, evidence_row, plain_rows},
        timeline_step_contents::{
            ActionConsequence, OfferedAction, SettledNodeState, SettledStep, StepActionButton,
            StepActionSlot, StepNodeState, TimelineStep,
        },
    },
    sharing::analysis_page::{
        analysis_presentation::trust_list_step,
        trusted_detections_section::trust_list_contents::TrustListReading,
    },
    signatures::database_updates_page::database_updates_presentation::{
        signature_node_state, signature_status_step,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectionStepAction {
    OpenDatabaseUpdates,
    OpenScanEngine,
    OpenOnAccessScanning,
    OpenScheduledScans,
    OpenManualScan,
    OpenDetections,
    OpenAnalysis,
}

impl StepActionButton for ProtectionStepAction {
    fn button_label(&self) -> String {
        match self {
            Self::OpenDatabaseUpdates => gettext("Open Database Updates"),
            Self::OpenScanEngine => gettext("Open Scan Engine"),
            Self::OpenOnAccessScanning => gettext("Open On-Access Scanning"),
            Self::OpenScheduledScans => gettext("Open Scheduled Scans"),
            Self::OpenManualScan => gettext("Open Manual Scan"),
            Self::OpenDetections => gettext("Open Detections"),
            Self::OpenAnalysis => gettext("Open Analysis"),
        }
    }

    fn action_consequence(&self) -> ActionConsequence {
        match self {
            Self::OpenDatabaseUpdates
            | Self::OpenScanEngine
            | Self::OpenOnAccessScanning
            | Self::OpenScheduledScans
            | Self::OpenManualScan
            | Self::OpenDetections
            | Self::OpenAnalysis => ActionConsequence::OrdinaryAction,
        }
    }
}

pub type ProtectionStep = TimelineStep<ProtectionStepAction>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionTimeline {
    pub coverage_summary: String,
    pub protection_steps: Vec<ProtectionStep>,
    pub engine_steps: Vec<ProtectionStep>,
    pub review_steps: Vec<ProtectionStep>,
}

#[derive(Clone)]
pub struct ProtectionActivity {
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

fn offer_for_condition(
    checked_condition: CheckedCondition,
    offered_action: ProtectionStepAction,
) -> OfferedAction<ProtectionStepAction> {
    if checked_condition.node_state() == SettledNodeState::Completed {
        OfferedAction::plain(offered_action)
    } else {
        OfferedAction::suggested(offered_action)
    }
}

fn scan_engine_offer(checked_condition: CheckedCondition) -> StepActionSlot<ProtectionStepAction> {
    StepActionSlot::ActionOffered(offer_for_condition(
        checked_condition,
        ProtectionStepAction::OpenScanEngine,
    ))
}

fn scheduled_scan_offer(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    daemon_answering: bool,
) -> StepActionSlot<ProtectionStepAction> {
    StepActionSlot::ActionOffered(offer_for_condition(
        scheduled_scan_condition(scheduled_scan_evidence, daemon_answering),
        if last_scheduled_run_failed(scheduled_scan_evidence) {
            ProtectionStepAction::OpenManualScan
        } else {
            ProtectionStepAction::OpenScheduledScans
        },
    ))
}

fn runtime_review_action() -> StepActionSlot<ProtectionStepAction> {
    StepActionSlot::ActionOffered(OfferedAction::plain(ProtectionStepAction::OpenScanEngine))
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
                if exclusion_found {
                    ProtectionStepAction::OpenManualScan
                } else {
                    ProtectionStepAction::OpenScheduledScans
                },
            )),
            ..SettledStep::without_offers(SettledNodeState::NeedsReview)
        },
    ))
}

fn trust_list_review_step(trust_list_reading: &TrustListReading) -> Option<ProtectionStep> {
    trust_list_step(trust_list_reading, |checked_condition| {
        StepActionSlot::ActionOffered(offer_for_condition(
            checked_condition,
            ProtectionStepAction::OpenAnalysis,
        ))
    })
}

fn signature_overview_step(
    signature_evidence: &SignatureEvidence,
    moment_context: MomentContext,
    distribution_family: DistributionFamily,
) -> ProtectionStep {
    let open_action = ProtectionStepAction::OpenDatabaseUpdates;
    signature_status_step(
        signature_evidence,
        moment_context,
        distribution_family,
        StepActionSlot::ActionOffered(
            if signature_node_state(signature_evidence, moment_context.reference_moment)
                == SettledNodeState::Completed
            {
                OfferedAction::plain(open_action)
            } else {
                OfferedAction::suggested(open_action)
            },
        ),
    )
}

fn alerts_overview_step(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
) -> ProtectionStep {
    alerts_status_step(
        alert_readiness,
        background_service_state,
        StepActionSlot::ActionOffered(offer_for_condition(
            alerts_condition(alert_readiness, background_service_state),
            ProtectionStepAction::OpenDetections,
        )),
    )
}

fn on_access_coverage(on_access_evidence: &OnAccessEvidence) -> Option<String> {
    let OnAccessEvidence {
        on_access_scanner: OnAccessScanner::MonitorRunning,
        on_access_config:
            OnAccessConfig::ConfigRead {
                watch_scope: watch_scope @ WatchScope::WatchedLocations { .. },
                configured_prevention,
                setting_conflicts,
                ..
            },
        kernel_blocking_support,
        ..
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
    Some(
        match on_access_blocking(
            *configured_prevention,
            setting_conflicts,
            *kernel_blocking_support,
        ) {
            OnAccessBlocking::BlocksDetectedFiles => {
                gettext("{paths} blocked on access").replace("{paths}", &watched_paths)
            }
            OnAccessBlocking::KernelSupportUnknown(_) => {
                gettext("{paths} checked on access, blocking unknown")
                    .replace("{paths}", &watched_paths)
            }
            OnAccessBlocking::PreventionOff
            | OnAccessBlocking::PreventionConflictsWithMounts
            | OnAccessBlocking::KernelCannotBlock => {
                gettext("{paths} checked on access, not blocked").replace("{paths}", &watched_paths)
            }
        },
    )
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
        scan_engine_offer(engine_condition(&protection_evidence.engine_installation)),
    ))
    .filter(|installation_step| installation_step.node_state() != StepNodeState::Completed);
    ProtectionTimeline {
        coverage_summary: coverage_summary(protection_evidence),
        protection_steps: vec![
            on_access_step(
                &protection_evidence.on_access_evidence,
                daemon_answering,
                distribution_family,
                StepActionSlot::ActionOffered(offer_for_condition(
                    on_access_condition(&protection_evidence.on_access_evidence, daemon_answering),
                    ProtectionStepAction::OpenOnAccessScanning,
                )),
            ),
            scheduled_scan_step(
                &protection_evidence.scheduled_scan_evidence,
                daemon_answering,
                protection_activity.moment_context(),
                distribution_family,
                scheduled_scan_offer(
                    &protection_evidence.scheduled_scan_evidence,
                    daemon_answering,
                ),
            ),
            alerts_overview_step(
                alert_readiness,
                protection_evidence.background_service_state,
            ),
        ],
        engine_steps: engine_problem
            .into_iter()
            .chain(program_trust_step(
                &protection_evidence.program_trust,
                TrustedProgramGroup::AllClamavPrograms,
            ))
            .chain([
                signature_overview_step(
                    &protection_evidence.signature_evidence,
                    protection_activity.moment_context(),
                    distribution_family,
                ),
                daemon_step(
                    &protection_evidence.daemon_evidence,
                    distribution_family,
                    scan_engine_offer(daemon_condition(&protection_evidence.daemon_evidence)),
                ),
            ])
            .collect(),
        review_steps: runtime_reduction_step(
            &protection_evidence.runtime_reductions,
            ReducedSettingGroup::AllSettings,
            runtime_review_action(),
        )
        .into_iter()
        .chain(account_settings_step(
            &protection_evidence.account_setting_findings,
        ))
        .chain(trust_list_review_step(&protection_evidence.trust_list))
        .collect(),
    }
}

#[cfg(test)]
mod protection_timeline_presentation_tests {
    use jiff::SignedDuration;

    use super::*;
    use crate::{
        host_services::{
            detection_journal::detection_journal_follower::JournalAccess,
            protection_evidence::{
                host_protection_evidence::{
                    ClamdConfigReadFailure, ClamdUserExclusion, ConfiguredPrevention,
                    DaemonEvidence, OnAccessSizeLimit, OverridesChangeTime, OverridesReadFailure,
                    ProgramTrustFinding, ProgramTrustInspection, ReducedSetting, RuntimeReductions,
                    ScanUnitResult,
                },
                protection_evidence_fixtures::{
                    REFERENCE_MOMENT, empty_trust_list, english_formatters, healthy_evidence,
                },
                service_run_journal::{ScanRunFindings, ScanRunHistory},
            },
            systemd_bus::host_systemd_units::UnitTimestamp,
        },
        shared_widgets::step_timeline::timeline_step_contents::{
            EvidenceMoment, EvidenceRowControl, StepEvidenceRow, StepPhase,
        },
        sharing::analysis_page::trusted_detections_section::trust_list_contents::{
            AllowlistEntries, ForeignAllowlistFile, TrustListContents,
        },
    };

    fn idle_activity() -> ProtectionActivity {
        ProtectionActivity {
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
            &crate::host_services::protection_evidence::host_protection_evidence::gather_protection_evidence(false).await,
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
        assert!(
            scheduled_step
                .offered_actions()
                .iter()
                .all(|offered_action| offered_action.offered_action
                    == ProtectionStepAction::OpenScheduledScans)
        );
        let on_access_step = step_titled(&healthy_steps, "On-access blocking");
        assert_eq!(
            row_named(on_access_step, "Watched folders").evidence_moment,
            EvidenceMoment::SettingValue
        );
        assert_eq!(
            row_control_named(on_access_step, "Watched folders"),
            &EvidenceRowControl::NoRowControl
        );
        let signature_step = step_titled(&healthy_steps, "Signatures current");
        assert_eq!(
            signature_step.header_offer(),
            Some(OfferedAction::plain(
                ProtectionStepAction::OpenDatabaseUpdates
            ))
        );
        assert!(
            signature_step
                .shown_evidence_rows()
                .iter()
                .all(|step_evidence| step_evidence.evidence_name != "Manual update")
        );
        assert!(
            signature_step
                .status_text
                .starts_with("Definitions built 5 hours ago (")
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
    fn an_unreadable_scan_service_claims_no_scheduled_coverage() {
        let unreadable_service = system_timer_with(ScanServiceEvidence::ServiceUnreadable);
        assert!(!coverage_summary(&unreadable_service).contains("scanned on a schedule"));
    }

    #[test]
    fn a_failed_scheduled_run_opens_the_manual_scan_page_to_run_it_again() {
        let failed_run = system_timer_with(ScanServiceEvidence::ServiceConfigured {
            scan_targets: vec!["/tmp".to_owned()],
            last_result: ScanUnitResult::ScannerError { exit_status: 2 },
        });
        let protection_steps = idle_timeline(&failed_run).protection_steps;
        assert_eq!(
            step_titled(&protection_steps, "Scheduled scan").header_offer(),
            Some(OfferedAction::suggested(
                ProtectionStepAction::OpenManualScan
            ))
        );
        let no_schedule = ProtectionEvidence {
            scheduled_scan_evidence: ScheduledScanEvidence::NoSchedule,
            ..healthy_evidence()
        };
        let protection_steps = idle_timeline(&no_schedule).protection_steps;
        assert_eq!(
            step_titled(&protection_steps, "Scheduled scan").header_offer(),
            Some(OfferedAction::suggested(
                ProtectionStepAction::OpenScheduledScans
            ))
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
            program_trust: ProgramTrustInspection::ProgramsChecked(vec![
                ProgramTrustFinding::OnlyReplaceableProgram {
                    program_name: "clamdscan",
                    replaceable_paths: vec!["/home/user/.local/bin/clamdscan".to_owned()],
                },
            ]),
            ..healthy_evidence()
        };
        let engine_steps = idle_timeline(&protection_evidence).engine_steps;
        assert_eq!(engine_steps[0].node_state(), StepNodeState::HasFailed);
        assert_eq!(engine_steps.len(), 3);
    }

    #[test]
    fn a_foreign_allowlist_appears_under_needs_review_and_opens_analysis() {
        let protection_evidence = ProtectionEvidence {
            trust_list: TrustListReading::ListsRead(TrustListContents {
                foreign_allowlists: vec![ForeignAllowlistFile {
                    file_name: "local.ign2".to_owned(),
                    allowlist_entries: AllowlistEntries::EntriesCounted { entry_count: 3 },
                }],
                ..empty_trust_list()
            }),
            ..healthy_evidence()
        };
        let review_steps = idle_timeline(&protection_evidence).review_steps;
        assert_eq!(review_steps.len(), 1);
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            review_steps[0].header_offer(),
            Some(OfferedAction::suggested(ProtectionStepAction::OpenAnalysis))
        );
        assert!(
            idle_timeline(&ProtectionEvidence {
                trust_list: TrustListReading::FolderMissing,
                ..healthy_evidence()
            })
            .review_steps
            .is_empty()
        );
    }

    #[test]
    fn a_runtime_reduction_stays_visible_as_needing_review() {
        let protection_evidence = ProtectionEvidence {
            runtime_reductions: RuntimeReductions::SettingsReduced {
                change_time: OverridesChangeTime::ChangedAt {
                    changed_at: REFERENCE_MOMENT,
                },
                reduced_settings: vec![
                    crate::host_services::protection_evidence::host_protection_evidence::ReducedSetting {
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
                ProtectionStepAction::OpenManualScan
            ))
        );
    }

    #[test]
    fn an_ignored_shadowing_program_only_needs_review() {
        let protection_evidence = ProtectionEvidence {
            program_trust: ProgramTrustInspection::ProgramsChecked(vec![
                ProgramTrustFinding::ReplaceableProgramIgnored {
                    program_name: "clamscan",
                    trusted_path: "/usr/bin/clamscan".to_owned(),
                    ignored_paths: vec!["/home/user/.local/bin/clamscan".to_owned()],
                },
            ]),
            ..healthy_evidence()
        };
        assert_eq!(
            idle_timeline(&protection_evidence).engine_steps[0].node_state(),
            StepNodeState::NeedsReview
        );
    }

    #[test]
    fn on_access_coverage_names_only_watched_and_blocked_locations() {
        let coverage_with = |on_access_config| {
            coverage_summary(&ProtectionEvidence {
                on_access_evidence: on_access_with(on_access_config),
                ..healthy_evidence()
            })
        };
        assert!(
            coverage_with(OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedFolder {
                        folder_path: "/home/user/Downloads".to_owned(),
                    },
                    other_locations: Vec::new(),
                },
                configured_prevention: ConfiguredPrevention::PreventionOff,
                setting_conflicts: Vec::new(),
                clamd_user_exclusion: ClamdUserExclusion::ClamdUserExcluded,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            })
            .contains("not blocked")
        );
        assert!(
            !coverage_with(OnAccessConfig::ConfigUnreadable(
                ClamdConfigReadFailure::NoReadableConfig,
            ))
            .contains("on access")
        );
        assert!(
            !coverage_with(OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::NothingWatched,
                configured_prevention: ConfiguredPrevention::PreventionRequested,
                setting_conflicts: Vec::new(),
                clamd_user_exclusion: ClamdUserExclusion::ClamdUserExcluded,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            })
            .contains("on access")
        );
        assert!(
            coverage_with(OnAccessConfig::ConfigRead {
                watch_scope: WatchScope::WatchedLocations {
                    first_location: WatchedLocation::WatchedMount {
                        mount_path: "/".to_owned(),
                    },
                    other_locations: Vec::new(),
                },
                configured_prevention: ConfiguredPrevention::PreventionRequested,
                setting_conflicts: Vec::new(),
                clamd_user_exclusion: ClamdUserExclusion::ClamdUserExcluded,
                size_limit: OnAccessSizeLimit::DefaultLimit,
            })
            .starts_with("/ blocked on access")
        );
    }

    #[test]
    fn the_on_access_step_opens_its_page_and_keeps_its_settings_links() {
        let protection_steps = idle_timeline(&healthy_evidence()).protection_steps;
        let on_access_step = step_titled(&protection_steps, "On-access blocking");
        assert_eq!(
            on_access_step.header_offer(),
            Some(OfferedAction::plain(
                ProtectionStepAction::OpenOnAccessScanning
            ))
        );
    }

    #[test]
    fn the_alerts_step_is_status_only_and_opens_detections() {
        let protection_steps = idle_timeline(&ProtectionEvidence {
            background_service_state: UnitState::UnitNotFound,
            ..healthy_evidence()
        })
        .protection_steps;
        let alerts_step = step_titled(&protection_steps, "Alerts");
        assert_eq!(alerts_step.node_state(), StepNodeState::NeedsReview);
        assert!(alerts_step.guidance_commands.is_empty());
        assert!(alerts_step.shown_evidence_rows().is_empty());
        assert_eq!(
            alerts_step.header_offer(),
            Some(OfferedAction::suggested(
                ProtectionStepAction::OpenDetections
            ))
        );
        let healthy_steps = idle_timeline(&healthy_evidence()).protection_steps;
        assert_eq!(
            step_titled(&healthy_steps, "Alerts").header_offer(),
            Some(OfferedAction::plain(ProtectionStepAction::OpenDetections))
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
            ..healthy_evidence().on_access_evidence
        }
    }

    #[test]
    fn unreadable_runtime_changes_are_unknown_rather_than_nothing_reduced() {
        let protection_evidence = ProtectionEvidence {
            runtime_reductions: RuntimeReductions::OverridesUnreadable(
                OverridesReadFailure::OverridesFileUnreadable {
                    failure_kind: std::io::ErrorKind::PermissionDenied,
                },
            ),
            ..healthy_evidence()
        };
        let review_steps = idle_timeline(&protection_evidence).review_steps;
        assert_eq!(review_steps[0].node_state(), StepNodeState::NeedsReview);
        assert!(
            review_steps[0]
                .status_text
                .starts_with("Unknown whether settings were reduced")
        );
    }

    #[test]
    fn an_interrupted_program_check_is_unknown_rather_than_trusted() {
        let protection_evidence = ProtectionEvidence {
            program_trust: ProgramTrustInspection::CheckInterrupted,
            ..healthy_evidence()
        };
        let engine_steps = idle_timeline(&protection_evidence).engine_steps;
        let trust_step = step_titled(&engine_steps, "Scanner programs can be trusted");
        assert_eq!(trust_step.node_state(), StepNodeState::NeedsReview);
        assert!(trust_step.status_text.starts_with("Unknown"));
    }

    #[test]
    fn an_active_daemon_that_does_not_answer_leaves_on_access_waiting() {
        let protection_evidence = ProtectionEvidence {
            daemon_evidence: DaemonEvidence::UnitActiveNotAnswering {
                service_unit: "clamav-daemon.service",
            },
            ..healthy_evidence()
        };
        assert_eq!(
            state_of(&protection_evidence, "On-access blocking"),
            StepNodeState::AwaitingPrerequisite
        );
        let engine_steps = idle_timeline(&protection_evidence).engine_steps;
        let daemon_step = step_titled(&engine_steps, "Daemon running");
        assert_eq!(daemon_step.node_state(), StepNodeState::HasFailed);
        assert_eq!(
            daemon_step.header_offer(),
            Some(OfferedAction::suggested(
                ProtectionStepAction::OpenScanEngine
            ))
        );
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
        assert_eq!(
            state_of(&protection_evidence, "Scheduled scan"),
            StepNodeState::HasFailed
        );
        assert!(!coverage_summary(&protection_evidence).contains("scanned on a schedule"));
    }
}
