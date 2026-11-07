use gettextrs::gettext;

use crate::{
    hardening_page::suggested_audit_commands::SuggestedRemedy,
    host_services::{
        clamav_programs::distribution_install_guides::DistributionFamily,
        desktop::locale_formatting::exact_local_time_text,
        protection_evidence::{
            host_protection_evidence::{
                ProtectionEvidence, ScanServiceEvidence, ScanUnitResult, ScheduledScanEvidence,
                TimerState,
            },
            service_run_journal::{ScanRunFindings, ScanRunHistory},
        },
        systemd_bus::host_systemd_units::UnitTimestamp,
    },
    scans::scan_engine_page::scan_engine_presentation::{daemon_awaited_text, daemon_is_answering},
    shared_widgets::step_timeline::{
        step_evidence_builders::{
            CheckedCondition, MomentContext, evidence_row, plain_rows, remedy_commands,
            timed_evidence_row, unknown_run_text,
        },
        timeline_step_contents::{
            ActionConsequence, EvidenceMoment, SettledStep, StepActionButton, StepActionSlot,
            StepEvidenceRow, TimelineStep,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduledScanAction {}

impl StepActionButton for ScheduledScanAction {
    fn button_label(&self) -> String {
        match *self {}
    }

    fn action_consequence(&self) -> ActionConsequence {
        match *self {}
    }
}

pub type ScheduledScanStep = TimelineStep<ScheduledScanAction>;

impl From<ScanRunHistory> for EvidenceMoment {
    fn from(run_history: ScanRunHistory) -> Self {
        match run_history {
            ScanRunHistory::CompletedScan { finished_at, .. } => Self::PastEvent {
                happened_at: finished_at,
            },
            ScanRunHistory::NoCompletedScan => Self::NeverHappened,
            ScanRunHistory::JournalUnreadable(_) => Self::CurrentFact,
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
        ScanRunHistory::JournalUnreadable(read_failure) => unknown_run_text(read_failure),
    };
    timed_evidence_row(
        gettext("Last scan"),
        EvidenceMoment::from(last_completed_run),
        evidence_value,
        moment_context,
    )
}

pub const fn scan_result_failed(last_result: &ScanUnitResult) -> bool {
    match last_result {
        ScanUnitResult::NothingFound | ScanUnitResult::ThreatsFound => false,
        ScanUnitResult::ScannerError { .. } | ScanUnitResult::ServiceFailed { .. } => true,
    }
}

pub fn scanned_folders_text(scan_service: &ScanServiceEvidence) -> String {
    match scan_service {
        ScanServiceEvidence::ServiceConfigured { scan_targets, .. } => scan_targets.join("\n"),
        ScanServiceEvidence::ServiceMissing | ScanServiceEvidence::ServiceUnreadable => {
            gettext("Unknown")
        }
    }
}

pub const fn scheduled_scan_condition(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    daemon_answering: bool,
) -> CheckedCondition {
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerInactive | TimerState::TimerActive { .. },
            ..
        } if !daemon_answering => CheckedCondition::PrerequisiteMissing,
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerInactive,
            ..
        } => CheckedCondition::ConditionFailed,
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerActive { .. },
            scan_service,
            ..
        } => match scan_service {
            ScanServiceEvidence::ServiceConfigured { last_result, .. }
                if scan_result_failed(last_result) =>
            {
                CheckedCondition::ReviewSuggested
            }
            ScanServiceEvidence::ServiceConfigured { .. } => CheckedCondition::ConditionMet,
            ScanServiceEvidence::ServiceMissing => CheckedCondition::ReviewSuggested,
            ScanServiceEvidence::ServiceUnreadable => CheckedCondition::EvidenceUnknown,
        },
        ScheduledScanEvidence::LazaretSchedule => CheckedCondition::ConditionMet,
        ScheduledScanEvidence::NoSchedule => CheckedCondition::ReviewSuggested,
    }
}

pub fn last_scheduled_run_failed(scheduled_scan_evidence: &ScheduledScanEvidence) -> bool {
    matches!(
        scheduled_scan_evidence,
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerActive { .. },
            scan_service: ScanServiceEvidence::ServiceConfigured { last_result, .. },
            ..
        } if scan_result_failed(last_result)
    )
}

fn scheduled_status_text(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    daemon_answering: bool,
) -> String {
    match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer { .. } if !daemon_answering => daemon_awaited_text(),
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerInactive,
            ..
        } => gettext("The system timer is not active"),
        ScheduledScanEvidence::SystemTimer {
            timer_state: TimerState::TimerActive { next_run },
            scan_service,
            ..
        } => match scan_service {
            ScanServiceEvidence::ServiceConfigured { last_result, .. }
                if scan_result_failed(last_result) =>
            {
                gettext("The last scan ended with an error")
            }
            ScanServiceEvidence::ServiceConfigured { .. } => {
                gettext("Next scan: {time}").replace("{time}", &next_run_text(*next_run))
            }
            ScanServiceEvidence::ServiceMissing => {
                gettext("The timer starts a scan service that is not installed")
            }
            ScanServiceEvidence::ServiceUnreadable => {
                gettext("The scan service could not be read from systemd")
            }
        },
        ScheduledScanEvidence::LazaretSchedule => gettext("Scheduled by Lazaret"),
        ScheduledScanEvidence::NoSchedule => gettext("No scan is scheduled"),
    }
}

fn system_timer_rows(
    timer_state: &TimerState,
    scan_service: &ScanServiceEvidence,
    last_completed_run: ScanRunHistory,
    moment_context: MomentContext,
) -> Vec<StepEvidenceRow> {
    let next_scan_row = match timer_state {
        TimerState::TimerActive { next_run } => next_run_row(*next_run, moment_context),
        TimerState::TimerInactive => evidence_row(
            gettext("Next scan"),
            gettext("Not scheduled, because the timer is not active"),
        ),
    };
    vec![
        next_scan_row,
        last_run_row(last_completed_run, moment_context),
        StepEvidenceRow {
            evidence_moment: EvidenceMoment::SettingValue,
            ..evidence_row(
                gettext("Folders scanned"),
                scanned_folders_text(scan_service),
            )
        },
    ]
}

pub fn scheduled_scan_step<StepAction: StepActionButton>(
    scheduled_scan_evidence: &ScheduledScanEvidence,
    daemon_answering: bool,
    moment_context: MomentContext,
    distribution_family: DistributionFamily,
    header_action: StepActionSlot<StepAction>,
) -> TimelineStep<StepAction> {
    let evidence_rows = match scheduled_scan_evidence {
        ScheduledScanEvidence::SystemTimer {
            timer_state,
            scan_service,
            last_completed_run,
            ..
        } => system_timer_rows(
            timer_state,
            scan_service,
            *last_completed_run,
            moment_context,
        ),
        ScheduledScanEvidence::LazaretSchedule | ScheduledScanEvidence::NoSchedule => Vec::new(),
    };
    let guidance_commands = match scheduled_scan_evidence {
        ScheduledScanEvidence::NoSchedule => {
            remedy_commands(SuggestedRemedy::ScheduledScanEnable, distribution_family)
        }
        ScheduledScanEvidence::SystemTimer { .. } | ScheduledScanEvidence::LazaretSchedule => {
            Vec::new()
        }
    };
    TimelineStep::settled(
        gettext("Scheduled scan"),
        gettext(
            "A scheduled scan catches files that were not opened, or that only became detectable \
             after a signature update.",
        ),
        scheduled_status_text(scheduled_scan_evidence, daemon_answering),
        SettledStep {
            evidence_rows: plain_rows(evidence_rows),
            header_action,
            ..SettledStep::without_offers(
                scheduled_scan_condition(scheduled_scan_evidence, daemon_answering).node_state(),
            )
        },
    )
    .with_guidance_commands(guidance_commands)
}

pub fn scheduled_scans_page_steps(
    protection_evidence: &ProtectionEvidence,
    moment_context: MomentContext,
    distribution_family: DistributionFamily,
) -> Vec<ScheduledScanStep> {
    vec![scheduled_scan_step(
        &protection_evidence.scheduled_scan_evidence,
        daemon_is_answering(&protection_evidence.daemon_evidence),
        moment_context,
        distribution_family,
        StepActionSlot::NoAction,
    )]
}

#[cfg(test)]
mod scheduled_scans_presentation_tests {
    use jiff::SignedDuration;

    use super::*;
    use crate::{
        host_services::{
            protection_evidence::{
                host_protection_evidence::DaemonEvidence,
                protection_evidence_fixtures::{
                    REFERENCE_MOMENT, english_formatters, healthy_evidence,
                },
            },
            systemd_bus::host_systemd_units::ServiceFailureKind,
            systemd_journal::unit_journal_reader::UnitJournalReadFailure,
        },
        shared_widgets::step_timeline::timeline_step_contents::StepNodeState,
    };

    fn reference_context() -> MomentContext {
        MomentContext {
            moment_formatters: english_formatters(),
            reference_moment: REFERENCE_MOMENT,
        }
    }

    fn page_step_with(protection_evidence: &ProtectionEvidence) -> ScheduledScanStep {
        scheduled_scans_page_steps(
            protection_evidence,
            reference_context(),
            DistributionFamily::NixosFamily,
        )
        .remove(0)
    }

    fn step_of(scheduled_scan_evidence: ScheduledScanEvidence) -> ScheduledScanStep {
        page_step_with(&ProtectionEvidence {
            scheduled_scan_evidence,
            ..healthy_evidence()
        })
    }

    fn row_value<'step>(
        scheduled_step: &'step ScheduledScanStep,
        evidence_name: &str,
    ) -> &'step str {
        &scheduled_step
            .shown_evidence_rows()
            .into_iter()
            .find(|step_evidence| step_evidence.evidence_name == evidence_name)
            .unwrap()
            .evidence_value
    }

    fn system_timer_with(scan_service: ScanServiceEvidence) -> ScheduledScanEvidence {
        ScheduledScanEvidence::SystemTimer {
            service_unit: "clamdscan.service",
            timer_state: TimerState::TimerActive {
                next_run: UnitTimestamp::RecordedAt {
                    recorded_at: REFERENCE_MOMENT + SignedDuration::from_hours(6),
                },
            },
            scan_service,
            last_completed_run: ScanRunHistory::NoCompletedScan,
        }
    }

    #[test]
    fn each_row_says_whether_it_is_past_upcoming_or_a_setting() {
        let scheduled_step = step_of(ScheduledScanEvidence::SystemTimer {
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
        });
        assert_eq!(row_value(&scheduled_step, "Next scan"), "in 3 days");
        assert_eq!(
            row_value(&scheduled_step, "Last scan"),
            "2 hours ago · nothing found"
        );
        assert_eq!(row_value(&scheduled_step, "Folders scanned"), "/tmp");
    }

    #[test]
    fn the_schedule_page_offers_no_run_now() {
        let scheduled_step = page_step_with(&healthy_evidence());
        assert_eq!(scheduled_step.node_state(), StepNodeState::Completed);
        assert!(scheduled_step.offered_actions().is_empty());
    }

    #[test]
    fn an_unreadable_scan_service_after_a_readable_timer_needs_review() {
        let scheduled_step = step_of(system_timer_with(ScanServiceEvidence::ServiceUnreadable));
        assert_eq!(scheduled_step.node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            scheduled_step.status_text,
            "The scan service could not be read from systemd"
        );
    }

    #[test]
    fn a_missing_scan_service_is_not_reported_as_completed() {
        assert_eq!(
            step_of(system_timer_with(ScanServiceEvidence::ServiceMissing)).node_state(),
            StepNodeState::NeedsReview
        );
    }

    #[test]
    fn a_failed_last_run_is_reported_and_marked_for_a_rerun() {
        let failed_evidence = system_timer_with(ScanServiceEvidence::ServiceConfigured {
            scan_targets: vec!["/tmp".to_owned()],
            last_result: ScanUnitResult::ScannerError { exit_status: 2 },
        });
        assert_eq!(
            step_of(failed_evidence.clone()).status_text,
            "The last scan ended with an error"
        );
        assert!(last_scheduled_run_failed(&failed_evidence));
        assert!(!last_scheduled_run_failed(
            &healthy_evidence().scheduled_scan_evidence
        ));
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
    fn an_unreadable_scan_journal_is_unknown_rather_than_not_run_yet() {
        let ScheduledScanEvidence::SystemTimer {
            service_unit,
            timer_state,
            scan_service,
            ..
        } = healthy_evidence().scheduled_scan_evidence
        else {
            panic!("the healthy evidence has a system timer");
        };
        let scheduled_step = step_of(ScheduledScanEvidence::SystemTimer {
            service_unit,
            timer_state,
            scan_service,
            last_completed_run: ScanRunHistory::JournalUnreadable(
                UnitJournalReadFailure::ReadingTaskInterrupted,
            ),
        });
        assert_eq!(
            row_value(&scheduled_step, "Last scan"),
            "Unknown. Reading the system journal stopped before it finished"
        );
    }

    #[test]
    fn an_inactive_timer_fails() {
        let scheduled_step = step_of(ScheduledScanEvidence::SystemTimer {
            service_unit: "clamdscan.service",
            timer_state: TimerState::TimerInactive,
            scan_service: ScanServiceEvidence::ServiceConfigured {
                scan_targets: vec!["/tmp".to_owned()],
                last_result: ScanUnitResult::NothingFound,
            },
            last_completed_run: ScanRunHistory::NoCompletedScan,
        });
        assert_eq!(scheduled_step.node_state(), StepNodeState::HasFailed);
        assert_eq!(
            row_value(&scheduled_step, "Next scan"),
            "Not scheduled, because the timer is not active"
        );
    }

    #[test]
    fn a_stopped_daemon_leaves_the_schedule_waiting() {
        let scheduled_step = page_step_with(&ProtectionEvidence {
            daemon_evidence: DaemonEvidence::UnitStopped {
                service_unit: "clamav-daemon.service",
            },
            ..healthy_evidence()
        });
        assert_eq!(
            scheduled_step.node_state(),
            StepNodeState::AwaitingPrerequisite
        );
        assert_eq!(
            scheduled_step.status_text,
            "Needs the daemon, see Scan Engine"
        );
    }

    #[test]
    fn no_schedule_suggests_setting_one_up() {
        let scheduled_step = step_of(ScheduledScanEvidence::NoSchedule);
        assert_eq!(scheduled_step.node_state(), StepNodeState::NeedsReview);
        assert!(!scheduled_step.guidance_commands.is_empty());
    }
}
