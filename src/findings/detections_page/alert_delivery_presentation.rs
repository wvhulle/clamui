use gettextrs::gettext;

use crate::{
    host_services::{
        clamav_programs::distribution_install_guides::DistributionFamily,
        detection_journal::detection_journal_follower::JournalAccess,
        protection_evidence::{
            host_protection_evidence::ProtectionEvidence,
            process_attach_scope::{ProcessAttachReadFailure, ProcessAttachScope},
        },
        systemd_bus::host_systemd_units::{UnitActivity, UnitState},
    },
    shared_widgets::{
        journal_follow_failure_text::journal_follow_failure_text,
        step_timeline::{
            step_evidence_builders::{CheckedCondition, evidence_row, plain_rows, remedy_commands},
            suggested_remedy_commands::SuggestedRemedy,
            timeline_step_contents::{
                ActionConsequence, ActionableEvidenceRow, OfferedAction, SettledStep,
                StepActionButton, StepActionSlot, TimelineStep,
            },
        },
    },
};

const NIXOS_PTRACE_SNIPPET: &str = "boot.kernel.sysctl.\"kernel.yama.ptrace_scope\" = 1;";
const SYSCTL_PTRACE_COMMAND: &str = "echo 'kernel.yama.ptrace_scope = 1' | sudo tee \
                                     /etc/sysctl.d/10-ptrace.conf && sudo sysctl --system";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlertStepAction {
    OpenPreferences,
}

impl StepActionButton for AlertStepAction {
    fn button_label(&self) -> String {
        match self {
            Self::OpenPreferences => gettext("Open Preferences"),
        }
    }

    fn action_consequence(&self) -> ActionConsequence {
        match self {
            Self::OpenPreferences => ActionConsequence::OrdinaryAction,
        }
    }
}

pub type AlertStep = TimelineStep<AlertStepAction>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlertReadiness {
    pub journal_access: JournalAccess,
    pub notifications_enabled: bool,
}

const fn background_service_runs(background_service_state: UnitState) -> bool {
    matches!(
        background_service_state,
        UnitState::UnitLoaded(UnitActivity::UnitActive)
    )
}

pub fn alerts_condition(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
) -> CheckedCondition {
    match &alert_readiness.journal_access {
        JournalAccess::JournalUnreadable | JournalAccess::FollowingFailed(_) => {
            CheckedCondition::ConditionFailed
        }
        JournalAccess::FollowingJournal
            if !alert_readiness.notifications_enabled
                || !background_service_runs(background_service_state) =>
        {
            CheckedCondition::ReviewSuggested
        }
        JournalAccess::FollowingJournal => CheckedCondition::ConditionMet,
    }
}

fn alerts_status_text(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
) -> String {
    match &alert_readiness.journal_access {
        JournalAccess::JournalUnreadable => {
            gettext("The system journal can't be read. Add your user to the systemd-journal group.")
        }
        JournalAccess::FollowingFailed(follow_failure) => {
            journal_follow_failure_text(follow_failure)
        }
        JournalAccess::FollowingJournal if !alert_readiness.notifications_enabled => {
            gettext("Notifications are turned off in the preferences")
        }
        JournalAccess::FollowingJournal if !background_service_runs(background_service_state) => {
            gettext(
                "Alerts stop when you quit Lazaret, because it isn't set up to run in the \
                 background",
            )
        }
        JournalAccess::FollowingJournal => {
            gettext("Running in the background and following the journal")
        }
    }
}

fn alerts_timeline_step<StepAction: StepActionButton>(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
    header_action: StepActionSlot<StepAction>,
    evidence_rows: Vec<ActionableEvidenceRow<StepAction>>,
) -> TimelineStep<StepAction> {
    TimelineStep::settled(
        gettext("Alerts"),
        gettext(
            "Lazaret follows the system journal and notifies you when something is detected. It \
             can only do that while it is running, so it should run in the background.",
        ),
        alerts_status_text(alert_readiness, background_service_state),
        SettledStep {
            header_action,
            evidence_rows,
            ..SettledStep::without_offers(
                alerts_condition(alert_readiness, background_service_state).node_state(),
            )
        },
    )
}

pub fn alerts_status_step<StepAction: StepActionButton>(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
    header_action: StepActionSlot<StepAction>,
) -> TimelineStep<StepAction> {
    alerts_timeline_step(
        alert_readiness,
        background_service_state,
        header_action,
        Vec::new(),
    )
}

fn notifications_text(notifications_enabled: bool) -> String {
    if notifications_enabled {
        gettext("On")
    } else {
        gettext("Off")
    }
}

fn background_service_text(background_service_state: UnitState) -> String {
    match background_service_state {
        UnitState::UnitLoaded(UnitActivity::UnitActive) => gettext("Running"),
        UnitState::UnitLoaded(UnitActivity::UnitInactive) => gettext("Not running"),
        UnitState::UnitNotFound => gettext("Not set up"),
        UnitState::SystemdUnavailable => gettext("Unknown, systemd can't be reached"),
    }
}

fn journal_access_text(journal_access: &JournalAccess) -> String {
    match journal_access {
        JournalAccess::FollowingJournal => gettext("Followed"),
        JournalAccess::JournalUnreadable => gettext("Can't be read"),
        JournalAccess::FollowingFailed(_) => gettext("Following stopped"),
    }
}

pub fn alert_delivery_step(
    alert_readiness: &AlertReadiness,
    background_service_state: UnitState,
    distribution_family: DistributionFamily,
) -> AlertStep {
    let preferences_offer = if alert_readiness.notifications_enabled {
        StepActionSlot::NoAction
    } else {
        StepActionSlot::ActionOffered(OfferedAction::suggested(AlertStepAction::OpenPreferences))
    };
    let guidance_commands = if alert_readiness.journal_access == JournalAccess::FollowingJournal
        && alert_readiness.notifications_enabled
        && !background_service_runs(background_service_state)
    {
        remedy_commands(SuggestedRemedy::BackgroundAlertsEnable, distribution_family)
    } else {
        Vec::new()
    };
    alerts_timeline_step(
        alert_readiness,
        background_service_state,
        preferences_offer,
        plain_rows([
            evidence_row(
                gettext("Notifications"),
                notifications_text(alert_readiness.notifications_enabled),
            ),
            evidence_row(
                gettext("Background service"),
                background_service_text(background_service_state),
            ),
            evidence_row(
                gettext("System journal"),
                journal_access_text(&alert_readiness.journal_access),
            ),
        ]),
    )
    .with_guidance_commands(guidance_commands)
}

pub const fn process_attach_condition(
    process_attach_scope: ProcessAttachScope,
) -> CheckedCondition {
    match process_attach_scope {
        ProcessAttachScope::AttachRestricted => CheckedCondition::ConditionMet,
        ProcessAttachScope::AnyProgramMayAttach | ProcessAttachScope::YamaNotLoaded => {
            CheckedCondition::ReviewSuggested
        }
        ProcessAttachScope::ScopeUnreadable(_) => CheckedCondition::EvidenceUnknown,
    }
}

fn process_attach_failure_text(read_failure: ProcessAttachReadFailure) -> String {
    match read_failure {
        ProcessAttachReadFailure::ScopeFileUnreadable { failure_kind } => gettext(
            "Whether other programs can attach is unknown, because the kernel setting can't be \
             read: {reason}",
        )
        .replace("{reason}", &failure_kind.to_string()),
        ProcessAttachReadFailure::ScopeValueUnrecognized => gettext(
            "Whether other programs can attach is unknown, because the kernel reports a value \
             Lazaret doesn't recognize",
        ),
        ProcessAttachReadFailure::ReadingTaskInterrupted => gettext(
            "Whether other programs can attach is unknown, because the check stopped before it \
             finished",
        ),
    }
}

fn process_attach_status_text(process_attach_scope: ProcessAttachScope) -> String {
    match process_attach_scope {
        ProcessAttachScope::AttachRestricted => {
            gettext("Programs can't attach to other programs you run, such as Lazaret")
        }
        ProcessAttachScope::AnyProgramMayAttach => gettext(
            "Any program you run can attach to Lazaret and change what it shows, including \
             detections and the decisions you make here",
        ),
        ProcessAttachScope::YamaNotLoaded => gettext(
            "This kernel doesn't restrict attaching, so any program you run can attach to Lazaret \
             and change what it shows",
        ),
        ProcessAttachScope::ScopeUnreadable(read_failure) => {
            process_attach_failure_text(read_failure)
        }
    }
}

const fn ptrace_scope_command(distribution_family: DistributionFamily) -> &'static str {
    match distribution_family {
        DistributionFamily::NixosFamily => NIXOS_PTRACE_SNIPPET,
        DistributionFamily::DebianFamily
        | DistributionFamily::FedoraWorkstation
        | DistributionFamily::FedoraAtomic
        | DistributionFamily::ArchFamily
        | DistributionFamily::UnrecognizedFamily => SYSCTL_PTRACE_COMMAND,
    }
}

pub fn process_attach_step(
    process_attach_scope: ProcessAttachScope,
    distribution_family: DistributionFamily,
) -> AlertStep {
    let guidance_commands = match process_attach_scope {
        ProcessAttachScope::AnyProgramMayAttach => {
            vec![ptrace_scope_command(distribution_family).to_owned()]
        }
        ProcessAttachScope::AttachRestricted
        | ProcessAttachScope::YamaNotLoaded
        | ProcessAttachScope::ScopeUnreadable(_) => Vec::new(),
    };
    TimelineStep::settled(
        gettext("Other programs can't attach to Lazaret"),
        gettext(
            "A program that attaches to Lazaret can hide alerts or change your decisions. Setting \
             kernel.yama.ptrace_scope to 1 lets only a program's parent attach to it.",
        ),
        process_attach_status_text(process_attach_scope),
        SettledStep::without_offers(process_attach_condition(process_attach_scope).node_state()),
    )
    .with_guidance_commands(guidance_commands)
}

pub fn alert_group_steps(
    protection_evidence: &ProtectionEvidence,
    alert_readiness: &AlertReadiness,
    distribution_family: DistributionFamily,
) -> Vec<AlertStep> {
    vec![
        alert_delivery_step(
            alert_readiness,
            protection_evidence.background_service_state,
            distribution_family,
        ),
        process_attach_step(
            protection_evidence.process_attach_scope,
            distribution_family,
        ),
    ]
}

#[cfg(test)]
mod alert_delivery_presentation_tests {
    use super::*;
    use crate::{
        host_services::protection_evidence::protection_evidence_fixtures::healthy_evidence,
        shared_widgets::step_timeline::timeline_step_contents::StepNodeState,
    };

    fn ready_alerts() -> AlertReadiness {
        AlertReadiness {
            journal_access: JournalAccess::FollowingJournal,
            notifications_enabled: true,
        }
    }

    fn alert_step_state(
        alert_readiness: &AlertReadiness,
        background_service_state: UnitState,
    ) -> StepNodeState {
        alert_delivery_step(
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
    fn the_alert_step_shows_notifications_service_and_journal() {
        let delivery_step = alert_delivery_step(
            &ready_alerts(),
            UnitState::UnitNotFound,
            DistributionFamily::NixosFamily,
        );
        let shown_rows = delivery_step
            .shown_evidence_rows()
            .into_iter()
            .map(|step_evidence| {
                (
                    step_evidence.evidence_name.as_str(),
                    step_evidence.evidence_value.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            shown_rows,
            vec![
                ("Notifications", "On"),
                ("Background service", "Not set up"),
                ("System journal", "Followed"),
            ]
        );
        assert_eq!(
            delivery_step.guidance_commands,
            vec!["services.lazaret.enable = true;".to_owned()]
        );
        assert_eq!(delivery_step.header_offer(), None);
    }

    #[test]
    fn turned_off_notifications_offer_the_preferences() {
        let delivery_step = alert_delivery_step(
            &AlertReadiness {
                notifications_enabled: false,
                ..ready_alerts()
            },
            UnitState::UnitLoaded(UnitActivity::UnitActive),
            DistributionFamily::NixosFamily,
        );
        assert_eq!(
            delivery_step.header_offer(),
            Some(OfferedAction::suggested(AlertStepAction::OpenPreferences))
        );
        assert!(delivery_step.guidance_commands.is_empty());
    }

    #[test]
    fn the_process_attach_step_follows_the_ptrace_scope() {
        let restricted_step = process_attach_step(
            ProcessAttachScope::AttachRestricted,
            DistributionFamily::NixosFamily,
        );
        assert_eq!(restricted_step.node_state(), StepNodeState::Completed);
        assert_eq!(
            restricted_step.step_title,
            "Other programs can't attach to Lazaret"
        );
        assert!(restricted_step.guidance_commands.is_empty());
        let open_step = process_attach_step(
            ProcessAttachScope::AnyProgramMayAttach,
            DistributionFamily::DebianFamily,
        );
        assert_eq!(open_step.node_state(), StepNodeState::NeedsReview);
        assert_eq!(
            open_step.guidance_commands,
            vec![SYSCTL_PTRACE_COMMAND.to_owned()]
        );
        assert_eq!(
            process_attach_step(
                ProcessAttachScope::YamaNotLoaded,
                DistributionFamily::NixosFamily
            )
            .node_state(),
            StepNodeState::NeedsReview
        );
        let unknown_step = process_attach_step(
            ProcessAttachScope::ScopeUnreadable(ProcessAttachReadFailure::ReadingTaskInterrupted),
            DistributionFamily::NixosFamily,
        );
        assert_eq!(unknown_step.node_state(), StepNodeState::NeedsReview);
        assert!(
            unknown_step
                .status_text
                .starts_with("Whether other programs")
        );
    }

    #[test]
    fn the_alert_group_lists_delivery_then_process_attach() {
        let group_steps = alert_group_steps(
            &healthy_evidence(),
            &ready_alerts(),
            DistributionFamily::NixosFamily,
        );
        assert_eq!(
            group_steps
                .iter()
                .map(|alert_step| alert_step.step_title.as_str())
                .collect::<Vec<_>>(),
            vec!["Alerts", "Other programs can't attach to Lazaret"]
        );
        assert!(
            group_steps
                .iter()
                .all(|alert_step| alert_step.node_state() == StepNodeState::Completed)
        );
    }
}
