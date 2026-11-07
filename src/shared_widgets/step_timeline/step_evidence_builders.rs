use gettextrs::gettext;
use jiff::Timestamp;

use crate::{
    host_services::{
        clamav_programs::distribution_install_guides::DistributionFamily,
        desktop::locale_formatting::MomentFormatters,
        systemd_journal::unit_journal_reader::UnitJournalReadFailure,
    },
    shared_widgets::{
        host_read_failure_text::unit_journal_failure_text,
        step_timeline::{
            suggested_remedy_commands::{SuggestedRemedy, suggested_command},
            timeline_step_contents::{
                ActionableEvidenceRow, EvidenceMoment, SettledNodeState, SettledStep,
                StepActionButton, StepEvidenceRow, TimelineStep, moment_value_text,
            },
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckedCondition {
    ConditionMet,
    SetupSuggested,
    ReviewSuggested,
    EvidenceUnknown,
    ConditionFailed,
    PrerequisiteMissing,
}

impl CheckedCondition {
    pub const fn node_state(self) -> SettledNodeState {
        match self {
            Self::ConditionMet => SettledNodeState::Completed,
            Self::SetupSuggested => SettledNodeState::ActNext,
            Self::ReviewSuggested | Self::EvidenceUnknown => SettledNodeState::NeedsReview,
            Self::ConditionFailed => SettledNodeState::HasFailed,
            Self::PrerequisiteMissing => SettledNodeState::AwaitingPrerequisite,
        }
    }
}

#[derive(Clone, Copy)]
pub struct MomentContext {
    pub moment_formatters: &'static MomentFormatters,
    pub reference_moment: Timestamp,
}

pub fn daemon_awaited_text() -> String {
    gettext("Needs the daemon, see Scan Engine")
}

pub const fn evidence_row(evidence_name: String, evidence_value: String) -> StepEvidenceRow {
    StepEvidenceRow::current_fact(evidence_name, evidence_value)
}

pub fn timed_evidence_row(
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

pub const fn no_guidance_step<StepAction: StepActionButton>(
    step_title: String,
    mechanism_details: String,
    node_state: SettledNodeState,
    status_text: String,
) -> TimelineStep<StepAction> {
    TimelineStep::settled(
        step_title,
        mechanism_details,
        status_text,
        SettledStep::without_offers(node_state),
    )
}

pub fn plain_rows<StepAction>(
    evidence_rows: impl IntoIterator<Item = StepEvidenceRow>,
) -> Vec<ActionableEvidenceRow<StepAction>> {
    evidence_rows.into_iter().map(Into::into).collect()
}

pub fn remedy_commands(
    suggested_remedy: SuggestedRemedy,
    distribution_family: DistributionFamily,
) -> Vec<String> {
    suggested_command(suggested_remedy, distribution_family)
        .into_iter()
        .map(str::to_owned)
        .collect()
}

pub fn unknown_run_text(read_failure: UnitJournalReadFailure) -> String {
    gettext("Unknown. {reason}").replace("{reason}", &unit_journal_failure_text(read_failure))
}
