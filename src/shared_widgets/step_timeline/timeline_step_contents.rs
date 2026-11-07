use std::fmt::Debug;

use gettextrs::gettext;
use jiff::Timestamp;

use crate::host_services::desktop::locale_formatting::MomentFormatters;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepNodeState {
    Completed,
    ActNext,
    InProgress,
    NeedsReview,
    HasFailed,
    AwaitingPrerequisite,
}

impl StepNodeState {
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::ActNext | Self::NeedsReview | Self::HasFailed)
    }

    pub const fn icon_name(self) -> &'static str {
        match self {
            Self::Completed => "object-select-symbolic",
            Self::ActNext | Self::InProgress => "media-record-symbolic",
            Self::NeedsReview => "dialog-warning-symbolic",
            Self::HasFailed => "dialog-error-symbolic",
            Self::AwaitingPrerequisite => "content-loading-symbolic",
        }
    }

    pub const fn style_class(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::ActNext | Self::InProgress => "accent",
            Self::NeedsReview => "warning",
            Self::HasFailed => "error",
            Self::AwaitingPrerequisite => "dim-label",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettledNodeState {
    Completed,
    ActNext,
    NeedsReview,
    HasFailed,
    AwaitingPrerequisite,
}

impl From<SettledNodeState> for StepNodeState {
    fn from(settled_state: SettledNodeState) -> Self {
        match settled_state {
            SettledNodeState::Completed => Self::Completed,
            SettledNodeState::ActNext => Self::ActNext,
            SettledNodeState::NeedsReview => Self::NeedsReview,
            SettledNodeState::HasFailed => Self::HasFailed,
            SettledNodeState::AwaitingPrerequisite => Self::AwaitingPrerequisite,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionConsequence {
    OrdinaryAction,
    DestructiveAction,
}

pub trait StepActionButton: Clone + Debug + Send + 'static {
    fn button_label(&self) -> String;
    fn action_consequence(&self) -> ActionConsequence;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionEmphasis {
    SuggestedAction,
    PlainAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ButtonStyle {
    DestructiveButton,
    SuggestedButton,
    PlainButton,
}

impl ButtonStyle {
    pub const fn css_class(self) -> Option<&'static str> {
        match self {
            Self::DestructiveButton => Some("destructive-action"),
            Self::SuggestedButton => Some("suggested-action"),
            Self::PlainButton => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferedAction<StepAction> {
    pub offered_action: StepAction,
    pub action_emphasis: ActionEmphasis,
}

impl<StepAction: StepActionButton> OfferedAction<StepAction> {
    pub const fn plain(offered_action: StepAction) -> Self {
        Self {
            offered_action,
            action_emphasis: ActionEmphasis::PlainAction,
        }
    }

    pub const fn suggested(offered_action: StepAction) -> Self {
        Self {
            offered_action,
            action_emphasis: ActionEmphasis::SuggestedAction,
        }
    }

    pub fn button_style(&self) -> ButtonStyle {
        match (
            self.offered_action.action_consequence(),
            self.action_emphasis,
        ) {
            (
                ActionConsequence::DestructiveAction,
                ActionEmphasis::SuggestedAction | ActionEmphasis::PlainAction,
            ) => ButtonStyle::DestructiveButton,
            (ActionConsequence::OrdinaryAction, ActionEmphasis::SuggestedAction) => {
                ButtonStyle::SuggestedButton
            }
            (ActionConsequence::OrdinaryAction, ActionEmphasis::PlainAction) => {
                ButtonStyle::PlainButton
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepActionSlot<StepAction> {
    NoAction,
    ActionOffered(OfferedAction<StepAction>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepChoiceRow<StepAction> {
    pub choice_description: String,
    pub chosen_action: StepAction,
}

impl<StepAction: StepActionButton> StepChoiceRow<StepAction> {
    pub fn offered_choice(&self) -> OfferedAction<StepAction> {
        OfferedAction::plain(self.chosen_action.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceMoment {
    CurrentFact,
    HappeningNow,
    PastEvent { happened_at: Timestamp },
    NeverHappened,
    UpcomingEvent { due_at: Timestamp },
    NothingUpcoming,
    SettingValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepEvidenceRow {
    pub evidence_name: String,
    pub evidence_value: String,
    pub evidence_moment: EvidenceMoment,
}

impl StepEvidenceRow {
    pub const fn current_fact(evidence_name: String, evidence_value: String) -> Self {
        Self {
            evidence_name,
            evidence_value,
            evidence_moment: EvidenceMoment::CurrentFact,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceRowControl<StepAction> {
    NoRowControl,
    RowButton(OfferedAction<StepAction>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionableEvidenceRow<StepAction> {
    pub shown_evidence: StepEvidenceRow,
    pub row_control: EvidenceRowControl<StepAction>,
}

impl<StepAction> From<StepEvidenceRow> for ActionableEvidenceRow<StepAction> {
    fn from(shown_evidence: StepEvidenceRow) -> Self {
        Self {
            shown_evidence,
            row_control: EvidenceRowControl::NoRowControl,
        }
    }
}

pub fn moment_value_text(
    moment_formatters: &MomentFormatters,
    evidence_moment: EvidenceMoment,
    moment_details: String,
    reference_moment: Timestamp,
) -> String {
    let relative_text = match evidence_moment {
        EvidenceMoment::PastEvent { happened_at } => moment_formatters
            .relative_moment_text(happened_at.min(reference_moment), reference_moment),
        EvidenceMoment::UpcomingEvent { due_at } => {
            moment_formatters.relative_moment_text(due_at, reference_moment)
        }
        EvidenceMoment::CurrentFact
        | EvidenceMoment::HappeningNow
        | EvidenceMoment::NeverHappened
        | EvidenceMoment::NothingUpcoming
        | EvidenceMoment::SettingValue => return moment_details,
    };
    if moment_details.is_empty() {
        relative_text
    } else {
        gettext("{moment} · {details}")
            .replace("{moment}", &relative_text)
            .replace("{details}", &moment_details)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettledStep<StepAction> {
    pub node_state: SettledNodeState,
    pub evidence_rows: Vec<ActionableEvidenceRow<StepAction>>,
    pub choice_rows: Vec<StepChoiceRow<StepAction>>,
    pub header_action: StepActionSlot<StepAction>,
}

impl<StepAction> SettledStep<StepAction> {
    pub const fn without_offers(node_state: SettledNodeState) -> Self {
        Self {
            node_state,
            evidence_rows: Vec::new(),
            choice_rows: Vec::new(),
            header_action: StepActionSlot::NoAction,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelSlot<StepAction> {
    NotCancellable,
    Cancellable { cancel_action: StepAction },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningStep<StepAction> {
    pub evidence_rows: Vec<StepEvidenceRow>,
    pub cancel_slot: CancelSlot<StepAction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepPhase<StepAction> {
    StepSettled(SettledStep<StepAction>),
    StepRunning(RunningStep<StepAction>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineStep<StepAction> {
    pub step_title: String,
    pub mechanism_details: String,
    pub status_text: String,
    pub guidance_commands: Vec<String>,
    pub step_phase: StepPhase<StepAction>,
}

impl<StepAction: StepActionButton> TimelineStep<StepAction> {
    pub const fn settled(
        step_title: String,
        mechanism_details: String,
        status_text: String,
        settled_step: SettledStep<StepAction>,
    ) -> Self {
        Self {
            step_title,
            mechanism_details,
            status_text,
            guidance_commands: Vec::new(),
            step_phase: StepPhase::StepSettled(settled_step),
        }
    }

    pub const fn running(
        step_title: String,
        mechanism_details: String,
        status_text: String,
        running_step: RunningStep<StepAction>,
    ) -> Self {
        Self {
            step_title,
            mechanism_details,
            status_text,
            guidance_commands: Vec::new(),
            step_phase: StepPhase::StepRunning(running_step),
        }
    }

    pub fn with_guidance_commands(self, guidance_commands: Vec<String>) -> Self {
        Self {
            guidance_commands,
            ..self
        }
    }

    pub fn node_state(&self) -> StepNodeState {
        match &self.step_phase {
            StepPhase::StepSettled(settled_step) => settled_step.node_state.into(),
            StepPhase::StepRunning(_) => StepNodeState::InProgress,
        }
    }

    pub fn header_offer(&self) -> Option<OfferedAction<StepAction>> {
        match &self.step_phase {
            StepPhase::StepSettled(SettledStep {
                header_action: StepActionSlot::ActionOffered(offered_action),
                ..
            }) => Some(offered_action.clone()),
            StepPhase::StepRunning(RunningStep {
                cancel_slot: CancelSlot::Cancellable { cancel_action },
                ..
            }) => Some(OfferedAction::plain(cancel_action.clone())),
            StepPhase::StepSettled(SettledStep {
                header_action: StepActionSlot::NoAction,
                ..
            })
            | StepPhase::StepRunning(RunningStep {
                cancel_slot: CancelSlot::NotCancellable,
                ..
            }) => None,
        }
    }
}

#[cfg(test)]
impl<StepAction: StepActionButton> TimelineStep<StepAction> {
    pub fn shown_evidence_rows(&self) -> Vec<&StepEvidenceRow> {
        match &self.step_phase {
            StepPhase::StepSettled(settled_step) => settled_step
                .evidence_rows
                .iter()
                .map(|actionable_row| &actionable_row.shown_evidence)
                .collect(),
            StepPhase::StepRunning(running_step) => running_step.evidence_rows.iter().collect(),
        }
    }

    pub fn offered_actions(&self) -> Vec<OfferedAction<StepAction>> {
        let StepPhase::StepSettled(settled_step) = &self.step_phase else {
            return self.header_offer().into_iter().collect();
        };
        self.header_offer()
            .into_iter()
            .chain(
                settled_step.evidence_rows.iter().filter_map(
                    |actionable_row| match &actionable_row.row_control {
                        EvidenceRowControl::RowButton(offered_action) => {
                            Some(offered_action.clone())
                        }
                        EvidenceRowControl::NoRowControl => None,
                    },
                ),
            )
            .chain(
                settled_step
                    .choice_rows
                    .iter()
                    .map(StepChoiceRow::offered_choice),
            )
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimelineStepRowOutput<StepAction> {
    ActionChosen(StepAction),
    CopyRequested(String),
}

#[cfg(test)]
mod timeline_step_contents_tests {
    use icu::locale::locale;

    use super::*;

    const NOW: Timestamp = Timestamp::constant(1_794_223_800, 0);

    fn english_formatters() -> MomentFormatters {
        MomentFormatters::try_for_locales(&locale!("en"), &locale!("en")).unwrap()
    }

    #[test]
    fn timed_rows_lead_with_the_moment_and_keep_their_details() {
        let moment_formatters = english_formatters();
        assert_eq!(
            moment_value_text(
                &moment_formatters,
                EvidenceMoment::PastEvent {
                    happened_at: NOW - jiff::SignedDuration::from_hours(2)
                },
                "nothing found".to_owned(),
                NOW
            ),
            "2 hours ago · nothing found"
        );
        assert_eq!(
            moment_value_text(
                &moment_formatters,
                EvidenceMoment::PastEvent {
                    happened_at: NOW + jiff::SignedDuration::from_secs(90)
                },
                String::new(),
                NOW
            ),
            "now"
        );
        assert_eq!(
            moment_value_text(
                &moment_formatters,
                EvidenceMoment::NeverHappened,
                "Not run yet".to_owned(),
                NOW
            ),
            "Not run yet"
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SampleStepAction {
        EraseSampleFile,
        StartSampleRun,
        StopSampleRun,
    }

    impl StepActionButton for SampleStepAction {
        fn button_label(&self) -> String {
            format!("{self:?}")
        }

        fn action_consequence(&self) -> ActionConsequence {
            match self {
                Self::EraseSampleFile => ActionConsequence::DestructiveAction,
                Self::StartSampleRun | Self::StopSampleRun => ActionConsequence::OrdinaryAction,
            }
        }
    }

    #[test]
    fn a_destructive_action_is_styled_destructive_however_it_is_offered() {
        assert_eq!(
            OfferedAction::suggested(SampleStepAction::EraseSampleFile).button_style(),
            ButtonStyle::DestructiveButton
        );
        assert_eq!(
            OfferedAction::plain(SampleStepAction::EraseSampleFile).button_style(),
            ButtonStyle::DestructiveButton
        );
        assert_eq!(
            StepChoiceRow {
                choice_description: "Erase".to_owned(),
                chosen_action: SampleStepAction::EraseSampleFile,
            }
            .offered_choice()
            .button_style(),
            ButtonStyle::DestructiveButton
        );
        assert_eq!(
            OfferedAction::suggested(SampleStepAction::StartSampleRun).button_style(),
            ButtonStyle::SuggestedButton
        );
    }

    #[test]
    fn a_running_step_offers_nothing_but_its_cancel_action() {
        let running_step = TimelineStep::running(
            "Sample".to_owned(),
            String::new(),
            "Running".to_owned(),
            RunningStep {
                evidence_rows: vec![StepEvidenceRow::current_fact(
                    "Output".to_owned(),
                    "line".to_owned(),
                )],
                cancel_slot: CancelSlot::Cancellable {
                    cancel_action: SampleStepAction::StopSampleRun,
                },
            },
        );
        assert_eq!(running_step.node_state(), StepNodeState::InProgress);
        assert_eq!(
            running_step.offered_actions(),
            vec![OfferedAction::plain(SampleStepAction::StopSampleRun)]
        );
        let uncancellable_step = TimelineStep {
            step_phase: StepPhase::StepRunning(RunningStep {
                evidence_rows: Vec::new(),
                cancel_slot: CancelSlot::NotCancellable,
            }),
            ..running_step
        };
        assert_eq!(uncancellable_step.offered_actions(), Vec::new());
    }
}
