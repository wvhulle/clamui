use crate::application_window::settings_navigation::SettingsSubpage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepNodeState {
    Completed,
    ActNext,
    InProgress,
    NeedsReview,
    HasFailed,
    AwaitingEarlier,
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
            Self::AwaitingEarlier => "content-loading-symbolic",
        }
    }

    pub const fn style_class(self) -> &'static str {
        match self {
            Self::Completed => "success",
            Self::ActNext | Self::InProgress => "accent",
            Self::NeedsReview => "warning",
            Self::HasFailed => "error",
            Self::AwaitingEarlier => "dim-label",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimelineStepAction {
    UpdateSignatures,
    RunScheduledScan { service_unit: &'static str },
    OpenSettingsSubpage(SettingsSubpage),
    QuarantineIncident,
    AskIncidentDeletion,
    DeleteIncidentFile,
    CancelIncidentDeletion,
    DismissIncident,
    LookUpIncidentSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepActionSlot {
    NoAction,
    ActionOffered {
        action_label: String,
        chosen_action: TimelineStepAction,
        action_suggested: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepChoiceRow {
    pub choice_description: String,
    pub choice_label: String,
    pub chosen_action: TimelineStepAction,
    pub choice_destructive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepEvidenceRow {
    pub evidence_name: String,
    pub evidence_value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimelineStep {
    pub step_title: String,
    pub mechanism_details: String,
    pub node_state: StepNodeState,
    pub status_text: String,
    pub evidence_rows: Vec<StepEvidenceRow>,
    pub guidance_commands: Vec<String>,
    pub choice_rows: Vec<StepChoiceRow>,
    pub action_slot: StepActionSlot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TimelineStepRowOutput {
    ActionChosen(TimelineStepAction),
    CopyRequested(String),
}
