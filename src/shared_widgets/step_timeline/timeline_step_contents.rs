use gettextrs::gettext;
use jiff::Timestamp;

use crate::{
    application_window::settings_navigation::SettingsSubpage,
    host_services::desktop::locale_formatting::MomentFormatters,
};

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
pub enum TimelineStepAction {
    UpdateSignatures,
    CancelSignatureUpdate,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceMoment {
    CurrentFact,
    HappeningNow,
    PastEvent { happened_at: Timestamp },
    NeverHappened,
    UpcomingEvent { due_at: Timestamp },
    NothingUpcoming,
    FixedSetting,
    ChangeableSetting { settings_subpage: SettingsSubpage },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepEvidenceRow {
    pub evidence_name: String,
    pub evidence_value: String,
    pub evidence_moment: EvidenceMoment,
    pub row_action: StepActionSlot,
}

impl StepEvidenceRow {
    pub const fn current_fact(evidence_name: String, evidence_value: String) -> Self {
        Self {
            evidence_name,
            evidence_value,
            evidence_moment: EvidenceMoment::CurrentFact,
            row_action: StepActionSlot::NoAction,
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
        | EvidenceMoment::FixedSetting
        | EvidenceMoment::ChangeableSetting { .. } => return moment_details,
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
}
