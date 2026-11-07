use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::desktop::locale_formatting::exact_local_time_text,
    shared_widgets::step_timeline::timeline_step_contents::{
        ActionableEvidenceRow, EvidenceMoment, EvidenceRowControl, OfferedAction, StepActionButton,
        StepChoiceRow, StepEvidenceRow, StepPhase, TimelineStep, TimelineStepRowOutput,
    },
};

pub enum TimelineDetailRow<StepAction> {
    StepChoice(StepChoiceRow<StepAction>),
    ActionableEvidence(ActionableEvidenceRow<StepAction>),
    RunningEvidence(StepEvidenceRow),
    GuidanceCommand(String),
}

pub fn detail_rows_of<StepAction: StepActionButton>(
    timeline_step: &TimelineStep<StepAction>,
) -> Vec<TimelineDetailRow<StepAction>> {
    let phase_rows = match &timeline_step.step_phase {
        StepPhase::StepSettled(settled_step) => settled_step
            .choice_rows
            .iter()
            .cloned()
            .map(TimelineDetailRow::StepChoice)
            .chain(
                settled_step
                    .evidence_rows
                    .iter()
                    .cloned()
                    .map(TimelineDetailRow::ActionableEvidence),
            )
            .collect::<Vec<_>>(),
        StepPhase::StepRunning(running_step) => running_step
            .evidence_rows
            .iter()
            .cloned()
            .map(TimelineDetailRow::RunningEvidence)
            .collect(),
    };
    phase_rows
        .into_iter()
        .chain(
            timeline_step
                .guidance_commands
                .iter()
                .cloned()
                .map(TimelineDetailRow::GuidanceCommand),
        )
        .collect()
}

fn moment_prefix(evidence_moment: EvidenceMoment) -> Option<gtk::Widget> {
    let icon_name = match evidence_moment {
        EvidenceMoment::CurrentFact => return None,
        EvidenceMoment::HappeningNow => return Some(adw::Spinner::new().upcast()),
        EvidenceMoment::PastEvent { .. } | EvidenceMoment::NeverHappened => {
            "document-open-recent-symbolic"
        }
        EvidenceMoment::UpcomingEvent { .. } | EvidenceMoment::NothingUpcoming => "alarm-symbolic",
        EvidenceMoment::SettingValue => "emblem-system-symbolic",
    };
    let moment_icon = gtk::Image::from_icon_name(icon_name);
    moment_icon.add_css_class("dim-label");
    Some(moment_icon.upcast())
}

fn exact_moment_text(evidence_moment: EvidenceMoment) -> Option<String> {
    match evidence_moment {
        EvidenceMoment::PastEvent { happened_at } => Some(exact_local_time_text(happened_at)),
        EvidenceMoment::UpcomingEvent { due_at } => Some(exact_local_time_text(due_at)),
        EvidenceMoment::CurrentFact
        | EvidenceMoment::HappeningNow
        | EvidenceMoment::NeverHappened
        | EvidenceMoment::NothingUpcoming
        | EvidenceMoment::SettingValue => None,
    }
}

fn evidence_row(step_evidence: &StepEvidenceRow) -> adw::ActionRow {
    let evidence_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(&step_evidence.evidence_name)
        .subtitle(&step_evidence.evidence_value)
        .subtitle_selectable(true)
        .subtitle_lines(0)
        .css_classes(["property"])
        .build();
    if let Some(exact_moment) = exact_moment_text(step_evidence.evidence_moment) {
        evidence_row.set_tooltip_text(Some(&exact_moment));
    }
    if let Some(moment_widget) = moment_prefix(step_evidence.evidence_moment) {
        evidence_row.add_prefix(&moment_widget);
    }
    evidence_row
}

pub fn offered_action_button<StepAction: StepActionButton>(
    offered_action: &OfferedAction<StepAction>,
) -> gtk::Button {
    let action_button = gtk::Button::builder()
        .label(offered_action.offered_action.button_label())
        .valign(gtk::Align::Center)
        .build();
    if let Some(style_class) = offered_action.button_style().css_class() {
        action_button.add_css_class(style_class);
    }
    action_button
}

fn action_choosing_button<StepAction: StepActionButton>(
    offered_action: &OfferedAction<StepAction>,
    sender: FactorySender<TimelineDetailRow<StepAction>>,
) -> gtk::Button {
    let action_button = offered_action_button(offered_action);
    let chosen_action = offered_action.offered_action.clone();
    action_button.connect_clicked(move |_clicked_button| {
        let _step_closed =
            sender.output(TimelineStepRowOutput::ActionChosen(chosen_action.clone()));
    });
    action_button
}

fn attach_row_control<StepAction: StepActionButton>(
    evidence_row: &adw::ActionRow,
    row_control: &EvidenceRowControl<StepAction>,
    sender: FactorySender<TimelineDetailRow<StepAction>>,
) {
    match row_control {
        EvidenceRowControl::NoRowControl => {}
        EvidenceRowControl::RowButton(offered_action) => {
            evidence_row.add_suffix(&action_choosing_button(offered_action, sender));
        }
    }
}

fn guidance_command_row(guidance_command: &str) -> adw::ActionRow {
    let command_label = gtk::Label::builder()
        .label(guidance_command)
        .use_markup(false)
        .selectable(true)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .hexpand(true)
        .xalign(0.0)
        .css_classes(["monospace"])
        .build();
    let command_row = adw::ActionRow::new();
    command_row.add_prefix(&command_label);
    command_row
}

fn copy_button<StepAction: StepActionButton>(
    copied_command: String,
    sender: FactorySender<TimelineDetailRow<StepAction>>,
) -> gtk::Button {
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(gettext("Copy"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    copy_button.connect_clicked(move |_clicked_button| {
        let _step_closed =
            sender.output(TimelineStepRowOutput::CopyRequested(copied_command.clone()));
    });
    copy_button
}

fn choice_row<StepAction>(step_choice: &StepChoiceRow<StepAction>) -> adw::ActionRow {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(&step_choice.choice_description)
        .title_lines(0)
        .build()
}

impl<StepAction: StepActionButton> FactoryComponent for TimelineDetailRow<StepAction> {
    type ParentWidget = adw::ExpanderRow;
    type CommandOutput = ();
    type Input = ();
    type Output = TimelineStepRowOutput<StepAction>;
    type Init = Self;
    type Root = adw::ActionRow;
    type Widgets = ();
    type Index = DynamicIndex;

    fn init_model(
        detail_row: Self::Init,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        detail_row
    }

    fn init_root(&self) -> Self::Root {
        match self {
            Self::StepChoice(step_choice) => choice_row(step_choice),
            Self::ActionableEvidence(actionable_row) => {
                evidence_row(&actionable_row.shown_evidence)
            }
            Self::RunningEvidence(step_evidence) => evidence_row(step_evidence),
            Self::GuidanceCommand(guidance_command) => guidance_command_row(guidance_command),
        }
    }

    fn init_widgets(
        &mut self,
        _row_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &gtk::Widget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        match self {
            Self::StepChoice(step_choice) => {
                root.add_suffix(&action_choosing_button(
                    &step_choice.offered_choice(),
                    sender,
                ));
            }
            Self::GuidanceCommand(guidance_command) => {
                root.add_suffix(&copy_button(guidance_command.clone(), sender));
            }
            Self::ActionableEvidence(actionable_row) => {
                attach_row_control(&root, &actionable_row.row_control, sender);
            }
            Self::RunningEvidence(_) => {}
        }
    }
}
