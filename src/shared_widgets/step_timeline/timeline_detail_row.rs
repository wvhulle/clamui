use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::shared_widgets::step_timeline::timeline_step_contents::{
    StepChoiceRow, StepEvidenceRow, TimelineStep, TimelineStepRowOutput,
};

pub enum TimelineDetailRow {
    StepChoice(StepChoiceRow),
    StepEvidence(StepEvidenceRow),
    GuidanceCommand(String),
    MechanismDetails(String),
}

pub fn detail_rows_of(timeline_step: &TimelineStep) -> Vec<TimelineDetailRow> {
    timeline_step
        .choice_rows
        .iter()
        .cloned()
        .map(TimelineDetailRow::StepChoice)
        .chain(
            timeline_step
                .evidence_rows
                .iter()
                .cloned()
                .map(TimelineDetailRow::StepEvidence),
        )
        .chain(
            timeline_step
                .guidance_commands
                .iter()
                .cloned()
                .map(TimelineDetailRow::GuidanceCommand),
        )
        .chain(std::iter::once(TimelineDetailRow::MechanismDetails(
            timeline_step.mechanism_details.clone(),
        )))
        .collect()
}

fn wrapped_text_row(row_text: &str) -> adw::ActionRow {
    let text_label = gtk::Label::builder()
        .label(row_text)
        .use_markup(false)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .xalign(0.0)
        .hexpand(true)
        .margin_top(6)
        .margin_bottom(6)
        .css_classes(["dim-label"])
        .build();
    let text_row = adw::ActionRow::new();
    text_row.add_prefix(&text_label);
    text_row
}

fn evidence_row(step_evidence: &StepEvidenceRow) -> adw::ActionRow {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(&step_evidence.evidence_name)
        .subtitle(&step_evidence.evidence_value)
        .subtitle_selectable(true)
        .subtitle_lines(0)
        .css_classes(["property"])
        .build()
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

fn copy_button(copied_command: String, sender: FactorySender<TimelineDetailRow>) -> gtk::Button {
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

fn choice_row(step_choice: &StepChoiceRow) -> adw::ActionRow {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(&step_choice.choice_description)
        .title_lines(0)
        .build()
}

fn choice_button(
    step_choice: &StepChoiceRow,
    sender: FactorySender<TimelineDetailRow>,
) -> gtk::Button {
    let choice_button = gtk::Button::builder()
        .label(&step_choice.choice_label)
        .valign(gtk::Align::Center)
        .build();
    if step_choice.choice_destructive {
        choice_button.add_css_class("destructive-action");
    }
    let chosen_action = step_choice.chosen_action;
    choice_button.connect_clicked(move |_clicked_button| {
        let _step_closed = sender.output(TimelineStepRowOutput::ActionChosen(chosen_action));
    });
    choice_button
}

impl FactoryComponent for TimelineDetailRow {
    type ParentWidget = adw::ExpanderRow;
    type CommandOutput = ();
    type Input = ();
    type Output = TimelineStepRowOutput;
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
            Self::StepEvidence(step_evidence) => evidence_row(step_evidence),
            Self::GuidanceCommand(guidance_command) => guidance_command_row(guidance_command),
            Self::MechanismDetails(mechanism_details) => wrapped_text_row(mechanism_details),
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
            Self::StepChoice(step_choice) => root.add_suffix(&choice_button(step_choice, sender)),
            Self::GuidanceCommand(guidance_command) => {
                root.add_suffix(&copy_button(guidance_command.clone(), sender));
            }
            Self::StepEvidence(_) | Self::MechanismDetails(_) => {}
        }
    }
}
