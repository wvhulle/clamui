use gettextrs::gettext;
use relm4::{
    FactorySender, RelmWidgetExt, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::step_timeline::timeline_step_model::{
    StepActionSlot, StepChoiceRow, StepEvidenceRow, StepNodeState, TimelineStep,
    TimelineStepRequest,
};

pub struct TimelineStepRow {
    timeline_step: TimelineStep,
    previously_needed_attention: bool,
    displayed_rows: Vec<gtk::Widget>,
}

#[derive(Debug)]
pub enum TimelineStepRowInput {
    StepChanged(Box<TimelineStep>),
    ActionButtonClicked,
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

fn guidance_command_row(
    guidance_command: &str,
    sender: &FactorySender<TimelineStepRow>,
) -> adw::ActionRow {
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
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(gettext("Copy"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let copied_command = guidance_command.to_owned();
    let row_sender = sender.clone();
    copy_button.connect_clicked(move |_clicked_button| {
        let _parent_gone =
            row_sender.output(TimelineStepRequest::CopyRequested(copied_command.clone()));
    });
    let command_row = adw::ActionRow::new();
    command_row.add_prefix(&command_label);
    command_row.add_suffix(&copy_button);
    command_row
}

fn choice_row(
    step_choice: &StepChoiceRow,
    sender: &FactorySender<TimelineStepRow>,
) -> adw::ActionRow {
    let choice_button = gtk::Button::builder()
        .label(&step_choice.choice_label)
        .valign(gtk::Align::Center)
        .build();
    if step_choice.choice_destructive {
        choice_button.add_css_class("destructive-action");
    }
    let chosen_action = step_choice.chosen_action;
    let row_sender = sender.clone();
    choice_button.connect_clicked(move |_clicked_button| {
        let _parent_gone = row_sender.output(TimelineStepRequest::ActionChosen(chosen_action));
    });
    let choice_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(&step_choice.choice_description)
        .title_lines(0)
        .build();
    choice_row.add_suffix(&choice_button);
    choice_row
}

impl TimelineStepRow {
    fn replace_displayed_rows(
        &mut self,
        expander_row: &adw::ExpanderRow,
        sender: &FactorySender<Self>,
    ) {
        self.displayed_rows
            .drain(..)
            .for_each(|displayed_row| expander_row.remove(&displayed_row));
        let evidence_rows = self.timeline_step.evidence_rows.iter().map(evidence_row);
        let command_rows = self
            .timeline_step
            .guidance_commands
            .iter()
            .map(|guidance_command| guidance_command_row(guidance_command, sender));
        let choice_rows = self
            .timeline_step
            .choice_rows
            .iter()
            .map(|step_choice| choice_row(step_choice, sender));
        self.displayed_rows = choice_rows
            .chain(evidence_rows)
            .chain(command_rows)
            .chain(std::iter::once(wrapped_text_row(
                &self.timeline_step.mechanism_details,
            )))
            .map(|step_row| step_row.upcast::<gtk::Widget>())
            .collect();
        self.displayed_rows
            .iter()
            .for_each(|displayed_row| expander_row.add_row(displayed_row));
    }

    fn is_running(&self) -> bool {
        self.timeline_step.node_state == StepNodeState::InProgress
    }

    fn action_label(&self) -> &str {
        match &self.timeline_step.action_slot {
            StepActionSlot::NoAction => "",
            StepActionSlot::ActionOffered { action_label, .. } => action_label,
        }
    }

    fn action_is_suggested(&self) -> bool {
        matches!(
            self.timeline_step.action_slot,
            StepActionSlot::ActionOffered {
                action_suggested: true,
                ..
            }
        )
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for TimelineStepRow {
    type Init = TimelineStep;
    type Input = TimelineStepRowInput;
    type Output = TimelineStepRequest;
    type CommandOutput = ();
    type ParentWidget = adw::PreferencesGroup;

    view! {
        #[root]
        #[name = "expander_row"]
        adw::ExpanderRow {
            set_use_markup: false,
            set_subtitle_lines: 0,
            #[watch]
            set_title: &self.timeline_step.step_title,
            #[watch]
            set_subtitle: &self.timeline_step.status_text,

            add_prefix = &gtk::Image {
                #[watch]
                set_icon_name: Some(self.timeline_step.node_state.icon_name()),
                #[watch]
                set_css_classes: &[self.timeline_step.node_state.style_class()],
                #[watch]
                set_visible: !self.is_running(),
            },

            add_prefix = &adw::Spinner {
                #[watch]
                set_visible: self.is_running(),
            },

            add_suffix = &gtk::Button {
                set_valign: gtk::Align::Center,
                #[watch]
                set_label: self.action_label(),
                #[watch]
                set_visible: !self.action_label().is_empty(),
                #[watch]
                set_sensitive: !self.is_running(),
                #[watch]
                set_class_active: ("suggested-action", self.action_is_suggested()),
                connect_clicked => TimelineStepRowInput::ActionButtonClicked,
            },
        }
    }

    fn init_model(
        timeline_step: TimelineStep,
        _step_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            timeline_step,
            previously_needed_attention: false,
            displayed_rows: Vec::new(),
        }
    }

    fn init_widgets(
        &mut self,
        _step_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let widgets = view_output!();
        self.replace_displayed_rows(&widgets.expander_row, &sender);
        self.previously_needed_attention = self.timeline_step.node_state.needs_attention();
        widgets
            .expander_row
            .set_expanded(self.previously_needed_attention);
        widgets
    }

    fn update_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        row_input: TimelineStepRowInput,
        sender: FactorySender<Self>,
    ) {
        match row_input {
            TimelineStepRowInput::StepChanged(timeline_step) => {
                let needs_attention = timeline_step.node_state.needs_attention();
                if needs_attention && !self.previously_needed_attention {
                    widgets.expander_row.set_expanded(true);
                }
                self.previously_needed_attention = needs_attention;
                self.timeline_step = *timeline_step;
                self.replace_displayed_rows(&widgets.expander_row, &sender);
            }
            TimelineStepRowInput::ActionButtonClicked => {
                if let StepActionSlot::ActionOffered { chosen_action, .. } =
                    self.timeline_step.action_slot
                {
                    let _parent_gone =
                        sender.output(TimelineStepRequest::ActionChosen(chosen_action));
                }
            }
        }
        self.update_view(widgets, sender);
    }
}
