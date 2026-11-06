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
        EvidenceMoment, StepActionSlot, StepChoiceRow, StepEvidenceRow, TimelineStep,
        TimelineStepAction, TimelineStepRowOutput,
    },
};

pub enum TimelineDetailRow {
    StepChoice(StepChoiceRow),
    StepEvidence(StepEvidenceRow),
    GuidanceCommand(String),
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
        EvidenceMoment::FixedSetting | EvidenceMoment::ChangeableSetting { .. } => {
            "emblem-system-symbolic"
        }
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
        | EvidenceMoment::FixedSetting
        | EvidenceMoment::ChangeableSetting { .. } => None,
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

fn row_action_button(
    row_action: &StepActionSlot,
    sender: FactorySender<TimelineDetailRow>,
) -> Option<gtk::Button> {
    let StepActionSlot::ActionOffered {
        action_label,
        chosen_action,
        action_suggested,
    } = row_action
    else {
        return None;
    };
    let action_button = gtk::Button::builder()
        .label(action_label)
        .valign(gtk::Align::Center)
        .build();
    if *action_suggested {
        action_button.add_css_class("suggested-action");
    }
    let chosen_action = *chosen_action;
    action_button.connect_clicked(move |_clicked_button| {
        let _step_closed = sender.output(TimelineStepRowOutput::ActionChosen(chosen_action));
    });
    Some(action_button)
}

fn attach_settings_link(
    evidence_row: &adw::ActionRow,
    evidence_moment: EvidenceMoment,
    sender: FactorySender<TimelineDetailRow>,
) {
    let EvidenceMoment::ChangeableSetting { settings_subpage } = evidence_moment else {
        return;
    };
    evidence_row.set_activatable(true);
    evidence_row.set_tooltip_text(Some(&gettext("Change in the settings")));
    evidence_row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    evidence_row.connect_activated(move |_activated_row| {
        let _step_closed = sender.output(TimelineStepRowOutput::ActionChosen(
            TimelineStepAction::OpenSettingsSubpage(settings_subpage),
        ));
    });
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
            Self::StepEvidence(step_evidence) => {
                if let Some(action_button) =
                    row_action_button(&step_evidence.row_action, sender.clone())
                {
                    root.add_suffix(&action_button);
                }
                attach_settings_link(&root, step_evidence.evidence_moment, sender);
            }
        }
    }
}
