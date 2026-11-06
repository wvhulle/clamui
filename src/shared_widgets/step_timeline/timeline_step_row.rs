use relm4::{
    FactorySender, RelmWidgetExt, adw,
    adw::prelude::*,
    gtk,
    gtk::glib,
    prelude::{DynamicIndex, FactoryComponent, FactoryVecDeque},
};

use crate::shared_widgets::step_timeline::{
    timeline_detail_row::{TimelineDetailRow, detail_rows_of},
    timeline_step_contents::{StepActionSlot, StepNodeState, TimelineStep, TimelineStepRowOutput},
};

pub struct TimelineStepRow {
    timeline_step: TimelineStep,
    expanded: bool,
    details_changed: bool,
}

#[derive(Debug)]
pub enum TimelineStepRowInput {
    StepChanged(Box<TimelineStep>),
    ExpansionToggled(bool),
    ActionButtonClicked,
}

pub struct TimelineStepRowWidgets {
    expander_row: adw::ExpanderRow,
    expansion_handler: glib::SignalHandlerId,
    status_image: gtk::Image,
    running_spinner: adw::Spinner,
    action_button: gtk::Button,
    detail_rows: FactoryVecDeque<TimelineDetailRow>,
}

impl TimelineStepRow {
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

impl FactoryComponent for TimelineStepRow {
    type ParentWidget = adw::PreferencesGroup;
    type CommandOutput = ();
    type Input = TimelineStepRowInput;
    type Output = TimelineStepRowOutput;
    type Init = TimelineStep;
    type Root = adw::ExpanderRow;
    type Widgets = TimelineStepRowWidgets;
    type Index = DynamicIndex;

    fn init_model(
        timeline_step: TimelineStep,
        _step_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            expanded: timeline_step.node_state.needs_attention(),
            timeline_step,
            details_changed: true,
        }
    }

    fn init_root(&self) -> Self::Root {
        adw::ExpanderRow::builder()
            .use_markup(false)
            .subtitle_lines(0)
            .build()
    }

    fn init_widgets(
        &mut self,
        _step_index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let status_image = gtk::Image::new();
        let running_spinner = adw::Spinner::new();
        let action_button = gtk::Button::builder().valign(gtk::Align::Center).build();
        root.add_prefix(&status_image);
        root.add_prefix(&running_spinner);
        root.add_suffix(&action_button);
        let click_sender = sender.input_sender().clone();
        action_button.connect_clicked(move |_clicked_button| {
            click_sender.emit(TimelineStepRowInput::ActionButtonClicked);
        });
        let expansion_sender = sender.input_sender().clone();
        let expansion_handler = root.connect_expanded_notify(move |expander_row| {
            expansion_sender.emit(TimelineStepRowInput::ExpansionToggled(
                expander_row.is_expanded(),
            ));
        });
        let mut widgets = TimelineStepRowWidgets {
            detail_rows: FactoryVecDeque::builder()
                .launch(root.clone())
                .forward(sender.output_sender(), std::convert::identity),
            expander_row: root,
            expansion_handler,
            status_image,
            running_spinner,
            action_button,
        };
        self.update_view(&mut widgets, sender);
        widgets
    }

    fn update(&mut self, row_input: Self::Input, sender: FactorySender<Self>) {
        self.details_changed = false;
        match row_input {
            TimelineStepRowInput::StepChanged(timeline_step) => {
                if timeline_step.node_state.needs_attention()
                    && !self.timeline_step.node_state.needs_attention()
                {
                    self.expanded = true;
                }
                self.timeline_step = *timeline_step;
                self.details_changed = true;
            }
            TimelineStepRowInput::ExpansionToggled(expanded) => self.expanded = expanded,
            TimelineStepRowInput::ActionButtonClicked => {
                if let StepActionSlot::ActionOffered { chosen_action, .. } =
                    self.timeline_step.action_slot
                {
                    let _parent_gone =
                        sender.output(TimelineStepRowOutput::ActionChosen(chosen_action));
                }
            }
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: FactorySender<Self>) {
        let expander_row = &widgets.expander_row;
        expander_row.set_title(&self.timeline_step.step_title);
        expander_row.set_subtitle(&self.timeline_step.status_text);
        expander_row.block_signal(&widgets.expansion_handler);
        expander_row.set_expanded(self.expanded);
        expander_row.unblock_signal(&widgets.expansion_handler);
        widgets
            .status_image
            .set_icon_name(Some(self.timeline_step.node_state.icon_name()));
        widgets
            .status_image
            .set_css_classes(&[self.timeline_step.node_state.style_class()]);
        widgets.status_image.set_visible(!self.is_running());
        widgets.running_spinner.set_visible(self.is_running());
        widgets.action_button.set_label(self.action_label());
        widgets
            .action_button
            .set_visible(!self.action_label().is_empty());
        widgets.action_button.set_sensitive(!self.is_running());
        widgets
            .action_button
            .set_class_active("suggested-action", self.action_is_suggested());
        if self.details_changed {
            let mut detail_guard = widgets.detail_rows.guard();
            detail_guard.clear();
            detail_rows_of(&self.timeline_step)
                .into_iter()
                .for_each(|detail_row| {
                    detail_guard.push_back(detail_row);
                });
        }
    }
}
