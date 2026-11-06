use gettextrs::gettext;
use relm4::{
    FactorySender, RelmWidgetExt, adw,
    adw::prelude::*,
    gtk,
    gtk::glib,
    prelude::{DynamicIndex, FactoryComponent, FactoryVecDeque},
};

use crate::shared_widgets::step_timeline::{
    timeline_detail_row::{TimelineDetailRow, detail_rows_of},
    timeline_step_contents::{
        ButtonStyle, StepActionButton, StepNodeState, TimelineStep, TimelineStepRowOutput,
    },
};

pub struct TimelineStepRow<StepAction> {
    timeline_step: TimelineStep<StepAction>,
    expanded: bool,
    details_changed: bool,
}

#[derive(Debug)]
pub enum TimelineStepRowInput<StepAction> {
    StepChanged(Box<TimelineStep<StepAction>>),
    ExpansionToggled(bool),
    ActionButtonClicked,
}

pub struct TimelineStepRowWidgets<StepAction: StepActionButton> {
    expander_row: adw::ExpanderRow,
    expansion_handler: glib::SignalHandlerId,
    status_image: gtk::Image,
    running_spinner: adw::Spinner,
    action_button: gtk::Button,
    explanation_button: gtk::MenuButton,
    explanation_label: gtk::Label,
    detail_rows: FactoryVecDeque<TimelineDetailRow<StepAction>>,
}

impl<StepAction: StepActionButton> TimelineStepRow<StepAction> {
    fn is_running(&self) -> bool {
        self.timeline_step.node_state() == StepNodeState::InProgress
    }

    fn has_detail_rows(&self) -> bool {
        !detail_rows_of(&self.timeline_step).is_empty()
    }
}

fn show_header_button<StepAction: StepActionButton>(
    action_button: &gtk::Button,
    timeline_step: &TimelineStep<StepAction>,
) {
    let Some(header_offer) = timeline_step.header_offer() else {
        action_button.set_visible(false);
        return;
    };
    action_button.set_label(&header_offer.offered_action.button_label());
    action_button.set_visible(true);
    let button_style = header_offer.button_style();
    [ButtonStyle::DestructiveButton, ButtonStyle::SuggestedButton]
        .into_iter()
        .filter_map(ButtonStyle::css_class)
        .for_each(|style_class| {
            action_button
                .set_class_active(style_class, button_style.css_class() == Some(style_class));
        });
}

impl<StepAction: StepActionButton> FactoryComponent for TimelineStepRow<StepAction> {
    type ParentWidget = adw::PreferencesGroup;
    type CommandOutput = ();
    type Input = TimelineStepRowInput<StepAction>;
    type Output = TimelineStepRowOutput<StepAction>;
    type Init = TimelineStep<StepAction>;
    type Root = adw::ExpanderRow;
    type Widgets = TimelineStepRowWidgets<StepAction>;
    type Index = DynamicIndex;

    fn init_model(
        timeline_step: TimelineStep<StepAction>,
        _step_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            expanded: timeline_step.node_state().needs_attention(),
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
        let explanation_label = gtk::Label::builder()
            .use_markup(false)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .max_width_chars(48)
            .xalign(0.0)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(6)
            .margin_end(6)
            .build();
        let explanation_button = gtk::MenuButton::builder()
            .icon_name("help-about-symbolic")
            .tooltip_text(gettext("Why this matters"))
            .valign(gtk::Align::Center)
            .css_classes(["flat"])
            .popover(&gtk::Popover::builder().child(&explanation_label).build())
            .build();
        root.add_prefix(&status_image);
        root.add_prefix(&running_spinner);
        root.add_suffix(&action_button);
        root.add_suffix(&explanation_button);
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
            explanation_button,
            explanation_label,
        };
        self.update_view(&mut widgets, sender);
        widgets
    }

    fn update(&mut self, row_input: Self::Input, sender: FactorySender<Self>) {
        self.details_changed = false;
        match row_input {
            TimelineStepRowInput::StepChanged(timeline_step) => {
                if timeline_step.node_state().needs_attention()
                    && !self.timeline_step.node_state().needs_attention()
                {
                    self.expanded = true;
                }
                self.timeline_step = *timeline_step;
                self.details_changed = true;
            }
            TimelineStepRowInput::ExpansionToggled(expanded) => self.expanded = expanded,
            TimelineStepRowInput::ActionButtonClicked => {
                if let Some(header_offer) = self.timeline_step.header_offer() {
                    let _parent_gone = sender.output(TimelineStepRowOutput::ActionChosen(
                        header_offer.offered_action,
                    ));
                }
            }
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: FactorySender<Self>) {
        let expander_row = &widgets.expander_row;
        expander_row.set_title(&self.timeline_step.step_title);
        expander_row.set_subtitle(&self.timeline_step.status_text);
        expander_row.block_signal(&widgets.expansion_handler);
        expander_row.set_enable_expansion(self.has_detail_rows());
        expander_row.set_expanded(self.expanded && self.has_detail_rows());
        expander_row.unblock_signal(&widgets.expansion_handler);
        let node_state = self.timeline_step.node_state();
        widgets
            .status_image
            .set_icon_name(Some(node_state.icon_name()));
        widgets
            .status_image
            .set_css_classes(&[node_state.style_class()]);
        widgets
            .explanation_label
            .set_label(&self.timeline_step.mechanism_details);
        widgets
            .explanation_button
            .set_visible(!self.timeline_step.mechanism_details.is_empty());
        widgets.status_image.set_visible(!self.is_running());
        widgets.running_spinner.set_visible(self.is_running());
        show_header_button(&widgets.action_button, &self.timeline_step);
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
