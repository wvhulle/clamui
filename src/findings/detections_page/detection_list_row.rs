use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::findings::detections_page::incident_timeline_presentation::{
    DisplayedDetection, detection_needs_attention, detection_summary_text, displayed_file_name,
    displayed_file_path,
};

pub struct DetectionListRow {
    displayed_detection: DisplayedDetection,
}

#[derive(Debug)]
pub enum DetectionListRowOutput {
    IncidentOpened(i64),
}

impl DetectionListRow {
    fn needs_attention(&self) -> bool {
        detection_needs_attention(&self.displayed_detection)
    }

    const fn attention_icon(&self, needs_attention: bool) -> &'static str {
        if needs_attention {
            "dialog-warning-symbolic"
        } else {
            "object-select-symbolic"
        }
    }

    const fn attention_style(&self, needs_attention: bool) -> &'static str {
        if needs_attention {
            "warning"
        } else {
            "success"
        }
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for DetectionListRow {
    type Init = DisplayedDetection;
    type Input = ();
    type Output = DetectionListRowOutput;
    type CommandOutput = ();
    type ParentWidget = adw::PreferencesGroup;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &displayed_file_name(&self.displayed_detection.stored_detection),
            set_subtitle: &detection_summary_text(&self.displayed_detection),
            set_subtitle_lines: 0,
            set_tooltip_text: Some(&displayed_file_path(&self.displayed_detection.stored_detection)),
            set_activatable: true,
            connect_activated[sender, detection_id = self.displayed_detection.stored_detection.detection_id] => move |_activated_row| {
                let _page_closed = sender.output(DetectionListRowOutput::IncidentOpened(detection_id));
            },

            add_prefix = &gtk::Image {
                set_icon_name: Some(self.attention_icon(self.needs_attention())),
                add_css_class: self.attention_style(self.needs_attention()),
            },
            add_suffix = &gtk::Image {
                set_icon_name: Some("go-next-symbolic"),
            },
        }
    }

    fn init_model(
        displayed_detection: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            displayed_detection,
        }
    }
}
