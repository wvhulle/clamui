use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::{
    host_services::{
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::exact_local_time_text,
    },
    scans::removable_drives_page::{
        removable_drives_presentation::{drive_decision_icon, drive_decision_text},
        removable_drives_state::DriveEvent,
    },
};

pub struct DriveEventRow {
    drive_event: DriveEvent,
}

impl DriveEventRow {
    fn event_subtitle(&self) -> String {
        format!(
            "{} · {}",
            exact_local_time_text(self.drive_event.seen_at),
            drive_decision_text(self.drive_event.drive_decision)
        )
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for DriveEventRow {
    type Init = DriveEvent;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &self.drive_event.drive_name,
            set_subtitle: &self.event_subtitle(),
            set_tooltip_text: Some(&sanitize_scanner_line(&self.drive_event.mount_path.to_string_lossy())),
            add_prefix = &gtk::Image {
                set_icon_name: Some(drive_decision_icon(self.drive_event.drive_decision)),
            },
        }
    }

    fn init_model(
        drive_event: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { drive_event }
    }
}
