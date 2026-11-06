use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    gtk::glib,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::activity_history::activity_history_database::{
        ActivityEntryRecord, ActivityStatus,
    },
    logs_page::activity_export_formats::{activity_status_text, activity_summary_text},
};

pub fn formatted_local_time(timestamp_unix: i64) -> String {
    glib::DateTime::from_unix_local(timestamp_unix)
        .and_then(|local_time| local_time.format("%x %X"))
        .map_or_else(|_format_failure| timestamp_unix.to_string(), String::from)
}

fn status_icon(activity_status: ActivityStatus) -> &'static str {
    match activity_status {
        ActivityStatus::ScanClean
        | ActivityStatus::UpdateApplied
        | ActivityStatus::UpdateAlreadyCurrent => "object-select-symbolic",
        ActivityStatus::ScanInfected
        | ActivityStatus::ScanFailed
        | ActivityStatus::UpdateFailed => "dialog-warning-symbolic",
        ActivityStatus::ScanCancelled
        | ActivityStatus::ScanSkipped
        | ActivityStatus::UpdateCancelled
        | ActivityStatus::UpdateRequested => "content-loading-symbolic",
    }
}

fn entry_subtitle(activity_entry: &ActivityEntryRecord) -> String {
    let first_target = activity_entry.activity_targets.lines().next();
    [
        formatted_local_time(activity_entry.started_at_unix),
        activity_status_text(activity_entry.activity_status),
    ]
    .into_iter()
    .chain(first_target.map(str::to_owned))
    .collect::<Vec<_>>()
    .join(" • ")
}

pub struct ActivityEntryRow {
    pub activity_entry: ActivityEntryRecord,
}

#[relm4::factory(pub)]
impl FactoryComponent for ActivityEntryRow {
    type Init = ActivityEntryRecord;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_activatable: true,
            set_title: &activity_summary_text(&self.activity_entry),
            set_subtitle: &entry_subtitle(&self.activity_entry),

            add_suffix = &gtk::Image {
                set_icon_name: Some(status_icon(self.activity_entry.activity_status)),
                set_tooltip_text: Some(&activity_status_text(self.activity_entry.activity_status)),
            },
        }
    }

    fn init_model(
        activity_entry: ActivityEntryRecord,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { activity_entry }
    }
}
