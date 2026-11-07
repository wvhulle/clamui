use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityEntryRecord, ActivityRecord, ScanActivityStatus, UpdateActivityStatus,
        },
        desktop::locale_formatting::exact_local_time_text,
    },
    shared_widgets::activity_entries::activity_export_formats::{
        activity_status_text, activity_summary_text,
    },
};

fn status_icon(activity_record: &ActivityRecord) -> &'static str {
    match activity_record {
        ActivityRecord::ScanActivity { scan_status, .. } => match scan_status {
            ScanActivityStatus::ScanClean => "object-select-symbolic",
            ScanActivityStatus::ScanInfected { .. } | ScanActivityStatus::ScanFailed => {
                "dialog-warning-symbolic"
            }
            ScanActivityStatus::ScanCancelled => "content-loading-symbolic",
        },
        ActivityRecord::SkippedScan { .. } => "content-loading-symbolic",
        ActivityRecord::UpdateActivity { update_status } => match update_status {
            UpdateActivityStatus::UpdateApplied | UpdateActivityStatus::UpdateAlreadyCurrent => {
                "object-select-symbolic"
            }
            UpdateActivityStatus::UpdateFailed => "dialog-warning-symbolic",
            UpdateActivityStatus::UpdateCancelled
            | UpdateActivityStatus::UpdateRequested
            | UpdateActivityStatus::UpdateResultUnknown => "content-loading-symbolic",
        },
    }
}

fn entry_subtitle(activity_entry: &ActivityEntryRecord) -> String {
    let first_target = activity_entry.activity_record.scan_targets().first();
    [
        exact_local_time_text(activity_entry.started_at),
        activity_status_text(&activity_entry.activity_record),
    ]
    .into_iter()
    .chain(first_target.map(|scan_target| scan_target.display().to_string()))
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
                set_icon_name: Some(status_icon(&self.activity_entry.activity_record)),
                set_tooltip_text: Some(&activity_status_text(&self.activity_entry.activity_record)),
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
