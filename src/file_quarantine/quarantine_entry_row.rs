use bytesize::ByteSize;
use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    file_quarantine::quarantine_entry_database::QuarantineEntryRecord,
    malware_scan::scanner_output_parser::sanitize_scanner_line,
};

pub struct QuarantineEntryRow {
    entry_record: QuarantineEntryRecord,
}

#[derive(Debug)]
pub enum QuarantineEntryRowOutput {
    RestoreRequested { entry_id: i64 },
    DeleteRequested { entry_id: i64 },
}

#[relm4::factory(pub)]
impl FactoryComponent for QuarantineEntryRow {
    type Init = QuarantineEntryRecord;
    type Input = ();
    type Output = QuarantineEntryRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &sanitize_scanner_line(&self.entry_record.threat_name),
            set_subtitle: &format!(
                "{}\n{} · {}",
                sanitize_scanner_line(&self.entry_record.original_path.to_string_lossy()),
                self.entry_record.detection_date,
                ByteSize::b(self.entry_record.file_size),
            ),
            set_subtitle_lines: 0,

            add_suffix = &gtk::Button {
                set_label: &gettext("Restore"),
                set_valign: gtk::Align::Center,
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::RestoreRequested { entry_id });
                },
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Delete"),
                set_valign: gtk::Align::Center,
                add_css_class: "destructive-action",
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::DeleteRequested { entry_id });
                },
            },
        }
    }

    fn init_model(
        entry_record: QuarantineEntryRecord,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { entry_record }
    }
}
