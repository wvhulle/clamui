use std::path::PathBuf;

use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line;

pub struct ScanTargetRow {
    pub target_path: PathBuf,
}

#[derive(Debug)]
pub enum ScanTargetRowOutput {
    RemoveRequested(DynamicIndex),
}

#[relm4::factory(pub)]
impl FactoryComponent for ScanTargetRow {
    type Init = PathBuf;
    type Input = ();
    type Output = ScanTargetRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &sanitize_scanner_line(&self.target_path.to_string_lossy()),
            set_title_lines: 0,

            add_prefix = &gtk::Image {
                set_icon_name: Some(if self.target_path.is_dir() {
                    "folder-symbolic"
                } else {
                    "text-x-generic-symbolic"
                }),
            },

            add_suffix = &gtk::Button {
                set_icon_name: "edit-delete-symbolic",
                set_tooltip_text: Some(&gettext("Remove")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanTargetRowOutput::RemoveRequested(index.clone()));
                },
            },
        }
    }

    fn init_model(
        target_path: PathBuf,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { target_path }
    }
}
