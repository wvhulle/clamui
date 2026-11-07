use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::host_services::clamav_scanner::{
    scan_exclusion_rules::{ExclusionEntry, PRESET_DIRECTORY_NAMES},
    scanner_output_parser::sanitize_scanner_line,
};

pub fn is_preset_pattern(exclusion_pattern: &str) -> bool {
    PRESET_DIRECTORY_NAMES.contains(&exclusion_pattern)
}

fn preset_description(exclusion_pattern: &str) -> String {
    match exclusion_pattern {
        "node_modules" => gettext("Node.js dependencies"),
        ".git" => gettext("Git repository data"),
        ".venv" => gettext("Python virtual environment"),
        "build" => gettext("Build output directory"),
        "dist" => gettext("Distribution output directory"),
        "__pycache__" => gettext("Python bytecode cache"),
        _other_pattern => String::new(),
    }
}

pub struct ScanExclusionRow {
    exclusion_entry: ExclusionEntry,
}

#[derive(Debug)]
pub enum ScanExclusionRowOutput {
    EnabledToggled {
        exclusion_pattern: String,
        is_enabled: bool,
    },
    RemovalRequested {
        exclusion_pattern: String,
    },
}

impl ScanExclusionRow {
    fn is_preset(&self) -> bool {
        is_preset_pattern(&self.exclusion_entry.exclusion_pattern)
    }

    fn shown_title(&self) -> String {
        if self.is_preset() {
            self.exclusion_entry.exclusion_pattern.clone()
        } else {
            sanitize_scanner_line(&self.exclusion_entry.exclusion_pattern)
        }
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for ScanExclusionRow {
    type Init = ExclusionEntry;
    type Input = ();
    type Output = ScanExclusionRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::SwitchRow {
            set_use_markup: false,
            set_title: &self.shown_title(),
            set_subtitle: &preset_description(&self.exclusion_entry.exclusion_pattern),
            set_active: self.exclusion_entry.is_enabled,
            connect_active_notify[sender, exclusion_pattern = self.exclusion_entry.exclusion_pattern.clone()] => move |changed_row| {
                let _page_closed = sender.output(ScanExclusionRowOutput::EnabledToggled {
                    exclusion_pattern: exclusion_pattern.clone(),
                    is_enabled: changed_row.is_active(),
                });
            },

            add_suffix = &gtk::Button {
                set_icon_name: "user-trash-symbolic",
                set_tooltip_text: Some(&gettext("Remove")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                set_visible: !self.is_preset(),
                connect_clicked[sender, exclusion_pattern = self.exclusion_entry.exclusion_pattern.clone()] => move |_clicked_button| {
                    let _page_closed = sender.output(ScanExclusionRowOutput::RemovalRequested {
                        exclusion_pattern: exclusion_pattern.clone(),
                    });
                },
            },
        }
    }

    fn init_model(
        exclusion_entry: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { exclusion_entry }
    }
}
