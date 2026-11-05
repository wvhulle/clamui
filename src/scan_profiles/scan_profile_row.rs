use gettextrs::{gettext, ngettext};
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    scan_profiles::scan_profile_store::ScanProfile,
};

pub struct ScanProfileRow {
    pub scan_profile: ScanProfile,
}

#[derive(Debug)]
pub enum ScanProfileRowOutput {
    StartScan(DynamicIndex),
    OpenEditor(DynamicIndex),
    ConfirmDeletion(DynamicIndex),
    SaveExport(DynamicIndex),
}

fn profile_subtitle(scan_profile: &ScanProfile) -> String {
    let target_count = scan_profile.scan_targets.len();
    let target_text = ngettext(
        "{count} target",
        "{count} targets",
        u32::try_from(target_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &target_count.to_string());
    let builtin_text = scan_profile.is_builtin.then(|| gettext("Default profile"));
    std::iter::once(sanitize_scanner_line(&scan_profile.displayed_description()))
        .filter(|description_text| !description_text.is_empty())
        .chain(std::iter::once(target_text))
        .chain(builtin_text)
        .collect::<Vec<_>>()
        .join(" • ")
}

#[relm4::factory(pub)]
impl FactoryComponent for ScanProfileRow {
    type Init = ScanProfile;
    type Input = ();
    type Output = ScanProfileRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &sanitize_scanner_line(&self.scan_profile.displayed_name()),
            set_subtitle: &profile_subtitle(&self.scan_profile),
            set_subtitle_lines: 0,

            add_suffix = &gtk::Button {
                set_icon_name: "media-playback-start-symbolic",
                set_tooltip_text: Some(&gettext("Run")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::StartScan(index.clone()));
                },
            },

            add_suffix = &gtk::Button {
                set_icon_name: "document-edit-symbolic",
                set_tooltip_text: Some(&gettext("Edit")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::OpenEditor(index.clone()));
                },
            },

            add_suffix = &gtk::Button {
                set_icon_name: "user-trash-symbolic",
                set_tooltip_text: Some(&gettext("Delete")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                set_sensitive: !self.scan_profile.is_builtin,
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::ConfirmDeletion(index.clone()));
                },
            },

            add_suffix = &gtk::Button {
                set_icon_name: "document-save-symbolic",
                set_tooltip_text: Some(&gettext("Export")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::SaveExport(index.clone()));
                },
            },
        }
    }

    fn init_model(
        scan_profile: ScanProfile,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { scan_profile }
    }
}
