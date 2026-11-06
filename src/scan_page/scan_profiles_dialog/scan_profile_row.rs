use gettextrs::{gettext, ngettext};
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    scan_page::scan_profiles_dialog::{
        profile_display_text::{displayed_profile_description, displayed_profile_name},
        scan_profile_store::{ProfileOrigin, ScanProfile},
    },
};

pub struct ScanProfileRow {
    pub scan_profile: ScanProfile,
}

#[derive(Debug)]
pub enum ScanProfileRowOutput {
    ScanRequested(DynamicIndex),
    EditRequested(DynamicIndex),
    DeletionRequested(DynamicIndex),
    ExportRequested(DynamicIndex),
}

fn profile_is_deletable(scan_profile: &ScanProfile) -> bool {
    match scan_profile.profile_origin {
        ProfileOrigin::Builtin(_builtin_profile) => false,
        ProfileOrigin::Custom { .. } => true,
    }
}

fn profile_subtitle(scan_profile: &ScanProfile) -> String {
    let target_count = scan_profile.profile_draft.scan_targets.len();
    let target_text = ngettext(
        "{count} target",
        "{count} targets",
        u32::try_from(target_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &target_count.to_string());
    let builtin_text = match scan_profile.profile_origin {
        ProfileOrigin::Builtin(_builtin_profile) => Some(gettext("Default profile")),
        ProfileOrigin::Custom { .. } => None,
    };
    std::iter::once(sanitize_scanner_line(&displayed_profile_description(
        scan_profile,
    )))
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
            set_title: &sanitize_scanner_line(&displayed_profile_name(&self.scan_profile)),
            set_subtitle: &profile_subtitle(&self.scan_profile),
            set_subtitle_lines: 0,

            add_suffix = &gtk::Button {
                set_icon_name: "media-playback-start-symbolic",
                set_tooltip_text: Some(&gettext("Run")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::ScanRequested(index.clone()));
                },
            },

            add_suffix = &gtk::Button {
                set_icon_name: "document-edit-symbolic",
                set_tooltip_text: Some(&gettext("Edit")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::EditRequested(index.clone()));
                },
            },

            add_suffix = &gtk::Button {
                set_icon_name: "user-trash-symbolic",
                set_tooltip_text: Some(&gettext("Delete")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                set_sensitive: profile_is_deletable(&self.scan_profile),
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::DeletionRequested(index.clone()));
                },
            },

            add_suffix = &gtk::Button {
                set_icon_name: "document-save-symbolic",
                set_tooltip_text: Some(&gettext("Export")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, index] => move |_clicked_button| {
                    let _parent_gone = sender.output(ScanProfileRowOutput::ExportRequested(index.clone()));
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
