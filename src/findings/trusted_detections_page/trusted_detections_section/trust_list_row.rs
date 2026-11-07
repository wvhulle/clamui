use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::host_services::clamav_admin_service::trust_requests::TrustChoice;

#[derive(Clone, Debug)]
pub enum TrustRemoval {
    NotRemovableHere,
    RemovableWith(TrustChoice),
}

#[derive(Clone, Debug)]
pub struct TrustListRow {
    pub row_title: String,
    pub row_subtitle: String,
    pub shows_hash: bool,
    pub needs_attention: bool,
    pub dimmed: bool,
    pub trust_removal: TrustRemoval,
}

#[derive(Debug)]
pub enum TrustListRowOutput {
    RemovalRequested(TrustChoice),
}

impl TrustListRow {
    pub fn empty_list(empty_text: String) -> Self {
        Self {
            row_title: empty_text,
            row_subtitle: String::new(),
            shows_hash: false,
            needs_attention: false,
            dimmed: true,
            trust_removal: TrustRemoval::NotRemovableHere,
        }
    }

    fn is_removable(&self) -> bool {
        matches!(self.trust_removal, TrustRemoval::RemovableWith(_))
    }

    fn row_style_classes(&self) -> Vec<&'static str> {
        [
            self.shows_hash.then_some("property"),
            self.dimmed.then_some("dim-label"),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for TrustListRow {
    type Init = Self;
    type Input = ();
    type Output = TrustListRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &self.row_title,
            set_title_lines: if self.shows_hash { 0 } else { 1 },
            set_subtitle: &self.row_subtitle,
            set_css_classes: &self.row_style_classes(),

            add_prefix = &gtk::Image {
                set_icon_name: Some("dialog-warning-symbolic"),
                add_css_class: "warning",
                set_visible: self.needs_attention,
            },

            add_suffix = &gtk::Button {
                set_icon_name: "user-trash-symbolic",
                set_tooltip_text: Some(&gettext("Remove")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                set_visible: self.is_removable(),
                connect_clicked[sender, trust_removal = self.trust_removal.clone()] => move |_clicked_button| {
                    if let TrustRemoval::RemovableWith(removal_choice) = &trust_removal {
                        let _page_closed = sender.output(TrustListRowOutput::RemovalRequested(removal_choice.clone()));
                    }
                },
            },
        }
    }

    fn init_model(
        trust_list_row: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        trust_list_row
    }
}
