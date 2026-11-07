use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line;

pub struct ProfileValueRow {
    pub listed_value: String,
}

#[derive(Debug)]
pub enum ProfileValueRowOutput {
    RemovalRequested(String),
}

#[relm4::factory(pub)]
impl FactoryComponent for ProfileValueRow {
    type Init = String;
    type Input = ();
    type Output = ProfileValueRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &sanitize_scanner_line(&self.listed_value),

            add_suffix = &gtk::Button {
                set_icon_name: "user-trash-symbolic",
                set_tooltip_text: Some(&gettext("Remove")),
                set_valign: gtk::Align::Center,
                add_css_class: "flat",
                connect_clicked[sender, removed_value = self.listed_value.clone()] => move |_clicked_button| {
                    let _editor_closed = sender.output(ProfileValueRowOutput::RemovalRequested(removed_value.clone()));
                },
            },
        }
    }

    fn init_model(
        listed_value: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { listed_value }
    }
}
