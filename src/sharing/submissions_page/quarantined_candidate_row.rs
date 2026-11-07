use gettextrs::gettext;
use relm4::{FactorySender, adw, adw::prelude::*, gtk, prelude::FactoryComponent};

use crate::sharing::submissions_page::submissions_presentation::CandidateRowView;

#[derive(Debug)]
pub enum QuarantinedCandidateRowOutput {
    SubmissionRequested { entry_id: i64 },
}

pub struct QuarantinedCandidateRow {
    row_view: CandidateRowView,
}

#[relm4::factory(pub)]
impl FactoryComponent for QuarantinedCandidateRow {
    type Init = CandidateRowView;
    type Input = ();
    type Output = QuarantinedCandidateRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        adw::ActionRow {
            set_use_markup: false,
            set_title: &self.row_view.row_title,
            set_subtitle: &self.row_view.row_subtitle,
            set_subtitle_lines: 0,

            add_suffix = &gtk::Button {
                set_label: &gettext("Submit…"),
                set_valign: gtk::Align::Center,
                #[watch]
                set_sensitive: self.row_view.allows_sending(),
                connect_clicked[sender, entry_id = self.row_view.entry_id] => move |_clicked_button| {
                    let _page_closed = sender.output(QuarantinedCandidateRowOutput::SubmissionRequested { entry_id });
                },
            },
        }
    }

    fn init_model(
        row_view: Self::Init,
        _row_index: &Self::Index,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { row_view }
    }
}
