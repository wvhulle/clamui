use gettextrs::{gettext, ngettext};
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    shared_widgets::scan_runs::scan_results_section::scan_results_state::{
        ProblemPathGroup, ScanResultsView,
    },
};

const PROBLEM_PATH_ROW_LIMIT: usize = 200;

pub enum ScanProblemRow {
    SkippedPaths(ProblemPathGroup),
    ScanNotice(String),
    ScanDetails(String),
}

pub fn problem_rows_of(results_view: &ScanResultsView) -> Vec<ScanProblemRow> {
    results_view
        .problem_path_groups
        .iter()
        .cloned()
        .map(ScanProblemRow::SkippedPaths)
        .chain(
            results_view
                .notice_lines
                .iter()
                .cloned()
                .map(ScanProblemRow::ScanNotice),
        )
        .chain(
            Some(results_view.noteworthy_output.clone())
                .filter(|noteworthy_output| !noteworthy_output.is_empty())
                .map(ScanProblemRow::ScanDetails),
        )
        .collect()
}

fn plain_text_row(row_title: &str) -> adw::ActionRow {
    let plain_row = adw::ActionRow::new();
    plain_row.set_use_markup(false);
    plain_row.set_title(row_title);
    plain_row
}

fn notice_row(notice_line: &str) -> adw::ActionRow {
    let notice_row = plain_text_row(notice_line);
    notice_row.set_title_lines(0);
    notice_row
}

fn problem_path_expander(path_group: &ProblemPathGroup) -> adw::ExpanderRow {
    let path_expander = adw::ExpanderRow::new();
    path_expander.set_use_markup(false);
    path_expander.set_title(&path_group.group_title);
    path_expander.set_subtitle(&path_group.group_explanation);
    path_group
        .listed_paths
        .iter()
        .take(PROBLEM_PATH_ROW_LIMIT)
        .for_each(|listed_path| {
            path_expander.add_row(&plain_text_row(&sanitize_scanner_line(listed_path)));
        });
    let hidden_path_count = path_group
        .listed_paths
        .len()
        .saturating_sub(PROBLEM_PATH_ROW_LIMIT);
    if hidden_path_count > 0 {
        path_expander.add_row(
            &adw::ActionRow::builder()
                .use_markup(false)
                .title(
                    ngettext(
                        "{count} more file, listed in the exported report",
                        "{count} more files, listed in the exported report",
                        u32::try_from(hidden_path_count).unwrap_or(u32::MAX),
                    )
                    .replace("{count}", &hidden_path_count.to_string()),
                )
                .css_classes(["dim-label"])
                .build(),
        );
    }
    path_expander
}

fn scan_details_expander(noteworthy_output: &str) -> adw::ExpanderRow {
    let details_expander = adw::ExpanderRow::builder()
        .title(gettext("Scan details"))
        .build();
    details_expander.add_row(
        &gtk::Label::builder()
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .selectable(true)
            .use_markup(false)
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .css_classes(["monospace"])
            .label(noteworthy_output)
            .build(),
    );
    details_expander
}

impl FactoryComponent for ScanProblemRow {
    type ParentWidget = gtk::ListBox;
    type CommandOutput = ();
    type Input = ();
    type Output = ();
    type Init = Self;
    type Root = adw::PreferencesRow;
    type Widgets = ();
    type Index = DynamicIndex;

    fn init_model(
        problem_row: Self::Init,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        problem_row
    }

    fn init_root(&self) -> Self::Root {
        match self {
            Self::SkippedPaths(path_group) => problem_path_expander(path_group).upcast(),
            Self::ScanNotice(notice_line) => notice_row(notice_line).upcast(),
            Self::ScanDetails(noteworthy_output) => {
                scan_details_expander(noteworthy_output).upcast()
            }
        }
    }

    fn init_widgets(
        &mut self,
        _row_index: &DynamicIndex,
        _root: Self::Root,
        _returned_widget: &gtk::ListBoxRow,
        _sender: FactorySender<Self>,
    ) -> Self::Widgets {
    }
}
