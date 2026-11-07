use futures::{StreamExt, stream::BoxStream};
use gettextrs::gettext;
use jiff::tz::TimeZone;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk,
    typed_view::list::TypedListView,
};

use crate::{
    host_services::systemd_journal::service_log_contents::ServiceLogContents,
    shared_widgets::{
        awaited_dialogs::{
            TextExportOutcome, deliver_local_outcome, describe_export_failure, exported_text,
        },
        component_streams::{RunningStream, run_stream},
        loading_indicators::{
            LOADED_PAGE_NAME, LOADING_PAGE_NAME, empty_placeholder_row, loading_placeholder_row,
        },
        service_log::service_log_state::{
            LogRowFilter, MISSING_LOG_PAGE_NAME, NO_MATCHING_ROWS_PAGE_NAME, ServiceLogView,
            ShownLogRow, exported_log_text, filtered_log_rows,
        },
    },
};

pub struct ServiceLogGroupInit {
    pub group_title: String,
    pub missing_log_title: String,
    pub export_file_name: &'static str,
    pub log_updates: BoxStream<'static, ServiceLogContents>,
}

pub struct ServiceLogGroup {
    export_file_name: &'static str,
    log_view: ServiceLogView,
    row_filter: LogRowFilter,
    log_list: TypedListView<ShownLogRow, gtk::NoSelection>,
    shown_row_count: usize,
    _log_follow: RunningStream,
}

#[derive(Debug)]
pub enum ServiceLogGroupInput {
    CopyLogRequested,
    ExportLogRequested,
    SearchQueryChanged(String),
    NotableOnlyToggled(bool),
}

#[derive(Debug)]
pub enum ServiceLogGroupOutput {
    ToastRequested(String),
}

#[derive(Debug)]
pub enum ServiceLogGroupCommand {
    LogContentsRead(ServiceLogContents),
    TextExportFinished(TextExportOutcome),
}

impl ServiceLogGroup {
    fn request_toast(sender: &ComponentSender<Self>, toast_text: String) {
        let _page_closed = sender.output(ServiceLogGroupOutput::ToastRequested(toast_text));
    }

    fn exported_log(&self) -> Option<String> {
        match &self.log_view {
            ServiceLogView::LogRead(log_contents) => {
                exported_log_text(log_contents, &TimeZone::system())
            }
            ServiceLogView::LogReading => None,
        }
    }

    fn refill_log_table(&mut self) {
        let shown_rows = match &self.log_view {
            ServiceLogView::LogRead(log_contents) => {
                filtered_log_rows(log_contents, &self.row_filter)
            }
            ServiceLogView::LogReading => Vec::new(),
        };
        self.shown_row_count = shown_rows.len();
        self.log_list.clear();
        self.log_list.extend_from_iter(shown_rows.into_iter().rev());
    }
}

#[relm4::component(pub)]
impl Component for ServiceLogGroup {
    type Init = ServiceLogGroupInit;
    type Input = ServiceLogGroupInput;
    type Output = ServiceLogGroupOutput;
    type CommandOutput = ServiceLogGroupCommand;

    view! {
        adw::PreferencesGroup {
            set_title: &group_title,
            #[watch]
            set_description: Some(&gtk::glib::markup_escape_text(&model.log_view.source_text())),
            #[wrap(Some)]
            set_header_suffix = &gtk::Box {
                set_spacing: 6,
                set_valign: gtk::Align::Center,

                gtk::ToggleButton {
                    set_icon_name: "dialog-warning-symbolic",
                    set_tooltip_text: Some(&gettext("Only detections, warnings and errors")),
                    add_css_class: "flat",
                    #[watch]
                    set_sensitive: model.log_view.has_log_rows(),
                    connect_toggled[sender] => move |notable_toggle| {
                        sender.input(ServiceLogGroupInput::NotableOnlyToggled(
                            notable_toggle.is_active(),
                        ));
                    },
                },

                gtk::Button {
                    set_icon_name: "edit-copy-symbolic",
                    set_tooltip_text: Some(&gettext("Copy")),
                    add_css_class: "flat",
                    #[watch]
                    set_sensitive: model.log_view.has_log_rows(),
                    connect_clicked => ServiceLogGroupInput::CopyLogRequested,
                },

                gtk::Button {
                    set_icon_name: "document-save-symbolic",
                    set_tooltip_text: Some(&gettext("Export Text")),
                    add_css_class: "flat",
                    #[watch]
                    set_sensitive: model.log_view.has_log_rows(),
                    connect_clicked => ServiceLogGroupInput::ExportLogRequested,
                },
            },

            gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_spacing: 6,

                gtk::SearchEntry {
                    set_placeholder_text: Some(&gettext("Search log")),
                    #[watch]
                    set_visible: model.log_view.has_log_rows(),
                    connect_search_changed[sender] => move |search_entry| {
                        sender.input(ServiceLogGroupInput::SearchQueryChanged(
                            search_entry.text().into(),
                        ));
                    },
                },

                gtk::Stack {
                    add_named[Some(LOADING_PAGE_NAME)] = &gtk::ListBox {
                        add_css_class: "boxed-list",
                        set_selection_mode: gtk::SelectionMode::None,
                        append: &loading_placeholder_row(&gettext("Reading the log…")),
                    },
                    add_named[Some(MISSING_LOG_PAGE_NAME)] = &gtk::ListBox {
                        add_css_class: "boxed-list",
                        set_selection_mode: gtk::SelectionMode::None,
                        append: &empty_placeholder_row(&missing_log_title),
                    },
                    add_named[Some(NO_MATCHING_ROWS_PAGE_NAME)] = &gtk::ListBox {
                        add_css_class: "boxed-list",
                        set_selection_mode: gtk::SelectionMode::None,
                        append: &empty_placeholder_row(&gettext("No log lines match")),
                    },
                    add_named[Some(LOADED_PAGE_NAME)] = &gtk::Frame {
                        gtk::ScrolledWindow {
                            set_min_content_height: 240,
                            set_max_content_height: 480,
                            set_propagate_natural_height: true,
                            set_hscrollbar_policy: gtk::PolicyType::Never,

                            #[local_ref]
                            log_list_view -> gtk::ListView {
                                set_show_separators: true,
                            },
                        },
                    },
                    #[watch]
                    set_visible_child_name: model.log_view.shown_page_name(model.shown_row_count),
                },
            },
        }
    }

    fn init(
        group_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let ServiceLogGroupInit {
            group_title,
            missing_log_title,
            export_file_name,
            log_updates,
        } = group_init;
        let model = Self {
            export_file_name,
            log_view: ServiceLogView::LogReading,
            row_filter: LogRowFilter::default(),
            log_list: TypedListView::new(),
            shown_row_count: 0,
            _log_follow: run_stream(
                &sender,
                log_updates.map(ServiceLogGroupCommand::LogContentsRead),
            ),
        };
        let log_list_view = &model.log_list.view;
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        group_input: ServiceLogGroupInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match group_input {
            ServiceLogGroupInput::CopyLogRequested => {
                if let Some(log_text) = self.exported_log() {
                    root.clipboard().set_text(&log_text);
                    Self::request_toast(&sender, gettext("Log copied to clipboard"));
                }
            }
            ServiceLogGroupInput::ExportLogRequested => {
                if let Some(log_text) = self.exported_log() {
                    deliver_local_outcome(
                        sender.command_sender().clone(),
                        exported_text(self.export_file_name.to_owned(), log_text),
                        |export_outcome| {
                            Some(ServiceLogGroupCommand::TextExportFinished(export_outcome))
                        },
                    );
                }
            }
            ServiceLogGroupInput::SearchQueryChanged(search_query) => {
                self.row_filter.search_query = search_query;
                self.refill_log_table();
            }
            ServiceLogGroupInput::NotableOnlyToggled(notable_only) => {
                self.row_filter.notable_only = notable_only;
                self.refill_log_table();
            }
        }
    }

    fn update_cmd(
        &mut self,
        group_command: ServiceLogGroupCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match group_command {
            ServiceLogGroupCommand::LogContentsRead(log_contents) => {
                self.log_view = ServiceLogView::LogRead(log_contents);
                self.refill_log_table();
            }
            ServiceLogGroupCommand::TextExportFinished(TextExportOutcome::TextSaved) => {
                Self::request_toast(&sender, gettext("Exported."));
            }
            ServiceLogGroupCommand::TextExportFinished(TextExportOutcome::ExportCancelled) => {}
            ServiceLogGroupCommand::TextExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => {
                Self::request_toast(&sender, describe_export_failure(&export_failure));
            }
        }
    }
}
