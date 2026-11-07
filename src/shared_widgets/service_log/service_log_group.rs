use futures::{StreamExt, stream::BoxStream};
use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};

use crate::{
    host_services::systemd_journal::service_log_contents::ServiceLogContents,
    shared_widgets::{
        awaited_dialogs::{
            TextExportOutcome, deliver_local_outcome, describe_export_failure, exported_text,
        },
        component_streams::{RunningStream, run_stream},
        loading_indicators::{LOADED_PAGE_NAME, LOADING_PAGE_NAME, loading_status_page},
        service_log::service_log_state::{MISSING_LOG_PAGE_NAME, ServiceLogView},
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
    log_text_changed: bool,
    _log_follow: RunningStream,
}

#[derive(Debug)]
pub enum ServiceLogGroupInput {
    CopyLogRequested,
    ExportLogRequested,
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

                gtk::Button {
                    set_icon_name: "edit-copy-symbolic",
                    set_tooltip_text: Some(&gettext("Copy")),
                    add_css_class: "flat",
                    #[watch]
                    set_sensitive: model.log_view.shown_log_text().is_some(),
                    connect_clicked => ServiceLogGroupInput::CopyLogRequested,
                },

                gtk::Button {
                    set_icon_name: "document-save-symbolic",
                    set_tooltip_text: Some(&gettext("Export Text")),
                    add_css_class: "flat",
                    #[watch]
                    set_sensitive: model.log_view.shown_log_text().is_some(),
                    connect_clicked => ServiceLogGroupInput::ExportLogRequested,
                },
            },

            gtk::Stack {
                #[local_ref]
                add_named[Some(LOADING_PAGE_NAME)] = log_loading_page -> adw::StatusPage {},
                add_named[Some(MISSING_LOG_PAGE_NAME)] = &adw::StatusPage {
                    add_css_class: "compact",
                    set_icon_name: Some("document-open-recent-symbolic"),
                    set_title: &missing_log_title,
                },
                add_named[Some(LOADED_PAGE_NAME)] = &gtk::ScrolledWindow {
                    set_min_content_height: 240,
                    set_max_content_height: 480,
                    set_propagate_natural_height: true,
                    add_css_class: "card",

                    gtk::TextView {
                        set_editable: false,
                        set_monospace: true,
                        set_wrap_mode: gtk::WrapMode::WordChar,
                        set_top_margin: 12,
                        set_bottom_margin: 12,
                        set_left_margin: 12,
                        set_right_margin: 12,
                        #[wrap(Some)]
                        set_buffer = &gtk::TextBuffer {
                            #[track(model.log_text_changed)]
                            set_text: model.log_view.shown_log_text().unwrap_or_default(),
                        },
                    },
                },
                #[watch]
                set_visible_child_name: model.log_view.shown_page_name(),
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
            log_text_changed: true,
            _log_follow: run_stream(
                &sender,
                log_updates.map(ServiceLogGroupCommand::LogContentsRead),
            ),
        };
        let log_loading_page = &loading_status_page(&gettext("Reading the log…"));
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        group_input: ServiceLogGroupInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        self.log_text_changed = false;
        match group_input {
            ServiceLogGroupInput::CopyLogRequested => {
                if let Some(log_text) = self.log_view.shown_log_text() {
                    root.clipboard().set_text(log_text);
                    Self::request_toast(&sender, gettext("Log copied to clipboard"));
                }
            }
            ServiceLogGroupInput::ExportLogRequested => {
                if let Some(log_text) = self.log_view.shown_log_text() {
                    deliver_local_outcome(
                        sender.command_sender().clone(),
                        exported_text(self.export_file_name.to_owned(), log_text.to_owned()),
                        |export_outcome| {
                            Some(ServiceLogGroupCommand::TextExportFinished(export_outcome))
                        },
                    );
                }
            }
        }
    }

    fn update_cmd(
        &mut self,
        group_command: ServiceLogGroupCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.log_text_changed = false;
        match group_command {
            ServiceLogGroupCommand::LogContentsRead(log_contents) => {
                self.log_view = ServiceLogView::LogRead(log_contents);
                self.log_text_changed = true;
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
