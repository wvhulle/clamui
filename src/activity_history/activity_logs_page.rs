use std::time::Duration;

use futures::{
    StreamExt,
    future::{AbortHandle, ready},
    stream,
};
use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    activity_history::{
        activity_entry_row::{ActivityEntryRow, formatted_local_time},
        activity_export_formats::{
            activity_detail_text, activity_entries_as_csv, activity_entries_as_json,
        },
        activity_history_database::{ActivityEntryRecord, ActivityHistory, ActivityHistoryFailure},
        daemon_log_reader::{DaemonLogContents, read_daemon_log},
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    text_export_dialog::{TextExportOutcome, describe_export_failure, save_text_with_dialog},
};

const LIVE_REFRESH_INTERVAL: Duration = Duration::from_secs(3);

enum SelectedEntryView {
    NoEntrySelected,
    EntrySelected(ActivityEntryRecord),
}

enum DaemonLogRefresh {
    ManualRefresh,
    LiveRefresh { refresh_abort_handle: AbortHandle },
}

pub struct ActivityLogsPage {
    activity_history: ActivityHistory,
    listed_entries: Vec<ActivityEntryRecord>,
    entry_rows: FactoryVecDeque<ActivityEntryRow>,
    selected_entry: SelectedEntryView,
    detail_buffer: gtk::TextBuffer,
    daemon_buffer: gtk::TextBuffer,
    daemon_source_text: String,
    daemon_log_refresh: DaemonLogRefresh,
    history_notice: String,
}

#[derive(Debug)]
pub enum ActivityLogsPageInput {
    ReloadEntriesRequested,
    EntryActivated { row_position: usize },
    ClearAllRequested,
    ClearAllConfirmed,
    ExportAllCsvRequested,
    ExportAllJsonRequested,
    CopyDetailRequested,
    ExportDetailRequested,
    RefreshDaemonLogRequested,
    LiveDaemonLogToggled,
    CopyDaemonLogRequested,
    ExportDaemonLogRequested,
}

#[derive(Debug)]
pub enum ActivityLogsPageCommand {
    EntriesLoaded(Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>),
    EntriesCleared(Result<(), ActivityHistoryFailure>),
    DaemonLogRead(DaemonLogContents),
    TextExportFinished(TextExportOutcome),
}

impl ActivityLogsPage {
    fn reload_entries(&self, sender: &ComponentSender<Self>) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            ActivityLogsPageCommand::EntriesLoaded(activity_history.list_recent_entries().await)
        });
    }

    fn refresh_daemon_log(&self, sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            ActivityLogsPageCommand::DaemonLogRead(read_daemon_log().await)
        });
    }

    fn start_live_refresh(&mut self, sender: &ComponentSender<Self>) {
        let (periodic_reads, refresh_abort_handle) = stream::abortable(
            stream::unfold((), |()| async {
                tokio::time::sleep(LIVE_REFRESH_INTERVAL).await;
                Some((read_daemon_log().await, ()))
            })
            .boxed(),
        );
        self.daemon_log_refresh = DaemonLogRefresh::LiveRefresh {
            refresh_abort_handle,
        };
        sender.command(move |command_output, shutdown| {
            shutdown
                .register(periodic_reads.for_each(move |daemon_log| {
                    command_output.emit(ActivityLogsPageCommand::DaemonLogRead(daemon_log));
                    ready(())
                }))
                .drop_on_shutdown()
        });
    }

    fn export_text(
        &self,
        root: &adw::ToastOverlay,
        suggested_name: &'static str,
        exported_text: String,
        sender: &ComponentSender<Self>,
    ) {
        let parent_widget = root.clone().upcast::<gtk::Widget>();
        let command_sender = sender.command_sender().clone();
        relm4::spawn_local(async move {
            let export_outcome =
                save_text_with_dialog(&parent_widget, suggested_name, exported_text).await;
            let _page_closed =
                command_sender.send(ActivityLogsPageCommand::TextExportFinished(export_outcome));
        });
    }

    fn selected_detail_text(&self) -> String {
        match &self.selected_entry {
            SelectedEntryView::NoEntrySelected => gettext("Select a log entry to view details."),
            SelectedEntryView::EntrySelected(activity_entry) => activity_detail_text(
                activity_entry,
                &formatted_local_time(activity_entry.started_at_unix),
            ),
        }
    }

    fn has_selected_entry(&self) -> bool {
        matches!(self.selected_entry, SelectedEntryView::EntrySelected(_))
    }

    fn select_entry(&mut self, selected_entry: SelectedEntryView) {
        self.selected_entry = selected_entry;
        self.detail_buffer.set_text(&self.selected_detail_text());
    }

    fn confirm_clear_all(&self, root: &adw::ToastOverlay, sender: &ComponentSender<Self>) {
        let confirmation_dialog = adw::AlertDialog::new(
            Some(&gettext("Clear All Logs?")),
            Some(&gettext(
                "This will permanently delete all historical logs. This action cannot be undone.",
            )),
        );
        confirmation_dialog.add_response("cancel", &gettext("Cancel"));
        confirmation_dialog.add_response("clear", &gettext("Clear All"));
        confirmation_dialog.set_response_appearance("clear", adw::ResponseAppearance::Destructive);
        confirmation_dialog.set_close_response("cancel");
        let input_sender = sender.input_sender().clone();
        confirmation_dialog.connect_response(Some("clear"), move |_dialog, _response| {
            input_sender.emit(ActivityLogsPageInput::ClearAllConfirmed);
        });
        confirmation_dialog.present(Some(root));
    }
}

fn log_text_view(text_buffer: &gtk::TextBuffer) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .vexpand(true)
        .min_content_height(180)
        .css_classes(["card"])
        .child(
            &gtk::TextView::builder()
                .buffer(text_buffer)
                .editable(false)
                .monospace(true)
                .wrap_mode(gtk::WrapMode::WordChar)
                .top_margin(12)
                .bottom_margin(12)
                .left_margin(12)
                .right_margin(12)
                .build(),
        )
        .build()
}

#[relm4::component(pub)]
impl Component for ActivityLogsPage {
    type Init = ActivityHistory;
    type Input = ActivityLogsPageInput;
    type Output = ();
    type CommandOutput = ActivityLogsPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_margin_top: 6,
                set_margin_bottom: 18,
                set_margin_start: 18,
                set_margin_end: 18,
                set_spacing: 12,

                adw::ViewSwitcher {
                    set_policy: adw::ViewSwitcherPolicy::Wide,
                    set_stack: Some(&log_stack),
                },

                #[name = "log_stack"]
                adw::ViewStack {
                    set_vexpand: true,

                    add_titled_with_icon[Some("history"), &gettext("Historical Logs"), "document-open-recent-symbolic"] = &gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 12,

                        gtk::Box {
                            set_spacing: 6,

                            gtk::Box {
                                set_orientation: gtk::Orientation::Vertical,
                                set_hexpand: true,

                                gtk::Label {
                                    set_xalign: 0.0,
                                    add_css_class: "heading",
                                    set_label: &gettext("Historical Logs"),
                                },

                                gtk::Label {
                                    set_xalign: 0.0,
                                    add_css_class: "dim-label",
                                    set_label: &gettext("Previous scan and update operations"),
                                },
                            },

                            gtk::Button {
                                set_icon_name: "view-refresh-symbolic",
                                set_tooltip_text: Some(&gettext("Refresh")),
                                set_valign: gtk::Align::Center,
                                add_css_class: "flat",
                                connect_clicked => ActivityLogsPageInput::ReloadEntriesRequested,
                            },

                            gtk::MenuButton {
                                set_icon_name: "document-save-symbolic",
                                set_tooltip_text: Some(&gettext("Export All")),
                                set_valign: gtk::Align::Center,
                                add_css_class: "flat",
                                #[watch]
                                set_sensitive: !model.listed_entries.is_empty(),
                                #[wrap(Some)]
                                set_popover = &gtk::Popover {
                                    gtk::Box {
                                        set_orientation: gtk::Orientation::Vertical,

                                        gtk::Button {
                                            set_label: &gettext("Export CSV"),
                                            add_css_class: "flat",
                                            connect_clicked => ActivityLogsPageInput::ExportAllCsvRequested,
                                        },

                                        gtk::Button {
                                            set_label: &gettext("Export JSON"),
                                            add_css_class: "flat",
                                            connect_clicked => ActivityLogsPageInput::ExportAllJsonRequested,
                                        },
                                    },
                                },
                            },

                            gtk::Button {
                                set_label: &gettext("Clear All"),
                                set_valign: gtk::Align::Center,
                                add_css_class: "flat",
                                #[watch]
                                set_sensitive: !model.listed_entries.is_empty(),
                                connect_clicked => ActivityLogsPageInput::ClearAllRequested,
                            },
                        },

                        gtk::Label {
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "error",
                            #[watch]
                            set_visible: !model.history_notice.is_empty(),
                            #[watch]
                            set_label: &model.history_notice,
                        },

                        gtk::ScrolledWindow {
                            set_min_content_height: 180,
                            set_vexpand: true,
                            set_hscrollbar_policy: gtk::PolicyType::Never,

                            #[local_ref]
                            entry_list -> gtk::ListBox {
                                add_css_class: "boxed-list",
                                set_valign: gtk::Align::Start,
                                set_selection_mode: gtk::SelectionMode::Single,
                                #[wrap(Some)]
                                set_placeholder = &adw::StatusPage {
                                    add_css_class: "compact",
                                    set_icon_name: Some("document-open-recent-symbolic"),
                                    set_title: &gettext("No historical logs yet."),
                                },
                                connect_row_activated[sender] => move |_entry_list, activated_row| {
                                    sender.input(ActivityLogsPageInput::EntryActivated {
                                        row_position: activated_row.index().max(0) as usize,
                                    });
                                },
                            },
                        },

                        gtk::Box {
                            set_spacing: 6,

                            gtk::Label {
                                set_xalign: 0.0,
                                set_hexpand: true,
                                add_css_class: "heading",
                                set_label: &gettext("Log Details"),
                            },

                            gtk::Button {
                                set_icon_name: "edit-copy-symbolic",
                                set_tooltip_text: Some(&gettext("Copy")),
                                add_css_class: "flat",
                                #[watch]
                                set_sensitive: model.has_selected_entry(),
                                connect_clicked => ActivityLogsPageInput::CopyDetailRequested,
                            },

                            gtk::Button {
                                set_icon_name: "document-save-symbolic",
                                set_tooltip_text: Some(&gettext("Export Text")),
                                add_css_class: "flat",
                                #[watch]
                                set_sensitive: model.has_selected_entry(),
                                connect_clicked => ActivityLogsPageInput::ExportDetailRequested,
                            },
                        },

                        append: &log_text_view(&model.detail_buffer),
                    },

                    add_titled_with_icon[Some("daemon"), &gettext("ClamAV Daemon"), "utilities-terminal-symbolic"] = &gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 12,

                        gtk::Box {
                            set_spacing: 6,

                            gtk::Box {
                                set_orientation: gtk::Orientation::Vertical,
                                set_hexpand: true,

                                gtk::Label {
                                    set_xalign: 0.0,
                                    add_css_class: "heading",
                                    set_label: &gettext("ClamAV Daemon"),
                                },

                                gtk::Label {
                                    set_xalign: 0.0,
                                    set_ellipsize: gtk::pango::EllipsizeMode::Middle,
                                    add_css_class: "dim-label",
                                    #[watch]
                                    set_label: &model.daemon_source_text,
                                },
                            },

                            gtk::ToggleButton {
                                set_label: &gettext("Live Updates"),
                                set_valign: gtk::Align::Center,
                                connect_clicked => ActivityLogsPageInput::LiveDaemonLogToggled,
                            },

                            gtk::Button {
                                set_icon_name: "view-refresh-symbolic",
                                set_tooltip_text: Some(&gettext("Refresh")),
                                set_valign: gtk::Align::Center,
                                add_css_class: "flat",
                                connect_clicked => ActivityLogsPageInput::RefreshDaemonLogRequested,
                            },

                            gtk::Button {
                                set_icon_name: "edit-copy-symbolic",
                                set_tooltip_text: Some(&gettext("Copy")),
                                set_valign: gtk::Align::Center,
                                add_css_class: "flat",
                                connect_clicked => ActivityLogsPageInput::CopyDaemonLogRequested,
                            },

                            gtk::Button {
                                set_icon_name: "document-save-symbolic",
                                set_tooltip_text: Some(&gettext("Export Text")),
                                set_valign: gtk::Align::Center,
                                add_css_class: "flat",
                                connect_clicked => ActivityLogsPageInput::ExportDaemonLogRequested,
                            },
                        },

                        append: &log_text_view(&model.daemon_buffer),
                    },
                },
            },
        }
    }

    fn init(
        activity_history: ActivityHistory,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let entry_rows = FactoryVecDeque::builder()
            .launch(gtk::ListBox::default())
            .detach();
        let mut model = Self {
            activity_history,
            listed_entries: Vec::new(),
            entry_rows,
            selected_entry: SelectedEntryView::NoEntrySelected,
            detail_buffer: gtk::TextBuffer::new(None),
            daemon_buffer: gtk::TextBuffer::new(None),
            daemon_source_text: gettext("Checking…"),
            daemon_log_refresh: DaemonLogRefresh::ManualRefresh,
            history_notice: String::new(),
        };
        model.select_entry(SelectedEntryView::NoEntrySelected);
        model.reload_entries(&sender);
        model.refresh_daemon_log(&sender);
        let entry_list = model.entry_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ActivityLogsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ActivityLogsPageInput::ReloadEntriesRequested => self.reload_entries(&sender),
            ActivityLogsPageInput::EntryActivated { row_position } => {
                if let Some(activity_entry) = self.listed_entries.get(row_position) {
                    self.select_entry(SelectedEntryView::EntrySelected(activity_entry.clone()));
                }
            }
            ActivityLogsPageInput::ClearAllRequested => self.confirm_clear_all(root, &sender),
            ActivityLogsPageInput::ClearAllConfirmed => {
                let activity_history = self.activity_history.clone();
                sender.oneshot_command(async move {
                    ActivityLogsPageCommand::EntriesCleared(
                        activity_history.clear_all_entries().await,
                    )
                });
            }
            ActivityLogsPageInput::ExportAllCsvRequested => {
                self.export_text(
                    root,
                    "clamui-logs.csv",
                    activity_entries_as_csv(&self.listed_entries),
                    &sender,
                );
            }
            ActivityLogsPageInput::ExportAllJsonRequested => {
                match activity_entries_as_json(&self.listed_entries) {
                    Ok(exported_json) => {
                        self.export_text(root, "clamui-logs.json", exported_json, &sender);
                    }
                    Err(json_failure) => {
                        root.add_toast(adw::Toast::new(&json_failure.to_string()));
                    }
                }
            }
            ActivityLogsPageInput::CopyDetailRequested => {
                root.clipboard().set_text(&self.selected_detail_text());
                root.add_toast(adw::Toast::new(&gettext("Log details copied to clipboard")));
            }
            ActivityLogsPageInput::ExportDetailRequested => {
                self.export_text(root, "clamui-log.txt", self.selected_detail_text(), &sender);
            }
            ActivityLogsPageInput::RefreshDaemonLogRequested => self.refresh_daemon_log(&sender),
            ActivityLogsPageInput::LiveDaemonLogToggled => match &self.daemon_log_refresh {
                DaemonLogRefresh::ManualRefresh => self.start_live_refresh(&sender),
                DaemonLogRefresh::LiveRefresh {
                    refresh_abort_handle,
                } => {
                    refresh_abort_handle.abort();
                    self.daemon_log_refresh = DaemonLogRefresh::ManualRefresh;
                }
            },
            ActivityLogsPageInput::CopyDaemonLogRequested => {
                let (buffer_start, buffer_end) = self.daemon_buffer.bounds();
                root.clipboard().set_text(&self.daemon_buffer.text(
                    &buffer_start,
                    &buffer_end,
                    false,
                ));
                root.add_toast(adw::Toast::new(&gettext("Daemon logs copied to clipboard")));
            }
            ActivityLogsPageInput::ExportDaemonLogRequested => {
                let (buffer_start, buffer_end) = self.daemon_buffer.bounds();
                self.export_text(
                    root,
                    "clamd-logs.txt",
                    self.daemon_buffer
                        .text(&buffer_start, &buffer_end, false)
                        .to_string(),
                    &sender,
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ActivityLogsPageCommand,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_command {
            ActivityLogsPageCommand::EntriesLoaded(Ok(listed_entries)) => {
                self.history_notice.clear();
                let mut entry_rows_guard = self.entry_rows.guard();
                entry_rows_guard.clear();
                listed_entries.iter().cloned().for_each(|listed_entry| {
                    entry_rows_guard.push_back(listed_entry);
                });
                drop(entry_rows_guard);
                self.listed_entries = listed_entries;
            }
            ActivityLogsPageCommand::EntriesLoaded(Err(load_failure)) => {
                self.history_notice = gettext("Failed to load historical logs: {error}")
                    .replace("{error}", &load_failure.to_string());
            }
            ActivityLogsPageCommand::EntriesCleared(clear_outcome) => {
                match clear_outcome {
                    Ok(()) => {
                        self.select_entry(SelectedEntryView::NoEntrySelected);
                        root.add_toast(adw::Toast::new(&gettext("Historical logs cleared.")));
                    }
                    Err(clear_failure) => {
                        self.history_notice = gettext("Failed to clear logs: {error}")
                            .replace("{error}", &clear_failure.to_string());
                    }
                }
                self.reload_entries(&sender);
            }
            ActivityLogsPageCommand::DaemonLogRead(daemon_log) => match daemon_log {
                DaemonLogContents::FromLogFile { log_path, log_text } => {
                    self.daemon_source_text = sanitize_scanner_line(&log_path.to_string_lossy());
                    self.daemon_buffer.set_text(&log_text);
                }
                DaemonLogContents::FromSystemJournal { log_text } => {
                    self.daemon_source_text = gettext("System journal");
                    self.daemon_buffer.set_text(&log_text);
                }
                DaemonLogContents::NoReadableLog => {
                    self.daemon_source_text = gettext("Daemon log file not found.");
                    self.daemon_buffer.set_text("");
                }
            },
            ActivityLogsPageCommand::TextExportFinished(TextExportOutcome::TextSaved) => {
                root.add_toast(adw::Toast::new(&gettext("Exported.")));
            }
            ActivityLogsPageCommand::TextExportFinished(TextExportOutcome::ExportCancelled) => {}
            ActivityLogsPageCommand::TextExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => {
                root.add_toast(adw::Toast::new(&describe_export_failure(&export_failure)));
            }
        }
    }
}
