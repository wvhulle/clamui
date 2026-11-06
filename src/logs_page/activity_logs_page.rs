use std::time::Duration;

use futures::{
    StreamExt,
    future::{AbortHandle, ready},
    stream,
};
use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
    prelude::FactoryVecDeque,
};

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityEntryRecord, ActivityHistory, ActivityHistoryFailure,
        },
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        settings_helper::helper_audit_records::{HelperAuditEntry, newest_helper_audit_entries},
    },
    logs_page::{
        activity_entry_row::{ActivityEntryRow, formatted_local_time},
        activity_export_formats::{
            activity_detail_text, activity_entries_as_csv, activity_entries_as_json,
        },
        daemon_log_reader::{DaemonLogContents, read_daemon_log},
        system_change_row::SystemChangeRow,
    },
    shared_widgets::{
        file_dialog_requests::{TextExportOutcome, describe_export_failure, request_text_export},
        loading_indicators::{FirstLoad, loading_placeholder_stack},
    },
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

const SYSTEM_CHANGE_LIMIT: usize = 200;

pub struct ActivityLogsPage {
    activity_history: ActivityHistory,
    listed_entries: Vec<ActivityEntryRecord>,
    entry_rows: FactoryVecDeque<ActivityEntryRow>,
    selected_entry: SelectedEntryView,
    detail_text_changed: bool,
    daemon_log_text: String,
    daemon_log_changed: bool,
    daemon_source_text: String,
    daemon_log_refresh: DaemonLogRefresh,
    history_notice: String,
    first_load: FirstLoad,
    system_change_rows: FactoryVecDeque<SystemChangeRow>,
    toaster: Toaster,
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
    RefreshSystemChangesRequested,
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
    SystemChangesLoaded(Result<Vec<HelperAuditEntry>, String>),
}

impl ActivityLogsPage {
    fn reload_system_changes(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            ActivityLogsPageCommand::SystemChangesLoaded(
                tokio::task::spawn_blocking(|| {
                    newest_helper_audit_entries(SYSTEM_CHANGE_LIMIT)
                        .map_err(|journal_failure| journal_failure.to_string())
                })
                .await
                .unwrap_or_else(|interrupted_read| Err(interrupted_read.to_string())),
            )
        });
    }

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
        suggested_name: &'static str,
        exported_text: String,
        sender: &ComponentSender<Self>,
    ) {
        request_text_export(
            suggested_name.to_owned(),
            exported_text,
            sender.command_sender().clone(),
            ActivityLogsPageCommand::TextExportFinished,
        );
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
        self.detail_text_changed = true;
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

fn show_system_changes(
    system_change_rows: &mut FactoryVecDeque<SystemChangeRow>,
    loaded_changes: Result<Vec<HelperAuditEntry>, String>,
) {
    let mut row_guard = system_change_rows.guard();
    row_guard.clear();
    match loaded_changes {
        Ok(audit_entries) if audit_entries.is_empty() => {
            row_guard.push_back(SystemChangeRow::ListNotice(gettext(
                "No ClamAV settings or trusted detections were changed through Lazaret",
            )));
        }
        Ok(audit_entries) => audit_entries.into_iter().for_each(|audit_entry| {
            row_guard.push_back(SystemChangeRow::ChangeRecorded(audit_entry));
        }),
        Err(journal_failure) => {
            row_guard.push_back(SystemChangeRow::ListNotice(
                gettext("The system journal can't be read: {error}")
                    .replace("{error}", &journal_failure),
            ));
        }
    }
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
                set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::ViewSwitcher {
                        set_policy: adw::ViewSwitcherPolicy::Wide,
                        set_stack: Some(&log_stack),
                    },
                },

                #[wrap(Some)]
                set_content = &gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_margin_top: 12,
                    set_margin_bottom: 18,
                    set_margin_start: 18,
                    set_margin_end: 18,
                    set_spacing: 12,

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
                                    #[local_ref]
                                    set_placeholder = placeholder_stack -> gtk::Stack {
                                        #[watch]
                                        set_visible_child_name: model.first_load.shown_page_name(),
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

    gtk::ScrolledWindow {
                                set_vexpand: true,
                                set_min_content_height: 180,
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
                                        #[track(model.detail_text_changed)]
                                        set_text: &model.selected_detail_text(),
                                    },
                                },
                            },
                        },

                        add_titled_with_icon[Some("system-changes"), &gettext("System Changes"), "changes-prevent-symbolic"] = &gtk::Box {
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
                                        set_label: &gettext("System Changes"),
                                    },

                                    gtk::Label {
                                        set_xalign: 0.0,
                                        set_wrap: true,
                                        add_css_class: "dim-label",
                                        set_label: &gettext("ClamAV settings and trusted detections changed through Lazaret, as recorded by the system. Software running as you can't remove these records."),
                                    },
                                },

                                gtk::Button {
                                    set_icon_name: "view-refresh-symbolic",
                                    set_tooltip_text: Some(&gettext("Refresh")),
                                    set_valign: gtk::Align::Center,
                                    add_css_class: "flat",
                                    connect_clicked => ActivityLogsPageInput::RefreshSystemChangesRequested,
                                },
                            },

                            gtk::ScrolledWindow {
                                set_vexpand: true,
                                set_hscrollbar_policy: gtk::PolicyType::Never,

                                #[local_ref]
                                system_change_list -> gtk::ListBox {
                                    add_css_class: "boxed-list",
                                    set_selection_mode: gtk::SelectionMode::None,
                                    set_valign: gtk::Align::Start,
                                },
                            },
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

    gtk::ScrolledWindow {
                                set_vexpand: true,
                                set_min_content_height: 180,
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
                                        #[track(model.daemon_log_changed)]
                                        set_text: &model.daemon_log_text,
                                    },
                                },
                            },
                        },
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
        let model = Self {
            activity_history,
            listed_entries: Vec::new(),
            entry_rows,
            selected_entry: SelectedEntryView::NoEntrySelected,
            detail_text_changed: true,
            daemon_log_text: String::new(),
            daemon_log_changed: true,
            daemon_source_text: gettext("Checking…"),
            daemon_log_refresh: DaemonLogRefresh::ManualRefresh,
            history_notice: String::new(),
            first_load: FirstLoad::StillLoading,
            system_change_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            toaster: Toaster::new(&root),
        };
        model.reload_entries(&sender);
        model.refresh_daemon_log(&sender);
        Self::reload_system_changes(&sender);
        let entry_list = model.entry_rows.widget();
        let system_change_list = model.system_change_rows.widget();
        let placeholder_stack = &loading_placeholder_stack(
            &gettext("Loading history…"),
            &adw::StatusPage::builder()
                .css_classes(["compact"])
                .icon_name("document-open-recent-symbolic")
                .title(gettext("No historical logs yet."))
                .build(),
        );
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ActivityLogsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        self.detail_text_changed = false;
        self.daemon_log_changed = false;
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
                    "lazaret-logs.csv",
                    activity_entries_as_csv(&self.listed_entries),
                    &sender,
                );
            }
            ActivityLogsPageInput::ExportAllJsonRequested => {
                match activity_entries_as_json(&self.listed_entries) {
                    Ok(exported_json) => {
                        self.export_text("lazaret-logs.json", exported_json, &sender);
                    }
                    Err(json_failure) => {
                        self.toaster.toast(&json_failure.to_string());
                    }
                }
            }
            ActivityLogsPageInput::CopyDetailRequested => {
                root.clipboard().set_text(&self.selected_detail_text());
                self.toaster
                    .toast(&gettext("Log details copied to clipboard"));
            }
            ActivityLogsPageInput::ExportDetailRequested => {
                self.export_text("lazaret-log.txt", self.selected_detail_text(), &sender);
            }
            ActivityLogsPageInput::RefreshDaemonLogRequested => self.refresh_daemon_log(&sender),
            ActivityLogsPageInput::RefreshSystemChangesRequested => {
                Self::reload_system_changes(&sender);
            }
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
                root.clipboard().set_text(&self.daemon_log_text);
                self.toaster
                    .toast(&gettext("Daemon logs copied to clipboard"));
            }
            ActivityLogsPageInput::ExportDaemonLogRequested => {
                self.export_text("clamd-logs.txt", self.daemon_log_text.clone(), &sender);
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ActivityLogsPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.detail_text_changed = false;
        self.daemon_log_changed = false;
        match page_command {
            ActivityLogsPageCommand::SystemChangesLoaded(loaded_changes) => {
                show_system_changes(&mut self.system_change_rows, loaded_changes);
            }
            ActivityLogsPageCommand::EntriesLoaded(Ok(listed_entries)) => {
                self.first_load = FirstLoad::LoadFinished;
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
                self.first_load = FirstLoad::LoadFinished;
                self.history_notice = gettext("Failed to load historical logs: {error}")
                    .replace("{error}", &load_failure.to_string());
            }
            ActivityLogsPageCommand::EntriesCleared(clear_outcome) => {
                match clear_outcome {
                    Ok(()) => {
                        self.select_entry(SelectedEntryView::NoEntrySelected);
                        self.toaster.toast(&gettext("Historical logs cleared."));
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
                    self.daemon_log_text = log_text;
                    self.daemon_log_changed = true;
                }
                DaemonLogContents::FromSystemJournal { log_text } => {
                    self.daemon_source_text = gettext("System journal");
                    self.daemon_log_text = log_text;
                    self.daemon_log_changed = true;
                }
                DaemonLogContents::NoReadableLog => {
                    self.daemon_source_text = gettext("Daemon log file not found.");
                    self.daemon_log_text.clear();
                    self.daemon_log_changed = true;
                }
            },
            ActivityLogsPageCommand::TextExportFinished(TextExportOutcome::TextSaved) => {
                self.toaster.toast(&gettext("Exported."));
            }
            ActivityLogsPageCommand::TextExportFinished(TextExportOutcome::ExportCancelled) => {}
            ActivityLogsPageCommand::TextExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => {
                self.toaster
                    .toast(&describe_export_failure(&export_failure));
            }
        }
    }
}
