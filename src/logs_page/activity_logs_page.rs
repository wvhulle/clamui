use futures::StreamExt;
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
        desktop::locale_formatting::exact_local_time_text,
        settings_helper::helper_audit_records::{HelperAuditEntry, newest_helper_audit_entries},
    },
    logs_page::{
        activity_entry_row::ActivityEntryRow,
        activity_export_formats::{
            activity_detail_text, activity_entries_as_csv, activity_entries_as_json,
        },
        activity_logs_state::{
            DaemonLogView, HistoryActionOutcome, HistoryView, SystemChangesReadFailure,
            SystemChangesView,
        },
        daemon_log_reader::{DaemonLogContents, daemon_log_updates, read_daemon_log},
        system_change_row::SystemChangeRow,
    },
    shared_widgets::{
        awaited_dialogs::{
            AlertChoice, TextExportOutcome, add_alert_choice, add_dismissing_choice, alert_choice,
            deliver_local_outcome, describe_export_failure, exported_text as exported_text_file,
        },
        component_streams::{RunningStream, run_stream},
        host_read_failure_text::unit_journal_failure_text,
        loading_indicators::{LOAD_FAILED_PAGE_NAME, loading_placeholder_stack},
    },
};

enum SelectedEntryView {
    NoEntrySelected,
    EntrySelected(ActivityEntryRecord),
}

enum DaemonLogRefresh {
    ManualRefresh,
    LiveRefresh { _live_refresh: RunningStream },
}

const SYSTEM_CHANGE_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClearLogsChoice {
    ClearAllChosen,
    ClearCancelled,
}

impl AlertChoice for ClearLogsChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[Self::ClearAllChosen];
    const DISMISSING_CHOICE: Self = Self::ClearCancelled;

    fn response_id(self) -> &'static str {
        match self {
            Self::ClearAllChosen => "clear",
            Self::ClearCancelled => "cancel",
        }
    }
}

pub struct ActivityLogsPage {
    activity_history: ActivityHistory,
    history_view: HistoryView,
    entry_rows: FactoryVecDeque<ActivityEntryRow>,
    selected_entry: SelectedEntryView,
    detail_text_changed: bool,
    daemon_log_view: DaemonLogView,
    daemon_log_changed: bool,
    daemon_log_refresh: DaemonLogRefresh,
    system_changes_view: SystemChangesView,
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
    SystemChangesLoaded(Result<Vec<HelperAuditEntry>, SystemChangesReadFailure>),
}

impl ActivityLogsPage {
    fn reload_system_changes(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            ActivityLogsPageCommand::SystemChangesLoaded(
                tokio::task::spawn_blocking(|| newest_helper_audit_entries(SYSTEM_CHANGE_LIMIT))
                    .await
                    .map_err(SystemChangesReadFailure::from)
                    .and_then(|journal_outcome| {
                        journal_outcome.map_err(SystemChangesReadFailure::from)
                    }),
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
        self.daemon_log_refresh = DaemonLogRefresh::LiveRefresh {
            _live_refresh: run_stream(
                sender,
                daemon_log_updates().map(ActivityLogsPageCommand::DaemonLogRead),
            ),
        };
    }

    fn export_text(
        &self,
        suggested_name: &'static str,
        exported_text: String,
        sender: &ComponentSender<Self>,
    ) {
        deliver_local_outcome(
            sender.command_sender().clone(),
            exported_text_file(suggested_name.to_owned(), exported_text),
            |export_outcome| Some(ActivityLogsPageCommand::TextExportFinished(export_outcome)),
        );
    }

    fn selected_detail_text(&self) -> String {
        match &self.selected_entry {
            SelectedEntryView::NoEntrySelected => gettext("Select a log entry to view details."),
            SelectedEntryView::EntrySelected(activity_entry) => activity_detail_text(
                activity_entry,
                &exact_local_time_text(activity_entry.started_at),
            ),
        }
    }

    fn history_notice_text(&self) -> String {
        match &self.history_view {
            HistoryView::HistoryLoaded {
                last_action: HistoryActionOutcome::ClearingFailed(clear_failure),
                ..
            } => gettext("Failed to clear logs: {error}")
                .replace("{error}", &clear_failure.to_string()),
            HistoryView::HistoryLoaded {
                last_action: HistoryActionOutcome::NoActionTaken,
                ..
            }
            | HistoryView::HistoryLoading
            | HistoryView::HistoryLoadFailed(_) => String::new(),
        }
    }

    fn history_failure_text(&self) -> String {
        match &self.history_view {
            HistoryView::HistoryLoadFailed(load_failure) => {
                gettext("Failed to load historical logs: {error}")
                    .replace("{error}", &load_failure.to_string())
            }
            HistoryView::HistoryLoading | HistoryView::HistoryLoaded { .. } => String::new(),
        }
    }

    fn system_changes_failure_text(&self) -> String {
        match &self.system_changes_view {
            SystemChangesView::SystemChangesFailed(
                SystemChangesReadFailure::JournalUnreadable(journal_failure),
            ) => gettext("The system journal can't be read: {error}")
                .replace("{error}", &journal_failure.to_string()),
            SystemChangesView::SystemChangesFailed(
                SystemChangesReadFailure::JournalReadInterrupted(interrupted_read),
            ) => gettext("The system journal can't be read: {error}")
                .replace("{error}", &interrupted_read.to_string()),
            SystemChangesView::SystemChangesLoading | SystemChangesView::SystemChangesLoaded => {
                String::new()
            }
        }
    }

    fn daemon_source_text(&self) -> String {
        match &self.daemon_log_view {
            DaemonLogView::DaemonLogReading => gettext("Checking…"),
            DaemonLogView::DaemonLogRead(DaemonLogContents::FromLogFile { log_path, .. }) => {
                sanitize_scanner_line(&log_path.to_string_lossy())
            }
            DaemonLogView::DaemonLogRead(DaemonLogContents::FromSystemJournal { .. }) => {
                gettext("System journal")
            }
            DaemonLogView::DaemonLogRead(DaemonLogContents::NoReadableLog) => {
                gettext("Daemon log file not found.")
            }
            DaemonLogView::DaemonLogRead(DaemonLogContents::JournalUnreadable(read_failure)) => {
                gettext("Daemon log file not found. {reason}")
                    .replace("{reason}", &unit_journal_failure_text(*read_failure))
            }
        }
    }

    fn has_listed_entries(&self) -> bool {
        !self.history_view.listed_entries().is_empty()
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
        add_dismissing_choice::<ClearLogsChoice>(&confirmation_dialog, &gettext("Cancel"));
        add_alert_choice(
            &confirmation_dialog,
            ClearLogsChoice::ClearAllChosen,
            &gettext("Clear All"),
        );
        confirmation_dialog.set_response_appearance(
            ClearLogsChoice::ClearAllChosen.response_id(),
            adw::ResponseAppearance::Destructive,
        );
        deliver_local_outcome(
            sender.input_sender().clone(),
            alert_choice(confirmation_dialog, root.clone().upcast()),
            |clear_choice| match clear_choice {
                ClearLogsChoice::ClearAllChosen => Some(ActivityLogsPageInput::ClearAllConfirmed),
                ClearLogsChoice::ClearCancelled => None,
            },
        );
    }
}

fn replace_rows<Row>(row_factory: &mut FactoryVecDeque<Row>, row_inits: Vec<Row::Init>)
where
    Row: relm4::prelude::FactoryComponent<Index = relm4::prelude::DynamicIndex>,
{
    let mut row_guard = row_factory.guard();
    row_guard.clear();
    row_inits.into_iter().for_each(|row_init| {
        row_guard.push_back(row_init);
    });
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
                                    set_sensitive: model.has_listed_entries(),
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
                                    set_sensitive: model.has_listed_entries(),
                                    connect_clicked => ActivityLogsPageInput::ClearAllRequested,
                                },
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_wrap: true,
                                add_css_class: "error",
                                #[watch]
                                set_visible: matches!(
                                    model.history_view,
                                    HistoryView::HistoryLoaded {
                                        last_action: HistoryActionOutcome::ClearingFailed(_),
                                        ..
                                    }
                                ),
                                #[watch]
                                set_label: &model.history_notice_text(),
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
                                        add_named[Some(LOAD_FAILED_PAGE_NAME)] = &adw::StatusPage {
                                            add_css_class: "compact",
                                            set_icon_name: Some("dialog-error-symbolic"),
                                            set_title: &gettext("Historical logs can't be read"),
                                            #[watch]
                                            set_description: Some(&gtk::glib::markup_escape_text(&model.history_failure_text())),
                                        },
                                        #[watch]
                                        set_visible_child_name: model.history_view.placeholder_page_name(),
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
                                    #[wrap(Some)]
                                    #[local_ref]
                                    set_placeholder = system_change_placeholder_stack -> gtk::Stack {
                                        add_named[Some(LOAD_FAILED_PAGE_NAME)] = &adw::StatusPage {
                                            add_css_class: "compact",
                                            set_icon_name: Some("dialog-error-symbolic"),
                                            set_title: &gettext("System changes can't be read"),
                                            #[watch]
                                            set_description: Some(&gtk::glib::markup_escape_text(&model.system_changes_failure_text())),
                                        },
                                        #[watch]
                                        set_visible_child_name: model.system_changes_view.placeholder_page_name(),
                                    },
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
                                        set_label: &model.daemon_source_text(),
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
                                    #[watch]
                                    set_sensitive: model.daemon_log_view.shown_log_text().is_some(),
                                    connect_clicked => ActivityLogsPageInput::CopyDaemonLogRequested,
                                },

                                gtk::Button {
                                    set_icon_name: "document-save-symbolic",
                                    set_tooltip_text: Some(&gettext("Export Text")),
                                    set_valign: gtk::Align::Center,
                                    add_css_class: "flat",
                                    #[watch]
                                    set_sensitive: model.daemon_log_view.shown_log_text().is_some(),
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
                                        set_text: model.daemon_log_view.shown_log_text().unwrap_or_default(),
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
            history_view: HistoryView::HistoryLoading,
            entry_rows,
            selected_entry: SelectedEntryView::NoEntrySelected,
            detail_text_changed: true,
            daemon_log_view: DaemonLogView::DaemonLogReading,
            daemon_log_changed: true,
            daemon_log_refresh: DaemonLogRefresh::ManualRefresh,
            system_changes_view: SystemChangesView::SystemChangesLoading,
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
        let system_change_placeholder_stack = &loading_placeholder_stack(
            &gettext("Loading system changes…"),
            &adw::StatusPage::builder()
                .css_classes(["compact"])
                .icon_name("changes-prevent-symbolic")
                .title(gettext(
                    "No ClamAV settings or trusted detections were changed through Lazaret",
                ))
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
                if let Some(activity_entry) = self.history_view.listed_entries().get(row_position) {
                    self.select_entry(SelectedEntryView::EntrySelected(activity_entry.clone()));
                }
            }
            ActivityLogsPageInput::ClearAllRequested => self.confirm_clear_all(root, &sender),
            ActivityLogsPageInput::ClearAllConfirmed => {
                self.history_view =
                    std::mem::replace(&mut self.history_view, HistoryView::HistoryLoading)
                        .with_clearing_started();
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
                    activity_entries_as_csv(self.history_view.listed_entries()),
                    &sender,
                );
            }
            ActivityLogsPageInput::ExportAllJsonRequested => {
                match activity_entries_as_json(self.history_view.listed_entries()) {
                    Ok(exported_json) => {
                        self.export_text("lazaret-logs.json", exported_json, &sender);
                    }
                    Err(json_failure) => {
                        self.toaster.toast(
                            &gettext("Could not export the logs: {error}")
                                .replace("{error}", &json_failure.to_string()),
                        );
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
                DaemonLogRefresh::LiveRefresh { .. } => {
                    self.daemon_log_refresh = DaemonLogRefresh::ManualRefresh;
                }
            },
            ActivityLogsPageInput::CopyDaemonLogRequested => {
                if let Some(log_text) = self.daemon_log_view.shown_log_text() {
                    root.clipboard().set_text(log_text);
                    self.toaster
                        .toast(&gettext("Daemon logs copied to clipboard"));
                }
            }
            ActivityLogsPageInput::ExportDaemonLogRequested => {
                if let Some(log_text) = self.daemon_log_view.shown_log_text() {
                    self.export_text("clamd-logs.txt", log_text.to_owned(), &sender);
                }
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
            ActivityLogsPageCommand::SystemChangesLoaded(Ok(audit_entries)) => {
                self.system_changes_view = SystemChangesView::SystemChangesLoaded;
                replace_rows(&mut self.system_change_rows, audit_entries);
            }
            ActivityLogsPageCommand::SystemChangesLoaded(Err(read_failure)) => {
                self.system_changes_view = SystemChangesView::SystemChangesFailed(read_failure);
                replace_rows(&mut self.system_change_rows, Vec::new());
            }
            ActivityLogsPageCommand::EntriesLoaded(load_outcome) => {
                self.history_view =
                    std::mem::replace(&mut self.history_view, HistoryView::HistoryLoading)
                        .with_loaded_entries(load_outcome);
                replace_rows(
                    &mut self.entry_rows,
                    self.history_view.listed_entries().to_vec(),
                );
            }
            ActivityLogsPageCommand::EntriesCleared(clear_outcome) => {
                match clear_outcome {
                    Ok(()) => {
                        self.select_entry(SelectedEntryView::NoEntrySelected);
                        self.toaster.toast(&gettext("Historical logs cleared."));
                    }
                    Err(clear_failure) => {
                        self.history_view =
                            std::mem::replace(&mut self.history_view, HistoryView::HistoryLoading)
                                .with_clearing_failure(clear_failure);
                    }
                }
                self.reload_entries(&sender);
            }
            ActivityLogsPageCommand::DaemonLogRead(daemon_log) => {
                self.daemon_log_view = DaemonLogView::DaemonLogRead(daemon_log);
                self.daemon_log_changed = true;
            }
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
