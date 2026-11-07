use gettextrs::gettext;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, adw,
    adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    host_services::activity_history::activity_history_database::{
        ActivityEntryRecord, ActivityHistory, ActivityHistoryFailure,
    },
    shared_widgets::{
        activity_entries::{
            activity_entry_row::ActivityEntryRow,
            activity_history_filter::{ActivityHistoryFilter, FilteredHistoryView},
            activity_transcript_dialog::ActivityTranscriptDialog,
        },
        loading_indicators::{LOAD_FAILED_PAGE_NAME, loading_placeholder_stack},
    },
};

pub struct ActivityHistoryGroupInit {
    pub activity_history: ActivityHistory,
    pub history_filter: ActivityHistoryFilter,
    pub group_title: String,
    pub group_description: String,
    pub empty_title: String,
    pub empty_icon_name: &'static str,
}

enum TranscriptDialogView {
    DialogClosed,
    DialogOpen {
        _transcript_dialog: Controller<ActivityTranscriptDialog>,
    },
}

pub struct ActivityHistoryGroup {
    activity_history: ActivityHistory,
    history_filter: ActivityHistoryFilter,
    history_view: FilteredHistoryView,
    history_rows: FactoryVecDeque<ActivityEntryRow>,
    transcript_dialog: TranscriptDialogView,
}

#[derive(Debug)]
pub enum ActivityHistoryGroupInput {
    ReloadRequested,
    EntryActivated { row_position: usize },
}

#[derive(Debug)]
pub enum ActivityHistoryGroupCommand {
    HistoryLoaded(Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>),
}

fn history_failure_text(history_view: &FilteredHistoryView) -> String {
    match history_view {
        FilteredHistoryView::HistoryLoadFailed(load_failure) => {
            gettext("Failed to load historical logs: {error}")
                .replace("{error}", &load_failure.to_string())
        }
        FilteredHistoryView::HistoryLoading | FilteredHistoryView::HistoryLoaded(_) => {
            String::new()
        }
    }
}

impl ActivityHistoryGroup {
    fn reload_history(&self, sender: &ComponentSender<Self>) {
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            ActivityHistoryGroupCommand::HistoryLoaded(activity_history.list_recent_entries().await)
        });
    }

    fn open_transcript(&mut self, row_position: usize, root: &adw::PreferencesGroup) {
        let Some(activity_entry) = self.history_view.listed_entries().get(row_position) else {
            return;
        };
        let transcript_dialog = ActivityTranscriptDialog::builder()
            .launch(activity_entry.clone())
            .detach();
        transcript_dialog.widget().present(Some(root));
        self.transcript_dialog = TranscriptDialogView::DialogOpen {
            _transcript_dialog: transcript_dialog,
        };
    }
}

#[relm4::component(pub)]
impl Component for ActivityHistoryGroup {
    type Init = ActivityHistoryGroupInit;
    type Input = ActivityHistoryGroupInput;
    type Output = ();
    type CommandOutput = ActivityHistoryGroupCommand;

    view! {
        adw::PreferencesGroup {
            set_title: &group_init.group_title,
            set_description: Some(&group_init.group_description),

            #[local_ref]
            history_list -> gtk::ListBox {
                add_css_class: "boxed-list",
                set_selection_mode: gtk::SelectionMode::None,
                #[wrap(Some)]
                #[local_ref]
                set_placeholder = history_placeholder -> gtk::Stack {
                    add_named[Some(LOAD_FAILED_PAGE_NAME)] = &adw::StatusPage {
                        add_css_class: "compact",
                        set_icon_name: Some("dialog-error-symbolic"),
                        set_title: &gettext("Historical logs can't be read"),
                        #[watch]
                        set_description: Some(&gtk::glib::markup_escape_text(
                            &history_failure_text(&model.history_view),
                        )),
                    },
                    #[watch]
                    set_visible_child_name: model.history_view.placeholder_page_name(),
                },
                connect_row_activated[sender] => move |_history_list, activated_row| {
                    sender.input(ActivityHistoryGroupInput::EntryActivated {
                        row_position: usize::try_from(activated_row.index()).unwrap_or_default(),
                    });
                },
            },
        }
    }

    fn init(
        group_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            activity_history: group_init.activity_history.clone(),
            history_filter: group_init.history_filter,
            history_view: FilteredHistoryView::HistoryLoading,
            history_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            transcript_dialog: TranscriptDialogView::DialogClosed,
        };
        let history_list = model.history_rows.widget();
        let history_placeholder = &loading_placeholder_stack(
            &gettext("Loading history…"),
            &adw::StatusPage::builder()
                .css_classes(["compact"])
                .icon_name(group_init.empty_icon_name)
                .title(group_init.empty_title.as_str())
                .build(),
        );
        let widgets = view_output!();
        model.reload_history(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        group_input: ActivityHistoryGroupInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match group_input {
            ActivityHistoryGroupInput::ReloadRequested => self.reload_history(&sender),
            ActivityHistoryGroupInput::EntryActivated { row_position } => {
                self.open_transcript(row_position, root);
            }
        }
    }

    fn update_cmd(
        &mut self,
        group_command: ActivityHistoryGroupCommand,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match group_command {
            ActivityHistoryGroupCommand::HistoryLoaded(load_outcome) => {
                self.history_view =
                    FilteredHistoryView::from_load_outcome(load_outcome, self.history_filter);
                let mut history_guard = self.history_rows.guard();
                history_guard.clear();
                self.history_view
                    .listed_entries()
                    .iter()
                    .cloned()
                    .for_each(|activity_entry| {
                        history_guard.push_back(activity_entry);
                    });
            }
        }
    }
}
