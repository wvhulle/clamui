use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    file_quarantine::{
        quarantine_entry_database::{QuarantineEntryRecord, QuarantineVault},
        quarantine_entry_row::{QuarantineEntryRow, QuarantineEntryRowOutput},
        quarantine_file_moves::QuarantineMoveFailure,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    shared_page_widget_templates::ClampedPage,
};

pub fn describe_quarantine_failure(move_failure: &QuarantineMoveFailure) -> String {
    match move_failure {
        QuarantineMoveFailure::FileHashMismatch => {
            gettext("File hash mismatch — file may be corrupted")
        }
        QuarantineMoveFailure::EntryNotFound { entry_id } => {
            gettext("Quarantine entry not found: {id}").replace("{id}", &entry_id.to_string())
        }
        QuarantineMoveFailure::RecordingFailedFileRestored { .. } => gettext(
            "Failed to record quarantine entry in database. File has been restored to original \
             location.",
        ),
        QuarantineMoveFailure::RecordingFailedRollbackFailed {
            rollback_failure,
            payload_path,
            ..
        } => gettext(
            "Failed to record quarantine entry in database. Rollback also failed: {error}. File \
             may be orphaned at: {path}",
        )
        .replace("{error}", &rollback_failure.to_string())
        .replace(
            "{path}",
            &sanitize_scanner_line(&payload_path.to_string_lossy()),
        ),
        QuarantineMoveFailure::EntryRecordNotRemoved => gettext(
            "The file was moved, but its quarantine record could not be removed. It may still \
             appear in the list.",
        ),
        other_failure => other_failure.to_string(),
    }
}

pub struct QuarantineEntriesPage {
    quarantine_vault: QuarantineVault,
    entry_rows: FactoryVecDeque<QuarantineEntryRow>,
    status_message: String,
}

#[derive(Debug)]
pub enum QuarantineEntriesPageInput {
    ReloadEntriesRequested,
    RestoreEntryRequested { entry_id: i64 },
    DeleteEntryRequested { entry_id: i64 },
    DeleteEntryConfirmed { entry_id: i64 },
}

#[derive(Debug)]
pub enum QuarantineEntriesPageCommand {
    EntriesLoaded(Result<Vec<QuarantineEntryRecord>, QuarantineMoveFailure>),
    EntryOperationFinished(Result<QuarantineEntryRecord, QuarantineMoveFailure>),
}

impl QuarantineEntriesPage {
    fn reload_entries(&self, sender: &ComponentSender<Self>) {
        let quarantine_vault = self.quarantine_vault.clone();
        let command_sender = sender.command_sender().clone();
        relm4::spawn(async move {
            let _page_closed = command_sender.send(QuarantineEntriesPageCommand::EntriesLoaded(
                quarantine_vault.list_quarantine_entries().await,
            ));
        });
    }

    fn confirm_entry_deletion(&self, entry_id: i64, sender: &ComponentSender<Self>) {
        let confirmation_dialog = adw::AlertDialog::new(
            Some(&gettext("Delete Quarantined File?")),
            Some(&gettext("The file will be permanently deleted.")),
        );
        confirmation_dialog.add_response("cancel", &gettext("Cancel"));
        confirmation_dialog.add_response("delete", &gettext("Delete"));
        confirmation_dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        let input_sender = sender.input_sender().clone();
        confirmation_dialog.connect_response(Some("delete"), move |_dialog, _response| {
            input_sender.emit(QuarantineEntriesPageInput::DeleteEntryConfirmed { entry_id });
        });
        confirmation_dialog.present(relm4::main_application().active_window().as_ref());
    }
}

#[relm4::component(pub)]
impl Component for QuarantineEntriesPage {
    type Init = QuarantineVault;
    type Input = QuarantineEntriesPageInput;
    type Output = ();
    type CommandOutput = QuarantineEntriesPageCommand;

    view! {
        #[template]
        ClampedPage {
            #[template_child]
            page_content {
                gtk::Label {
                    add_css_class: "title-2",
                    set_xalign: 0.0,
                    set_label: &gettext("Quarantine"),
                },

                gtk::Label {
                    set_xalign: 0.0,
                    set_wrap: true,
                    set_selectable: true,
                    #[watch]
                    set_visible: !model.status_message.is_empty(),
                    #[watch]
                    set_label: &model.status_message,
                },

                gtk::Label {
                    set_xalign: 0.0,
                    add_css_class: "dim-label",
                    set_label: &gettext("Quarantine is empty"),
                    #[watch]
                    set_visible: model.entry_rows.is_empty(),
                },

                #[local_ref]
                entry_list -> gtk::ListBox {
                    add_css_class: "boxed-list",
                    set_selection_mode: gtk::SelectionMode::None,
                    #[watch]
                    set_visible: !model.entry_rows.is_empty(),
                },
            },
        }
    }

    fn init(
        quarantine_vault: QuarantineVault,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let entry_rows = FactoryVecDeque::builder()
            .launch(gtk::ListBox::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                QuarantineEntryRowOutput::RestoreRequested { entry_id } => {
                    QuarantineEntriesPageInput::RestoreEntryRequested { entry_id }
                }
                QuarantineEntryRowOutput::DeleteRequested { entry_id } => {
                    QuarantineEntriesPageInput::DeleteEntryRequested { entry_id }
                }
            });
        let model = Self {
            quarantine_vault,
            entry_rows,
            status_message: String::new(),
        };
        model.reload_entries(&sender);
        let entry_list = model.entry_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: QuarantineEntriesPageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        let quarantine_vault = self.quarantine_vault.clone();
        let command_sender = sender.command_sender().clone();
        match page_input {
            QuarantineEntriesPageInput::ReloadEntriesRequested => self.reload_entries(&sender),
            QuarantineEntriesPageInput::RestoreEntryRequested { entry_id } => {
                relm4::spawn(async move {
                    let _page_closed =
                        command_sender.send(QuarantineEntriesPageCommand::EntryOperationFinished(
                            quarantine_vault.restore_quarantined_file(entry_id).await,
                        ));
                });
            }
            QuarantineEntriesPageInput::DeleteEntryRequested { entry_id } => {
                self.confirm_entry_deletion(entry_id, &sender);
            }
            QuarantineEntriesPageInput::DeleteEntryConfirmed { entry_id } => {
                relm4::spawn(async move {
                    let _page_closed =
                        command_sender.send(QuarantineEntriesPageCommand::EntryOperationFinished(
                            quarantine_vault.delete_quarantined_file(entry_id).await,
                        ));
                });
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: QuarantineEntriesPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            QuarantineEntriesPageCommand::EntriesLoaded(Ok(listed_entries)) => {
                let mut entry_rows_guard = self.entry_rows.guard();
                entry_rows_guard.clear();
                listed_entries.into_iter().for_each(|listed_entry| {
                    entry_rows_guard.push_back(listed_entry);
                });
            }
            QuarantineEntriesPageCommand::EntriesLoaded(Err(load_failure)) => {
                self.status_message = describe_quarantine_failure(&load_failure);
            }
            QuarantineEntriesPageCommand::EntryOperationFinished(operation_outcome) => {
                self.status_message = operation_outcome
                    .err()
                    .as_ref()
                    .map(describe_quarantine_failure)
                    .unwrap_or_default();
                self.reload_entries(&sender);
            }
        }
    }
}
