use std::time::{Duration, SystemTime};

use bytesize::ByteSize;
use futures::{StreamExt, stream};
use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    host_services::{
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        quarantine_vault::{
            quarantine_entry_database::{QuarantineEntryRecord, QuarantineVault},
            quarantine_file_moves::QuarantineMoveFailure,
        },
        settings_helper::trust_requests::{
            TrustChoice, TrustOutcome, request_trust_change, trust_outcome_text,
        },
    },
    quarantine_page::quarantine_entry_row::{QuarantineEntryRow, QuarantineEntryRowOutput},
    shared_widgets::{
        loading_indicators::{FirstLoad, loading_placeholder_stack},
        page_widget_templates::ClampedPage,
        trust_confirmation_dialog::present_trust_confirmation,
    },
};

pub fn describe_quarantine_failure(move_failure: &QuarantineMoveFailure) -> String {
    match move_failure {
        QuarantineMoveFailure::FileHashMismatch => {
            gettext("File hash mismatch — file may be corrupted")
        }
        QuarantineMoveFailure::BlockedFileOnOtherFilesystem => gettext(
            "On-access scanning blocks this file and it is on another filesystem, so it cannot be \
             moved to quarantine. You can delete it instead.",
        ),
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

const OLD_ENTRY_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub fn entry_matches_search(entry_record: &QuarantineEntryRecord, search_text: &str) -> bool {
    let lowercase_search = search_text.trim().to_lowercase();
    entry_record
        .threat_name
        .to_lowercase()
        .contains(&lowercase_search)
        || entry_record
            .original_path
            .to_string_lossy()
            .to_lowercase()
            .contains(&lowercase_search)
}

pub fn entry_is_older_than(
    entry_record: &QuarantineEntryRecord,
    maximum_age: Duration,
    current_time: SystemTime,
) -> bool {
    humantime::parse_rfc3339_weak(&entry_record.detection_date).is_ok_and(|detection_time| {
        current_time
            .duration_since(detection_time)
            .is_ok_and(|entry_age| entry_age > maximum_age)
    })
}

pub struct QuarantineEntriesPage {
    quarantine_vault: QuarantineVault,
    listed_entries: Vec<QuarantineEntryRecord>,
    search_text: String,
    entry_rows: FactoryVecDeque<QuarantineEntryRow>,
    status_message: String,
    first_load: FirstLoad,
}

#[derive(Debug)]
pub enum QuarantineEntriesPageInput {
    ReloadEntriesRequested,
    RestoreEntryRequested { entry_id: i64 },
    DeleteEntryRequested { entry_id: i64 },
    DeleteEntryConfirmed { entry_id: i64 },
    SearchTextChanged(String),
    ClearOldEntriesRequested,
    ClearOldEntriesConfirmed,
    ToastRequested(String),
    TrustRequested(TrustChoice),
    TrustConfirmed(TrustChoice),
}

#[derive(Debug)]
pub enum QuarantineEntriesPageCommand {
    EntriesLoaded(Result<Vec<QuarantineEntryRecord>, QuarantineMoveFailure>),
    EntryOperationFinished(Result<QuarantineEntryRecord, QuarantineMoveFailure>),
    OldEntriesCleared(Vec<Result<QuarantineEntryRecord, QuarantineMoveFailure>>),
    TrustChangeFinished(TrustOutcome),
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

    fn old_entries(&self) -> Vec<&QuarantineEntryRecord> {
        let current_time = SystemTime::now();
        self.listed_entries
            .iter()
            .filter(|entry_record| entry_is_older_than(entry_record, OLD_ENTRY_AGE, current_time))
            .collect()
    }

    fn total_stored_size(&self) -> String {
        ByteSize::b(
            self.listed_entries
                .iter()
                .map(|entry_record| entry_record.file_size)
                .sum(),
        )
        .to_string()
    }

    fn entry_count_text(&self) -> String {
        ngettext(
            "{count} item",
            "{count} items",
            u32::try_from(self.listed_entries.len()).unwrap_or(u32::MAX),
        )
        .replace("{count}", &self.listed_entries.len().to_string())
    }

    fn show_matching_entries(&mut self) {
        let mut entry_rows_guard = self.entry_rows.guard();
        entry_rows_guard.clear();
        self.listed_entries
            .iter()
            .filter(|entry_record| entry_matches_search(entry_record, &self.search_text))
            .cloned()
            .for_each(|entry_record| {
                entry_rows_guard.push_back(entry_record);
            });
    }

    fn confirm_clearing_old_entries(&self, sender: &ComponentSender<Self>) {
        let old_entry_count = self.old_entries().len();
        let confirmation_dialog = adw::AlertDialog::new(
            Some(&gettext("Clear Old Items?")),
            Some(
                &ngettext(
                    "{count} quarantined file older than 30 days will be permanently deleted.",
                    "{count} quarantined files older than 30 days will be permanently deleted.",
                    u32::try_from(old_entry_count).unwrap_or(u32::MAX),
                )
                .replace("{count}", &old_entry_count.to_string()),
            ),
        );
        confirmation_dialog.add_response("cancel", &gettext("Cancel"));
        confirmation_dialog.add_response("delete", &gettext("Delete"));
        confirmation_dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        confirmation_dialog.set_close_response("cancel");
        let input_sender = sender.input_sender().clone();
        confirmation_dialog.connect_response(Some("delete"), move |_dialog, _response| {
            input_sender.emit(QuarantineEntriesPageInput::ClearOldEntriesConfirmed);
        });
        confirmation_dialog.present(relm4::main_application().active_window().as_ref());
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
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::WindowTitle {
                        set_title: &gettext("Quarantine"),
                        #[watch]
                        set_subtitle: &model.entry_count_text(),
                    },

                    pack_end = &gtk::MenuButton {
                        set_icon_name: "view-more-symbolic",
                        set_tooltip_text: Some(&gettext("More")),
                        #[wrap(Some)]
                        set_popover = &gtk::Popover {
                            gtk::Button {
                                set_label: &gettext("Clear Old Items…"),
                                add_css_class: "flat",
                                #[watch]
                                set_sensitive: !model.old_entries().is_empty(),
                                connect_clicked[sender] => move |clicked_button| {
                                    if let Some(enclosing_popover) = clicked_button
                                        .ancestor(gtk::Popover::static_type())
                                        .and_downcast::<gtk::Popover>()
                                    {
                                        enclosing_popover.popdown();
                                    }
                                    sender.input(QuarantineEntriesPageInput::ClearOldEntriesRequested);
                                },
                            },
                        },
                    },

                    pack_end = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Refresh")),
                        connect_clicked => QuarantineEntriesPageInput::ReloadEntriesRequested,
                    },

                    #[name = "search_toggle"]
                    pack_end = &gtk::ToggleButton {
                        set_icon_name: "system-search-symbolic",
                        set_tooltip_text: Some(&gettext("Search")),
                    },
                },

                #[name = "search_bar"]
                add_top_bar = &gtk::SearchBar {
                    #[wrap(Some)]
                    set_child = &gtk::SearchEntry {
                        set_placeholder_text: Some(&gettext("Search by threat name or path")),
                        connect_search_changed[sender] => move |search_entry| {
                            sender.input(QuarantineEntriesPageInput::SearchTextChanged(
                                search_entry.text().to_string(),
                            ));
                        },
                    },
                },

                #[wrap(Some)]
                #[template]
                set_content = &ClampedPage {
                    #[template_child]
                    page_content {
                        adw::PreferencesGroup {
                            set_title: &gettext("Quarantine Storage"),
                            set_description: Some(&gettext("Detected threats isolated from your system. Expand an entry to check its reputation.")),

                            adw::ActionRow {
                                set_title: &gettext("Total Size"),
                                #[watch]
                                set_subtitle: &model.total_stored_size(),
                                add_prefix = &gtk::Image { set_icon_name: Some("drive-harddisk-symbolic") },
                            },
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

                        #[local_ref]
                        entry_list -> gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                            #[wrap(Some)]
                            #[local_ref]
                            set_placeholder = placeholder_stack -> gtk::Stack {
                                #[watch]
                                set_visible_child_name: model.first_load.shown_page_name(),
                            },
                        },
                    },
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
                QuarantineEntryRowOutput::RestoreEntry { entry_id } => {
                    QuarantineEntriesPageInput::RestoreEntryRequested { entry_id }
                }
                QuarantineEntryRowOutput::DeleteEntry { entry_id } => {
                    QuarantineEntriesPageInput::DeleteEntryRequested { entry_id }
                }
                QuarantineEntryRowOutput::ShowToast(toast_message) => {
                    QuarantineEntriesPageInput::ToastRequested(toast_message)
                }
                QuarantineEntryRowOutput::TrustEntry(trust_choice) => {
                    QuarantineEntriesPageInput::TrustRequested(trust_choice)
                }
            });
        let model = Self {
            quarantine_vault,
            listed_entries: Vec::new(),
            search_text: String::new(),
            entry_rows,
            status_message: String::new(),
            first_load: FirstLoad::StillLoading,
        };
        model.reload_entries(&sender);
        let entry_list = model.entry_rows.widget();
        let placeholder_stack = &loading_placeholder_stack(
            &gettext("Loading quarantine…"),
            &adw::StatusPage::builder()
                .css_classes(["compact"])
                .icon_name("security-high-symbolic")
                .title(gettext("Quarantine is empty"))
                .description(gettext("Threats you quarantine will appear here"))
                .build(),
        );
        let widgets = view_output!();
        widgets
            .search_toggle
            .bind_property("active", &widgets.search_bar, "search-mode-enabled")
            .bidirectional()
            .sync_create()
            .build();
        widgets.search_bar.set_key_capture_widget(Some(&root));
        let search_shortcuts = gtk::ShortcutController::new();
        search_shortcuts.set_scope(gtk::ShortcutScope::Managed);
        let shortcut_toggle = widgets.search_toggle.clone();
        search_shortcuts.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>f"),
            Some(gtk::CallbackAction::new(
                move |_shortcut_widget, _arguments| {
                    shortcut_toggle.set_active(true);
                    gtk::glib::Propagation::Stop
                },
            )),
        ));
        root.add_controller(search_shortcuts);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: QuarantineEntriesPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        let quarantine_vault = self.quarantine_vault.clone();
        let command_sender = sender.command_sender().clone();
        match page_input {
            QuarantineEntriesPageInput::ToastRequested(toast_message) => {
                root.add_toast(
                    adw::Toast::builder()
                        .title(toast_message)
                        .use_markup(false)
                        .build(),
                );
            }
            QuarantineEntriesPageInput::TrustRequested(trust_choice) => {
                present_trust_confirmation(
                    root,
                    trust_choice,
                    sender.input_sender().clone(),
                    QuarantineEntriesPageInput::TrustConfirmed,
                );
            }
            QuarantineEntriesPageInput::TrustConfirmed(confirmed_choice) => {
                sender.oneshot_command(async move {
                    QuarantineEntriesPageCommand::TrustChangeFinished(
                        request_trust_change(confirmed_choice).await,
                    )
                });
            }
            QuarantineEntriesPageInput::ReloadEntriesRequested => self.reload_entries(&sender),
            QuarantineEntriesPageInput::RestoreEntryRequested { entry_id } => {
                relm4::spawn(async move {
                    let _page_closed =
                        command_sender.send(QuarantineEntriesPageCommand::EntryOperationFinished(
                            quarantine_vault.restore_quarantined_file(entry_id).await,
                        ));
                });
            }
            QuarantineEntriesPageInput::SearchTextChanged(search_text) => {
                self.search_text = search_text;
                self.show_matching_entries();
            }
            QuarantineEntriesPageInput::ClearOldEntriesRequested => {
                self.confirm_clearing_old_entries(&sender);
            }
            QuarantineEntriesPageInput::ClearOldEntriesConfirmed => {
                let old_entry_ids = self
                    .old_entries()
                    .into_iter()
                    .map(|entry_record| entry_record.entry_id)
                    .collect::<Vec<_>>();
                relm4::spawn(async move {
                    let deletion_outcomes = stream::iter(old_entry_ids)
                        .then(|entry_id| {
                            let quarantine_vault = quarantine_vault.clone();
                            async move { quarantine_vault.delete_quarantined_file(entry_id).await }
                        })
                        .collect::<Vec<_>>()
                        .await;
                    let _page_closed = command_sender.send(
                        QuarantineEntriesPageCommand::OldEntriesCleared(deletion_outcomes),
                    );
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
        root: &Self::Root,
    ) {
        match page_command {
            QuarantineEntriesPageCommand::TrustChangeFinished(trust_outcome) => {
                root.add_toast(
                    adw::Toast::builder()
                        .title(trust_outcome_text(&trust_outcome))
                        .use_markup(false)
                        .build(),
                );
            }
            QuarantineEntriesPageCommand::EntriesLoaded(Ok(listed_entries)) => {
                self.first_load = FirstLoad::LoadFinished;
                self.listed_entries = listed_entries;
                self.show_matching_entries();
            }
            QuarantineEntriesPageCommand::EntriesLoaded(Err(load_failure)) => {
                self.first_load = FirstLoad::LoadFinished;
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
            QuarantineEntriesPageCommand::OldEntriesCleared(deletion_outcomes) => {
                self.status_message = deletion_outcomes
                    .iter()
                    .filter_map(|deletion_outcome| deletion_outcome.as_ref().err())
                    .map(describe_quarantine_failure)
                    .collect::<Vec<_>>()
                    .join("\n");
                self.reload_entries(&sender);
            }
        }
    }
}

#[cfg(test)]
mod quarantine_entries_page_tests {
    use std::path::PathBuf;

    use super::*;

    fn entry_detected_on(detection_date: &str) -> QuarantineEntryRecord {
        QuarantineEntryRecord {
            entry_id: 1,
            original_path: PathBuf::from("/home/user/Downloads/Invoice.exe"),
            quarantine_path: PathBuf::from("/vault/payload"),
            threat_name: "Win.Trojan.Agent".to_owned(),
            detection_date: detection_date.to_owned(),
            file_size: 1,
            file_hash: String::new(),
            original_permissions: 0o644,
        }
    }

    #[test]
    fn search_matches_threat_names_and_paths_case_insensitively() {
        let entry_record = entry_detected_on("2026-11-01T00:00:00Z");
        assert!(entry_matches_search(&entry_record, "trojan"));
        assert!(entry_matches_search(&entry_record, " invoice "));
        assert!(entry_matches_search(&entry_record, ""));
        assert!(!entry_matches_search(&entry_record, "ransom"));
    }

    #[test]
    fn age_is_compared_with_the_detection_date() {
        let current_time =
            humantime::parse_rfc3339("2026-11-05T00:00:00Z").expect("fixture current time");
        assert!(entry_is_older_than(
            &entry_detected_on("2026-10-01T00:00:00.000Z"),
            OLD_ENTRY_AGE,
            current_time
        ));
        assert!(!entry_is_older_than(
            &entry_detected_on("2026-11-01T00:00:00.000Z"),
            OLD_ENTRY_AGE,
            current_time
        ));
    }

    #[test]
    fn an_unparseable_date_is_never_treated_as_old() {
        assert!(!entry_is_older_than(
            &entry_detected_on("not a date"),
            OLD_ENTRY_AGE,
            SystemTime::now()
        ));
    }
}
