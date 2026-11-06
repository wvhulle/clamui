use std::collections::HashMap;

use futures::{StreamExt, stream};
use gettextrs::{gettext, ngettext};
use jiff::{SignedDuration, Timestamp};
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, actions::ActionName, adw,
    adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    application_window::application_actions::PreferencesPageAction,
    host_services::{
        clamav_programs::false_positive_submission::{
            FalsePositiveReport, SubmissionOutcome, SubmittedContent, submission_outcome_text,
            submit_false_positive,
        },
        clamav_scanner::{
            content_verdict::{ContentVerdict, scan_content_with_current_signatures},
            scanner_output_parser::sanitize_scanner_line,
        },
        desktop::locale_formatting::byte_size_text,
        quarantine_vault::{
            quarantine_entry_database::{
                QuarantineEntryRecord, QuarantineVault, StoredDetectionDate,
            },
            quarantine_file_moves::QuarantineMoveFailure,
        },
        settings_helper::trust_requests::{
            TrustChoice, TrustOutcome, request_trust_change, trust_outcome_text,
        },
    },
    preferences_dialog::preferences_dialog_component::PreferencesPageName,
    quarantine_page::quarantine_entry_row::{
        QuarantineEntryRow, QuarantineEntryRowInput, QuarantineEntryRowOutput, RowRecheckState,
    },
    shared_widgets::{
        awaited_dialogs::{alert_response, deliver_local_outcome},
        component_streams::{RunningStream, run_stream, run_stream_to_completion},
        false_positive_report_dialog::{ReportedDetection, present_false_positive_report},
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

const OLD_ENTRY_AGE: SignedDuration = SignedDuration::from_hours(30 * 24);

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
    maximum_age: SignedDuration,
    current_time: Timestamp,
) -> bool {
    match entry_record.detection_date {
        StoredDetectionDate::DetectedAt(detected_at) => {
            current_time.duration_since(detected_at) > maximum_age
        }
        StoredDetectionDate::UnreadableText(_) => false,
    }
}

pub struct QuarantineEntriesPage {
    quarantine_vault: QuarantineVault,
    listed_entries: Vec<QuarantineEntryRecord>,
    search_text: String,
    entry_rows: FactoryVecDeque<QuarantineEntryRow>,
    status_message: String,
    first_load: FirstLoad,
    search_mode_enabled: bool,
    toaster: Toaster,
    recheck_states: HashMap<i64, RowRecheckState>,
    recheck_progress: RecheckProgress,
}

#[derive(Debug)]
enum RecheckProgress {
    RecheckIdle,
    RecheckRunning { _recheck_stream: RunningStream },
}

#[derive(Debug)]
pub enum QuarantineEntriesPageInput {
    ReloadEntriesRequested,
    RestoreEntryRequested { entry_id: i64 },
    RestoreEntryConfirmed { entry_id: i64 },
    RecheckAllRequested,
    DeleteEntryRequested { entry_id: i64 },
    DeleteEntryConfirmed { entry_id: i64 },
    SearchTextChanged(String),
    SearchModeToggled(bool),
    ClearOldEntriesRequested,
    ClearOldEntriesConfirmed,
    HashCopyRequested(String),
    OnlineLookupsRequested,
    ReportLinkRequested(String),
    TrustRequested(TrustChoice),
    TrustConfirmed(TrustChoice),
    FalsePositiveReportRequested(ReportedDetection),
    FalsePositiveReportConfirmed(FalsePositiveReport),
}

#[derive(Debug)]
pub enum QuarantineEntriesPageCommand {
    EntriesLoaded(Result<Vec<QuarantineEntryRecord>, QuarantineMoveFailure>),
    EntryOperationFinished(Result<QuarantineEntryRecord, QuarantineMoveFailure>),
    OldEntriesCleared(Vec<Result<QuarantineEntryRecord, QuarantineMoveFailure>>),
    TrustChangeFinished(TrustOutcome),
    FalsePositiveReportFinished(SubmissionOutcome),
    RestoreCheckFinished {
        entry_id: i64,
        content_verdict: ContentVerdict,
    },
    RecheckVerdictArrived {
        entry_id: i64,
        content_verdict: ContentVerdict,
    },
    RecheckFinished,
}

async fn verdict_for_entry(quarantine_vault: &QuarantineVault, entry_id: i64) -> ContentVerdict {
    match quarantine_vault.read_payload_plaintext(entry_id).await {
        Ok(payload_plaintext) => scan_content_with_current_signatures(payload_plaintext).await,
        Err(read_failure) => ContentVerdict::VerdictUnavailable {
            failure_text: read_failure.to_string(),
        },
    }
}

struct RestoreConfirmationText {
    heading: String,
    verdict_text: String,
    confirm_label: String,
    restores_detected_file: bool,
}

fn restore_confirmation_text(content_verdict: &ContentVerdict) -> RestoreConfirmationText {
    match content_verdict {
        ContentVerdict::NoLongerDetected => RestoreConfirmationText {
            heading: gettext("Restore This File?"),
            verdict_text: gettext("ClamAV no longer detects this file with today's signatures."),
            confirm_label: gettext("Restore"),
            restores_detected_file: false,
        },
        ContentVerdict::StillDetected { detection_name } => RestoreConfirmationText {
            heading: gettext("Restore a File ClamAV Still Detects?"),
            verdict_text: gettext(
                "ClamAV still detects this file as {detection} with today's signatures. Only \
                 restore it if you are sure it is a false positive, and consider trusting it \
                 first.",
            )
            .replace("{detection}", detection_name),
            confirm_label: gettext("Restore Anyway"),
            restores_detected_file: true,
        },
        ContentVerdict::VerdictUnavailable { failure_text } => RestoreConfirmationText {
            heading: gettext("Restore an Unchecked File?"),
            verdict_text: gettext(
                "The file could not be checked again before restoring it: {error}",
            )
            .replace("{error}", failure_text),
            confirm_label: gettext("Restore Anyway"),
            restores_detected_file: true,
        },
    }
}

fn restore_destination_note(entry_record: &QuarantineEntryRecord) -> String {
    let home_directory = gtk::glib::home_dir();
    if entry_record.original_path.starts_with(&home_directory) {
        String::new()
    } else {
        gettext("This location is outside your home folder.")
    }
}

fn plain_text_toast(toast_text: &str) -> adw::Toast {
    adw::Toast::builder()
        .title(toast_text)
        .use_markup(false)
        .build()
}

impl QuarantineEntriesPage {
    fn send_recheck_states(&self) {
        self.entry_rows
            .iter()
            .enumerate()
            .for_each(|(row_position, entry_row)| {
                self.entry_rows.send(
                    row_position,
                    QuarantineEntryRowInput::RecheckStateChanged(
                        self.recheck_states
                            .get(&entry_row.entry_id())
                            .cloned()
                            .unwrap_or(RowRecheckState::NotRechecked),
                    ),
                );
            });
    }

    fn present_restore_confirmation(
        &self,
        entry_id: i64,
        content_verdict: &ContentVerdict,
        root: &adw::ToastOverlay,
        sender: &ComponentSender<Self>,
    ) {
        let Some(entry_record) = self
            .listed_entries
            .iter()
            .find(|listed_entry| listed_entry.entry_id == entry_id)
        else {
            return;
        };
        let RestoreConfirmationText {
            heading,
            verdict_text,
            confirm_label,
            restores_detected_file,
        } = restore_confirmation_text(content_verdict);
        let restore_dialog = adw::AlertDialog::new(
            Some(&heading),
            Some(&[verdict_text, gettext("The file goes back to:")].join("\n\n")),
        );
        let destination_label = gtk::Label::builder()
            .label(sanitize_scanner_line(
                &entry_record.original_path.to_string_lossy(),
            ))
            .use_markup(false)
            .selectable(true)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::Char)
            .css_classes(["monospace", "card"])
            .build();
        let destination_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
        destination_box.append(&destination_label);
        let destination_note = restore_destination_note(entry_record);
        if !destination_note.is_empty() {
            destination_box.append(
                &gtk::Label::builder()
                    .label(destination_note)
                    .wrap(true)
                    .css_classes(["warning"])
                    .build(),
            );
        }
        restore_dialog.set_extra_child(Some(&destination_box));
        restore_dialog.add_response("cancel", &gettext("Cancel"));
        restore_dialog.add_response("restore", &confirm_label);
        restore_dialog.set_response_appearance(
            "restore",
            if restores_detected_file {
                adw::ResponseAppearance::Destructive
            } else {
                adw::ResponseAppearance::Suggested
            },
        );
        restore_dialog.set_default_response(Some("cancel"));
        restore_dialog.set_close_response("cancel");
        deliver_local_outcome(
            sender.input_sender().clone(),
            alert_response(restore_dialog, root.clone().upcast()),
            move |chosen_response| {
                (chosen_response == "restore")
                    .then_some(QuarantineEntriesPageInput::RestoreEntryConfirmed { entry_id })
            },
        );
    }

    fn start_recheck(&mut self, sender: &ComponentSender<Self>) {
        if matches!(
            self.recheck_progress,
            RecheckProgress::RecheckRunning { .. }
        ) || self.listed_entries.is_empty()
        {
            return;
        }
        let rechecked_ids = self
            .listed_entries
            .iter()
            .map(|listed_entry| listed_entry.entry_id)
            .collect::<Vec<_>>();
        rechecked_ids.iter().for_each(|entry_id| {
            self.recheck_states
                .insert(*entry_id, RowRecheckState::Rechecking);
        });
        self.send_recheck_states();
        let quarantine_vault = self.quarantine_vault.clone();
        let recheck_commands = stream::iter(rechecked_ids)
            .then(move |entry_id| {
                let quarantine_vault = quarantine_vault.clone();
                async move {
                    QuarantineEntriesPageCommand::RecheckVerdictArrived {
                        entry_id,
                        content_verdict: verdict_for_entry(&quarantine_vault, entry_id).await,
                    }
                }
            })
            .chain(stream::iter([
                QuarantineEntriesPageCommand::RecheckFinished,
            ]));
        self.recheck_progress = RecheckProgress::RecheckRunning {
            _recheck_stream: run_stream(sender, recheck_commands),
        };
    }

    fn reload_entries(&self, sender: &ComponentSender<Self>) {
        let quarantine_vault = self.quarantine_vault.clone();
        sender.oneshot_command(async move {
            QuarantineEntriesPageCommand::EntriesLoaded(
                quarantine_vault.list_quarantine_entries().await,
            )
        });
    }

    fn old_entries(&self) -> Vec<&QuarantineEntryRecord> {
        let current_time = Timestamp::now();
        self.listed_entries
            .iter()
            .filter(|entry_record| entry_is_older_than(entry_record, OLD_ENTRY_AGE, current_time))
            .collect()
    }

    fn total_stored_size(&self) -> String {
        byte_size_text(
            self.listed_entries
                .iter()
                .map(|entry_record| entry_record.file_size)
                .sum(),
        )
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
        drop(entry_rows_guard);
        self.send_recheck_states();
    }

    fn confirm_clearing_old_entries(
        &self,
        root: &adw::ToastOverlay,
        sender: &ComponentSender<Self>,
    ) {
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
        deliver_local_outcome(
            sender.input_sender().clone(),
            alert_response(confirmation_dialog, root.clone().upcast()),
            |chosen_response| {
                (chosen_response == "delete")
                    .then_some(QuarantineEntriesPageInput::ClearOldEntriesConfirmed)
            },
        );
    }

    fn confirm_entry_deletion(
        &self,
        entry_id: i64,
        root: &adw::ToastOverlay,
        sender: &ComponentSender<Self>,
    ) {
        let confirmation_dialog = adw::AlertDialog::new(
            Some(&gettext("Delete Quarantined File?")),
            Some(&gettext("The file will be permanently deleted.")),
        );
        confirmation_dialog.add_response("cancel", &gettext("Cancel"));
        confirmation_dialog.add_response("delete", &gettext("Delete"));
        confirmation_dialog.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
        deliver_local_outcome(
            sender.input_sender().clone(),
            alert_response(confirmation_dialog, root.clone().upcast()),
            move |chosen_response| {
                (chosen_response == "delete")
                    .then_some(QuarantineEntriesPageInput::DeleteEntryConfirmed { entry_id })
            },
        );
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
            add_controller = gtk::ShortcutController {
                set_scope: gtk::ShortcutScope::Managed,
                add_shortcut: gtk::Shortcut::new(
                    gtk::ShortcutTrigger::parse_string("<Control>f"),
                    Some(gtk::CallbackAction::new({
                        let shortcut_sender = sender.input_sender().clone();
                        move |_shortcut_widget, _arguments| {
                            shortcut_sender.emit(QuarantineEntriesPageInput::SearchModeToggled(true));
                            gtk::glib::Propagation::Stop
                        }
                    })),
                ),
            },

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
                        set_label: &gettext("Check Again"),
                        set_tooltip_text: Some(&gettext("Scan every quarantined file with the current signatures")),
                        #[watch]
                        set_sensitive: matches!(model.recheck_progress, RecheckProgress::RecheckIdle)
                            && !model.listed_entries.is_empty(),
                        connect_clicked => QuarantineEntriesPageInput::RecheckAllRequested,
                    },

                    pack_end = &gtk::Button {
                        set_icon_name: "view-refresh-symbolic",
                        set_tooltip_text: Some(&gettext("Refresh")),
                        connect_clicked => QuarantineEntriesPageInput::ReloadEntriesRequested,
                    },

                    pack_end = &gtk::ToggleButton {
                        set_icon_name: "system-search-symbolic",
                        set_tooltip_text: Some(&gettext("Search")),
                        #[watch]
                        #[block_signal(search_toggle_handler)]
                        set_active: model.search_mode_enabled,
                        connect_toggled[sender] => move |search_toggle| {
                            sender.input(QuarantineEntriesPageInput::SearchModeToggled(search_toggle.is_active()));
                        } @search_toggle_handler,
                    },
                },

                add_top_bar = &gtk::SearchBar {
                    set_key_capture_widget: Some(&root),
                    #[watch]
                    #[block_signal(search_bar_handler)]
                    set_search_mode: model.search_mode_enabled,
                    connect_search_mode_enabled_notify[sender] => move |search_bar| {
                        sender.input(QuarantineEntriesPageInput::SearchModeToggled(search_bar.is_search_mode()));
                    } @search_bar_handler,

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
                QuarantineEntryRowOutput::RestoreRequested { entry_id } => {
                    QuarantineEntriesPageInput::RestoreEntryRequested { entry_id }
                }
                QuarantineEntryRowOutput::DeletionRequested { entry_id } => {
                    QuarantineEntriesPageInput::DeleteEntryRequested { entry_id }
                }
                QuarantineEntryRowOutput::HashCopyRequested(file_hash) => {
                    QuarantineEntriesPageInput::HashCopyRequested(file_hash)
                }
                QuarantineEntryRowOutput::OnlineLookupsRequested => {
                    QuarantineEntriesPageInput::OnlineLookupsRequested
                }
                QuarantineEntryRowOutput::ReportLinkRequested(report_url) => {
                    QuarantineEntriesPageInput::ReportLinkRequested(report_url)
                }
                QuarantineEntryRowOutput::TrustRequested(trust_choice) => {
                    QuarantineEntriesPageInput::TrustRequested(trust_choice)
                }
                QuarantineEntryRowOutput::FalsePositiveReportRequested(reported_detection) => {
                    QuarantineEntriesPageInput::FalsePositiveReportRequested(reported_detection)
                }
            });
        let model = Self {
            quarantine_vault,
            listed_entries: Vec::new(),
            search_text: String::new(),
            entry_rows,
            status_message: String::new(),
            first_load: FirstLoad::StillLoading,
            search_mode_enabled: false,
            toaster: Toaster::new(&root),
            recheck_states: HashMap::new(),
            recheck_progress: RecheckProgress::RecheckIdle,
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
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: QuarantineEntriesPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        let quarantine_vault = self.quarantine_vault.clone();
        match page_input {
            QuarantineEntriesPageInput::HashCopyRequested(file_hash) => {
                root.clipboard().set_text(&file_hash);
                self.toaster
                    .add_toast(plain_text_toast(&gettext("Hash copied to clipboard")));
            }
            QuarantineEntriesPageInput::OnlineLookupsRequested => {
                let _action_missing = root.activate_action(
                    &PreferencesPageAction::action_name(),
                    Some(&PreferencesPageName::OnlineLookups.page_name().to_variant()),
                );
            }
            QuarantineEntriesPageInput::ReportLinkRequested(report_url) => {
                gtk::UriLauncher::new(&report_url).launch(
                    root.root().and_downcast::<gtk::Window>().as_ref(),
                    gtk::gio::Cancellable::NONE,
                    |_launch_outcome| {},
                );
            }
            QuarantineEntriesPageInput::SearchModeToggled(search_mode_enabled) => {
                self.search_mode_enabled = search_mode_enabled;
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
            QuarantineEntriesPageInput::FalsePositiveReportRequested(reported_detection) => {
                present_false_positive_report(
                    root,
                    reported_detection,
                    sender.input_sender().clone(),
                    QuarantineEntriesPageInput::FalsePositiveReportConfirmed,
                );
            }
            QuarantineEntriesPageInput::FalsePositiveReportConfirmed(false_positive_report) => {
                let quarantine_vault = self.quarantine_vault.clone();
                sender.oneshot_command(async move {
                    let submission_outcome = match &false_positive_report.submitted_content {
                        SubmittedContent::QuarantinedEntry { entry_id } => {
                            match quarantine_vault.read_payload_plaintext(*entry_id).await {
                                Ok(payload_plaintext) => {
                                    submit_false_positive(false_positive_report, payload_plaintext)
                                        .await
                                }
                                Err(read_failure) => SubmissionOutcome::SubmissionFailed {
                                    failure_text: read_failure.to_string(),
                                },
                            }
                        }
                        SubmittedContent::DetectedFile { .. } => {
                            SubmissionOutcome::SubmissionFailed {
                                failure_text: gettext("report it from the scan results"),
                            }
                        }
                    };
                    QuarantineEntriesPageCommand::FalsePositiveReportFinished(submission_outcome)
                });
            }
            QuarantineEntriesPageInput::ReloadEntriesRequested => self.reload_entries(&sender),
            QuarantineEntriesPageInput::RestoreEntryRequested { entry_id } => {
                self.recheck_states
                    .insert(entry_id, RowRecheckState::Rechecking);
                self.send_recheck_states();
                sender.oneshot_command(async move {
                    QuarantineEntriesPageCommand::RestoreCheckFinished {
                        entry_id,
                        content_verdict: verdict_for_entry(&quarantine_vault, entry_id).await,
                    }
                });
            }
            QuarantineEntriesPageInput::RecheckAllRequested => self.start_recheck(&sender),
            QuarantineEntriesPageInput::RestoreEntryConfirmed { entry_id } => {
                run_stream_to_completion(
                    &sender,
                    stream::once(async move {
                        QuarantineEntriesPageCommand::EntryOperationFinished(
                            quarantine_vault.restore_quarantined_file(entry_id).await,
                        )
                    }),
                );
            }
            QuarantineEntriesPageInput::SearchTextChanged(search_text) => {
                self.search_text = search_text;
                self.show_matching_entries();
            }
            QuarantineEntriesPageInput::ClearOldEntriesRequested => {
                self.confirm_clearing_old_entries(root, &sender);
            }
            QuarantineEntriesPageInput::ClearOldEntriesConfirmed => {
                let old_entry_ids = self
                    .old_entries()
                    .into_iter()
                    .map(|entry_record| entry_record.entry_id)
                    .collect::<Vec<_>>();
                run_stream_to_completion(
                    &sender,
                    stream::once(async move {
                        QuarantineEntriesPageCommand::OldEntriesCleared(
                            stream::iter(old_entry_ids)
                                .then(|entry_id| {
                                    let quarantine_vault = quarantine_vault.clone();
                                    async move {
                                        quarantine_vault.delete_quarantined_file(entry_id).await
                                    }
                                })
                                .collect::<Vec<_>>()
                                .await,
                        )
                    }),
                );
            }
            QuarantineEntriesPageInput::DeleteEntryRequested { entry_id } => {
                self.confirm_entry_deletion(entry_id, root, &sender);
            }
            QuarantineEntriesPageInput::DeleteEntryConfirmed { entry_id } => {
                run_stream_to_completion(
                    &sender,
                    stream::once(async move {
                        QuarantineEntriesPageCommand::EntryOperationFinished(
                            quarantine_vault.delete_quarantined_file(entry_id).await,
                        )
                    }),
                );
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
            QuarantineEntriesPageCommand::RestoreCheckFinished {
                entry_id,
                content_verdict,
            } => {
                self.recheck_states.insert(
                    entry_id,
                    RowRecheckState::Rechecked(content_verdict.clone()),
                );
                self.send_recheck_states();
                self.present_restore_confirmation(entry_id, &content_verdict, root, &sender);
            }
            QuarantineEntriesPageCommand::RecheckVerdictArrived {
                entry_id,
                content_verdict,
            } => {
                self.recheck_states
                    .insert(entry_id, RowRecheckState::Rechecked(content_verdict));
                self.send_recheck_states();
            }
            QuarantineEntriesPageCommand::RecheckFinished => {
                self.recheck_progress = RecheckProgress::RecheckIdle;
                let cleared_count = self
                    .recheck_states
                    .values()
                    .filter(|recheck_state| {
                        **recheck_state
                            == RowRecheckState::Rechecked(ContentVerdict::NoLongerDetected)
                    })
                    .count();
                self.toaster
                    .add_toast(plain_text_toast(&if cleared_count == 0 {
                        gettext("Every quarantined file is still detected or couldn't be checked")
                    } else {
                        ngettext(
                            "{count} quarantined file is no longer detected. Check it before \
                             restoring it.",
                            "{count} quarantined files are no longer detected. Check them before \
                             restoring them.",
                            u32::try_from(cleared_count).unwrap_or(u32::MAX),
                        )
                        .replace("{count}", &cleared_count.to_string())
                    }));
            }
            QuarantineEntriesPageCommand::FalsePositiveReportFinished(submission_outcome) => {
                self.toaster
                    .add_toast(plain_text_toast(&submission_outcome_text(
                        &submission_outcome,
                    )));
            }
            QuarantineEntriesPageCommand::TrustChangeFinished(trust_outcome) => {
                self.toaster
                    .add_toast(plain_text_toast(&trust_outcome_text(&trust_outcome)));
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
            detection_date: StoredDetectionDate::from(detection_date.to_owned()),
            file_size: bytesize::ByteSize::b(1),
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
        let current_time: Timestamp = "2026-11-05T00:00:00Z"
            .parse()
            .expect("fixture current time");
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
            Timestamp::now()
        ));
    }
}
