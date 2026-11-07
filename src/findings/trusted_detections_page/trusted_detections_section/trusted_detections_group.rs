use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, prelude::FactoryVecDeque,
};

use crate::{
    findings::trusted_detections_page::trusted_detections_section::{
        trust_list_contents::{
            AllowlistEntries, ForeignAllowlistFile, LazaretListReading, TrustListReadFailure,
            TrustListReading, TrustedFileEntry, read_configured_trust_list,
        },
        trust_list_row::{TrustListRow, TrustListRowOutput, TrustRemoval},
    },
    host_services::{
        desktop::locale_formatting::{byte_size_text, exact_local_time_text},
        settings_helper::{
            helper_audit_records::{
                AuditedAction, HelperAuditEntry, Requester, latest_applied_entry,
                newest_helper_audit_entries,
            },
            trust_requests::{TrustChoice, TrustOutcome, request_trust_change, trust_outcome_text},
        },
        systemd_journal::unit_journal_reader::{UnitJournalReadFailure, read_journal_off_thread},
    },
    shared_widgets::{
        host_read_failure_text::unit_journal_failure_text,
        trust_confirmation_dialog::present_trust_confirmation,
    },
};

const AUDIT_ENTRY_LIMIT: usize = 500;

#[derive(Clone, Debug)]
pub enum AuditHistoryReading {
    EntriesRead(Vec<HelperAuditEntry>),
    JournalUnreadable(UnitJournalReadFailure),
}

#[derive(Clone, Debug)]
pub struct TrustedDetectionsSnapshot {
    pub trust_list: TrustListReading,
    pub audit_history: AuditHistoryReading,
}

#[derive(Clone, Debug)]
enum TrustedDetectionsState {
    SnapshotLoading,
    SnapshotShown(TrustedDetectionsSnapshot),
}

impl TrustedDetectionsState {
    fn shows_other_allowlists(&self) -> bool {
        match self {
            Self::SnapshotLoading => false,
            Self::SnapshotShown(snapshot) => match &snapshot.trust_list {
                TrustListReading::ListsRead(trust_list) => {
                    !trust_list.foreign_allowlists.is_empty()
                }
                TrustListReading::FolderMissing => false,
                TrustListReading::FolderUnreadable(_) => true,
            },
        }
    }
}

pub async fn load_trusted_detections() -> TrustedDetectionsSnapshot {
    TrustedDetectionsSnapshot {
        trust_list: read_configured_trust_list().await,
        audit_history: read_journal_off_thread(|| newest_helper_audit_entries(AUDIT_ENTRY_LIMIT))
            .await
            .map_or_else(
                AuditHistoryReading::JournalUnreadable,
                AuditHistoryReading::EntriesRead,
            ),
    }
}

pub fn trust_list_failure_text(read_failure: &TrustListReadFailure) -> String {
    match read_failure {
        TrustListReadFailure::AccessDenied => gettext("Permission denied"),
        TrustListReadFailure::OtherReadFailure { failure_kind } => {
            gettext("Reading failed: {reason}").replace("{reason}", &failure_kind.to_string())
        }
        TrustListReadFailure::ReadingTaskAborted => gettext("Reading stopped before it finished"),
    }
}

fn added_text(audit_history: &AuditHistoryReading, adding_action: &AuditedAction) -> String {
    let audit_entries = match audit_history {
        AuditHistoryReading::EntriesRead(audit_entries) => audit_entries,
        AuditHistoryReading::JournalUnreadable(read_failure) => {
            return gettext("Unknown who added this. {reason}")
                .replace("{reason}", &unit_journal_failure_text(*read_failure));
        }
    };
    match latest_applied_entry(audit_entries, adding_action) {
        Some(audit_entry) => match audit_entry.requester {
            Requester::KnownUser { user_id } => gettext("Added {time} by user {uid}")
                .replace("{time}", &exact_local_time_text(audit_entry.recorded_at))
                .replace("{uid}", &user_id.to_string()),
            Requester::UnknownUser => gettext("Added {time} by an unknown user")
                .replace("{time}", &exact_local_time_text(audit_entry.recorded_at)),
        },
        None => gettext("No record of who added this in the system journal"),
    }
}

pub struct TrustedDetectionsSection {
    trusted_detections_state: TrustedDetectionsState,
    trusted_file_rows: FactoryVecDeque<TrustListRow>,
    ignored_signature_rows: FactoryVecDeque<TrustListRow>,
    foreign_allowlist_rows: FactoryVecDeque<TrustListRow>,
}

#[derive(Debug)]
pub enum TrustedDetectionsSectionInput {
    ReloadRequested,
    RemovalRequested(TrustChoice),
    RemovalConfirmed(TrustChoice),
}

#[derive(Debug)]
pub enum TrustedDetectionsSectionOutput {
    ToastRequested(String),
    TrustListChanged,
}

#[derive(Debug)]
pub enum TrustedDetectionsSectionCommand {
    SnapshotLoaded(TrustedDetectionsSnapshot),
    RemovalFinished(TrustOutcome),
}

fn trust_list_rows(
    sender: &ComponentSender<TrustedDetectionsSection>,
) -> FactoryVecDeque<TrustListRow> {
    FactoryVecDeque::builder()
        .launch(
            gtk::ListBox::builder()
                .css_classes(["boxed-list"])
                .selection_mode(gtk::SelectionMode::None)
                .build(),
        )
        .forward(sender.input_sender(), |row_output| match row_output {
            TrustListRowOutput::RemovalRequested(removal_choice) => {
                TrustedDetectionsSectionInput::RemovalRequested(removal_choice)
            }
        })
}

fn trusted_file_row(
    trusted_file: &TrustedFileEntry,
    audit_history: &AuditHistoryReading,
) -> TrustListRow {
    TrustListRow {
        row_title: trusted_file.sha256_hex.clone(),
        row_subtitle: format!(
            "{} · {}",
            byte_size_text(trusted_file.file_size),
            added_text(
                audit_history,
                &AuditedAction::TrustFile {
                    sha256_hex: trusted_file.sha256_hex.clone(),
                },
            )
        ),
        shows_hash: true,
        needs_attention: false,
        dimmed: false,
        trust_removal: TrustRemoval::RemovableWith(TrustChoice::ForgetTrustedFile {
            sha256_hex: trusted_file.sha256_hex.clone(),
        }),
    }
}

fn ignored_signature_row(
    signature_name: &str,
    audit_history: &AuditHistoryReading,
) -> TrustListRow {
    TrustListRow {
        row_title: signature_name.to_owned(),
        row_subtitle: added_text(
            audit_history,
            &AuditedAction::IgnoreSignature {
                signature_name: signature_name.to_owned(),
            },
        ),
        shows_hash: false,
        needs_attention: false,
        dimmed: false,
        trust_removal: TrustRemoval::RemovableWith(TrustChoice::StopIgnoringSignature {
            signature_name: signature_name.to_owned(),
        }),
    }
}

fn foreign_allowlist_row(foreign_allowlist: &ForeignAllowlistFile) -> TrustListRow {
    TrustListRow {
        row_title: foreign_allowlist.file_name.clone(),
        row_subtitle: match &foreign_allowlist.allowlist_entries {
            AllowlistEntries::EntriesCounted { entry_count } => ngettext(
                "{count} entry, not added through Lazaret",
                "{count} entries, not added through Lazaret",
                u32::try_from(*entry_count).unwrap_or(u32::MAX),
            )
            .replace("{count}", &entry_count.to_string()),
            AllowlistEntries::FileUnreadable(read_failure) => {
                gettext("Entries can't be counted ({reason}), not added through Lazaret")
                    .replace("{reason}", &trust_list_failure_text(read_failure))
            }
        },
        shows_hash: false,
        needs_attention: true,
        dimmed: false,
        trust_removal: TrustRemoval::NotRemovableHere,
    }
}

fn unreadable_row(row_title: String, read_failure: &TrustListReadFailure) -> TrustListRow {
    TrustListRow {
        row_title,
        row_subtitle: trust_list_failure_text(read_failure),
        shows_hash: false,
        needs_attention: true,
        dimmed: false,
        trust_removal: TrustRemoval::NotRemovableHere,
    }
}

fn rows_or_empty_notice(listed_rows: Vec<TrustListRow>, empty_text: String) -> Vec<TrustListRow> {
    if listed_rows.is_empty() {
        vec![TrustListRow::empty_list(empty_text)]
    } else {
        listed_rows
    }
}

fn lazaret_list_rows<ListEntry>(
    list_reading: &LazaretListReading<ListEntry>,
    entry_row: impl Fn(&ListEntry) -> TrustListRow,
    empty_text: String,
) -> Vec<TrustListRow> {
    match list_reading {
        LazaretListReading::ListRead(list_entries) => {
            rows_or_empty_notice(list_entries.iter().map(entry_row).collect(), empty_text)
        }
        LazaretListReading::ListUnreadable(read_failure) => vec![unreadable_row(
            gettext("Lazaret can't read this list"),
            read_failure,
        )],
    }
}

struct TrustListGroupRows {
    trusted_file_rows: Vec<TrustListRow>,
    ignored_signature_rows: Vec<TrustListRow>,
    foreign_allowlist_rows: Vec<TrustListRow>,
}

fn trust_list_group_rows(snapshot: &TrustedDetectionsSnapshot) -> TrustListGroupRows {
    let audit_history = &snapshot.audit_history;
    match &snapshot.trust_list {
        TrustListReading::ListsRead(trust_list) => TrustListGroupRows {
            trusted_file_rows: lazaret_list_rows(
                &trust_list.trusted_files,
                |trusted_file| trusted_file_row(trusted_file, audit_history),
                gettext("No trusted files"),
            ),
            ignored_signature_rows: lazaret_list_rows(
                &trust_list.ignored_signatures,
                |signature_name| ignored_signature_row(signature_name, audit_history),
                gettext("No ignored detections"),
            ),
            foreign_allowlist_rows: trust_list
                .foreign_allowlists
                .iter()
                .map(foreign_allowlist_row)
                .collect(),
        },
        TrustListReading::FolderMissing => TrustListGroupRows {
            trusted_file_rows: vec![TrustListRow::empty_list(gettext("No trusted files"))],
            ignored_signature_rows: vec![TrustListRow::empty_list(gettext(
                "No ignored detections",
            ))],
            foreign_allowlist_rows: Vec::new(),
        },
        TrustListReading::FolderUnreadable(read_failure) => {
            let folder_row = || {
                unreadable_row(
                    gettext("Lazaret can't read the signature folder"),
                    read_failure,
                )
            };
            TrustListGroupRows {
                trusted_file_rows: vec![folder_row()],
                ignored_signature_rows: vec![folder_row()],
                foreign_allowlist_rows: vec![folder_row()],
            }
        }
    }
}

fn replace_rows(shown_rows: &mut FactoryVecDeque<TrustListRow>, listed_rows: Vec<TrustListRow>) {
    let mut row_guard = shown_rows.guard();
    row_guard.clear();
    listed_rows.into_iter().for_each(|listed_row| {
        row_guard.push_back(listed_row);
    });
}

impl TrustedDetectionsSection {
    fn show_snapshot(&mut self, snapshot: TrustedDetectionsSnapshot) {
        let TrustListGroupRows {
            trusted_file_rows,
            ignored_signature_rows,
            foreign_allowlist_rows,
        } = trust_list_group_rows(&snapshot);
        replace_rows(&mut self.trusted_file_rows, trusted_file_rows);
        replace_rows(&mut self.ignored_signature_rows, ignored_signature_rows);
        replace_rows(&mut self.foreign_allowlist_rows, foreign_allowlist_rows);
        self.trusted_detections_state = TrustedDetectionsState::SnapshotShown(snapshot);
    }

    fn reload_snapshot(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            TrustedDetectionsSectionCommand::SnapshotLoaded(load_trusted_detections().await)
        });
    }
}

#[relm4::component(pub)]
impl Component for TrustedDetectionsSection {
    type Init = ();
    type Input = TrustedDetectionsSectionInput;
    type Output = TrustedDetectionsSectionOutput;
    type CommandOutput = TrustedDetectionsSectionCommand;

    view! {
        adw::PreferencesGroup {
            set_title: &gettext("Trusted Detections"),
            set_description: Some(&gettext(
                "ClamAV never reports what is listed here, in any scan on this computer. Every \
                 change needs your administrator password and is recorded in the system journal, \
                 where software running as you can't remove the record.",
            )),
            connect_map => TrustedDetectionsSectionInput::ReloadRequested,

            gtk::Box {
                set_orientation: gtk::Orientation::Vertical,
                set_spacing: 24,

                adw::PreferencesGroup {
                    set_title: &gettext("Trusted Files"),
                    set_description: Some(&gettext(
                        "Files trusted by their SHA-256 hash. Any change to such a file makes \
                         ClamAV check it again.",
                    )),
                    #[local_ref]
                    trusted_file_list -> gtk::ListBox {},
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Ignored Detections"),
                    set_description: Some(&gettext(
                        "Detection names that ClamAV ignores in every file.",
                    )),
                    #[local_ref]
                    ignored_signature_list -> gtk::ListBox {},
                },

                adw::PreferencesGroup {
                    set_title: &gettext("Other Allowlists"),
                    set_description: Some(&gettext(
                        "Allowlist files in the signature folder that Lazaret didn't write. \
                         Check that you or your administrator added them on purpose.",
                    )),
                    #[watch]
                    set_visible: model.trusted_detections_state.shows_other_allowlists(),
                    #[local_ref]
                    foreign_allowlist_list -> gtk::ListBox {},
                },
            },
        }
    }

    fn init(
        _page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            trusted_detections_state: TrustedDetectionsState::SnapshotLoading,
            trusted_file_rows: trust_list_rows(&sender),
            ignored_signature_rows: trust_list_rows(&sender),
            foreign_allowlist_rows: trust_list_rows(&sender),
        };
        let trusted_file_list = model.trusted_file_rows.widget();
        let ignored_signature_list = model.ignored_signature_rows.widget();
        let foreign_allowlist_list = model.foreign_allowlist_rows.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: TrustedDetectionsSectionInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            TrustedDetectionsSectionInput::ReloadRequested => Self::reload_snapshot(&sender),
            TrustedDetectionsSectionInput::RemovalRequested(removal_choice) => {
                present_trust_confirmation(
                    root,
                    removal_choice,
                    sender.input_sender().clone(),
                    TrustedDetectionsSectionInput::RemovalConfirmed,
                );
            }
            TrustedDetectionsSectionInput::RemovalConfirmed(confirmed_choice) => {
                sender.oneshot_command(async move {
                    TrustedDetectionsSectionCommand::RemovalFinished(
                        request_trust_change(confirmed_choice).await,
                    )
                });
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: TrustedDetectionsSectionCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            TrustedDetectionsSectionCommand::SnapshotLoaded(snapshot) => {
                self.show_snapshot(snapshot)
            }
            TrustedDetectionsSectionCommand::RemovalFinished(trust_outcome) => {
                let _page_closed = sender.output(TrustedDetectionsSectionOutput::ToastRequested(
                    trust_outcome_text(&trust_outcome),
                ));
                let _page_closed = sender.output(TrustedDetectionsSectionOutput::TrustListChanged);
                Self::reload_snapshot(&sender);
            }
        }
    }
}

#[cfg(test)]
mod trusted_detections_group_tests {
    use super::*;

    #[test]
    fn an_unreadable_audit_journal_does_not_claim_there_is_no_record() {
        let ignored_action = AuditedAction::IgnoreSignature {
            signature_name: "Win.Test.EICAR_HDB-1".to_owned(),
        };
        let unreadable_text = added_text(
            &AuditHistoryReading::JournalUnreadable(UnitJournalReadFailure::ReadingTaskInterrupted),
            &ignored_action,
        );
        assert!(unreadable_text.starts_with("Unknown who added this."));
        assert!(!unreadable_text.contains("No record"));
        assert_eq!(
            added_text(
                &AuditHistoryReading::EntriesRead(Vec::new()),
                &ignored_action
            ),
            "No record of who added this in the system journal"
        );
    }
}
