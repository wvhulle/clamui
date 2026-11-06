use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentParts, ComponentSender, abstractions::Toaster, adw, adw::prelude::*, gtk,
    prelude::FactoryVecDeque,
};

use crate::{
    host_services::{
        clamav_programs::database_directory_status::configured_database_directory,
        desktop::locale_formatting::{byte_size_text, exact_local_time_text},
        settings_helper::{
            helper_audit_records::{
                AuditedAction, HelperAuditEntry, Requester, latest_applied_entry,
                newest_helper_audit_entries,
            },
            trust_requests::{TrustChoice, TrustOutcome, request_trust_change, trust_outcome_text},
        },
    },
    protection_page::trusted_detections_page::{
        trust_list_contents::{
            ForeignAllowlistFile, TrustListContents, TrustedFileEntry, read_trust_list_contents,
        },
        trust_list_row::{TrustListRow, TrustListRowOutput, TrustRemoval},
    },
    shared_widgets::trust_confirmation_dialog::present_trust_confirmation,
};

const AUDIT_ENTRY_LIMIT: usize = 500;

#[derive(Clone, Debug, Default)]
pub struct TrustedDetectionsSnapshot {
    pub trust_list: TrustListContents,
    pub audit_entries: Vec<HelperAuditEntry>,
}

pub async fn load_trusted_detections() -> TrustedDetectionsSnapshot {
    tokio::task::spawn_blocking(|| TrustedDetectionsSnapshot {
        trust_list: read_trust_list_contents(&configured_database_directory()),
        audit_entries: newest_helper_audit_entries(AUDIT_ENTRY_LIMIT).unwrap_or_default(),
    })
    .await
    .unwrap_or_default()
}

fn added_text(audit_entries: &[HelperAuditEntry], adding_action: &AuditedAction) -> String {
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

pub struct TrustedDetectionsPage {
    snapshot: TrustedDetectionsSnapshot,
    trusted_file_rows: FactoryVecDeque<TrustListRow>,
    ignored_signature_rows: FactoryVecDeque<TrustListRow>,
    foreign_allowlist_rows: FactoryVecDeque<TrustListRow>,
    toaster: Toaster,
}

#[derive(Debug)]
pub enum TrustedDetectionsPageInput {
    RemovalRequested(TrustChoice),
    RemovalConfirmed(TrustChoice),
}

#[derive(Debug)]
pub enum TrustedDetectionsPageCommand {
    SnapshotLoaded(TrustedDetectionsSnapshot),
    RemovalFinished(TrustOutcome),
}

fn trust_list_rows(
    sender: &ComponentSender<TrustedDetectionsPage>,
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
                TrustedDetectionsPageInput::RemovalRequested(removal_choice)
            }
        })
}

fn trusted_file_row(
    trusted_file: &TrustedFileEntry,
    audit_entries: &[HelperAuditEntry],
) -> TrustListRow {
    TrustListRow {
        row_title: trusted_file.sha256_hex.clone(),
        row_subtitle: format!(
            "{} · {}",
            byte_size_text(trusted_file.file_size),
            added_text(
                audit_entries,
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

fn ignored_signature_row(signature_name: &str, audit_entries: &[HelperAuditEntry]) -> TrustListRow {
    TrustListRow {
        row_title: signature_name.to_owned(),
        row_subtitle: added_text(
            audit_entries,
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
        row_subtitle: ngettext(
            "{count} entry, not added through Lazaret",
            "{count} entries, not added through Lazaret",
            u32::try_from(foreign_allowlist.entry_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &foreign_allowlist.entry_count.to_string()),
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

fn replace_rows(shown_rows: &mut FactoryVecDeque<TrustListRow>, listed_rows: Vec<TrustListRow>) {
    let mut row_guard = shown_rows.guard();
    row_guard.clear();
    listed_rows.into_iter().for_each(|listed_row| {
        row_guard.push_back(listed_row);
    });
}

impl TrustedDetectionsPage {
    fn show_snapshot(&mut self, snapshot: TrustedDetectionsSnapshot) {
        let TrustedDetectionsSnapshot {
            trust_list,
            audit_entries,
        } = &snapshot;
        replace_rows(
            &mut self.trusted_file_rows,
            rows_or_empty_notice(
                trust_list
                    .trusted_files
                    .iter()
                    .map(|trusted_file| trusted_file_row(trusted_file, audit_entries))
                    .collect(),
                gettext("No trusted files"),
            ),
        );
        replace_rows(
            &mut self.ignored_signature_rows,
            rows_or_empty_notice(
                trust_list
                    .ignored_signatures
                    .iter()
                    .map(|signature_name| ignored_signature_row(signature_name, audit_entries))
                    .collect(),
                gettext("No ignored detections"),
            ),
        );
        replace_rows(
            &mut self.foreign_allowlist_rows,
            trust_list
                .foreign_allowlists
                .iter()
                .map(foreign_allowlist_row)
                .collect(),
        );
        self.snapshot = snapshot;
    }

    fn reload_snapshot(sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            TrustedDetectionsPageCommand::SnapshotLoaded(load_trusted_detections().await)
        });
    }
}

#[relm4::component(pub)]
impl Component for TrustedDetectionsPage {
    type Init = ();
    type Input = TrustedDetectionsPageInput;
    type Output = ();
    type CommandOutput = TrustedDetectionsPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::PreferencesPage {
                set_description: &gettext(
                    "ClamAV never reports what is listed here, in any scan on this computer. \
                     Every change needs your administrator password and is recorded in the \
                     system journal, where software running as you can't remove the record.",
                ),

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Trusted Files"),
                    set_description: Some(&gettext(
                        "Files trusted by their SHA-256 hash. Any change to such a file makes \
                         ClamAV check it again.",
                    )),
                    #[local_ref]
                    trusted_file_list -> gtk::ListBox {},
                },

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Ignored Detections"),
                    set_description: Some(&gettext(
                        "Detection names that ClamAV ignores in every file.",
                    )),
                    #[local_ref]
                    ignored_signature_list -> gtk::ListBox {},
                },

                add = &adw::PreferencesGroup {
                    set_title: &gettext("Other Allowlists"),
                    set_description: Some(&gettext(
                        "Allowlist files in the signature folder that Lazaret didn't write. \
                         Check that you or your administrator added them on purpose.",
                    )),
                    #[watch]
                    set_visible: !model.snapshot.trust_list.foreign_allowlists.is_empty(),
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
            snapshot: TrustedDetectionsSnapshot::default(),
            trusted_file_rows: trust_list_rows(&sender),
            ignored_signature_rows: trust_list_rows(&sender),
            foreign_allowlist_rows: trust_list_rows(&sender),
            toaster: Toaster::new(&root),
        };
        let trusted_file_list = model.trusted_file_rows.widget();
        let ignored_signature_list = model.ignored_signature_rows.widget();
        let foreign_allowlist_list = model.foreign_allowlist_rows.widget();
        let widgets = view_output!();
        Self::reload_snapshot(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: TrustedDetectionsPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            TrustedDetectionsPageInput::RemovalRequested(removal_choice) => {
                present_trust_confirmation(
                    root,
                    removal_choice,
                    sender.input_sender().clone(),
                    TrustedDetectionsPageInput::RemovalConfirmed,
                );
            }
            TrustedDetectionsPageInput::RemovalConfirmed(confirmed_choice) => {
                sender.oneshot_command(async move {
                    TrustedDetectionsPageCommand::RemovalFinished(
                        request_trust_change(confirmed_choice).await,
                    )
                });
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: TrustedDetectionsPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            TrustedDetectionsPageCommand::SnapshotLoaded(snapshot) => self.show_snapshot(snapshot),
            TrustedDetectionsPageCommand::RemovalFinished(trust_outcome) => {
                self.toaster.add_toast(
                    adw::Toast::builder()
                        .title(trust_outcome_text(&trust_outcome))
                        .use_markup(false)
                        .build(),
                );
                Self::reload_snapshot(&sender);
            }
        }
    }
}
