use gettextrs::{gettext, ngettext};
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};

use crate::{
    host_services::{
        clamav_programs::database_directory_status::configured_database_directory,
        settings_helper::{
            helper_audit_records::{AuditedOutcome, HelperAuditEntry, newest_helper_audit_entries},
            trust_requests::{
                TrustChoice, TrustOutcome, present_trust_confirmation, request_trust_change,
                trust_outcome_text,
            },
        },
    },
    logs_page::activity_entry_row::formatted_local_time,
    protection_page::trusted_detections_page::trust_list_contents::{
        ForeignAllowlistFile, TrustListContents, TrustedFileEntry, read_trust_list_contents,
    },
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

fn added_text(
    audit_entries: &[HelperAuditEntry],
    action_name: &str,
    subject_marker: &str,
) -> String {
    audit_entries
        .iter()
        .find(|audit_entry| {
            audit_entry.action_name == action_name
                && audit_entry.audited_outcome == AuditedOutcome::ActionApplied
                && audit_entry.action_subject.contains(subject_marker)
        })
        .map_or_else(
            || gettext("No record of who added this in the system journal"),
            |audit_entry| {
                gettext("Added {time} by user {uid}")
                    .replace(
                        "{time}",
                        &formatted_local_time(
                            i64::try_from(audit_entry.recorded_unix_seconds).unwrap_or(i64::MAX),
                        ),
                    )
                    .replace("{uid}", &audit_entry.requester_uid)
            },
        )
}

pub struct TrustedDetectionsPage {
    snapshot: TrustedDetectionsSnapshot,
    trusted_file_list: gtk::ListBox,
    ignored_signature_list: gtk::ListBox,
    foreign_allowlist_list: gtk::ListBox,
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

fn plain_list() -> gtk::ListBox {
    gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .build()
}

fn removal_button(
    removal_choice: TrustChoice,
    sender: &ComponentSender<TrustedDetectionsPage>,
) -> gtk::Button {
    let removal_button = gtk::Button::builder()
        .icon_name("user-trash-symbolic")
        .tooltip_text(gettext("Remove"))
        .valign(gtk::Align::Center)
        .css_classes(["flat"])
        .build();
    let input_sender = sender.input_sender().clone();
    removal_button.connect_clicked(move |_clicked_button| {
        input_sender.emit(TrustedDetectionsPageInput::RemovalRequested(
            removal_choice.clone(),
        ));
    });
    removal_button
}

fn trusted_file_row(
    trusted_file: &TrustedFileEntry,
    audit_entries: &[HelperAuditEntry],
    sender: &ComponentSender<TrustedDetectionsPage>,
) -> adw::ActionRow {
    let file_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(&trusted_file.sha256_hex)
        .title_lines(0)
        .subtitle(format!(
            "{} · {}",
            bytesize::ByteSize::b(trusted_file.file_size),
            added_text(audit_entries, "trust-file", &trusted_file.sha256_hex)
        ))
        .css_classes(["property"])
        .build();
    file_row.add_suffix(&removal_button(
        TrustChoice::ForgetTrustedFile {
            sha256_hex: trusted_file.sha256_hex.clone(),
        },
        sender,
    ));
    file_row
}

fn ignored_signature_row(
    signature_name: &str,
    audit_entries: &[HelperAuditEntry],
    sender: &ComponentSender<TrustedDetectionsPage>,
) -> adw::ActionRow {
    let signature_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(signature_name)
        .subtitle(added_text(
            audit_entries,
            "ignore-signature",
            &format!("named {signature_name}"),
        ))
        .build();
    signature_row.add_suffix(&removal_button(
        TrustChoice::StopIgnoringSignature {
            signature_name: signature_name.to_owned(),
        },
        sender,
    ));
    signature_row
}

fn foreign_allowlist_row(foreign_allowlist: &ForeignAllowlistFile) -> adw::ActionRow {
    let allowlist_row = adw::ActionRow::builder()
        .use_markup(false)
        .title(&foreign_allowlist.file_name)
        .subtitle(
            ngettext(
                "{count} entry, not added through Lazaret",
                "{count} entries, not added through Lazaret",
                u32::try_from(foreign_allowlist.entry_count).unwrap_or(u32::MAX),
            )
            .replace("{count}", &foreign_allowlist.entry_count.to_string()),
        )
        .build();
    allowlist_row.add_prefix(
        &gtk::Image::builder()
            .icon_name("dialog-warning-symbolic")
            .css_classes(["warning"])
            .build(),
    );
    allowlist_row
}

fn empty_row(empty_text: String) -> adw::ActionRow {
    adw::ActionRow::builder()
        .title(empty_text)
        .css_classes(["dim-label"])
        .build()
}

impl TrustedDetectionsPage {
    fn refill_lists(&self, sender: &ComponentSender<Self>) {
        let TrustedDetectionsSnapshot {
            trust_list,
            audit_entries,
        } = &self.snapshot;
        [
            &self.trusted_file_list,
            &self.ignored_signature_list,
            &self.foreign_allowlist_list,
        ]
        .into_iter()
        .for_each(gtk::ListBox::remove_all);
        trust_list.trusted_files.iter().for_each(|trusted_file| {
            self.trusted_file_list
                .append(&trusted_file_row(trusted_file, audit_entries, sender));
        });
        if trust_list.trusted_files.is_empty() {
            self.trusted_file_list
                .append(&empty_row(gettext("No trusted files")));
        }
        trust_list
            .ignored_signatures
            .iter()
            .for_each(|signature_name| {
                self.ignored_signature_list.append(&ignored_signature_row(
                    signature_name,
                    audit_entries,
                    sender,
                ));
            });
        if trust_list.ignored_signatures.is_empty() {
            self.ignored_signature_list
                .append(&empty_row(gettext("No ignored detections")));
        }
        trust_list
            .foreign_allowlists
            .iter()
            .for_each(|foreign_allowlist| {
                self.foreign_allowlist_list
                    .append(&foreign_allowlist_row(foreign_allowlist));
            });
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
            trusted_file_list: plain_list(),
            ignored_signature_list: plain_list(),
            foreign_allowlist_list: plain_list(),
        };
        let trusted_file_list = &model.trusted_file_list;
        let ignored_signature_list = &model.ignored_signature_list;
        let foreign_allowlist_list = &model.foreign_allowlist_list;
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
                let input_sender = sender.input_sender().clone();
                present_trust_confirmation(root, removal_choice, move |confirmed_choice| {
                    input_sender.emit(TrustedDetectionsPageInput::RemovalConfirmed(
                        confirmed_choice,
                    ));
                });
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
        root: &Self::Root,
    ) {
        match page_command {
            TrustedDetectionsPageCommand::SnapshotLoaded(snapshot) => {
                self.snapshot = snapshot;
                self.refill_lists(&sender);
            }
            TrustedDetectionsPageCommand::RemovalFinished(trust_outcome) => {
                root.add_toast(
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
