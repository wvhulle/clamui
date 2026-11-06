use bytesize::ByteSize;
use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::{
        clamav_scanner::scanner_output_parser::{displayed_threat_name, sanitize_scanner_line},
        quarantine_vault::quarantine_entry_database::QuarantineEntryRecord,
        settings_helper::trust_requests::{FileFingerprint, TrustChoice},
        threat_intel::file_reputation_check::{
            ReputationAnswers, SourceAnswer, check_hash_reputation,
        },
    },
    preferences_dialog::preferences_dialog_component::{
        PreferencesPageName, present_preferences_dialog,
    },
};

pub struct QuarantineEntryRow {
    entry_record: QuarantineEntryRecord,
    reputation_answers: ReputationAnswers,
}

#[derive(Debug)]
pub enum QuarantineEntryRowInput {
    CheckReputation,
    CopyHash,
    OpenVirusTotalReport,
    OpenOnlineLookups,
    TrustFile,
}

#[derive(Debug)]
pub enum QuarantineEntryRowOutput {
    RestoreEntry { entry_id: i64 },
    DeleteEntry { entry_id: i64 },
    TrustEntry(TrustChoice),
    ShowToast(String),
}

#[derive(Debug)]
pub enum QuarantineEntryRowCommand {
    ReputationChecked(ReputationAnswers),
}

impl QuarantineEntryRow {
    fn reputation_check_running(&self) -> bool {
        self.reputation_answers.circl_answer == SourceAnswer::Checking
    }

    fn virustotal_report_url(&self) -> &str {
        match &self.reputation_answers.virustotal_answer {
            SourceAnswer::AnsweredWithReport { report_url, .. } => report_url,
            _no_report => "",
        }
    }
}

fn source_row(source_name: &str) -> adw::ActionRow {
    adw::ActionRow::builder()
        .use_markup(false)
        .title(source_name)
        .subtitle_lines(0)
        .css_classes(["property"])
        .build()
}

#[relm4::factory(pub)]
impl FactoryComponent for QuarantineEntryRow {
    type Init = QuarantineEntryRecord;
    type Input = QuarantineEntryRowInput;
    type Output = QuarantineEntryRowOutput;
    type CommandOutput = QuarantineEntryRowCommand;
    type ParentWidget = gtk::ListBox;

    view! {
        #[root]
        #[name = "entry_expander"]
        adw::ExpanderRow {
            set_use_markup: false,
            set_title: &displayed_threat_name(&self.entry_record.threat_name),
            set_subtitle: &format!(
                "{}\n{} · {}",
                sanitize_scanner_line(&self.entry_record.original_path.to_string_lossy()),
                self.entry_record.detection_date,
                ByteSize::b(self.entry_record.file_size),
            ),
            set_subtitle_lines: 0,

            add_suffix = &gtk::Button {
                set_label: &gettext("Restore"),
                set_valign: gtk::Align::Center,
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::RestoreEntry { entry_id });
                },
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Delete"),
                set_valign: gtk::Align::Center,
                add_css_class: "destructive-action",
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::DeleteEntry { entry_id });
                },
            },

            add_row = &adw::ActionRow {
                set_title: &gettext("Reputation"),
                set_subtitle: &gettext("Only the file's SHA-256 hash is sent. The file itself never leaves this computer."),
                set_subtitle_lines: 0,

                add_suffix = &gtk::Button {
                    set_label: &gettext("Check"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_sensitive: !self.reputation_check_running(),
                    connect_clicked => QuarantineEntryRowInput::CheckReputation,
                },
            },

            add_row = &source_row("CIRCL hashlookup") -> adw::ActionRow {
                #[watch]
                set_subtitle: &self.reputation_answers.circl_answer.displayed_text(),
            },

            add_row = &source_row("MalwareBazaar") -> adw::ActionRow {
                #[watch]
                set_subtitle: &self.reputation_answers.bazaar_answer.displayed_text(),

                add_suffix = &gtk::Button {
                    set_label: &gettext("Add Key"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: self.reputation_answers.bazaar_answer == SourceAnswer::NeedsKey,
                    connect_clicked => QuarantineEntryRowInput::OpenOnlineLookups,
                },
            },

            add_row = &source_row("VirusTotal") -> adw::ActionRow {
                #[watch]
                set_subtitle: &self.reputation_answers.virustotal_answer.displayed_text(),

                add_suffix = &gtk::Button {
                    set_label: &gettext("Add Key"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: self.reputation_answers.virustotal_answer == SourceAnswer::NeedsKey,
                    connect_clicked => QuarantineEntryRowInput::OpenOnlineLookups,
                },

                add_suffix = &gtk::Button {
                    set_label: &gettext("View Report"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: !self.virustotal_report_url().is_empty(),
                    connect_clicked => QuarantineEntryRowInput::OpenVirusTotalReport,
                },
            },

            add_row = &adw::ActionRow {
                set_title: &gettext("False Positive"),
                set_subtitle: &gettext("Trust this exact file so ClamAV stops reporting it on this computer. Then restore it."),
                set_subtitle_lines: 0,

                add_suffix = &gtk::Button {
                    set_label: &gettext("Trust…"),
                    set_valign: gtk::Align::Center,
                    connect_clicked => QuarantineEntryRowInput::TrustFile,
                },
            },

            add_row = &adw::ActionRow {
                set_use_markup: false,
                set_title: "SHA-256",
                set_subtitle: &self.entry_record.file_hash,
                set_subtitle_selectable: true,
                add_css_class: "property",

                add_suffix = &gtk::Button {
                    set_icon_name: "edit-copy-symbolic",
                    set_tooltip_text: Some(&gettext("Copy Hash")),
                    set_valign: gtk::Align::Center,
                    add_css_class: "flat",
                    connect_clicked => QuarantineEntryRowInput::CopyHash,
                },
            },
        }
    }

    fn init_model(
        entry_record: QuarantineEntryRecord,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            entry_record,
            reputation_answers: ReputationAnswers::all_set_to(&SourceAnswer::NotChecked),
        }
    }

    fn update_with_view(
        &mut self,
        widgets: &mut Self::Widgets,
        row_input: QuarantineEntryRowInput,
        sender: FactorySender<Self>,
    ) {
        match row_input {
            QuarantineEntryRowInput::CheckReputation => {
                self.reputation_answers = ReputationAnswers::all_set_to(&SourceAnswer::Checking);
                let content_hash = self.entry_record.file_hash.clone();
                sender.oneshot_command(async move {
                    QuarantineEntryRowCommand::ReputationChecked(
                        check_hash_reputation(content_hash).await,
                    )
                });
            }
            QuarantineEntryRowInput::CopyHash => {
                widgets
                    .entry_expander
                    .clipboard()
                    .set_text(&self.entry_record.file_hash);
                let _parent_gone = sender.output(QuarantineEntryRowOutput::ShowToast(gettext(
                    "Hash copied to clipboard",
                )));
            }
            QuarantineEntryRowInput::OpenOnlineLookups => {
                present_preferences_dialog(PreferencesPageName::OnlineLookups);
            }
            QuarantineEntryRowInput::TrustFile => {
                let _parent_gone = sender.output(QuarantineEntryRowOutput::TrustEntry(
                    TrustChoice::TrustFile {
                        file_fingerprint: FileFingerprint {
                            sha256_hex: self.entry_record.file_hash.clone(),
                            file_size: self.entry_record.file_size,
                        },
                        shown_path: sanitize_scanner_line(
                            &self.entry_record.original_path.to_string_lossy(),
                        ),
                    },
                ));
            }
            QuarantineEntryRowInput::OpenVirusTotalReport => {
                gtk::UriLauncher::new(self.virustotal_report_url()).launch(
                    widgets
                        .entry_expander
                        .root()
                        .and_downcast::<gtk::Window>()
                        .as_ref(),
                    gtk::gio::Cancellable::NONE,
                    |_launch_outcome| {},
                );
            }
        }
        self.update_view(widgets, sender);
    }

    fn update_cmd(&mut self, row_command: QuarantineEntryRowCommand, _sender: FactorySender<Self>) {
        match row_command {
            QuarantineEntryRowCommand::ReputationChecked(reputation_answers) => {
                self.reputation_answers = reputation_answers;
            }
        }
    }
}
