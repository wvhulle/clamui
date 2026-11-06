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
        clamav_programs::false_positive_submission::SubmittedContent,
        clamav_scanner::{
            content_verdict::ContentVerdict,
            scanner_output_parser::{displayed_threat_name, sanitize_scanner_line},
        },
        quarantine_vault::quarantine_entry_database::QuarantineEntryRecord,
        settings_helper::trust_requests::{FileFingerprint, TrustChoice},
        threat_intel::file_reputation_check::{
            ReputationAnswers, SourceAnswer, check_hash_reputation,
        },
    },
    shared_widgets::false_positive_report_dialog::ReportedDetection,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RowRecheckState {
    NotRechecked,
    Rechecking,
    Rechecked(ContentVerdict),
}

pub struct QuarantineEntryRow {
    entry_record: QuarantineEntryRecord,
    reputation_answers: ReputationAnswers,
    recheck_state: RowRecheckState,
}

#[derive(Debug)]
pub enum QuarantineEntryRowInput {
    ReputationCheckRequested,
    HashCopyRequested,
    VirusTotalReportRequested,
    OnlineLookupsRequested,
    TrustFileRequested,
    FalsePositiveReportRequested,
    RecheckStateChanged(RowRecheckState),
}

#[derive(Debug)]
pub enum QuarantineEntryRowOutput {
    RestoreRequested { entry_id: i64 },
    DeletionRequested { entry_id: i64 },
    TrustRequested(TrustChoice),
    FalsePositiveReportRequested(ReportedDetection),
    HashCopyRequested(String),
    OnlineLookupsRequested,
    ReportLinkRequested(String),
}

#[derive(Debug)]
pub enum QuarantineEntryRowCommand {
    ReputationChecked(ReputationAnswers),
}

impl QuarantineEntryRow {
    pub const fn entry_id(&self) -> i64 {
        self.entry_record.entry_id
    }

    fn recheck_label(&self) -> String {
        match &self.recheck_state {
            RowRecheckState::Rechecking => gettext("Checking…"),
            RowRecheckState::Rechecked(ContentVerdict::NoLongerDetected) => {
                gettext("No longer detected")
            }
            RowRecheckState::Rechecked(ContentVerdict::StillDetected { .. }) => {
                gettext("Still detected")
            }
            RowRecheckState::Rechecked(ContentVerdict::VerdictUnavailable { .. })
            | RowRecheckState::NotRechecked => String::new(),
        }
    }

    fn recheck_style(&self) -> &'static str {
        match &self.recheck_state {
            RowRecheckState::Rechecked(ContentVerdict::NoLongerDetected) => "success",
            RowRecheckState::Rechecked(ContentVerdict::StillDetected { .. }) => "warning",
            RowRecheckState::Rechecking
            | RowRecheckState::Rechecked(ContentVerdict::VerdictUnavailable { .. })
            | RowRecheckState::NotRechecked => "dim-label",
        }
    }

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

            add_suffix = &gtk::Label {
                add_css_class: "caption-heading",
                set_valign: gtk::Align::Center,
                #[watch]
                set_visible: !self.recheck_label().is_empty(),
                #[watch]
                set_label: &self.recheck_label(),
                #[watch]
                set_css_classes: &["caption-heading", self.recheck_style()],
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Restore"),
                set_valign: gtk::Align::Center,
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::RestoreRequested { entry_id });
                },
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Delete"),
                set_valign: gtk::Align::Center,
                add_css_class: "destructive-action",
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::DeletionRequested { entry_id });
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
                    connect_clicked => QuarantineEntryRowInput::ReputationCheckRequested,
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
                    connect_clicked => QuarantineEntryRowInput::OnlineLookupsRequested,
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
                    connect_clicked => QuarantineEntryRowInput::OnlineLookupsRequested,
                },

                add_suffix = &gtk::Button {
                    set_label: &gettext("View Report"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: !self.virustotal_report_url().is_empty(),
                    connect_clicked => QuarantineEntryRowInput::VirusTotalReportRequested,
                },
            },

            add_row = &adw::ActionRow {
                set_title: &gettext("False Positive"),
                set_subtitle: &gettext("Trust this exact file so ClamAV stops reporting it on this computer, then restore it. Report it so a signature update fixes the detection for everyone."),
                set_subtitle_lines: 0,

                add_suffix = &gtk::Button {
                    set_label: &gettext("Report…"),
                    set_valign: gtk::Align::Center,
                    connect_clicked => QuarantineEntryRowInput::FalsePositiveReportRequested,
                },

                add_suffix = &gtk::Button {
                    set_label: &gettext("Trust…"),
                    set_valign: gtk::Align::Center,
                    connect_clicked => QuarantineEntryRowInput::TrustFileRequested,
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
                    connect_clicked => QuarantineEntryRowInput::HashCopyRequested,
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
            recheck_state: RowRecheckState::NotRechecked,
        }
    }

    fn update(&mut self, row_input: QuarantineEntryRowInput, sender: FactorySender<Self>) {
        match row_input {
            QuarantineEntryRowInput::ReputationCheckRequested => {
                self.reputation_answers = ReputationAnswers::all_set_to(&SourceAnswer::Checking);
                let content_hash = self.entry_record.file_hash.clone();
                sender.oneshot_command(async move {
                    QuarantineEntryRowCommand::ReputationChecked(
                        check_hash_reputation(content_hash).await,
                    )
                });
            }
            QuarantineEntryRowInput::HashCopyRequested => {
                let _page_closed = sender.output(QuarantineEntryRowOutput::HashCopyRequested(
                    self.entry_record.file_hash.clone(),
                ));
            }
            QuarantineEntryRowInput::OnlineLookupsRequested => {
                let _page_closed = sender.output(QuarantineEntryRowOutput::OnlineLookupsRequested);
            }
            QuarantineEntryRowInput::TrustFileRequested => {
                let _page_closed = sender.output(QuarantineEntryRowOutput::TrustRequested(
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
            QuarantineEntryRowInput::RecheckStateChanged(recheck_state) => {
                self.recheck_state = recheck_state;
            }
            QuarantineEntryRowInput::FalsePositiveReportRequested => {
                let _page_closed = sender.output(
                    QuarantineEntryRowOutput::FalsePositiveReportRequested(ReportedDetection {
                        detection_name: self.entry_record.threat_name.clone(),
                        submitted_content: SubmittedContent::QuarantinedEntry {
                            entry_id: self.entry_record.entry_id,
                        },
                        shown_path: sanitize_scanner_line(
                            &self.entry_record.original_path.to_string_lossy(),
                        ),
                    }),
                );
            }
            QuarantineEntryRowInput::VirusTotalReportRequested => {
                let _page_closed = sender.output(QuarantineEntryRowOutput::ReportLinkRequested(
                    self.virustotal_report_url().to_owned(),
                ));
            }
        }
    }

    fn update_cmd(&mut self, row_command: QuarantineEntryRowCommand, _sender: FactorySender<Self>) {
        match row_command {
            QuarantineEntryRowCommand::ReputationChecked(reputation_answers) => {
                self.reputation_answers = reputation_answers;
            }
        }
    }
}
