use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    gtk,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    findings::quarantine_page::quarantine_page_state::{
        EntryRowState, QuarantineRowInit, RowActivity, RowRecheckState, RowReputation,
    },
    host_services::{
        clamav_programs::false_positive_submission::SubmittedContent,
        clamav_scanner::{
            content_verdict::ContentVerdict,
            scanner_output_parser::{displayed_threat_name, sanitize_scanner_line},
        },
        desktop::locale_formatting::{byte_size_text, exact_local_time_text},
        quarantine_vault::{
            quarantine_entry_database::{QuarantineEntryRecord, StoredDetectionDate},
            quarantine_file_moves::RecordedPayloadHash,
        },
        settings_helper::trust_requests::{FileFingerprint, TrustChoice},
        threat_intel::file_reputation_check::{ReputationAnswers, SourceAnswer},
    },
    shared_widgets::false_positive_report_dialog::ReportedDetection,
};

pub fn quarantined_false_positive_detection(
    entry_record: &QuarantineEntryRecord,
) -> Option<ReportedDetection> {
    entry_record
        .threat_identity
        .matched_signature_name()
        .map(|signature_name| ReportedDetection {
            detection_name: signature_name.to_owned(),
            submitted_content: SubmittedContent::QuarantinedEntry {
                entry_id: entry_record.entry_id,
            },
            shown_path: sanitize_scanner_line(&entry_record.original_path.to_string_lossy()),
        })
}

pub struct QuarantineEntryRow {
    entry_record: QuarantineEntryRecord,
    row_state: EntryRowState,
}

#[derive(Debug)]
pub enum QuarantineEntryRowInput {
    ReputationCheckRequested,
    HashCopyRequested,
    VirusTotalReportRequested,
    OnlineLookupsRequested,
    TrustFileRequested,
    FalsePositiveReportRequested,
    RowStateChanged(EntryRowState),
}

#[derive(Debug)]
pub enum QuarantineEntryRowOutput {
    RestoreRequested { entry_id: i64 },
    ReputationCheckRequested { entry_id: i64, content_hash: String },
    DeletionRequested { entry_id: i64 },
    TrustRequested(TrustChoice),
    FalsePositiveReportRequested(ReportedDetection),
    HashCopyRequested(String),
    OnlineLookupsRequested,
    ReportLinkRequested(String),
}

impl QuarantineEntryRow {
    pub const fn entry_id(&self) -> i64 {
        self.entry_record.entry_id
    }

    fn recheck_label(&self) -> String {
        match &self.row_state.recheck_state {
            RowRecheckState::Rechecking => gettext("Checking…"),
            RowRecheckState::Rechecked(ContentVerdict::NoLongerDetected) => {
                gettext("No longer detected")
            }
            RowRecheckState::Rechecked(ContentVerdict::StillDetected { .. }) => {
                gettext("Still detected")
            }
            RowRecheckState::Rechecked(ContentVerdict::VerdictUnavailable(_))
            | RowRecheckState::NotRechecked => String::new(),
        }
    }

    fn recheck_style(&self) -> &'static str {
        match &self.row_state.recheck_state {
            RowRecheckState::Rechecked(ContentVerdict::NoLongerDetected) => "success",
            RowRecheckState::Rechecked(ContentVerdict::StillDetected { .. }) => "warning",
            RowRecheckState::Rechecking
            | RowRecheckState::Rechecked(ContentVerdict::VerdictUnavailable(_))
            | RowRecheckState::NotRechecked => "dim-label",
        }
    }

    fn known_sha256_hex(&self) -> Option<&str> {
        match &self.entry_record.payload_hash {
            RecordedPayloadHash::KnownSha256 { sha256_hex } => Some(sha256_hex),
            RecordedPayloadHash::IntegrityUnknown => None,
        }
    }

    fn payload_hash_text(&self) -> String {
        match &self.entry_record.payload_hash {
            RecordedPayloadHash::KnownSha256 { sha256_hex } => sha256_hex.clone(),
            RecordedPayloadHash::IntegrityUnknown => gettext(
                "Unknown. This quarantine record has no usable hash, so the file cannot be \
                 verified, checked online, trusted or restored. You can still delete it.",
            ),
        }
    }

    fn actions_available(&self) -> bool {
        self.row_state.row_activity == RowActivity::ActionsAvailable
    }

    fn reputation_check_running(&self) -> bool {
        matches!(
            self.row_state.row_reputation,
            RowReputation::CheckingReputation
        )
    }

    fn checked_answers(&self) -> Option<&ReputationAnswers> {
        match &self.row_state.row_reputation {
            RowReputation::ReputationChecked(reputation_answers) => Some(reputation_answers),
            RowReputation::NotChecked | RowReputation::CheckingReputation => None,
        }
    }

    fn source_answer_text(&self, chosen_source: fn(&ReputationAnswers) -> &SourceAnswer) -> String {
        match &self.row_state.row_reputation {
            RowReputation::NotChecked => gettext("Not checked yet"),
            RowReputation::CheckingReputation => gettext("Checking…"),
            RowReputation::ReputationChecked(reputation_answers) => {
                chosen_source(reputation_answers).displayed_text()
            }
        }
    }

    fn source_needs_key(&self, chosen_source: fn(&ReputationAnswers) -> &SourceAnswer) -> bool {
        self.checked_answers()
            .is_some_and(|reputation_answers| chosen_source(reputation_answers).needs_key())
    }

    fn virustotal_report_url(&self) -> Option<&str> {
        self.checked_answers().and_then(|reputation_answers| {
            match &reputation_answers.virustotal_answer {
                SourceAnswer::AnsweredWithReport { report_url, .. } => Some(report_url.as_str()),
                SourceAnswer::NeedsKey
                | SourceAnswer::Answered { .. }
                | SourceAnswer::Failed(_) => None,
            }
        })
    }
}

const fn circl_source(reputation_answers: &ReputationAnswers) -> &SourceAnswer {
    &reputation_answers.circl_answer
}

const fn bazaar_source(reputation_answers: &ReputationAnswers) -> &SourceAnswer {
    &reputation_answers.bazaar_answer
}

const fn virustotal_source(reputation_answers: &ReputationAnswers) -> &SourceAnswer {
    &reputation_answers.virustotal_answer
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
    type Init = QuarantineRowInit;
    type Input = QuarantineEntryRowInput;
    type Output = QuarantineEntryRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        #[root]
        #[name = "entry_expander"]
        adw::ExpanderRow {
            set_use_markup: false,
            set_title: &displayed_threat_name(&self.entry_record.threat_identity),
            set_subtitle: &format!(
                "{}\n{} · {}",
                sanitize_scanner_line(&self.entry_record.original_path.to_string_lossy()),
                match &self.entry_record.detection_date {
                    StoredDetectionDate::DetectedAt(detected_at) => exact_local_time_text(*detected_at),
                    StoredDetectionDate::UnreadableText(stored_text) => sanitize_scanner_line(stored_text),
                },
                byte_size_text(self.entry_record.file_size),
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

            add_suffix = &gtk::Label {
                set_label: &gettext("Integrity Unknown"),
                set_valign: gtk::Align::Center,
                set_css_classes: &["caption-heading", "warning"],
                set_visible: self.known_sha256_hex().is_none(),
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Restore"),
                set_valign: gtk::Align::Center,
                #[watch]
                set_sensitive: self.known_sha256_hex().is_some() && self.actions_available(),
                connect_clicked[sender, entry_id = self.entry_record.entry_id] => move |_clicked_button| {
                    let _parent_gone = sender.output(QuarantineEntryRowOutput::RestoreRequested { entry_id });
                },
            },

            add_suffix = &gtk::Button {
                set_label: &gettext("Delete"),
                set_valign: gtk::Align::Center,
                add_css_class: "destructive-action",
                #[watch]
                set_sensitive: self.actions_available(),
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
                    set_sensitive: self.known_sha256_hex().is_some() && !self.reputation_check_running(),
                    connect_clicked => QuarantineEntryRowInput::ReputationCheckRequested,
                },
            },

            add_row = &source_row("CIRCL hashlookup") -> adw::ActionRow {
                #[watch]
                set_subtitle: &self.source_answer_text(circl_source),
            },

            add_row = &source_row("MalwareBazaar") -> adw::ActionRow {
                #[watch]
                set_subtitle: &self.source_answer_text(bazaar_source),

                add_suffix = &gtk::Button {
                    set_label: &gettext("Add Key"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: self.source_needs_key(bazaar_source),
                    connect_clicked => QuarantineEntryRowInput::OnlineLookupsRequested,
                },
            },

            add_row = &source_row("VirusTotal") -> adw::ActionRow {
                #[watch]
                set_subtitle: &self.source_answer_text(virustotal_source),

                add_suffix = &gtk::Button {
                    set_label: &gettext("Add Key"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: self.source_needs_key(virustotal_source),
                    connect_clicked => QuarantineEntryRowInput::OnlineLookupsRequested,
                },

                add_suffix = &gtk::Button {
                    set_label: &gettext("View Report"),
                    set_valign: gtk::Align::Center,
                    #[watch]
                    set_visible: self.virustotal_report_url().is_some(),
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
                    set_visible: quarantined_false_positive_detection(&self.entry_record).is_some(),
                    connect_clicked => QuarantineEntryRowInput::FalsePositiveReportRequested,
                },

                add_suffix = &gtk::Button {
                    set_label: &gettext("Trust…"),
                    set_valign: gtk::Align::Center,
                    set_sensitive: self.known_sha256_hex().is_some(),
                    connect_clicked => QuarantineEntryRowInput::TrustFileRequested,
                },
            },

            add_row = &adw::ActionRow {
                set_use_markup: false,
                set_title: "SHA-256",
                set_subtitle: &self.payload_hash_text(),
                set_subtitle_lines: 0,
                set_subtitle_selectable: true,
                add_css_class: "property",

                add_suffix = &gtk::Button {
                    set_icon_name: "edit-copy-symbolic",
                    set_tooltip_text: Some(&gettext("Copy Hash")),
                    set_valign: gtk::Align::Center,
                    set_visible: self.known_sha256_hex().is_some(),
                    add_css_class: "flat",
                    connect_clicked => QuarantineEntryRowInput::HashCopyRequested,
                },
            },
        }
    }

    fn init_model(
        QuarantineRowInit {
            entry_record,
            row_state,
        }: QuarantineRowInit,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self {
            entry_record,
            row_state,
        }
    }

    fn update(&mut self, row_input: QuarantineEntryRowInput, sender: FactorySender<Self>) {
        match row_input {
            QuarantineEntryRowInput::ReputationCheckRequested => {
                let Some(content_hash) = self.known_sha256_hex().map(str::to_owned) else {
                    return;
                };
                let _page_closed =
                    sender.output(QuarantineEntryRowOutput::ReputationCheckRequested {
                        entry_id: self.entry_record.entry_id,
                        content_hash,
                    });
            }
            QuarantineEntryRowInput::HashCopyRequested => {
                if let Some(sha256_hex) = self.known_sha256_hex() {
                    let _page_closed = sender.output(QuarantineEntryRowOutput::HashCopyRequested(
                        sha256_hex.to_owned(),
                    ));
                }
            }
            QuarantineEntryRowInput::OnlineLookupsRequested => {
                let _page_closed = sender.output(QuarantineEntryRowOutput::OnlineLookupsRequested);
            }
            QuarantineEntryRowInput::TrustFileRequested => {
                let Some(sha256_hex) = self.known_sha256_hex().map(str::to_owned) else {
                    return;
                };
                let _page_closed = sender.output(QuarantineEntryRowOutput::TrustRequested(
                    TrustChoice::TrustFile {
                        file_fingerprint: FileFingerprint {
                            sha256_hex,
                            file_size: self.entry_record.file_size,
                        },
                        shown_path: sanitize_scanner_line(
                            &self.entry_record.original_path.to_string_lossy(),
                        ),
                    },
                ));
            }
            QuarantineEntryRowInput::RowStateChanged(row_state) => {
                self.row_state = row_state;
            }
            QuarantineEntryRowInput::FalsePositiveReportRequested => {
                let Some(reported_detection) =
                    quarantined_false_positive_detection(&self.entry_record)
                else {
                    return;
                };
                let _page_closed = sender.output(
                    QuarantineEntryRowOutput::FalsePositiveReportRequested(reported_detection),
                );
            }
            QuarantineEntryRowInput::VirusTotalReportRequested => {
                if let Some(report_url) = self.virustotal_report_url() {
                    let _page_closed = sender.output(
                        QuarantineEntryRowOutput::ReportLinkRequested(report_url.to_owned()),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod quarantine_entry_row_tests {
    use std::path::PathBuf;

    use super::*;
    use crate::host_services::clamav_scanner::scanner_output_parser::ThreatIdentity;

    fn quarantined_entry(threat_identity: ThreatIdentity) -> QuarantineEntryRecord {
        QuarantineEntryRecord {
            entry_id: 7,
            original_path: PathBuf::from("/home/user/Downloads/blocked.bin"),
            quarantine_path: PathBuf::from("/vault/payload"),
            threat_identity,
            detection_date: StoredDetectionDate::from("2026-11-01T00:00:00Z".to_owned()),
            file_size: bytesize::ByteSize::b(1),
            payload_hash: RecordedPayloadHash::IntegrityUnknown,
            original_permissions: 0o644,
        }
    }

    #[test]
    fn a_quarantined_on_access_block_cannot_be_reported_as_a_false_positive() {
        assert_eq!(
            quarantined_false_positive_detection(&quarantined_entry(
                ThreatIdentity::BlockedByOnAccess
            )),
            None
        );
    }

    #[test]
    fn a_quarantined_signature_is_reported_under_its_name() {
        assert_eq!(
            quarantined_false_positive_detection(&quarantined_entry(ThreatIdentity::Signature {
                signature_name: "Win.Test.EICAR_HDB-1".to_owned(),
            }))
            .map(|reported_detection| reported_detection.detection_name),
            Some("Win.Test.EICAR_HDB-1".to_owned())
        );
    }
}
