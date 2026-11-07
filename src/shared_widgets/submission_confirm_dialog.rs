use gettextrs::gettext;
use relm4::{Sender, adw, adw::prelude::*, gtk};

use crate::{
    host_services::clamav_programs::clamav_report_submission::{
        ClamavReport, ClamavReportKind, ClamavReportRequest, ReporterContact, SubmittedContent,
        contact_is_complete,
    },
    shared_widgets::awaited_dialogs::{
        AlertChoice, add_alert_choice, add_dismissing_choice, alert_choice, deliver_local_outcome,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubmissionDialogChoice {
    SendChosen,
    SendingCancelled,
}

impl AlertChoice for SubmissionDialogChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[Self::SendChosen];
    const DISMISSING_CHOICE: Self = Self::SendingCancelled;

    fn response_id(self) -> &'static str {
        match self {
            Self::SendChosen => "send",
            Self::SendingCancelled => "cancel",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClamavReportProposal {
    pub report_kind: ClamavReportKind,
    pub submitted_content: SubmittedContent,
    pub shown_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionProposal {
    ClamavReportProposed(ClamavReportProposal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmationText {
    pub heading: String,
    pub body_text: String,
    pub confirm_label: String,
}

fn sent_items_text(sent_items: &[String]) -> String {
    sent_items
        .iter()
        .map(|sent_item| format!("• {sent_item}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn assembled_body(
    file_line: String,
    sent_items: &[String],
    audience_text: String,
    shown_path: &str,
) -> String {
    [
        file_line,
        shown_path.to_owned(),
        gettext("What is sent:"),
        sent_items_text(sent_items),
        audience_text,
    ]
    .join("\n\n")
}

fn clamav_audience_text() -> String {
    gettext(
        "Cisco Talos, the team behind ClamAV, reviews it. Samples are processed by automation, \
         only Talos can access them, and they are never made public or shared with other \
         companies. A review takes at least 48 hours, and its outcome shows up in a later \
         signature database version.",
    )
}

pub fn confirmation_text(submission_proposal: &SubmissionProposal) -> ConfirmationText {
    match submission_proposal {
        SubmissionProposal::ClamavReportProposed(report_proposal) => {
            let (heading, mut sent_items) = match &report_proposal.report_kind {
                ClamavReportKind::FalsePositive { detection_name } => (
                    gettext("Report a False Positive to ClamAV?"),
                    vec![
                        gettext("The file's content"),
                        gettext("The detection name {detection}")
                            .replace("{detection}", detection_name),
                    ],
                ),
                ClamavReportKind::MissedMalware => (
                    gettext("Report Missed Malware to ClamAV?"),
                    vec![gettext("The file's content")],
                ),
            };
            sent_items.push(gettext(
                "Your name and email address, so Talos can contact you",
            ));
            ConfirmationText {
                heading,
                body_text: assembled_body(
                    gettext(
                        "Lazaret sends this file to ClamAV with clamsubmit. Only send files that \
                         contain nothing private.",
                    ),
                    &sent_items,
                    clamav_audience_text(),
                    &report_proposal.shown_path,
                ),
                confirm_label: gettext("Send Report"),
            }
        }
    }
}

fn contact_from_rows(name_row: &adw::EntryRow, email_row: &adw::EntryRow) -> ReporterContact {
    ReporterContact {
        reporter_name: name_row.text().to_string(),
        reporter_email: email_row.text().to_string(),
    }
}

fn confirmation_dialog(confirmation: &ConfirmationText) -> adw::AlertDialog {
    let submission_dialog =
        adw::AlertDialog::new(Some(&confirmation.heading), Some(&confirmation.body_text));
    add_dismissing_choice::<SubmissionDialogChoice>(&submission_dialog, &gettext("Cancel"));
    add_alert_choice(
        &submission_dialog,
        SubmissionDialogChoice::SendChosen,
        &confirmation.confirm_label,
    );
    submission_dialog.set_response_appearance(
        SubmissionDialogChoice::SendChosen.response_id(),
        adw::ResponseAppearance::Suggested,
    );
    submission_dialog
        .set_default_response(Some(SubmissionDialogChoice::SendingCancelled.response_id()));
    submission_dialog
}

pub fn present_clamav_report_confirmation<Message: 'static>(
    parent_widget: &impl IsA<gtk::Widget>,
    report_proposal: ClamavReportProposal,
    message_sender: Sender<Message>,
    confirmed_message: fn(ClamavReportRequest) -> Message,
) {
    let report_dialog = confirmation_dialog(&confirmation_text(
        &SubmissionProposal::ClamavReportProposed(report_proposal.clone()),
    ));
    let name_row = adw::EntryRow::builder().title(gettext("Your Name")).build();
    let email_row = adw::EntryRow::builder()
        .title(gettext("Your Email Address"))
        .input_purpose(gtk::InputPurpose::Email)
        .build();
    let contact_list = gtk::ListBox::builder()
        .css_classes(["boxed-list"])
        .selection_mode(gtk::SelectionMode::None)
        .build();
    contact_list.append(&name_row);
    contact_list.append(&email_row);
    report_dialog.set_extra_child(Some(&contact_list));
    let send_response = SubmissionDialogChoice::SendChosen.response_id();
    report_dialog.set_response_enabled(send_response, false);
    [&name_row, &email_row].into_iter().for_each(|contact_row| {
        let watched_dialog = report_dialog.clone();
        let watched_name = name_row.clone();
        let watched_email = email_row.clone();
        contact_row.connect_changed(move |_edited_row| {
            watched_dialog.set_response_enabled(
                send_response,
                contact_is_complete(&contact_from_rows(&watched_name, &watched_email)),
            );
        });
    });
    deliver_local_outcome(
        message_sender,
        alert_choice(report_dialog, parent_widget.clone().upcast()),
        move |report_choice| match report_choice {
            SubmissionDialogChoice::SendChosen => Some(confirmed_message(ClamavReportRequest {
                clamav_report: ClamavReport {
                    reporter_contact: contact_from_rows(&name_row, &email_row),
                    report_kind: report_proposal.report_kind,
                },
                submitted_content: report_proposal.submitted_content,
            })),
            SubmissionDialogChoice::SendingCancelled => None,
        },
    );
}

#[cfg(test)]
mod submission_confirm_dialog_tests {
    use std::path::PathBuf;

    use super::*;

    fn clamav_proposal(report_kind: ClamavReportKind) -> SubmissionProposal {
        SubmissionProposal::ClamavReportProposed(ClamavReportProposal {
            report_kind,
            submitted_content: SubmittedContent::FileOnDisk {
                file_path: PathBuf::from("/home/alex/Downloads/invoice.exe"),
            },
            shown_path: "/home/alex/Downloads/invoice.exe".to_owned(),
        })
    }

    #[test]
    fn a_clamav_report_names_the_file_the_service_and_its_privacy() {
        let false_positive_text =
            confirmation_text(&clamav_proposal(ClamavReportKind::FalsePositive {
                detection_name: "Win.Trojan.Agent-1".to_owned(),
            }));
        assert!(false_positive_text.heading.contains("ClamAV"));
        assert!(
            false_positive_text
                .body_text
                .contains("/home/alex/Downloads/invoice.exe")
        );
        assert!(false_positive_text.body_text.contains("Win.Trojan.Agent-1"));
        assert!(false_positive_text.body_text.contains("Cisco Talos"));
        assert!(false_positive_text.body_text.contains("never made public"));
        assert!(false_positive_text.body_text.contains("at least 48 hours"));
        assert!(false_positive_text.body_text.contains("email address"));
    }

    #[test]
    fn a_missed_malware_report_sends_no_detection_name() {
        let missed_text = confirmation_text(&clamav_proposal(ClamavReportKind::MissedMalware));
        assert!(missed_text.heading.contains("Missed Malware"));
        assert!(!missed_text.body_text.contains("detection name"));
        assert!(missed_text.body_text.contains("invoice.exe"));
    }
}
