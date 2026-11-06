use gettextrs::gettext;
use relm4::{Sender, adw, adw::prelude::*, gtk};

use crate::{
    host_services::clamav_programs::false_positive_submission::{
        FalsePositiveReport, ReporterContact, SubmittedContent, contact_is_complete,
    },
    shared_widgets::awaited_dialogs::{
        AlertChoice, add_alert_choice, add_dismissing_choice, alert_choice, deliver_local_outcome,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReportDialogChoice {
    SendReportChosen,
    ReportCancelled,
}

impl AlertChoice for ReportDialogChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[Self::SendReportChosen];
    const DISMISSING_CHOICE: Self = Self::ReportCancelled;

    fn response_id(self) -> &'static str {
        match self {
            Self::SendReportChosen => "send",
            Self::ReportCancelled => "cancel",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportedDetection {
    pub detection_name: String,
    pub submitted_content: SubmittedContent,
    pub shown_path: String,
}

fn contact_from_rows(name_row: &adw::EntryRow, email_row: &adw::EntryRow) -> ReporterContact {
    ReporterContact {
        reporter_name: name_row.text().to_string(),
        reporter_email: email_row.text().to_string(),
    }
}

pub fn present_false_positive_report<Message: 'static>(
    parent_widget: &impl IsA<gtk::Widget>,
    reported_detection: ReportedDetection,
    message_sender: Sender<Message>,
    confirmed_message: fn(FalsePositiveReport) -> Message,
) {
    let report_dialog = adw::AlertDialog::new(
        Some(&gettext("Report a False Positive?")),
        Some(
            &gettext(
                "Lazaret uploads this file to Cisco Talos, the team behind ClamAV, together with \
                 your name and email address, so they can check the detection and contact you. \
                 Only send files that contain nothing private.\n\n{detection}\n{path}",
            )
            .replace("{detection}", &reported_detection.detection_name)
            .replace("{path}", &reported_detection.shown_path),
        ),
    );
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
    let send_response = ReportDialogChoice::SendReportChosen.response_id();
    add_dismissing_choice::<ReportDialogChoice>(&report_dialog, &gettext("Cancel"));
    add_alert_choice(
        &report_dialog,
        ReportDialogChoice::SendReportChosen,
        &gettext("Send Report"),
    );
    report_dialog.set_response_appearance(send_response, adw::ResponseAppearance::Suggested);
    report_dialog.set_response_enabled(send_response, false);
    report_dialog.set_default_response(Some(ReportDialogChoice::ReportCancelled.response_id()));
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
            ReportDialogChoice::SendReportChosen => Some(confirmed_message(FalsePositiveReport {
                reporter_contact: contact_from_rows(&name_row, &email_row),
                detection_name: reported_detection.detection_name,
                submitted_content: reported_detection.submitted_content,
            })),
            ReportDialogChoice::ReportCancelled => None,
        },
    );
}
