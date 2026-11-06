use std::path::PathBuf;

use gettextrs::gettext;
use relm4::{Sender, adw, adw::prelude::*, gtk};

use crate::host_services::clamav_programs::false_positive_submission::{
    FalsePositiveReport, ReporterContact, contact_is_complete,
};

const SEND_RESPONSE: &str = "send";
const CANCEL_RESPONSE: &str = "cancel";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReportedDetection {
    pub detection_name: String,
    pub submitted_path: PathBuf,
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
    report_dialog.add_response(CANCEL_RESPONSE, &gettext("Cancel"));
    report_dialog.add_response(SEND_RESPONSE, &gettext("Send Report"));
    report_dialog.set_response_appearance(SEND_RESPONSE, adw::ResponseAppearance::Suggested);
    report_dialog.set_response_enabled(SEND_RESPONSE, false);
    report_dialog.set_default_response(Some(CANCEL_RESPONSE));
    report_dialog.set_close_response(CANCEL_RESPONSE);
    [&name_row, &email_row].into_iter().for_each(|contact_row| {
        let watched_dialog = report_dialog.clone();
        let watched_name = name_row.clone();
        let watched_email = email_row.clone();
        contact_row.connect_changed(move |_edited_row| {
            watched_dialog.set_response_enabled(
                SEND_RESPONSE,
                contact_is_complete(&contact_from_rows(&watched_name, &watched_email)),
            );
        });
    });
    report_dialog.connect_response(Some(SEND_RESPONSE), move |_dialog, _response| {
        message_sender.emit(confirmed_message(FalsePositiveReport {
            reporter_contact: contact_from_rows(&name_row, &email_row),
            detection_name: reported_detection.detection_name.clone(),
            submitted_path: reported_detection.submitted_path.clone(),
        }));
    });
    report_dialog.present(Some(parent_widget));
}
