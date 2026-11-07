use gettextrs::gettext;
use relm4::{Sender, adw, adw::prelude::*, gtk};

use crate::{
    host_services::{
        clamav_admin_service::trust_requests::TrustChoice,
        desktop::locale_formatting::exact_byte_size_text,
    },
    shared_widgets::awaited_dialogs::{
        AlertChoice, add_alert_choice, add_dismissing_choice, alert_choice, deliver_local_outcome,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TrustDialogChoice {
    TrustConfirmed,
    TrustCancelled,
}

impl AlertChoice for TrustDialogChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[Self::TrustConfirmed];
    const DISMISSING_CHOICE: Self = Self::TrustCancelled;

    fn response_id(self) -> &'static str {
        match self {
            Self::TrustConfirmed => "confirm",
            Self::TrustCancelled => "cancel",
        }
    }
}

struct ConfirmationText {
    heading: String,
    body: String,
    shown_value: String,
    confirm_label: String,
    lowers_protection: bool,
}

fn confirmation_text(trust_choice: &TrustChoice) -> ConfirmationText {
    match trust_choice {
        TrustChoice::TrustFile {
            file_fingerprint,
            shown_path,
        } => ConfirmationText {
            heading: gettext("Trust This File?"),
            body: gettext(
                "ClamAV will never report a file with exactly this content again, wherever it is \
                 on this computer and whichever scan finds it. Your administrator password is \
                 needed, and the password prompt shows the same SHA-256 hash as below.\n\n{path}",
            )
            .replace("{path}", shown_path),
            shown_value: gettext("SHA-256 {hash}\n{size}")
                .replace("{hash}", &file_fingerprint.sha256_hex)
                .replace("{size}", &exact_byte_size_text(file_fingerprint.file_size)),
            confirm_label: gettext("Trust"),
            lowers_protection: true,
        },
        TrustChoice::IgnoreSignature { signature_name } => ConfirmationText {
            heading: gettext("Ignore This Detection?"),
            body: gettext(
                "ClamAV will stop reporting every file with this detection, not just this one. \
                 Trusting the file by its hash is safer when only one file is a false positive.",
            ),
            shown_value: signature_name.clone(),
            confirm_label: gettext("Ignore"),
            lowers_protection: true,
        },
        TrustChoice::ForgetTrustedFile { sha256_hex } => ConfirmationText {
            heading: gettext("Stop Trusting This File?"),
            body: gettext("ClamAV will report this file again when it matches a signature."),
            shown_value: format!("SHA-256 {sha256_hex}"),
            confirm_label: gettext("Stop Trusting"),
            lowers_protection: false,
        },
        TrustChoice::StopIgnoringSignature { signature_name } => ConfirmationText {
            heading: gettext("Report This Detection Again?"),
            body: gettext("ClamAV will report files with this detection again."),
            shown_value: signature_name.clone(),
            confirm_label: gettext("Report Again"),
            lowers_protection: false,
        },
    }
}

fn shown_value_label(shown_value: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(shown_value)
        .use_markup(false)
        .selectable(true)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::Char)
        .css_classes(["monospace", "card"])
        .margin_top(6)
        .build()
}

pub fn present_trust_confirmation<Message: 'static>(
    parent_widget: &impl IsA<gtk::Widget>,
    trust_choice: TrustChoice,
    message_sender: Sender<Message>,
    confirmed_message: fn(TrustChoice) -> Message,
) {
    let ConfirmationText {
        heading,
        body,
        shown_value,
        confirm_label,
        lowers_protection,
    } = confirmation_text(&trust_choice);
    let confirmation_dialog = adw::AlertDialog::new(Some(&heading), Some(&body));
    confirmation_dialog.set_extra_child(Some(&shown_value_label(&shown_value)));
    add_dismissing_choice::<TrustDialogChoice>(&confirmation_dialog, &gettext("Cancel"));
    add_alert_choice(
        &confirmation_dialog,
        TrustDialogChoice::TrustConfirmed,
        &confirm_label,
    );
    confirmation_dialog.set_response_appearance(
        TrustDialogChoice::TrustConfirmed.response_id(),
        if lowers_protection {
            adw::ResponseAppearance::Destructive
        } else {
            adw::ResponseAppearance::Suggested
        },
    );
    confirmation_dialog.set_default_response(Some(TrustDialogChoice::TrustCancelled.response_id()));
    deliver_local_outcome(
        message_sender,
        alert_choice(confirmation_dialog, parent_widget.clone().upcast()),
        move |trust_dialog_choice| match trust_dialog_choice {
            TrustDialogChoice::TrustConfirmed => Some(confirmed_message(trust_choice)),
            TrustDialogChoice::TrustCancelled => None,
        },
    );
}

#[cfg(test)]
mod trust_confirmation_dialog_tests {
    use super::*;

    #[test]
    fn trusting_lowers_protection_and_forgetting_does_not() {
        assert!(
            confirmation_text(&TrustChoice::IgnoreSignature {
                signature_name: "Win.Test.EICAR_HDB-1".to_owned()
            })
            .lowers_protection
        );
        assert!(
            !confirmation_text(&TrustChoice::ForgetTrustedFile {
                sha256_hex: "00".to_owned()
            })
            .lowers_protection
        );
    }
}
