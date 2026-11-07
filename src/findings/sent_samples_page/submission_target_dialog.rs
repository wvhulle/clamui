use gettextrs::gettext;
use relm4::{Sender, adw, adw::prelude::*, gtk};

use crate::{
    findings::sent_samples_page::{
        sent_samples_presentation::target_choice_label, sent_samples_state::OfferedTarget,
        uploads_in_flight::UploadActivity,
    },
    host_services::activity_history::submission_history_store::SubmissionTarget,
    shared_widgets::awaited_dialogs::{
        AlertChoice, add_alert_choice, add_dismissing_choice, alert_choice, deliver_local_outcome,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetDialogChoice {
    TargetPicked(SubmissionTarget),
    TargetDismissed,
}

impl AlertChoice for TargetDialogChoice {
    const ANSWERING_CHOICES: &'static [Self] = &[
        Self::TargetPicked(SubmissionTarget::ClamavFalsePositive),
        Self::TargetPicked(SubmissionTarget::ClamavMissedMalware),
        Self::TargetPicked(SubmissionTarget::MalwareBazaarSample),
        Self::TargetPicked(SubmissionTarget::VirusTotalSample),
    ];
    const DISMISSING_CHOICE: Self = Self::TargetDismissed;

    fn response_id(self) -> &'static str {
        match self {
            Self::TargetPicked(SubmissionTarget::ClamavFalsePositive) => "clamav-false-positive",
            Self::TargetPicked(SubmissionTarget::ClamavMissedMalware) => "clamav-missed-malware",
            Self::TargetPicked(SubmissionTarget::MalwareBazaarSample) => "malware-bazaar",
            Self::TargetPicked(SubmissionTarget::VirusTotalSample) => "virustotal",
            Self::TargetDismissed => "cancel",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetChoiceRequest {
    pub entry_id: i64,
    pub file_name: String,
    pub offered_targets: Vec<OfferedTarget>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChosenTarget {
    pub entry_id: i64,
    pub submission_target: SubmissionTarget,
}

pub fn present_target_choice<Message: 'static>(
    parent_widget: &impl IsA<gtk::Widget>,
    choice_request: TargetChoiceRequest,
    message_sender: Sender<Message>,
    chosen_message: fn(ChosenTarget) -> Message,
) {
    let target_dialog = adw::AlertDialog::new(
        Some(&gettext("Where Should This File Go?")),
        Some(&format!(
            "{}\n\n{}",
            choice_request.file_name,
            gettext(
                "Each service gets the file itself. The next step shows exactly what is sent and \
                 who can see it."
            )
        )),
    );
    add_dismissing_choice::<TargetDialogChoice>(&target_dialog, &gettext("Cancel"));
    choice_request
        .offered_targets
        .iter()
        .for_each(|offered_target| {
            let target_choice = TargetDialogChoice::TargetPicked(offered_target.submission_target);
            add_alert_choice(
                &target_dialog,
                target_choice,
                &target_choice_label(offered_target.submission_target),
            );
            match offered_target.upload_activity {
                UploadActivity::UploadIdle => {}
                UploadActivity::UploadRunning => {
                    target_dialog.set_response_enabled(target_choice.response_id(), false);
                }
            }
        });
    target_dialog.set_default_response(Some(TargetDialogChoice::TargetDismissed.response_id()));
    let entry_id = choice_request.entry_id;
    deliver_local_outcome(
        message_sender,
        alert_choice(target_dialog, parent_widget.clone().upcast()),
        move |target_choice| match target_choice {
            TargetDialogChoice::TargetPicked(submission_target) => {
                Some(chosen_message(ChosenTarget {
                    entry_id,
                    submission_target,
                }))
            }
            TargetDialogChoice::TargetDismissed => None,
        },
    );
}
