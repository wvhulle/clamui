use std::{future::Future, path::PathBuf};

use gettextrs::gettext;
use relm4::{
    Sender, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, glib},
};

#[derive(Debug)]
pub enum TextExportOutcome {
    TextSaved,
    ExportCancelled,
    ExportFailed(glib::Error),
}

#[derive(Debug)]
pub enum ImportedFileOutcome {
    FileRead(Vec<u8>),
    ImportCancelled,
    ImportFailed(glib::Error),
}

pub fn describe_export_failure(export_failure: &glib::Error) -> String {
    gettext("Could not save the file: {error}").replace("{error}", &export_failure.to_string())
}

fn active_application_window() -> Option<gtk::Window> {
    relm4::main_application().active_window()
}

pub fn deliver_local_outcome<Outcome, Message>(
    message_sender: Sender<Message>,
    awaited_outcome: impl Future<Output = Outcome> + 'static,
    outcome_message: impl FnOnce(Outcome) -> Option<Message> + 'static,
) where
    Outcome: 'static,
    Message: 'static,
{
    relm4::spawn_local(async move {
        if let Some(delivered_message) = outcome_message(awaited_outcome.await) {
            message_sender.emit(delivered_message);
        }
    });
}

pub trait AlertChoice: Copy + Eq + 'static {
    const ANSWERING_CHOICES: &'static [Self];
    const DISMISSING_CHOICE: Self;

    fn response_id(self) -> &'static str;
}

pub fn alert_choice_for_response<Choice: AlertChoice>(response_id: &str) -> Choice {
    Choice::ANSWERING_CHOICES
        .iter()
        .copied()
        .find(|answering_choice| answering_choice.response_id() == response_id)
        .unwrap_or(Choice::DISMISSING_CHOICE)
}

pub fn add_alert_choice<Choice: AlertChoice>(
    alert_dialog: &adw::AlertDialog,
    alert_choice: Choice,
    choice_label: &str,
) {
    alert_dialog.add_response(alert_choice.response_id(), choice_label);
}

pub fn add_dismissing_choice<Choice: AlertChoice>(
    alert_dialog: &adw::AlertDialog,
    choice_label: &str,
) {
    let dismissing_response = Choice::DISMISSING_CHOICE.response_id();
    alert_dialog.add_response(dismissing_response, choice_label);
    alert_dialog.set_close_response(dismissing_response);
}

pub async fn alert_choice<Choice: AlertChoice>(
    alert_dialog: adw::AlertDialog,
    parent_widget: gtk::Widget,
) -> Choice {
    alert_choice_for_response(&alert_dialog.choose_future(Some(&parent_widget)).await)
}

pub async fn chosen_files_to_open(dialog_title: String) -> Vec<PathBuf> {
    let chosen_files = gtk::FileDialog::builder()
        .title(dialog_title)
        .build()
        .open_multiple_future(active_application_window().as_ref())
        .await;
    chosen_files
        .map(|chosen_files| {
            (0..chosen_files.n_items())
                .filter_map(|file_position| chosen_files.item(file_position))
                .filter_map(|chosen_object| chosen_object.downcast::<gio::File>().ok())
                .filter_map(|chosen_file| chosen_file.path())
                .collect()
        })
        .unwrap_or_default()
}

pub async fn chosen_folders_to_open(dialog_title: String) -> Vec<PathBuf> {
    gtk::FileDialog::builder()
        .title(dialog_title)
        .build()
        .select_folder_future(active_application_window().as_ref())
        .await
        .ok()
        .and_then(|chosen_folder| chosen_folder.path())
        .into_iter()
        .collect()
}

pub async fn imported_file(dialog_title: String) -> ImportedFileOutcome {
    let chosen_file = gtk::FileDialog::builder()
        .title(dialog_title)
        .build()
        .open_future(active_application_window().as_ref())
        .await;
    match chosen_file {
        Err(_dialog_dismissed) => ImportedFileOutcome::ImportCancelled,
        Ok(chosen_file) => match chosen_file.load_contents_future().await {
            Ok(loaded_contents) => ImportedFileOutcome::FileRead(loaded_contents.0.to_vec()),
            Err(read_failure) => ImportedFileOutcome::ImportFailed(read_failure),
        },
    }
}

pub async fn exported_text(suggested_name: String, exported_text: String) -> TextExportOutcome {
    let chosen_file = gtk::FileDialog::builder()
        .title(gettext("Export"))
        .initial_name(suggested_name)
        .build()
        .save_future(active_application_window().as_ref())
        .await;
    match chosen_file {
        Err(_dialog_dismissed) => TextExportOutcome::ExportCancelled,
        Ok(chosen_file) => match chosen_file
            .replace_contents_future(
                exported_text.into_bytes(),
                None,
                false,
                gio::FileCreateFlags::REPLACE_DESTINATION | gio::FileCreateFlags::PRIVATE,
            )
            .await
        {
            Ok(_written_contents) => TextExportOutcome::TextSaved,
            Err(failed_write) => TextExportOutcome::ExportFailed(failed_write.1),
        },
    }
}

#[cfg(test)]
mod alert_choice_tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SampleDialogChoice {
        KeepChosen,
        DiscardChosen,
        SampleDismissed,
    }

    impl AlertChoice for SampleDialogChoice {
        const ANSWERING_CHOICES: &'static [Self] = &[Self::KeepChosen, Self::DiscardChosen];
        const DISMISSING_CHOICE: Self = Self::SampleDismissed;

        fn response_id(self) -> &'static str {
            match self {
                Self::KeepChosen => "keep",
                Self::DiscardChosen => "discard",
                Self::SampleDismissed => "cancel",
            }
        }
    }

    #[test]
    fn known_responses_parse_to_their_choice() {
        assert_eq!(
            alert_choice_for_response::<SampleDialogChoice>("keep"),
            SampleDialogChoice::KeepChosen
        );
        assert_eq!(
            alert_choice_for_response::<SampleDialogChoice>("discard"),
            SampleDialogChoice::DiscardChosen
        );
        assert_eq!(
            alert_choice_for_response::<SampleDialogChoice>("cancel"),
            SampleDialogChoice::SampleDismissed
        );
    }

    #[test]
    fn unknown_responses_dismiss_the_dialog() {
        assert_eq!(
            alert_choice_for_response::<SampleDialogChoice>("close"),
            SampleDialogChoice::SampleDismissed
        );
        assert_eq!(
            alert_choice_for_response::<SampleDialogChoice>(""),
            SampleDialogChoice::SampleDismissed
        );
    }
}
