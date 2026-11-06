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

pub async fn alert_response(
    alert_dialog: adw::AlertDialog,
    parent_widget: gtk::Widget,
) -> glib::GString {
    alert_dialog.choose_future(Some(&parent_widget)).await
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
