use std::path::PathBuf;

use gettextrs::gettext;
use relm4::{
    Sender, gtk,
    gtk::{gio, glib, prelude::*},
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

pub fn request_files_to_open<Message: 'static>(
    dialog_title: String,
    message_sender: Sender<Message>,
    chosen_message: fn(Vec<PathBuf>) -> Message,
) {
    relm4::spawn_local(async move {
        let chosen_files = gtk::FileDialog::builder()
            .title(dialog_title)
            .build()
            .open_multiple_future(active_application_window().as_ref())
            .await;
        if let Ok(chosen_files) = chosen_files {
            let chosen_paths = (0..chosen_files.n_items())
                .filter_map(|file_position| chosen_files.item(file_position))
                .filter_map(|chosen_object| chosen_object.downcast::<gio::File>().ok())
                .filter_map(|chosen_file| chosen_file.path())
                .collect();
            message_sender.emit(chosen_message(chosen_paths));
        }
    });
}

pub fn request_folder_to_open<Message: 'static>(
    dialog_title: String,
    message_sender: Sender<Message>,
    chosen_message: fn(PathBuf) -> Message,
) {
    relm4::spawn_local(async move {
        let chosen_folder = gtk::FileDialog::builder()
            .title(dialog_title)
            .build()
            .select_folder_future(active_application_window().as_ref())
            .await;
        if let Some(folder_path) = chosen_folder
            .ok()
            .and_then(|chosen_folder| chosen_folder.path())
        {
            message_sender.emit(chosen_message(folder_path));
        }
    });
}

pub fn request_file_to_import<Message: 'static>(
    dialog_title: String,
    message_sender: Sender<Message>,
    imported_message: fn(ImportedFileOutcome) -> Message,
) {
    relm4::spawn_local(async move {
        let chosen_file = gtk::FileDialog::builder()
            .title(dialog_title)
            .build()
            .open_future(active_application_window().as_ref())
            .await;
        let import_outcome = match chosen_file {
            Err(_dialog_dismissed) => ImportedFileOutcome::ImportCancelled,
            Ok(chosen_file) => match chosen_file.load_contents_future().await {
                Ok(loaded_contents) => ImportedFileOutcome::FileRead(loaded_contents.0.to_vec()),
                Err(read_failure) => ImportedFileOutcome::ImportFailed(read_failure),
            },
        };
        message_sender.emit(imported_message(import_outcome));
    });
}

pub fn request_text_export<Message: 'static>(
    suggested_name: String,
    exported_text: String,
    message_sender: Sender<Message>,
    finished_message: fn(TextExportOutcome) -> Message,
) {
    relm4::spawn_local(async move {
        let chosen_file = gtk::FileDialog::builder()
            .title(gettext("Export"))
            .initial_name(suggested_name)
            .build()
            .save_future(active_application_window().as_ref())
            .await;
        let export_outcome = match chosen_file {
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
        };
        message_sender.emit(finished_message(export_outcome));
    });
}
