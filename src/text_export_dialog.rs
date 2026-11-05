use gettextrs::gettext;
use relm4::{
    gtk,
    gtk::{
        gio,
        gio::prelude::*,
        glib,
        prelude::{Cast, WidgetExt},
    },
};

#[derive(Debug)]
pub enum TextExportOutcome {
    TextSaved,
    ExportCancelled,
    ExportFailed(glib::Error),
}

pub fn describe_export_failure(export_failure: &glib::Error) -> String {
    gettext("Could not save the file: {error}").replace("{error}", &export_failure.to_string())
}

pub async fn save_text_with_dialog(
    parent_widget: &gtk::Widget,
    suggested_name: &str,
    exported_text: String,
) -> TextExportOutcome {
    let parent_window = parent_widget
        .root()
        .and_then(|window_root| window_root.downcast::<gtk::Window>().ok());
    let chosen_file = gtk::FileDialog::builder()
        .title(gettext("Export"))
        .initial_name(suggested_name)
        .build()
        .save_future(parent_window.as_ref())
        .await;
    let Ok(chosen_file) = chosen_file else {
        return TextExportOutcome::ExportCancelled;
    };
    let saved_contents = chosen_file
        .replace_contents_future(
            exported_text.into_bytes(),
            None,
            false,
            gio::FileCreateFlags::REPLACE_DESTINATION | gio::FileCreateFlags::PRIVATE,
        )
        .await;
    match saved_contents {
        Ok(_written_contents) => TextExportOutcome::TextSaved,
        Err(failed_write) => TextExportOutcome::ExportFailed(failed_write.1),
    }
}
