use gettextrs::gettext;
use relm4::{
    Sender, adw,
    adw::prelude::*,
    gtk::{gio, gio::prelude::SettingsExt},
};

use crate::{
    host_services::desktop::stored_settings::CLOSE_ACTION_KEY,
    shared_widgets::awaited_dialogs::{alert_response, deliver_local_outcome},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseAction {
    QuitCompletely,
    HideToTray,
    AskEachTime,
}

impl CloseAction {
    pub fn read_from(stored_settings: &gio::Settings) -> Self {
        match stored_settings.string(CLOSE_ACTION_KEY).as_str() {
            "minimize" => Self::HideToTray,
            "ask" => Self::AskEachTime,
            _quit => Self::QuitCompletely,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseAnswer {
    CloseCancelled,
    QuitChosen,
    KeepRunningChosen,
}

pub fn present_close_confirmation<Message: 'static>(
    window_root: &adw::ApplicationWindow,
    answer_sender: Sender<Message>,
    answered_message: fn(CloseAnswer) -> Message,
) {
    let close_dialog = adw::AlertDialog::new(
        Some(&gettext("Close Lazaret?")),
        Some(&gettext(
            "Detection alerts stop while Lazaret isn't running. Keep it running in the \
             background, or quit completely?",
        )),
    );
    close_dialog.add_response("cancel", &gettext("Cancel"));
    close_dialog.add_response("quit", &gettext("Quit"));
    close_dialog.add_response("minimize", &gettext("Keep Running"));
    close_dialog.set_default_response(Some("minimize"));
    close_dialog.set_close_response("cancel");
    deliver_local_outcome(
        answer_sender,
        alert_response(close_dialog, window_root.clone().upcast()),
        move |chosen_response| {
            Some(answered_message(match chosen_response.as_str() {
                "quit" => CloseAnswer::QuitChosen,
                "minimize" => CloseAnswer::KeepRunningChosen,
                _cancelled => CloseAnswer::CloseCancelled,
            }))
        },
    );
}
