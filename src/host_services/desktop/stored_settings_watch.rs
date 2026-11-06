use relm4::{
    Sender,
    gtk::{gio, gio::prelude::*},
};

pub fn forward_setting_changes<Message: 'static>(
    watched_settings: &gio::Settings,
    watched_keys: &[&'static str],
    message_sender: &Sender<Message>,
    changed_message: fn(&gio::Settings, &str) -> Message,
) {
    watched_keys.iter().for_each(|watched_key| {
        let change_sender = message_sender.clone();
        watched_settings.connect_changed(
            Some(watched_key),
            move |changed_settings, changed_key| {
                change_sender.emit(changed_message(changed_settings, changed_key));
            },
        );
        let _key_read_so_changes_are_emitted = watched_settings.value(watched_key);
    });
}
