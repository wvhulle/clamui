use std::collections::HashMap;

use relm4::{
    gtk,
    gtk::{
        gio,
        gio::prelude::*,
        glib,
        glib::variant::ToVariant,
        prelude::{GtkApplicationExt, GtkWindowExt, WidgetExt},
    },
};

use crate::{APPLICATION_ID, application_settings::preferences_dialog::application_settings};

const NOTIFICATIONS_ENABLED_KEY: &str = "notifications-enabled";
const NOTIFICATION_TIMEOUT_DEFAULT: i32 = -1;

fn window_has_user_attention(main_application: &gtk::Application) -> bool {
    main_application
        .active_window()
        .is_some_and(|active_window| active_window.is_visible() && active_window.is_active())
}

pub fn notify_outside_the_window(
    notification_id: &str,
    notification_title: &str,
    notification_body: &str,
) {
    let main_application = relm4::main_application();
    if !application_settings().boolean(NOTIFICATIONS_ENABLED_KEY)
        || window_has_user_attention(&main_application)
    {
        return;
    }
    let notification = gio::Notification::new(notification_title);
    notification.set_body(Some(notification_body));
    notification.set_default_action("app.show-window");
    main_application.send_notification(Some(notification_id), &notification);
}

pub fn send_session_notification(notification_title: &str, notification_body: &str) {
    if !application_settings().boolean(NOTIFICATIONS_ENABLED_KEY) {
        return;
    }
    let Ok(session_bus) = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) else {
        return;
    };
    let notification_arguments = (
        "ClamUI",
        0_u32,
        APPLICATION_ID,
        notification_title,
        notification_body,
        Vec::<String>::new(),
        HashMap::<String, glib::Variant>::new(),
        NOTIFICATION_TIMEOUT_DEFAULT,
    )
        .to_variant();
    let _notification_service_absent = session_bus.call_sync(
        Some("org.freedesktop.Notifications"),
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "Notify",
        Some(&notification_arguments),
        None,
        gio::DBusCallFlags::NONE,
        -1,
        gio::Cancellable::NONE,
    );
}
