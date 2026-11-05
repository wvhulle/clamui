use std::{os::unix::ffi::OsStrExt, path::PathBuf};

use relm4::gtk::{
    gio,
    gio::prelude::*,
    glib,
    glib::{VariantTy, variant::ToVariant},
};

use crate::APPLICATION_ID;

pub const SCAN_PATHS_ACTION: &str = "scan-paths";
pub const SHOW_WINDOW_ACTION: &str = "show-window";

pub fn application_object_path() -> String {
    format!("/{}", APPLICATION_ID.replace('.', "/"))
}

pub fn paths_as_variant(scan_targets: &[PathBuf]) -> glib::Variant {
    scan_targets
        .iter()
        .map(|scan_target| scan_target.as_os_str().as_bytes().to_vec())
        .collect::<Vec<_>>()
        .to_variant()
}

pub fn paths_from_variant(forwarded_paths: &glib::Variant) -> Vec<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    forwarded_paths
        .get::<Vec<Vec<u8>>>()
        .unwrap_or_default()
        .into_iter()
        .map(|path_bytes| PathBuf::from(std::ffi::OsString::from_vec(path_bytes)))
        .collect()
}

pub fn scan_paths_action_type() -> &'static VariantTy {
    VariantTy::new("aay").expect("the action type is a valid variant type")
}

fn running_instance_exists(session_bus: &gio::DBusConnection) -> bool {
    session_bus
        .call_sync(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            Some(&(APPLICATION_ID,).to_variant()),
            None,
            gio::DBusCallFlags::NONE,
            -1,
            gio::Cancellable::NONE,
        )
        .ok()
        .and_then(|name_reply| name_reply.get::<(bool,)>())
        .is_some_and(|name_reply| name_reply.0)
}

pub fn another_instance_is_running() -> bool {
    gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE)
        .is_ok_and(|session_bus| running_instance_exists(&session_bus))
}

pub fn forward_to_running_instance(scan_targets: &[PathBuf]) -> bool {
    let Ok(session_bus) = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE) else {
        return false;
    };
    if !running_instance_exists(&session_bus) {
        return false;
    }
    let remote_actions = gio::DBusActionGroup::get(
        &session_bus,
        Some(APPLICATION_ID),
        &application_object_path(),
    );
    if scan_targets.is_empty() {
        remote_actions.activate_action(SHOW_WINDOW_ACTION, None);
    } else {
        remote_actions.activate_action(SCAN_PATHS_ACTION, Some(&paths_as_variant(scan_targets)));
    }
    session_bus.flush_sync(gio::Cancellable::NONE).is_ok()
}

#[cfg(test)]
mod running_instance_forwarding_tests {
    use super::*;

    #[test]
    fn forwarded_paths_keep_non_utf8_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let scan_targets = vec![
            PathBuf::from(std::ffi::OsString::from_vec(b"/scan/\xff name".to_vec())),
            PathBuf::from("/scan/plain"),
        ];
        assert_eq!(
            paths_from_variant(&paths_as_variant(&scan_targets)),
            scan_targets
        );
    }

    #[test]
    fn the_object_path_follows_the_application_id() {
        assert_eq!(application_object_path(), "/io/github/wvhulle/ClamUI");
    }
}
