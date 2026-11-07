mod application_window;
mod findings;
mod headless_modes;
mod host_services;
#[cfg(test)]
mod host_verification_tests;
mod logs_page;
mod preferences_dialog;
mod protection_page;
mod scans;
mod shared_widgets;
mod sharing;
mod signatures;

use std::{path::PathBuf, process::ExitCode};

use gettextrs::{
    LocaleCategory, bind_textdomain_codeset, bindtextdomain, gettext, setlocale, textdomain,
};
use relm4::{
    adw,
    gtk::{gio::prelude::SettingsExt, glib},
};

use crate::{
    application_window::{
        application_window_shell::ApplicationWindowShell,
        startup_arguments::{
            StartupPageRequest, known_startup_page_names, parse_startup_arguments,
        },
    },
    headless_modes::headless_scheduled_scan::{parse_scheduled_scan_options, run_scheduled_scan},
    host_services::desktop::{
        running_instance_forwarding::{another_instance_is_running, forward_to_running_instance},
        stored_settings::{application_settings, settings_schema_is_installed},
    },
};

pub(crate) const RELEASE_APPLICATION_ID: &str = "page.codeberg.wvhulle.Lazaret";
pub(crate) const SETTINGS_SCHEMA_ID: &str = RELEASE_APPLICATION_ID;
pub(crate) const APPLICATION_ICON_NAME: &str = RELEASE_APPLICATION_ID;
pub(crate) const TRAY_ICON_NAME: &str = "page.codeberg.wvhulle.Lazaret-symbolic";
pub(crate) const TRAY_ATTENTION_ICON_NAME: &str =
    "page.codeberg.wvhulle.Lazaret-attention-symbolic";
#[cfg(not(debug_assertions))]
pub(crate) const APPLICATION_ID: &str = RELEASE_APPLICATION_ID;
#[cfg(debug_assertions)]
pub(crate) const APPLICATION_ID: &str = "page.codeberg.wvhulle.Lazaret.Devel";
#[cfg(not(debug_assertions))]
pub(crate) const APPLICATION_DATA_NAME: &str = "lazaret";
#[cfg(debug_assertions)]
pub(crate) const APPLICATION_DATA_NAME: &str = "lazaret-devel";
const TRANSLATION_DOMAIN: &str = "lazaret";
const INSTALLED_LOCALE_DIRECTORY: &str = match option_env!("LAZARET_LOCALE_DIRECTORY") {
    Some(locale_directory) => locale_directory,
    None => "/usr/local/share/locale",
};

pub(crate) fn application_data_directory() -> PathBuf {
    glib::user_data_dir().join(APPLICATION_DATA_NAME)
}

fn initialize_translations() {
    unsafe {
        setlocale(LocaleCategory::LcAll, "");
    }
    let _translations_unavailable = bindtextdomain(TRANSLATION_DOMAIN, INSTALLED_LOCALE_DIRECTORY)
        .and_then(|_bound_directory| bind_textdomain_codeset(TRANSLATION_DOMAIN, "UTF-8"))
        .and_then(|_bound_codeset| textdomain(TRANSLATION_DOMAIN));
}

fn main() -> ExitCode {
    initialize_translations();
    if !settings_schema_is_installed() {
        eprintln!(
            "{}",
            gettext(
                "The Lazaret settings schema is not installed. Run make install, or set \
                 GSETTINGS_SCHEMA_DIR."
            )
        );
        return ExitCode::FAILURE;
    }
    if let Some(scan_options) = parse_scheduled_scan_options(std::env::args()) {
        return run_scheduled_scan(scan_options);
    }
    let startup_request = parse_startup_arguments(std::env::args());
    if let StartupPageRequest::UnrecognizedPage {
        requested_page_name,
    } = &startup_request.startup_page
    {
        eprintln!(
            "{}",
            gettext("Lazaret has no page named {page}, so it opens Protection. Pages: {pages}")
                .replace("{page}", requested_page_name)
                .replace("{pages}", &known_startup_page_names().join(", "))
        );
    }
    if startup_request.start_in_background && another_instance_is_running() {
        return ExitCode::SUCCESS;
    }
    if !startup_request.start_in_background
        && forward_to_running_instance(&startup_request.scan_targets)
    {
        return ExitCode::SUCCESS;
    }
    let application = adw::Application::builder()
        .application_id(APPLICATION_ID)
        .build();
    let start_hidden = startup_request.start_in_background
        || application_settings().boolean("start-in-background");
    relm4::RelmApp::from_app(application)
        .with_args(Vec::new())
        .visible_on_activate(!start_hidden)
        .run_async::<ApplicationWindowShell>(startup_request);
    ExitCode::SUCCESS
}
