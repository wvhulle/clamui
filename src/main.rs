mod activity_history;
mod application_settings;
mod application_window_shell;
mod background_detections;
mod clamav_components;
mod desktop_integration;
mod file_process_lock;
mod file_quarantine;
#[cfg(test)]
mod host_verification_tests;
mod malware_scan;
mod protection_status;
mod scan_profiles;
mod scheduled_scans;
mod shared_page_widget_templates;
mod signature_sources;
mod startup_arguments;
mod step_timeline;
mod system_audit;
mod systemd_bus;
mod systemd_journal;
mod text_export_dialog;
mod threat_intel_lookup;
mod virus_database;

use std::{path::PathBuf, process::ExitCode};

use gettextrs::{
    LocaleCategory, bind_textdomain_codeset, bindtextdomain, gettext, setlocale, textdomain,
};
use relm4::{
    adw,
    gtk::{gio::prelude::SettingsExt, glib},
};

use crate::{
    application_settings::preferences_dialog::{
        application_settings, settings_schema_is_installed,
    },
    application_window_shell::ApplicationWindowShell,
    desktop_integration::running_instance_forwarding::{
        another_instance_is_running, forward_to_running_instance,
    },
    scheduled_scans::headless_scheduled_scan::{parse_scheduled_scan_options, run_scheduled_scan},
    startup_arguments::parse_startup_arguments,
};

pub(crate) const RELEASE_APPLICATION_ID: &str = "io.github.wvhulle.ClamUI";
pub(crate) const SETTINGS_SCHEMA_ID: &str = RELEASE_APPLICATION_ID;
pub(crate) const APPLICATION_ICON_NAME: &str = RELEASE_APPLICATION_ID;
#[cfg(not(debug_assertions))]
pub(crate) const APPLICATION_ID: &str = RELEASE_APPLICATION_ID;
#[cfg(debug_assertions)]
pub(crate) const APPLICATION_ID: &str = "io.github.wvhulle.ClamUI.Devel";
#[cfg(not(debug_assertions))]
pub(crate) const APPLICATION_DATA_NAME: &str = "clamui";
#[cfg(debug_assertions)]
pub(crate) const APPLICATION_DATA_NAME: &str = "clamui-devel";
const TRANSLATION_DOMAIN: &str = "clamui";
const INSTALLED_LOCALE_DIRECTORY: &str = match option_env!("CLAMUI_LOCALE_DIRECTORY") {
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
                "The ClamUI settings schema is not installed. Run make install, or set \
                 GSETTINGS_SCHEMA_DIR."
            )
        );
        return ExitCode::FAILURE;
    }
    if let Some(scan_options) = parse_scheduled_scan_options(std::env::args()) {
        return run_scheduled_scan(scan_options);
    }
    let startup_request = parse_startup_arguments(std::env::args());
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
