mod activity_history;
mod application_settings;
mod application_window_shell;
mod clamav_components;
mod file_quarantine;
#[cfg(test)]
mod host_verification_tests;
mod malware_scan;
mod scan_profiles;
mod shared_page_widget_templates;
mod startup_arguments;
mod text_export_dialog;
mod virus_database;

use std::process::ExitCode;

use gettextrs::{
    LocaleCategory, bind_textdomain_codeset, bindtextdomain, gettext, setlocale, textdomain,
};
use relm4::adw;

use crate::{
    application_settings::preferences_dialog::settings_schema_is_installed,
    application_window_shell::ApplicationWindowShell, startup_arguments::parse_startup_arguments,
};

pub(crate) const APPLICATION_ID: &str = "io.github.wvhulle.ClamUI";
const TRANSLATION_DOMAIN: &str = "clamui";
const INSTALLED_LOCALE_DIRECTORY: &str = match option_env!("CLAMUI_LOCALE_DIRECTORY") {
    Some(locale_directory) => locale_directory,
    None => "/usr/local/share/locale",
};

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
    let application = adw::Application::builder()
        .application_id(APPLICATION_ID)
        .build();
    let startup_request = parse_startup_arguments(std::env::args());
    relm4::RelmApp::from_app(application)
        .with_args(Vec::new())
        .run_async::<ApplicationWindowShell>(startup_request);
    ExitCode::SUCCESS
}
