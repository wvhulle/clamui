mod application_window_shell;
mod clamav_components;
mod file_quarantine;
#[cfg(test)]
mod host_verification_tests;
mod malware_scan;
mod shared_page_widget_templates;
mod virus_database;

use gettextrs::{LocaleCategory, bind_textdomain_codeset, bindtextdomain, setlocale, textdomain};
use relm4::adw;

use crate::application_window_shell::ApplicationWindowShell;

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

fn main() {
    initialize_translations();
    let application = adw::Application::builder()
        .application_id(APPLICATION_ID)
        .build();
    relm4::RelmApp::from_app(application).run_async::<ApplicationWindowShell>(());
}
