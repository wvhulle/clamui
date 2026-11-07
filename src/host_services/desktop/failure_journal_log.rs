use std::error::Error;

use relm4::gtk::glib;

const FAILURE_LOG_DOMAIN: &str = "lazaret";

pub fn log_failure_to_journal(failure_context: &str, failure: &dyn Error) {
    glib::g_warning!(FAILURE_LOG_DOMAIN, "{failure_context}: {failure}");
}

pub fn log_failed_outcome<Loaded, Failure: Error>(
    failure_context: &str,
    load_outcome: &Result<Loaded, Failure>,
) {
    if let Err(failure) = load_outcome {
        log_failure_to_journal(failure_context, failure);
    }
}
