use gettextrs::gettext;

use crate::host_services::clamav_scanner::{
    scanner_output_parser::sanitize_scanner_line, scanner_process_events::ScanStartFailure,
};

pub fn describe_start_failure(start_failure: &ScanStartFailure) -> String {
    match start_failure {
        ScanStartFailure::ScannerProgramMissing => {
            gettext("The ClamAV scanner is not installed or not on the search path.")
        }
        ScanStartFailure::ScannerProgramReplaceable {
            candidate_path,
            replaceable_path,
        } => gettext(
            "Lazaret refused to run {program}, because your account can replace {replaceable}. \
             Install ClamAV system-wide so a program planted by malware can't fake clean results.",
        )
        .replace(
            "{replaceable}",
            &sanitize_scanner_line(&replaceable_path.to_string_lossy()),
        )
        .replace(
            "{program}",
            &sanitize_scanner_line(&candidate_path.to_string_lossy()),
        ),
        ScanStartFailure::ScannerSpawnFailed(spawn_failure) => {
            gettext("The scanner could not be started: {error}")
                .replace("{error}", &spawn_failure.to_string())
        }
        ScanStartFailure::ScannerWorkDirectoryUnavailable(work_directory_failure) => {
            gettext("Unable to create the private scanner work directory: {error}")
                .replace("{error}", &work_directory_failure.to_string())
        }
        ScanStartFailure::ScannerOutputUncaptured => {
            gettext("The scanner output could not be captured.")
        }
        ScanStartFailure::DetectionSettingsUnreadable(settings_failure) => gettext(
            "The scan did not start, because the clamd detection settings could not be read: \
             {error}",
        )
        .replace("{error}", &settings_failure.to_string()),
        ScanStartFailure::ProgramLookupFailed(lookup_failure) => gettext(
            "The scan did not start, because the scanner programs could not be looked up: {error}",
        )
        .replace("{error}", &lookup_failure.to_string()),
        ScanStartFailure::ScanInputUnavailable {
            input_path,
            input_failure,
        } => gettext("Unable to safely open scan input {path}: {error}")
            .replace("{error}", &input_failure.to_string())
            .replace(
                "{path}",
                &sanitize_scanner_line(&input_path.to_string_lossy()),
            ),
    }
}

#[cfg(test)]
mod scanner_start_failure_text_tests {
    use super::*;
    use crate::host_services::{
        clamav_config::detection_options::DetectionSettingsFailure,
        clamav_scanner::scanner_command_builder::ProgramLookupFailure,
    };

    #[tokio::test]
    async fn unreadable_detection_settings_stop_the_scan_with_a_reason() {
        let abandoned_read = tokio::spawn(std::future::pending::<()>());
        abandoned_read.abort();
        let interrupted_read = abandoned_read.await.expect_err("the read was aborted");
        let start_text = describe_start_failure(&ScanStartFailure::DetectionSettingsUnreadable(
            DetectionSettingsFailure::ReadingTaskInterrupted(interrupted_read),
        ));
        assert!(start_text.contains("detection settings could not be read"));
    }

    #[tokio::test]
    async fn an_interrupted_program_lookup_stops_the_scan_with_a_reason() {
        let abandoned_lookup = tokio::spawn(std::future::pending::<()>());
        abandoned_lookup.abort();
        let interrupted_lookup = abandoned_lookup.await.expect_err("the lookup was aborted");
        let start_text = describe_start_failure(&ScanStartFailure::ProgramLookupFailed(
            ProgramLookupFailure::LookupInterrupted(interrupted_lookup),
        ));
        assert!(start_text.contains("scanner programs could not be looked up"));
    }
}
