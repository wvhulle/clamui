use std::{io::Read, process::Stdio, time::Duration};

use gettextrs::gettext;
use tokio::time::timeout;

use crate::host_services::{
    clamav_config::detection_options::host_clamscan_detection_arguments,
    clamav_scanner::{
        scanner_command_builder::{ScannerBackend, ScannerProgramPaths, probe_clamd_availability},
        scanner_output_parser::sanitize_scanner_line,
    },
    desktop::{content_pipe::pipe_content_for_child, flatpak_sandbox::host_program_async_command},
};

const VERDICT_TIMEOUT: Duration = Duration::from_secs(600);
const STANDARD_INPUT_PREFIX: &str = "stdin: ";
const FOUND_SUFFIX: &str = " FOUND";
const CLEAN_EXIT_CODE: i32 = 0;
const FOUND_EXIT_CODE: i32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContentVerdict {
    StillDetected { detection_name: String },
    NoLongerDetected,
    VerdictUnavailable { failure_text: String },
}

pub fn detection_in_report(report_text: &str) -> Option<String> {
    report_text.lines().find_map(|report_line| {
        report_line
            .trim()
            .strip_prefix(STANDARD_INPUT_PREFIX)
            .and_then(|detection_text| detection_text.strip_suffix(FOUND_SUFFIX))
            .map(sanitize_scanner_line)
    })
}

pub fn verdict_from_exit(
    exit_code: Option<i32>,
    report_text: &str,
    diagnostic_text: &str,
) -> ContentVerdict {
    match exit_code {
        Some(CLEAN_EXIT_CODE) => ContentVerdict::NoLongerDetected,
        Some(FOUND_EXIT_CODE) => ContentVerdict::StillDetected {
            detection_name: detection_in_report(report_text)
                .unwrap_or_else(|| gettext("an unnamed detection")),
        },
        _scanner_error => ContentVerdict::VerdictUnavailable {
            failure_text: sanitize_scanner_line(
                diagnostic_text
                    .lines()
                    .chain(report_text.lines())
                    .find(|output_line| !output_line.trim().is_empty())
                    .unwrap_or_default(),
            ),
        },
    }
}

pub async fn scan_content_with_current_signatures(
    content_source: impl Read + Send + 'static,
) -> ContentVerdict {
    let scanner_programs =
        tokio::task::spawn_blocking(ScannerProgramPaths::locate_trusted_programs)
            .await
            .unwrap_or_else(|_interrupted_lookup| ScannerProgramPaths::nothing_found());
    let scanner_backend = probe_clamd_availability(&scanner_programs).await;
    let (scanner_location, detection_arguments) = match scanner_backend {
        ScannerBackend::ClamdDaemon => (&scanner_programs.clamdscan_program, Vec::new()),
        ScannerBackend::StandaloneClamscan => (
            &scanner_programs.clamscan_program,
            tokio::task::spawn_blocking(host_clamscan_detection_arguments)
                .await
                .unwrap_or_default(),
        ),
    };
    let scanner_path = match scanner_location.runnable_path() {
        Ok(scanner_path) => scanner_path.to_path_buf(),
        Err(program_refusal) => {
            return ContentVerdict::VerdictUnavailable {
                failure_text: program_refusal.to_string(),
            };
        }
    };
    let content_pipe = match pipe_content_for_child(content_source) {
        Ok(content_pipe) => content_pipe,
        Err(pipe_failure) => {
            return ContentVerdict::VerdictUnavailable {
                failure_text: pipe_failure.to_string(),
            };
        }
    };
    let mut verdict_command = host_program_async_command(&scanner_path, &[("LC_ALL", "C")]);
    verdict_command
        .arg("--no-summary")
        .args(detection_arguments)
        .arg("-")
        .stdin(Stdio::from(content_pipe))
        .kill_on_drop(true);
    match timeout(VERDICT_TIMEOUT, verdict_command.output()).await {
        Ok(Ok(scanner_output)) => verdict_from_exit(
            scanner_output.status.code(),
            &String::from_utf8_lossy(&scanner_output.stdout),
            &String::from_utf8_lossy(&scanner_output.stderr),
        ),
        Ok(Err(spawn_failure)) => ContentVerdict::VerdictUnavailable {
            failure_text: spawn_failure.to_string(),
        },
        Err(_verdict_timed_out) => ContentVerdict::VerdictUnavailable {
            failure_text: gettext("the scan took too long"),
        },
    }
}

#[cfg(test)]
mod content_verdict_tests {
    use super::*;

    #[test]
    fn exit_codes_and_reports_become_verdicts() {
        assert_eq!(
            verdict_from_exit(Some(1), "stdin: Win.Test.EICAR_HDB-1 FOUND\n", ""),
            ContentVerdict::StillDetected {
                detection_name: "Win.Test.EICAR_HDB-1".to_owned()
            }
        );
        assert_eq!(
            verdict_from_exit(Some(0), "stdin: OK\n", ""),
            ContentVerdict::NoLongerDetected
        );
        assert_eq!(
            verdict_from_exit(Some(2), "", "ERROR: Can't connect to clamd\n"),
            ContentVerdict::VerdictUnavailable {
                failure_text: "ERROR: Can't connect to clamd".to_owned()
            }
        );
    }

    #[test]
    #[ignore = "needs a real ClamAV host"]
    fn host_scanner_detects_eicar_on_standard_input() {
        let eicar_pattern =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec();
        let content_verdict =
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(scan_content_with_current_signatures(std::io::Cursor::new(
                    eicar_pattern,
                )));
        assert!(
            matches!(content_verdict, ContentVerdict::StillDetected { .. }),
            "{content_verdict:?}"
        );
    }
}
