use std::{
    io::{self, Read},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use gettextrs::gettext;
use tokio::time::timeout;

use crate::host_services::{
    clamav_config::detection_options::host_clamscan_detection_arguments,
    clamav_programs::trusted_program_lookup::ProgramRefusal,
    clamav_scanner::{
        scanner_command_builder::{ScannerBackend, ScannerProgramPaths, probe_clamd_availability},
        scanner_exit_classification::{
            AbnormalScannerExit, ScannerExit, classify_scanner_exit_status,
        },
        scanner_output_parser::sanitize_scanner_line,
    },
    desktop::{content_pipe::pipe_content_for_child, flatpak_sandbox::host_program_async_command},
    quarantine_vault::quarantine_file_moves::QuarantineMoveFailure,
};

const VERDICT_TIMEOUT: Duration = Duration::from_secs(600);
const STANDARD_INPUT_PREFIX: &str = "stdin: ";
const FOUND_SUFFIX: &str = " FOUND";

#[derive(Debug, thiserror::Error)]
pub enum VerdictFailure {
    #[error("the scanner program cannot be used: {0}")]
    ScannerProgramRefused(#[from] ProgramRefusal),
    #[error("the content could not be passed to the scanner: {0}")]
    ContentPipeFailed(io::Error),
    #[error("the scanner could not be started: {0}")]
    ScannerSpawnFailed(io::Error),
    #[error("the scan took too long")]
    VerdictTimedOut,
    #[error("the scanner reported: {scanner_message}")]
    ScannerReported { scanner_message: String },
    #[error("the scanner exited abnormally: {0}")]
    ScannerExitedAbnormally(AbnormalScannerExit),
    #[error("the quarantined content could not be read: {0}")]
    PayloadUnreadable(QuarantineMoveFailure),
}

#[derive(Clone, Debug)]
pub enum ContentVerdict {
    StillDetected { detection_name: String },
    NoLongerDetected,
    VerdictUnavailable(Arc<VerdictFailure>),
}

impl From<VerdictFailure> for ContentVerdict {
    fn from(verdict_failure: VerdictFailure) -> Self {
        Self::VerdictUnavailable(Arc::new(verdict_failure))
    }
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
    scanner_exit: ScannerExit,
    report_text: &str,
    diagnostic_text: &str,
) -> ContentVerdict {
    match scanner_exit {
        ScannerExit::NoVirusFound => ContentVerdict::NoLongerDetected,
        ScannerExit::VirusFound => ContentVerdict::StillDetected {
            detection_name: detection_in_report(report_text)
                .unwrap_or_else(|| gettext("an unnamed detection")),
        },
        ScannerExit::ExitedAbnormally(abnormal_exit) => diagnostic_text
            .lines()
            .chain(report_text.lines())
            .map(str::trim)
            .find(|output_line| !output_line.is_empty())
            .map_or(
                VerdictFailure::ScannerExitedAbnormally(abnormal_exit),
                |scanner_message| VerdictFailure::ScannerReported {
                    scanner_message: scanner_message.to_owned(),
                },
            )
            .into(),
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
            return VerdictFailure::from(program_refusal).into();
        }
    };
    let content_pipe = match pipe_content_for_child(content_source) {
        Ok(content_pipe) => content_pipe,
        Err(pipe_failure) => {
            return VerdictFailure::ContentPipeFailed(pipe_failure).into();
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
            classify_scanner_exit_status(scanner_output.status),
            &String::from_utf8_lossy(&scanner_output.stdout),
            &String::from_utf8_lossy(&scanner_output.stderr),
        ),
        Ok(Err(spawn_failure)) => VerdictFailure::ScannerSpawnFailed(spawn_failure).into(),
        Err(_verdict_timed_out) => VerdictFailure::VerdictTimedOut.into(),
    }
}

#[cfg(test)]
mod content_verdict_tests {
    use super::*;

    #[test]
    fn scanner_exits_and_reports_become_verdicts() {
        assert!(matches!(
            verdict_from_exit(
                ScannerExit::VirusFound,
                "stdin: Win.Test.EICAR_HDB-1 FOUND\n",
                ""
            ),
            ContentVerdict::StillDetected { detection_name } if detection_name == "Win.Test.EICAR_HDB-1"
        ));
        assert!(matches!(
            verdict_from_exit(ScannerExit::NoVirusFound, "stdin: OK\n", ""),
            ContentVerdict::NoLongerDetected
        ));
        assert!(matches!(
            verdict_from_exit(
                ScannerExit::ExitedAbnormally(AbnormalScannerExit::ScannerError { exit_code: 2 }),
                "",
                "ERROR: Can't connect to clamd\n"
            ),
            ContentVerdict::VerdictUnavailable(verdict_failure)
                if matches!(
                    verdict_failure.as_ref(),
                    VerdictFailure::ScannerReported { scanner_message }
                        if scanner_message == "ERROR: Can't connect to clamd"
                )
        ));
    }

    #[test]
    fn a_silently_killed_scanner_keeps_its_signal() {
        let killed_exit = AbnormalScannerExit::KilledBySignal { signal_number: 9 };
        assert!(matches!(
            verdict_from_exit(ScannerExit::ExitedAbnormally(killed_exit), "", ""),
            ContentVerdict::VerdictUnavailable(verdict_failure)
                if matches!(
                    verdict_failure.as_ref(),
                    VerdictFailure::ScannerExitedAbnormally(reported_exit) if *reported_exit == killed_exit
                )
        ));
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
