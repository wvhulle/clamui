use std::{io, os::unix::process::ExitStatusExt, process::ExitStatus};

const NO_VIRUS_FOUND_EXIT_CODE: i32 = 0;
const VIRUS_FOUND_EXIT_CODE: i32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerExit {
    NoVirusFound,
    VirusFound,
    ExitedAbnormally(AbnormalScannerExit),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AbnormalScannerExit {
    #[error("the scanner reported an error with exit code {exit_code}")]
    ScannerError { exit_code: i32 },
    #[error("the scanner was stopped by signal {signal_number}")]
    KilledBySignal { signal_number: i32 },
    #[error("the scanner ended with the unrecognized wait status {raw_wait_status}")]
    UnrecognizedWaitStatus { raw_wait_status: i32 },
    #[error("waiting for the scanner failed: {wait_failure_kind}")]
    WaitFailed { wait_failure_kind: io::ErrorKind },
}

pub fn classify_scanner_exit_status(exit_status: ExitStatus) -> ScannerExit {
    match exit_status.code() {
        Some(NO_VIRUS_FOUND_EXIT_CODE) => ScannerExit::NoVirusFound,
        Some(VIRUS_FOUND_EXIT_CODE) => ScannerExit::VirusFound,
        Some(exit_code) => {
            ScannerExit::ExitedAbnormally(AbnormalScannerExit::ScannerError { exit_code })
        }
        None => ScannerExit::ExitedAbnormally(classify_exit_without_code(exit_status)),
    }
}

pub fn classify_exit_without_code(exit_status: ExitStatus) -> AbnormalScannerExit {
    exit_status.signal().map_or(
        AbnormalScannerExit::UnrecognizedWaitStatus {
            raw_wait_status: exit_status.into_raw(),
        },
        |signal_number| AbnormalScannerExit::KilledBySignal { signal_number },
    )
}

pub fn classify_scanner_wait(wait_outcome: io::Result<ExitStatus>) -> ScannerExit {
    match wait_outcome {
        Ok(exit_status) => classify_scanner_exit_status(exit_status),
        Err(wait_failure) => ScannerExit::ExitedAbnormally(AbnormalScannerExit::WaitFailed {
            wait_failure_kind: wait_failure.kind(),
        }),
    }
}

#[cfg(test)]
mod scanner_exit_classification_tests {
    use super::*;

    const SIGKILL_NUMBER: i32 = 9;

    fn exit_status_with_code(exit_code: i32) -> ExitStatus {
        ExitStatus::from_raw(exit_code << 8)
    }

    #[test]
    fn clamav_exit_codes_become_scanner_exits() {
        assert_eq!(
            classify_scanner_exit_status(exit_status_with_code(0)),
            ScannerExit::NoVirusFound
        );
        assert_eq!(
            classify_scanner_exit_status(exit_status_with_code(1)),
            ScannerExit::VirusFound
        );
        assert_eq!(
            classify_scanner_exit_status(exit_status_with_code(2)),
            ScannerExit::ExitedAbnormally(AbnormalScannerExit::ScannerError { exit_code: 2 })
        );
    }

    #[test]
    fn a_killed_scanner_keeps_its_signal_instead_of_an_exit_code() {
        assert_eq!(
            classify_scanner_exit_status(ExitStatus::from_raw(SIGKILL_NUMBER)),
            ScannerExit::ExitedAbnormally(AbnormalScannerExit::KilledBySignal {
                signal_number: SIGKILL_NUMBER
            })
        );
    }

    #[test]
    fn a_failed_wait_is_not_mistaken_for_an_exit_code() {
        assert_eq!(
            classify_scanner_wait(Err(io::Error::from(io::ErrorKind::NotFound))),
            ScannerExit::ExitedAbnormally(AbnormalScannerExit::WaitFailed {
                wait_failure_kind: io::ErrorKind::NotFound
            })
        );
    }
}
