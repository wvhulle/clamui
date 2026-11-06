use std::{io, process::ExitStatus};

use crate::host_services::clamav_scanner::scanner_exit_classification::{
    AbnormalScannerExit, classify_exit_without_code,
};

const UPDATER_SUCCESS_STATUS: i32 = 0;
const FRESHCLAM_ALREADY_CURRENT_STATUS: i32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureUpdaterProgram {
    Freshclam,
    Fangfrisch,
}

impl SignatureUpdaterProgram {
    pub const fn program_name(self) -> &'static str {
        match self {
            Self::Freshclam => "freshclam",
            Self::Fangfrisch => "fangfrisch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdaterExitMeaning {
    UpdateSucceeded,
    UpdateAlreadyCurrent,
    UpdaterError { exit_status: i32 },
}

pub const fn classify_updater_exit_status(
    updater_program: SignatureUpdaterProgram,
    exit_status: i32,
) -> UpdaterExitMeaning {
    match (updater_program, exit_status) {
        (
            SignatureUpdaterProgram::Freshclam | SignatureUpdaterProgram::Fangfrisch,
            UPDATER_SUCCESS_STATUS,
        ) => UpdaterExitMeaning::UpdateSucceeded,
        (SignatureUpdaterProgram::Freshclam, FRESHCLAM_ALREADY_CURRENT_STATUS) => {
            UpdaterExitMeaning::UpdateAlreadyCurrent
        }
        (SignatureUpdaterProgram::Freshclam | SignatureUpdaterProgram::Fangfrisch, exit_status) => {
            UpdaterExitMeaning::UpdaterError { exit_status }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshclamExit {
    UpdateSucceeded,
    UpdateAlreadyCurrent,
    ExitedAbnormally(AbnormalScannerExit),
}

pub fn classify_freshclam_wait(wait_outcome: io::Result<ExitStatus>) -> FreshclamExit {
    match wait_outcome {
        Ok(exit_status) => exit_status.code().map_or(
            FreshclamExit::ExitedAbnormally(classify_exit_without_code(exit_status)),
            |exit_code| match classify_updater_exit_status(
                SignatureUpdaterProgram::Freshclam,
                exit_code,
            ) {
                UpdaterExitMeaning::UpdateSucceeded => FreshclamExit::UpdateSucceeded,
                UpdaterExitMeaning::UpdateAlreadyCurrent => FreshclamExit::UpdateAlreadyCurrent,
                UpdaterExitMeaning::UpdaterError { exit_status } => {
                    FreshclamExit::ExitedAbnormally(AbnormalScannerExit::ScannerError {
                        exit_code: exit_status,
                    })
                }
            },
        ),
        Err(wait_failure) => FreshclamExit::ExitedAbnormally(AbnormalScannerExit::WaitFailed {
            wait_failure_kind: wait_failure.kind(),
        }),
    }
}

#[cfg(test)]
mod updater_exit_status_tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    const SIGKILL_NUMBER: i32 = 9;

    fn exit_status_with_code(exit_code: i32) -> ExitStatus {
        ExitStatus::from_raw(exit_code << 8)
    }

    #[test]
    fn freshclam_exit_one_is_already_current_but_fangfrisch_exit_one_is_an_error() {
        assert_eq!(
            classify_updater_exit_status(SignatureUpdaterProgram::Freshclam, 1),
            UpdaterExitMeaning::UpdateAlreadyCurrent
        );
        assert_eq!(
            classify_updater_exit_status(SignatureUpdaterProgram::Fangfrisch, 1),
            UpdaterExitMeaning::UpdaterError { exit_status: 1 }
        );
        assert_eq!(
            classify_updater_exit_status(SignatureUpdaterProgram::Freshclam, 52),
            UpdaterExitMeaning::UpdaterError { exit_status: 52 }
        );
    }

    #[test]
    fn freshclam_waits_become_typed_exits() {
        assert_eq!(
            classify_freshclam_wait(Ok(exit_status_with_code(0))),
            FreshclamExit::UpdateSucceeded
        );
        assert_eq!(
            classify_freshclam_wait(Ok(exit_status_with_code(1))),
            FreshclamExit::UpdateAlreadyCurrent
        );
        assert_eq!(
            classify_freshclam_wait(Ok(ExitStatus::from_raw(SIGKILL_NUMBER))),
            FreshclamExit::ExitedAbnormally(AbnormalScannerExit::KilledBySignal {
                signal_number: SIGKILL_NUMBER
            })
        );
        assert_eq!(
            classify_freshclam_wait(Err(io::Error::from(io::ErrorKind::Interrupted))),
            FreshclamExit::ExitedAbnormally(AbnormalScannerExit::WaitFailed {
                wait_failure_kind: io::ErrorKind::Interrupted
            })
        );
    }
}
