use gettextrs::gettext;

use crate::host_services::clamav_scanner::scanner_exit_classification::AbnormalScannerExit;

pub fn abnormal_scanner_exit_text(abnormal_exit: &AbnormalScannerExit) -> String {
    match abnormal_exit {
        AbnormalScannerExit::ScannerError { exit_code } => {
            gettext("The scanner stopped with error code {code}.")
                .replace("{code}", &exit_code.to_string())
        }
        AbnormalScannerExit::KilledBySignal { signal_number } => {
            gettext("The scanner was stopped by signal {signal}.")
                .replace("{signal}", &signal_number.to_string())
        }
        AbnormalScannerExit::UnrecognizedWaitStatus { raw_wait_status } => {
            gettext("The scanner ended in a way Lazaret does not recognize (wait status {status}).")
                .replace("{status}", &raw_wait_status.to_string())
        }
        AbnormalScannerExit::WaitFailed { wait_failure_kind } => {
            gettext("Lazaret lost track of the scanner process: {error}.")
                .replace("{error}", &wait_failure_kind.to_string())
        }
    }
}
