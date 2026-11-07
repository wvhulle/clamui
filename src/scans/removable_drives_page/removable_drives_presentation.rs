use std::path::Path;

use bytesize::ByteSize;
use gettextrs::gettext;
use relm4::gtk::glib;

use crate::{
    host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    scans::removable_drives_page::{
        drive_mount_checks::{
            DeviceAutoScanSettings, DriveScanDecision, DriveSizeLimit, DriveSkipReason,
        },
        removable_drives_state::DeviceScanStatus,
    },
    shared_widgets::scan_runs::scan_results_section::scan_results_state::ScanResultsStatus,
};

pub fn drive_size_text(drive_size: ByteSize) -> String {
    glib::format_size(drive_size.as_u64()).into()
}

pub fn shown_drive_name(drive_name: &str, mount_path: &Path) -> String {
    let fallback_name = mount_path
        .file_name()
        .unwrap_or(mount_path.as_os_str())
        .to_string_lossy();
    sanitize_scanner_line(if drive_name.trim().is_empty() {
        &fallback_name
    } else {
        drive_name
    })
}

pub fn auto_scan_state_text(auto_scan_settings: DeviceAutoScanSettings) -> String {
    match (
        auto_scan_settings.auto_scan_enabled,
        auto_scan_settings.drive_size_limit(),
    ) {
        (false, _) => gettext("Off"),
        (true, DriveSizeLimit::NoSizeLimit) => gettext("Scans every drive"),
        (true, DriveSizeLimit::LimitedTo(size_limit)) => {
            gettext("Scans drives up to {size}").replace("{size}", &drive_size_text(size_limit))
        }
    }
}

fn skip_reason_text(skip_reason: DriveSkipReason) -> String {
    match skip_reason {
        DriveSkipReason::SkippedLargerThanLimit {
            drive_size,
            size_limit,
        } => gettext("Not scanned: {size} is larger than the {limit} limit")
            .replace("{size}", &drive_size_text(drive_size))
            .replace("{limit}", &drive_size_text(size_limit)),
        DriveSkipReason::SkippedOnBattery => {
            gettext("Not scanned: the computer was running on battery")
        }
        DriveSkipReason::SkippedAutoScanOff => gettext("Not scanned: device auto-scan is off"),
        DriveSkipReason::SkippedWhileScanning => gettext("Not scanned: another scan was running"),
        DriveSkipReason::SizeUnreadable => {
            gettext("Not scanned: the size of the drive could not be read")
        }
    }
}

pub fn drive_decision_text(drive_decision: DriveScanDecision) -> String {
    match drive_decision {
        DriveScanDecision::DriveSettling => gettext("Checking the drive…"),
        DriveScanDecision::DriveScanning => gettext("Scanning…"),
        DriveScanDecision::ScannedDrive { scan_result } => match scan_result {
            ScanResultsStatus::ThreatsDetected => gettext("Scanned, threats found"),
            ScanResultsStatus::NoThreatsDetected => gettext("Scanned, no threats found"),
            ScanResultsStatus::FinishedWithProblems => {
                gettext("Scanned, but the scan did not finish cleanly")
            }
            ScanResultsStatus::ScanCancelled => gettext("Scan cancelled"),
        },
        DriveScanDecision::DriveSkipped(skip_reason) => skip_reason_text(skip_reason),
    }
}

pub const fn drive_decision_icon(drive_decision: DriveScanDecision) -> &'static str {
    match drive_decision {
        DriveScanDecision::DriveSettling | DriveScanDecision::DriveScanning => {
            "content-loading-symbolic"
        }
        DriveScanDecision::ScannedDrive {
            scan_result: ScanResultsStatus::NoThreatsDetected,
        } => "object-select-symbolic",
        DriveScanDecision::ScannedDrive {
            scan_result:
                ScanResultsStatus::ThreatsDetected | ScanResultsStatus::FinishedWithProblems,
        } => "dialog-warning-symbolic",
        DriveScanDecision::ScannedDrive {
            scan_result: ScanResultsStatus::ScanCancelled,
        }
        | DriveScanDecision::DriveSkipped(_) => "action-unavailable-symbolic",
    }
}

pub fn device_scan_title(device_scan_status: &DeviceScanStatus) -> String {
    match device_scan_status {
        DeviceScanStatus::DeviceScanRunning { drive_name } => {
            gettext("Scanning {drive}").replace("{drive}", drive_name)
        }
        DeviceScanStatus::NoDeviceScanYet | DeviceScanStatus::DeviceScanEnded { .. } => {
            gettext("Drive scan")
        }
    }
}

#[cfg(test)]
mod removable_drives_presentation_tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn each_skip_reason_says_why_the_drive_was_not_scanned() {
        assert_eq!(
            drive_decision_text(DriveScanDecision::DriveSkipped(
                DriveSkipReason::SkippedLargerThanLimit {
                    drive_size: ByteSize::gb(64),
                    size_limit: ByteSize::gb(32),
                }
            )),
            "Not scanned: 64.0\u{a0}GB is larger than the 32.0\u{a0}GB limit"
        );
        assert_eq!(
            drive_decision_text(DriveScanDecision::DriveSkipped(
                DriveSkipReason::SizeUnreadable
            )),
            "Not scanned: the size of the drive could not be read"
        );
        assert_eq!(
            drive_decision_text(DriveScanDecision::ScannedDrive {
                scan_result: ScanResultsStatus::ThreatsDetected
            }),
            "Scanned, threats found"
        );
    }

    #[test]
    fn the_auto_scan_state_names_the_size_limit() {
        let enabled_settings = DeviceAutoScanSettings {
            auto_scan_enabled: true,
            maximum_gigabytes: 32,
            skip_on_battery: true,
        };
        assert_eq!(
            auto_scan_state_text(enabled_settings),
            "Scans drives up to 32.0\u{a0}GB"
        );
        assert_eq!(
            auto_scan_state_text(DeviceAutoScanSettings {
                maximum_gigabytes: 0,
                ..enabled_settings
            }),
            "Scans every drive"
        );
        assert_eq!(
            auto_scan_state_text(DeviceAutoScanSettings {
                auto_scan_enabled: false,
                ..enabled_settings
            }),
            "Off"
        );
    }

    #[test]
    fn a_drive_without_a_name_is_shown_by_its_mount_folder() {
        let mount_path = PathBuf::from("/run/media/user/3A1F-0C2B");
        assert_eq!(shown_drive_name("", &mount_path), "3A1F-0C2B");
        assert_eq!(shown_drive_name("USB STICK", &mount_path), "USB STICK");
    }
}
