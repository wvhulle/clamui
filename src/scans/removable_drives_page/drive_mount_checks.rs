use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use bytesize::ByteSize;
use relm4::gtk::{gio, gio::prelude::*};

use crate::{
    headless_modes::headless_scheduled_scan::{POWER_SUPPLY_DIRECTORY, host_runs_on_battery},
    shared_widgets::scan_runs::scan_results_section::scan_results_state::ScanResultsStatus,
};

pub const DEVICE_SCAN_ENABLED_KEY: &str = "device-scan-enabled";
pub const DEVICE_SCAN_MAX_GIGABYTES_KEY: &str = "device-scan-max-gigabytes";
pub const DEVICE_SCAN_SKIP_BATTERY_KEY: &str = "device-scan-skip-on-battery";
pub const DEVICE_SCAN_SETTING_KEYS: [&str; 3] = [
    DEVICE_SCAN_ENABLED_KEY,
    DEVICE_SCAN_MAX_GIGABYTES_KEY,
    DEVICE_SCAN_SKIP_BATTERY_KEY,
];
const SETTLE_DELAY: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceAutoScanSettings {
    pub auto_scan_enabled: bool,
    pub maximum_gigabytes: u32,
    pub skip_on_battery: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveSizeLimit {
    NoSizeLimit,
    LimitedTo(ByteSize),
}

impl DeviceAutoScanSettings {
    pub fn read_from(stored_settings: &gio::Settings) -> Self {
        Self {
            auto_scan_enabled: stored_settings.boolean(DEVICE_SCAN_ENABLED_KEY),
            maximum_gigabytes: stored_settings.uint(DEVICE_SCAN_MAX_GIGABYTES_KEY),
            skip_on_battery: stored_settings.boolean(DEVICE_SCAN_SKIP_BATTERY_KEY),
        }
    }

    pub fn drive_size_limit(self) -> DriveSizeLimit {
        match self.maximum_gigabytes {
            0 => DriveSizeLimit::NoSizeLimit,
            maximum_gigabytes => {
                DriveSizeLimit::LimitedTo(ByteSize::gb(u64::from(maximum_gigabytes)))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTraits {
    pub drive_is_removable: bool,
    pub mount_can_eject: bool,
    pub mount_is_shadowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountedDevice {
    pub drive_name: String,
    pub mount_path: PathBuf,
    pub device_traits: DeviceTraits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerSource {
    OnMainsPower,
    OnBattery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveSizeReading {
    SizeRead(ByteSize),
    SizeUnreadable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettledDriveFacts {
    pub power_source: PowerSource,
    pub drive_size: DriveSizeReading,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveSkipReason {
    SkippedLargerThanLimit {
        drive_size: ByteSize,
        size_limit: ByteSize,
    },
    SkippedOnBattery,
    SkippedAutoScanOff,
    SkippedWhileScanning,
    SizeUnreadable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveScanDecision {
    DriveSettling,
    DriveScanning,
    ScannedDrive { scan_result: ScanResultsStatus },
    DriveSkipped(DriveSkipReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettledDriveCheck {
    DriveMayBeScanned,
    DriveNotScanned(DriveSkipReason),
}

pub fn device_qualifies_for_scan(device_traits: DeviceTraits) -> bool {
    !device_traits.mount_is_shadowed
        && (device_traits.drive_is_removable || device_traits.mount_can_eject)
}

pub fn mounted_drive_decision(auto_scan_settings: DeviceAutoScanSettings) -> DriveScanDecision {
    if auto_scan_settings.auto_scan_enabled {
        DriveScanDecision::DriveSettling
    } else {
        DriveScanDecision::DriveSkipped(DriveSkipReason::SkippedAutoScanOff)
    }
}

pub fn classify_settled_drive(
    auto_scan_settings: DeviceAutoScanSettings,
    settled_facts: SettledDriveFacts,
) -> SettledDriveCheck {
    let skip_reason = match (
        auto_scan_settings.auto_scan_enabled,
        auto_scan_settings.skip_on_battery,
        settled_facts.power_source,
        settled_facts.drive_size,
        auto_scan_settings.drive_size_limit(),
    ) {
        (false, ..) => DriveSkipReason::SkippedAutoScanOff,
        (true, true, PowerSource::OnBattery, ..) => DriveSkipReason::SkippedOnBattery,
        (true, _, _, DriveSizeReading::SizeUnreadable, _) => DriveSkipReason::SizeUnreadable,
        (
            true,
            _,
            _,
            DriveSizeReading::SizeRead(drive_size),
            DriveSizeLimit::LimitedTo(size_limit),
        ) if drive_size > size_limit => DriveSkipReason::SkippedLargerThanLimit {
            drive_size,
            size_limit,
        },
        (true, _, _, DriveSizeReading::SizeRead(_), _) => {
            return SettledDriveCheck::DriveMayBeScanned;
        }
    };
    SettledDriveCheck::DriveNotScanned(skip_reason)
}

pub fn mounted_device_of(added_mount: &gio::Mount) -> Option<MountedDevice> {
    let mount_path = added_mount.root().path()?;
    Some(MountedDevice {
        drive_name: added_mount.name().to_string(),
        mount_path,
        device_traits: DeviceTraits {
            drive_is_removable: added_mount
                .drive()
                .is_some_and(|mount_drive| mount_drive.is_removable()),
            mount_can_eject: added_mount.can_eject(),
            mount_is_shadowed: added_mount.is_shadowed(),
        },
    })
}

fn filesystem_size(mount_path: &Path) -> DriveSizeReading {
    match rustix::fs::statvfs(mount_path) {
        Ok(filesystem_status) => DriveSizeReading::SizeRead(ByteSize::b(
            filesystem_status
                .f_blocks
                .saturating_mul(filesystem_status.f_frsize),
        )),
        Err(_statvfs_failure) => DriveSizeReading::SizeUnreadable,
    }
}

pub async fn settled_drive_facts(mount_path: PathBuf) -> SettledDriveFacts {
    tokio::time::sleep(SETTLE_DELAY).await;
    let power_source = if host_runs_on_battery(Path::new(POWER_SUPPLY_DIRECTORY)) {
        PowerSource::OnBattery
    } else {
        PowerSource::OnMainsPower
    };
    let drive_size = tokio::task::spawn_blocking(move || filesystem_size(&mount_path))
        .await
        .unwrap_or(DriveSizeReading::SizeUnreadable);
    SettledDriveFacts {
        power_source,
        drive_size,
    }
}

#[cfg(test)]
mod drive_mount_checks_tests {
    use super::*;

    fn removable_device() -> DeviceTraits {
        DeviceTraits {
            drive_is_removable: true,
            mount_can_eject: false,
            mount_is_shadowed: false,
        }
    }

    const ENABLED_SETTINGS: DeviceAutoScanSettings = DeviceAutoScanSettings {
        auto_scan_enabled: true,
        maximum_gigabytes: 32,
        skip_on_battery: true,
    };

    fn facts_of(power_source: PowerSource, drive_size: DriveSizeReading) -> SettledDriveFacts {
        SettledDriveFacts {
            power_source,
            drive_size,
        }
    }

    fn small_drive_on_mains() -> SettledDriveFacts {
        facts_of(
            PowerSource::OnMainsPower,
            DriveSizeReading::SizeRead(ByteSize::gb(16)),
        )
    }

    #[test]
    fn only_visible_removable_or_ejectable_devices_qualify() {
        assert!(device_qualifies_for_scan(removable_device()));
        assert!(device_qualifies_for_scan(DeviceTraits {
            drive_is_removable: false,
            mount_can_eject: true,
            mount_is_shadowed: false,
        }));
        assert!(!device_qualifies_for_scan(DeviceTraits {
            drive_is_removable: false,
            mount_can_eject: false,
            mount_is_shadowed: false,
        }));
        assert!(!device_qualifies_for_scan(DeviceTraits {
            mount_is_shadowed: true,
            ..removable_device()
        }));
    }

    #[test]
    fn a_small_drive_on_mains_power_may_be_scanned() {
        assert_eq!(
            classify_settled_drive(ENABLED_SETTINGS, small_drive_on_mains()),
            SettledDriveCheck::DriveMayBeScanned
        );
    }

    #[test]
    fn a_drive_larger_than_the_limit_is_skipped_with_both_sizes() {
        let drive_size = ByteSize::gb(32) + ByteSize::b(1);
        assert_eq!(
            classify_settled_drive(
                ENABLED_SETTINGS,
                facts_of(
                    PowerSource::OnMainsPower,
                    DriveSizeReading::SizeRead(drive_size)
                ),
            ),
            SettledDriveCheck::DriveNotScanned(DriveSkipReason::SkippedLargerThanLimit {
                drive_size,
                size_limit: ByteSize::gb(32),
            })
        );
        assert_eq!(
            classify_settled_drive(
                ENABLED_SETTINGS,
                facts_of(
                    PowerSource::OnMainsPower,
                    DriveSizeReading::SizeRead(ByteSize::gb(32))
                ),
            ),
            SettledDriveCheck::DriveMayBeScanned
        );
    }

    #[test]
    fn zero_gigabytes_means_every_drive_size_is_scanned() {
        let unlimited_settings = DeviceAutoScanSettings {
            maximum_gigabytes: 0,
            ..ENABLED_SETTINGS
        };
        assert_eq!(
            unlimited_settings.drive_size_limit(),
            DriveSizeLimit::NoSizeLimit
        );
        assert_eq!(
            classify_settled_drive(
                unlimited_settings,
                facts_of(
                    PowerSource::OnMainsPower,
                    DriveSizeReading::SizeRead(ByteSize::b(u64::MAX))
                ),
            ),
            SettledDriveCheck::DriveMayBeScanned
        );
    }

    #[test]
    fn a_drive_on_battery_is_skipped_only_when_asked() {
        let on_battery = facts_of(
            PowerSource::OnBattery,
            DriveSizeReading::SizeRead(ByteSize::gb(16)),
        );
        assert_eq!(
            classify_settled_drive(ENABLED_SETTINGS, on_battery),
            SettledDriveCheck::DriveNotScanned(DriveSkipReason::SkippedOnBattery)
        );
        assert_eq!(
            classify_settled_drive(
                DeviceAutoScanSettings {
                    skip_on_battery: false,
                    ..ENABLED_SETTINGS
                },
                on_battery
            ),
            SettledDriveCheck::DriveMayBeScanned
        );
    }

    #[test]
    fn an_unreadable_size_is_never_scanned_as_if_it_fit() {
        assert_eq!(
            classify_settled_drive(
                ENABLED_SETTINGS,
                facts_of(PowerSource::OnMainsPower, DriveSizeReading::SizeUnreadable),
            ),
            SettledDriveCheck::DriveNotScanned(DriveSkipReason::SizeUnreadable)
        );
        assert_eq!(
            classify_settled_drive(
                DeviceAutoScanSettings {
                    maximum_gigabytes: 0,
                    ..ENABLED_SETTINGS
                },
                facts_of(PowerSource::OnMainsPower, DriveSizeReading::SizeUnreadable),
            ),
            SettledDriveCheck::DriveNotScanned(DriveSkipReason::SizeUnreadable)
        );
    }

    #[test]
    fn auto_scan_turned_off_skips_at_mount_and_after_settling() {
        let disabled_settings = DeviceAutoScanSettings {
            auto_scan_enabled: false,
            ..ENABLED_SETTINGS
        };
        assert_eq!(
            mounted_drive_decision(disabled_settings),
            DriveScanDecision::DriveSkipped(DriveSkipReason::SkippedAutoScanOff)
        );
        assert_eq!(
            mounted_drive_decision(ENABLED_SETTINGS),
            DriveScanDecision::DriveSettling
        );
        assert_eq!(
            classify_settled_drive(disabled_settings, small_drive_on_mains()),
            SettledDriveCheck::DriveNotScanned(DriveSkipReason::SkippedAutoScanOff)
        );
    }
}
