use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use relm4::gtk::{gio, gio::prelude::*};

use crate::headless_modes::headless_scheduled_scan::{
    POWER_SUPPLY_DIRECTORY, host_runs_on_battery,
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
const BYTES_PER_GIGABYTE: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceAutoScanSettings {
    pub auto_scan_enabled: bool,
    pub maximum_gigabytes: u32,
    pub skip_on_battery: bool,
}

impl DeviceAutoScanSettings {
    pub fn read_from(stored_settings: &gio::Settings) -> Self {
        Self {
            auto_scan_enabled: stored_settings.boolean(DEVICE_SCAN_ENABLED_KEY),
            maximum_gigabytes: stored_settings.uint(DEVICE_SCAN_MAX_GIGABYTES_KEY),
            skip_on_battery: stored_settings.boolean(DEVICE_SCAN_SKIP_BATTERY_KEY),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTraits {
    pub drive_is_removable: bool,
    pub mount_can_eject: bool,
    pub mount_is_shadowed: bool,
}

#[derive(Debug)]
pub struct MountedDevice {
    pub mount_path: PathBuf,
    pub device_traits: DeviceTraits,
}

pub fn device_qualifies_for_scan(device_traits: DeviceTraits) -> bool {
    !device_traits.mount_is_shadowed
        && (device_traits.drive_is_removable || device_traits.mount_can_eject)
}

pub fn device_size_is_allowed(device_bytes: u64, maximum_gigabytes: u64) -> bool {
    maximum_gigabytes == 0 || device_bytes <= maximum_gigabytes.saturating_mul(BYTES_PER_GIGABYTE)
}

pub fn mounted_device_of(added_mount: &gio::Mount) -> Option<MountedDevice> {
    Some(MountedDevice {
        mount_path: added_mount.root().path()?,
        device_traits: DeviceTraits {
            drive_is_removable: added_mount
                .drive()
                .is_some_and(|mount_drive| mount_drive.is_removable()),
            mount_can_eject: added_mount.can_eject(),
            mount_is_shadowed: added_mount.is_shadowed(),
        },
    })
}

fn filesystem_bytes(mount_path: &Path) -> Option<u64> {
    let filesystem_status = rustix::fs::statvfs(mount_path).ok()?;
    Some(
        filesystem_status
            .f_blocks
            .saturating_mul(filesystem_status.f_frsize),
    )
}

pub async fn settled_device_passes_limits(
    mount_path: PathBuf,
    auto_scan_settings: DeviceAutoScanSettings,
) -> bool {
    tokio::time::sleep(SETTLE_DELAY).await;
    if auto_scan_settings.skip_on_battery && host_runs_on_battery(Path::new(POWER_SUPPLY_DIRECTORY))
    {
        return false;
    }
    tokio::task::spawn_blocking(move || filesystem_bytes(&mount_path))
        .await
        .ok()
        .flatten()
        .is_some_and(|device_bytes| {
            device_size_is_allowed(
                device_bytes,
                u64::from(auto_scan_settings.maximum_gigabytes),
            )
        })
}

#[cfg(test)]
mod device_mount_scans_tests {
    use super::*;

    fn removable_device() -> DeviceTraits {
        DeviceTraits {
            drive_is_removable: true,
            mount_can_eject: false,
            mount_is_shadowed: false,
        }
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
    fn zero_means_no_size_limit() {
        assert!(device_size_is_allowed(u64::MAX, 0));
        assert!(device_size_is_allowed(32 * BYTES_PER_GIGABYTE, 32));
        assert!(!device_size_is_allowed(32 * BYTES_PER_GIGABYTE + 1, 32));
    }
}
