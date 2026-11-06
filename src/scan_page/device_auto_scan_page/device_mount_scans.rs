use std::{path::PathBuf, time::Duration};

use relm4::{
    gtk,
    gtk::{gio, gio::prelude::*, glib},
};

use crate::{
    headless_modes::headless_scheduled_scan::{POWER_SUPPLY_DIRECTORY, host_runs_on_battery},
    host_services::desktop::stored_settings::application_settings,
    scan_page::scan_page_component::{ScanPage, ScanPageInput},
};

pub const DEVICE_SCAN_ENABLED_KEY: &str = "device-scan-enabled";
pub const DEVICE_SCAN_MAX_GIGABYTES_KEY: &str = "device-scan-max-gigabytes";
pub const DEVICE_SCAN_SKIP_BATTERY_KEY: &str = "device-scan-skip-on-battery";
const SETTLE_DELAY: Duration = Duration::from_secs(3);
const BYTES_PER_GIGABYTE: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTraits {
    pub drive_is_removable: bool,
    pub mount_can_eject: bool,
    pub mount_is_shadowed: bool,
}

pub fn device_qualifies_for_scan(device_traits: DeviceTraits) -> bool {
    !device_traits.mount_is_shadowed
        && (device_traits.drive_is_removable || device_traits.mount_can_eject)
}

pub fn device_size_is_allowed(device_bytes: u64, maximum_gigabytes: u64) -> bool {
    maximum_gigabytes == 0 || device_bytes <= maximum_gigabytes.saturating_mul(BYTES_PER_GIGABYTE)
}

fn traits_of_mount(mounted_device: &gio::Mount) -> DeviceTraits {
    DeviceTraits {
        drive_is_removable: mounted_device
            .drive()
            .is_some_and(|mount_drive| mount_drive.is_removable()),
        mount_can_eject: mounted_device.can_eject(),
        mount_is_shadowed: mounted_device.is_shadowed(),
    }
}

async fn scan_device_when_allowed(
    mount_path: PathBuf,
    mount_root: gio::File,
    scan_page_sender: relm4::Sender<ScanPageInput>,
) {
    glib::timeout_future(SETTLE_DELAY).await;
    let settings = application_settings();
    if settings.boolean(DEVICE_SCAN_SKIP_BATTERY_KEY)
        && host_runs_on_battery(std::path::Path::new(POWER_SUPPLY_DIRECTORY))
    {
        return;
    }
    let Ok(filesystem_info) = mount_root
        .query_filesystem_info_future(gio::FILE_ATTRIBUTE_FILESYSTEM_SIZE, glib::Priority::DEFAULT)
        .await
    else {
        return;
    };
    let maximum_gigabytes = u64::from(settings.uint(DEVICE_SCAN_MAX_GIGABYTES_KEY));
    if device_size_is_allowed(
        filesystem_info.attribute_uint64(gio::FILE_ATTRIBUTE_FILESYSTEM_SIZE),
        maximum_gigabytes,
    ) {
        scan_page_sender.emit(ScanPageInput::DeviceMounted(mount_path));
    }
}

pub fn watch_device_mounts(scan_page: &relm4::Controller<ScanPage>) -> gio::VolumeMonitor {
    use relm4::ComponentController;
    let volume_monitor = gio::VolumeMonitor::get();
    let scan_page_sender = scan_page.sender().clone();
    volume_monitor.connect_mount_added(move |_volume_monitor, mounted_device| {
        if !application_settings().boolean(DEVICE_SCAN_ENABLED_KEY)
            || !device_qualifies_for_scan(traits_of_mount(mounted_device))
        {
            return;
        }
        let mount_root = mounted_device.root();
        if let Some(mount_path) = mount_root.path() {
            relm4::spawn_local(scan_device_when_allowed(
                mount_path,
                mount_root,
                scan_page_sender.clone(),
            ));
        }
    });
    let _gtk_keeps_running = gtk::is_initialized();
    volume_monitor
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
