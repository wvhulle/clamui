use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;

use crate::host_services::desktop::flatpak_sandbox::readable_host_path;

const COMPRESSED_KERNEL_CONFIG_PATH: &str = "/proc/config.gz";
const KERNEL_RELEASE_PATH: &str = "/proc/sys/kernel/osrelease";
const BOOT_DIRECTORY: &str = "/boot";
const PERMISSION_EVENTS_OPTION: &str = "CONFIG_FANOTIFY_ACCESS_PERMISSIONS";
const INOTIFY_WATCH_LIMIT_PATH: &str = "/proc/sys/fs/inotify/max_user_watches";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum KernelConfigReadFailure {
    #[error("neither /proc/config.gz nor /boot/config-<release> exists")]
    NoKernelConfigFound,
    #[error("the kernel configuration could not be read: {failure_kind}")]
    KernelConfigUnreadable { failure_kind: io::ErrorKind },
    #[error("/proc/config.gz is not valid gzip")]
    CompressedConfigCorrupt,
    #[error("the kernel release could not be read: {failure_kind}")]
    KernelReleaseUnreadable { failure_kind: io::ErrorKind },
    #[error("the task reading the kernel configuration stopped before it finished")]
    ReadingTaskAborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelBlockingSupport {
    PermissionEventsSupported,
    NotifyOnly,
    KernelConfigUnreadable(KernelConfigReadFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WatchLimitReadFailure {
    #[error("max_user_watches could not be read: {failure_kind}")]
    LimitFileUnreadable { failure_kind: io::ErrorKind },
    #[error("max_user_watches does not hold a number")]
    LimitNotANumber,
    #[error("the task reading max_user_watches stopped before it finished")]
    ReadingTaskAborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InotifyWatchLimit {
    LimitRead { max_user_watches: u64 },
    LimitUnreadable(WatchLimitReadFailure),
}

pub fn blocking_support_in_config(config_text: &str) -> KernelBlockingSupport {
    let permission_events_enabled = config_text.lines().any(|config_line| {
        config_line
            .trim()
            .strip_prefix(PERMISSION_EVENTS_OPTION)
            .and_then(|option_rest| option_rest.strip_prefix('='))
            .is_some_and(|option_value| matches!(option_value.trim(), "y" | "m"))
    });
    if permission_events_enabled {
        KernelBlockingSupport::PermissionEventsSupported
    } else {
        KernelBlockingSupport::NotifyOnly
    }
}

fn decompressed_config_text(compressed_bytes: &[u8]) -> Result<String, KernelConfigReadFailure> {
    let mut decompressed_bytes = Vec::new();
    GzDecoder::new(compressed_bytes)
        .read_to_end(&mut decompressed_bytes)
        .map_err(|_decode_failure| KernelConfigReadFailure::CompressedConfigCorrupt)?;
    Ok(String::from_utf8_lossy(&decompressed_bytes).into_owned())
}

pub struct KernelConfigLocations {
    pub compressed_config_path: PathBuf,
    pub kernel_release_path: PathBuf,
    pub boot_directory: PathBuf,
}

fn boot_config_path(
    config_locations: &KernelConfigLocations,
) -> Result<PathBuf, KernelConfigReadFailure> {
    let kernel_release =
        fs::read_to_string(&config_locations.kernel_release_path).map_err(|read_failure| {
            KernelConfigReadFailure::KernelReleaseUnreadable {
                failure_kind: read_failure.kind(),
            }
        })?;
    Ok(config_locations
        .boot_directory
        .join(format!("config-{}", kernel_release.trim())))
}

fn boot_config_text(
    config_locations: &KernelConfigLocations,
) -> Result<String, KernelConfigReadFailure> {
    fs::read(boot_config_path(config_locations)?)
        .map(|config_bytes| String::from_utf8_lossy(&config_bytes).into_owned())
        .map_err(|read_failure| match read_failure.kind() {
            io::ErrorKind::NotFound => KernelConfigReadFailure::NoKernelConfigFound,
            failure_kind => KernelConfigReadFailure::KernelConfigUnreadable { failure_kind },
        })
}

pub fn kernel_config_text(
    config_locations: &KernelConfigLocations,
) -> Result<String, KernelConfigReadFailure> {
    match fs::read(&config_locations.compressed_config_path) {
        Ok(compressed_bytes) => decompressed_config_text(&compressed_bytes),
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => {
            boot_config_text(config_locations)
        }
        Err(read_failure) => Err(KernelConfigReadFailure::KernelConfigUnreadable {
            failure_kind: read_failure.kind(),
        }),
    }
}

pub fn blocking_support_in_files(
    config_locations: &KernelConfigLocations,
) -> KernelBlockingSupport {
    kernel_config_text(config_locations).map_or_else(
        KernelBlockingSupport::KernelConfigUnreadable,
        |config_text| blocking_support_in_config(&config_text),
    )
}

pub fn inspect_kernel_blocking_support() -> KernelBlockingSupport {
    blocking_support_in_files(&KernelConfigLocations {
        compressed_config_path: readable_host_path(COMPRESSED_KERNEL_CONFIG_PATH),
        kernel_release_path: readable_host_path(KERNEL_RELEASE_PATH),
        boot_directory: readable_host_path(BOOT_DIRECTORY),
    })
}

pub fn watch_limit_in_file(watch_limit_path: &Path) -> InotifyWatchLimit {
    match fs::read_to_string(watch_limit_path) {
        Ok(limit_text) => limit_text.trim().parse().map_or(
            InotifyWatchLimit::LimitUnreadable(WatchLimitReadFailure::LimitNotANumber),
            |max_user_watches| InotifyWatchLimit::LimitRead { max_user_watches },
        ),
        Err(read_failure) => {
            InotifyWatchLimit::LimitUnreadable(WatchLimitReadFailure::LimitFileUnreadable {
                failure_kind: read_failure.kind(),
            })
        }
    }
}

pub fn inspect_inotify_watch_limit() -> InotifyWatchLimit {
    watch_limit_in_file(&readable_host_path(INOTIFY_WATCH_LIMIT_PATH))
}

#[cfg(test)]
mod kernel_on_access_support_tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};

    use super::*;

    const SUPPORTING_CONFIG: &str =
        "CONFIG_FANOTIFY=y\nCONFIG_FANOTIFY_ACCESS_PERMISSIONS=y\nCONFIG_INOTIFY_USER=y\n";
    const NOTIFY_ONLY_CONFIG: &str =
        "CONFIG_FANOTIFY=y\n# CONFIG_FANOTIFY_ACCESS_PERMISSIONS is not set\n";

    fn gzip_bytes(config_text: &str) -> Vec<u8> {
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gzip_encoder
            .write_all(config_text.as_bytes())
            .expect("gzip write");
        gzip_encoder.finish().expect("gzip finish")
    }

    #[test]
    fn permission_events_need_the_option_set_to_yes_or_module() {
        assert_eq!(
            blocking_support_in_config(SUPPORTING_CONFIG),
            KernelBlockingSupport::PermissionEventsSupported
        );
        assert_eq!(
            blocking_support_in_config(NOTIFY_ONLY_CONFIG),
            KernelBlockingSupport::NotifyOnly
        );
        assert_eq!(
            blocking_support_in_config("CONFIG_FANOTIFY_ACCESS_PERMISSIONS_EXTRA=y\n"),
            KernelBlockingSupport::NotifyOnly
        );
        assert_eq!(
            blocking_support_in_config(""),
            KernelBlockingSupport::NotifyOnly
        );
    }

    fn locations_in(temporary_root: &Path) -> KernelConfigLocations {
        KernelConfigLocations {
            compressed_config_path: temporary_root.join("config.gz"),
            kernel_release_path: temporary_root.join("osrelease"),
            boot_directory: temporary_root.join("boot"),
        }
    }

    #[test]
    fn a_gzip_proc_config_is_decompressed_before_parsing() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let config_locations = locations_in(temporary_root.path());
        fs::write(
            &config_locations.compressed_config_path,
            gzip_bytes(SUPPORTING_CONFIG),
        )
        .expect("config.gz");
        assert_eq!(
            blocking_support_in_files(&config_locations),
            KernelBlockingSupport::PermissionEventsSupported
        );
        fs::write(
            &config_locations.compressed_config_path,
            gzip_bytes(NOTIFY_ONLY_CONFIG),
        )
        .expect("config.gz");
        assert_eq!(
            blocking_support_in_files(&config_locations),
            KernelBlockingSupport::NotifyOnly
        );
    }

    #[test]
    fn a_corrupt_proc_config_is_unreadable_rather_than_notify_only() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let config_locations = locations_in(temporary_root.path());
        fs::write(&config_locations.compressed_config_path, SUPPORTING_CONFIG).expect("config.gz");
        assert_eq!(
            blocking_support_in_files(&config_locations),
            KernelBlockingSupport::KernelConfigUnreadable(
                KernelConfigReadFailure::CompressedConfigCorrupt
            )
        );
    }

    #[test]
    fn without_proc_config_the_boot_config_of_the_running_release_is_read() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let config_locations = locations_in(temporary_root.path());
        assert_eq!(
            blocking_support_in_files(&config_locations),
            KernelBlockingSupport::KernelConfigUnreadable(
                KernelConfigReadFailure::KernelReleaseUnreadable {
                    failure_kind: io::ErrorKind::NotFound
                }
            )
        );
        fs::write(&config_locations.kernel_release_path, "6.12.9-lazaret\n").expect("osrelease");
        assert_eq!(
            blocking_support_in_files(&config_locations),
            KernelBlockingSupport::KernelConfigUnreadable(
                KernelConfigReadFailure::NoKernelConfigFound
            )
        );
        fs::create_dir(&config_locations.boot_directory).expect("boot directory");
        fs::write(
            config_locations
                .boot_directory
                .join("config-6.12.9-lazaret"),
            SUPPORTING_CONFIG,
        )
        .expect("boot config");
        assert_eq!(
            blocking_support_in_files(&config_locations),
            KernelBlockingSupport::PermissionEventsSupported
        );
    }

    #[test]
    fn an_unreadable_proc_config_does_not_fall_back_to_notify_only() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        assert!(matches!(
            blocking_support_in_files(&KernelConfigLocations {
                compressed_config_path: temporary_root.path().to_path_buf(),
                ..locations_in(temporary_root.path())
            }),
            KernelBlockingSupport::KernelConfigUnreadable(
                KernelConfigReadFailure::KernelConfigUnreadable { .. }
            )
        ));
    }

    #[test]
    fn the_watch_limit_is_read_as_a_number_or_reported_unreadable() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let watch_limit = temporary_root.path().join("max_user_watches");
        fs::write(&watch_limit, "8192\n").expect("watch limit");
        assert_eq!(
            watch_limit_in_file(&watch_limit),
            InotifyWatchLimit::LimitRead {
                max_user_watches: 8192
            }
        );
        fs::write(&watch_limit, "many\n").expect("watch limit");
        assert_eq!(
            watch_limit_in_file(&watch_limit),
            InotifyWatchLimit::LimitUnreadable(WatchLimitReadFailure::LimitNotANumber)
        );
        assert_eq!(
            watch_limit_in_file(&temporary_root.path().join("missing")),
            InotifyWatchLimit::LimitUnreadable(WatchLimitReadFailure::LimitFileUnreadable {
                failure_kind: io::ErrorKind::NotFound
            })
        );
    }
}
