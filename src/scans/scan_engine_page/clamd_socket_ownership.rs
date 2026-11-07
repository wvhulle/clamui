use std::{
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};

use rustix::fs::Access;

use crate::host_services::{
    clamav_config::clamav_host_config::{HostConfigView, read_clamd_config},
    desktop::flatpak_sandbox::running_in_flatpak,
};

const DEFAULT_CLAMD_SOCKET: &str = "/run/clamav/clamd.ctl";
const STICKY_MODE_BIT: u32 = 0o1000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamdSocketOwnership {
    SocketProtected {
        socket_path: PathBuf,
    },
    SocketReplaceable {
        socket_path: PathBuf,
        replaceable_path: PathBuf,
    },
    SocketMissing {
        socket_path: PathBuf,
    },
    SocketNotCheckable,
}

fn configured_socket_path() -> PathBuf {
    match read_clamd_config() {
        HostConfigView::ConfigFound {
            config_settings, ..
        } => config_settings
            .into_iter()
            .find(|config_setting| config_setting.setting_key == "LocalSocket")
            .map(|config_setting| PathBuf::from(config_setting.setting_value))
            .filter(|socket_path| socket_path.is_absolute())
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CLAMD_SOCKET)),
        HostConfigView::ConfigNotFound => PathBuf::from(DEFAULT_CLAMD_SOCKET),
    }
}

fn user_controls_path(checked_path: &Path, user_id: u32) -> bool {
    fs::symlink_metadata(checked_path).is_ok_and(|path_metadata| {
        let sticky_directory =
            path_metadata.is_dir() && path_metadata.mode() & STICKY_MODE_BIT != 0;
        path_metadata.uid() == user_id
            || (!sticky_directory && rustix::fs::access(checked_path, Access::WRITE_OK).is_ok())
    })
}

pub fn inspect_socket_ownership(socket_path: &Path, user_id: u32) -> ClamdSocketOwnership {
    let socket_is_present = fs::symlink_metadata(socket_path)
        .is_ok_and(|socket_metadata| socket_metadata.file_type().is_socket());
    if !socket_is_present {
        return ClamdSocketOwnership::SocketMissing {
            socket_path: socket_path.to_path_buf(),
        };
    }
    socket_path
        .ancestors()
        .find(|checked_path| {
            if *checked_path == socket_path {
                fs::symlink_metadata(checked_path)
                    .is_ok_and(|socket_metadata| socket_metadata.uid() == user_id)
            } else {
                user_controls_path(checked_path, user_id)
            }
        })
        .map_or_else(
            || ClamdSocketOwnership::SocketProtected {
                socket_path: socket_path.to_path_buf(),
            },
            |replaceable_path| ClamdSocketOwnership::SocketReplaceable {
                socket_path: socket_path.to_path_buf(),
                replaceable_path: replaceable_path.to_path_buf(),
            },
        )
}

fn inspect_clamd_socket() -> ClamdSocketOwnership {
    if running_in_flatpak() {
        return ClamdSocketOwnership::SocketNotCheckable;
    }
    inspect_socket_ownership(
        &configured_socket_path(),
        rustix::process::getuid().as_raw(),
    )
}

pub async fn inspect_clamd_socket_off_thread() -> ClamdSocketOwnership {
    tokio::task::spawn_blocking(inspect_clamd_socket)
        .await
        .unwrap_or(ClamdSocketOwnership::SocketNotCheckable)
}

#[cfg(test)]
mod clamd_socket_ownership_tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn a_socket_in_a_directory_you_own_is_replaceable() {
        let socket_directory = tempfile::tempdir().unwrap();
        let socket_path = socket_directory.path().join("clamd.ctl");
        let _listening_socket = UnixListener::bind(&socket_path).unwrap();
        assert!(matches!(
            inspect_socket_ownership(&socket_path, rustix::process::getuid().as_raw()),
            ClamdSocketOwnership::SocketReplaceable { .. }
        ));
        assert!(matches!(
            inspect_socket_ownership(&socket_directory.path().join("absent.ctl"), 0),
            ClamdSocketOwnership::SocketMissing { .. }
        ));
    }
}
