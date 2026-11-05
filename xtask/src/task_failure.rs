use std::{io, process::ExitStatus};

#[derive(Debug, thiserror::Error)]
pub enum TaskFailure {
    #[error("the Wayland connection failed: {0}")]
    WaylandConnectionFailed(#[from] wayland_client::ConnectError),
    #[error("the Wayland globals could not be read: {0}")]
    WaylandGlobalsUnavailable(#[from] wayland_client::globals::GlobalError),
    #[error("the virtual pointer protocol is unavailable: {0}")]
    VirtualPointerUnsupported(#[from] wayland_client::globals::BindError),
    #[error("the Wayland queue failed: {0}")]
    WaylandDispatchFailed(#[from] wayland_client::DispatchError),
    #[error("the fixture systemd service failed: {0}")]
    FixtureSystemdFailed(#[from] zbus::Error),
    #[error("an interaction had no effect: {expected_effect}")]
    InteractionHadNoEffect { expected_effect: &'static str },
    #[error("file operation failed: {0}")]
    FileOperationFailed(#[from] io::Error),
    #[error("{tool_name} could not be started: {start_failure}")]
    ToolNotStarted {
        tool_name: &'static str,
        start_failure: io::Error,
    },
    #[error("{tool_name} failed with {exit_status}")]
    ToolFailed {
        tool_name: &'static str,
        exit_status: ExitStatus,
    },
    #[error("timed out waiting for {awaited_condition}")]
    NeverReady { awaited_condition: &'static str },
}
