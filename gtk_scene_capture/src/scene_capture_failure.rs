use std::{io, path::PathBuf, process::ExitStatus};

use crate::accessible_widget_lookup::WidgetLookupFailure;

#[derive(Debug, thiserror::Error)]
pub enum SceneCaptureFailure {
    #[error("the Wayland connection failed: {0}")]
    WaylandConnectionFailed(#[from] wayland_client::ConnectError),
    #[error("the Wayland globals could not be read: {0}")]
    WaylandGlobalsUnavailable(#[from] wayland_client::globals::GlobalError),
    #[error("the virtual pointer protocol is unavailable: {0}")]
    VirtualPointerUnsupported(#[from] wayland_client::globals::BindError),
    #[error("the Wayland queue failed: {0}")]
    WaylandDispatchFailed(#[from] wayland_client::DispatchError),
    #[error("the widget could not be used: {0}")]
    WidgetUnavailable(#[from] WidgetLookupFailure),
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
    #[error("no frames were captured for {}", .animation_path.display())]
    AnimationWithoutFrames { animation_path: PathBuf },
    #[error("timed out waiting for {awaited_condition}")]
    NeverReady { awaited_condition: &'static str },
}
