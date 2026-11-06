use std::{io, process::ExitStatus};

#[derive(Debug, thiserror::Error)]
pub enum TaskFailure {
    #[error("{0}")]
    SceneCaptureFailed(#[from] gtk_scene_capture::scene_capture_failure::SceneCaptureFailure),
    #[error("the fixture systemd service failed: {0}")]
    FixtureSystemdFailed(#[from] zbus::Error),
    #[error("environment variable {variable_name} is not set")]
    VariableMissing { variable_name: &'static str },
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
}
