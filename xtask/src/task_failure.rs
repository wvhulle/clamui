use std::{io, process::ExitStatus};

#[derive(Debug, thiserror::Error)]
pub enum TaskFailure {
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
