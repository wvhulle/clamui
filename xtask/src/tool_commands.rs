use std::{
    env,
    process::{Command, Stdio},
};

use crate::task_failure::TaskFailure;

pub fn required_variable(variable_name: &'static str) -> Result<String, TaskFailure> {
    env::var(variable_name)
        .ok()
        .filter(|variable_value| !variable_value.is_empty())
        .ok_or(TaskFailure::VariableMissing { variable_name })
}

pub fn run_tool(tool_name: &'static str, tool_command: &mut Command) -> Result<(), TaskFailure> {
    let exit_status =
        tool_command
            .status()
            .map_err(|start_failure| TaskFailure::ToolNotStarted {
                tool_name,
                start_failure,
            })?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name,
            exit_status,
        })
    }
}

pub fn tool_stdout(
    tool_name: &'static str,
    tool_command: &mut Command,
) -> Result<String, TaskFailure> {
    let tool_result = tool_command
        .stderr(Stdio::inherit())
        .output()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name,
            start_failure,
        })?;
    if tool_result.status.success() {
        Ok(String::from_utf8_lossy(&tool_result.stdout).into_owned())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name,
            exit_status: tool_result.status,
        })
    }
}
