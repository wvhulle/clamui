use std::{
    io::Write,
    process::{Command, Stdio},
};

use crate::task_failure::TaskFailure;

const CACHIX_CACHE_NAME: &str = "wvhulle";

fn command_output_lines(
    tool_command: &mut Command,
    tool_name: &'static str,
) -> Result<Vec<String>, TaskFailure> {
    let tool_result = tool_command
        .stderr(Stdio::inherit())
        .output()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name,
            start_failure,
        })?;
    if !tool_result.status.success() {
        return Err(TaskFailure::ToolFailed {
            tool_name,
            exit_status: tool_result.status,
        });
    }
    Ok(String::from_utf8_lossy(&tool_result.stdout)
        .lines()
        .map(str::to_owned)
        .filter(|output_line| !output_line.is_empty())
        .collect())
}

pub fn cacheable_store_paths(requisite_paths: Vec<String>) -> Vec<String> {
    requisite_paths
        .into_iter()
        .filter(|store_path| !store_path.ends_with(".drv"))
        .collect()
}

fn build_closure(installables: &[String]) -> Result<Vec<String>, TaskFailure> {
    let derivation_paths = command_output_lines(
        Command::new("nix")
            .args(["path-info", "--derivation"])
            .args(installables),
        "nix",
    )?;
    let requisite_paths = command_output_lines(
        Command::new("nix-store")
            .args(["--query", "--requisites", "--include-outputs"])
            .args(&derivation_paths),
        "nix-store",
    )?;
    Ok(cacheable_store_paths(requisite_paths))
}

pub fn push_build_closure(installables: &[String]) -> Result<(), TaskFailure> {
    let store_paths = build_closure(installables)?;
    let mut cachix_process = Command::new("cachix")
        .args(["push", CACHIX_CACHE_NAME])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name: "cachix",
            start_failure,
        })?;
    if let Some(mut cachix_input) = cachix_process.stdin.take() {
        cachix_input.write_all(store_paths.join("\n").as_bytes())?;
    }
    let cachix_result = cachix_process.wait_with_output()?;
    if cachix_result.status.success() {
        eprintln!(
            "xtask: {} store paths are in the {CACHIX_CACHE_NAME} cache",
            store_paths.len()
        );
        Ok(())
    } else {
        eprintln!(
            "{}{}",
            String::from_utf8_lossy(&cachix_result.stdout),
            String::from_utf8_lossy(&cachix_result.stderr)
        );
        Err(TaskFailure::ToolFailed {
            tool_name: "cachix",
            exit_status: cachix_result.status,
        })
    }
}

#[cfg(test)]
mod cachix_closure_push_tests {
    use super::*;

    #[test]
    fn derivation_files_are_left_out_of_the_push() {
        assert_eq!(
            cacheable_store_paths(vec![
                "/nix/store/aaa-lazaret-0.1.0".to_owned(),
                "/nix/store/bbb-lazaret-0.1.0.drv".to_owned(),
                "/nix/store/ccc-cargo-deps".to_owned(),
            ]),
            vec![
                "/nix/store/aaa-lazaret-0.1.0".to_owned(),
                "/nix/store/ccc-cargo-deps".to_owned(),
            ]
        );
    }
}
