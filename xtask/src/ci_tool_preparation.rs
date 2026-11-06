use std::{env, fs, path::Path, process::Command};

use crate::{
    task_failure::TaskFailure,
    tool_commands::{required_variable, run_tool},
};

const CI_TOOLS_DIRECTORY: &str = ".ci-tools";

pub fn prepare_ci_tools() -> Result<(), TaskFailure> {
    let tools_directory = Path::new(CI_TOOLS_DIRECTORY);
    fs::create_dir_all(tools_directory)?;
    let copied_xtask_path = tools_directory.join("xtask");
    if copied_xtask_path.exists() {
        fs::remove_file(&copied_xtask_path)?;
    }
    fs::copy(env::current_exe()?, copied_xtask_path)?;
    Ok(())
}

pub fn download_tools(
    binary_cache_url: &str,
    tool_installables: &[String],
) -> Result<(), TaskFailure> {
    run_tool(
        "nix",
        Command::new("nix")
            .args(["build", "--quiet", "--no-link"])
            .args(tool_installables),
    )?;
    run_tool(
        "nix",
        Command::new("nix")
            .args(["copy", "--quiet", "--to"])
            .arg(format!("{binary_cache_url}?compression=none"))
            .args(tool_installables),
    )
}

pub fn check_commit_messages(
    fetch_target_branch: bool,
    revision_ranges: &[String],
) -> Result<(), TaskFailure> {
    if fetch_target_branch {
        let target_branch = required_variable("CI_COMMIT_TARGET_BRANCH")?;
        run_tool(
            "git",
            Command::new("git").args(["fetch", "--quiet", "origin", &target_branch]),
        )?;
    }
    run_tool(
        "convco",
        Command::new("convco").arg("check").args(revision_ranges),
    )
}
