use std::{
    env, fs,
    path::Path,
    process::{Command, Stdio},
};

use crate::task_failure::TaskFailure;

const SCREENSHOTS_BRANCH: &str = "screenshots";
const PUBLISHING_BOT_NAME: &str = "wvhulle-bot";
const PUBLISHING_COMMITTER_EMAIL: &str = "willemvanhulle@protonmail.com";
const PUBLISHING_HOST: &str = "codeberg.org";

fn required_variable(variable_name: &'static str) -> Result<String, TaskFailure> {
    env::var(variable_name)
        .map_err(|_missing_variable| TaskFailure::VariableMissing { variable_name })
}

fn git_in(staging_directory: &Path) -> Command {
    let mut git_command = Command::new("git");
    git_command.current_dir(staging_directory);
    git_command
}

fn run_git(git_command: &mut Command) -> Result<(), TaskFailure> {
    let exit_status =
        git_command
            .status()
            .map_err(|start_failure| TaskFailure::ToolNotStarted {
                tool_name: "git",
                start_failure,
            })?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name: "git",
            exit_status,
        })
    }
}

fn git_output(git_command: &mut Command) -> Result<String, TaskFailure> {
    let git_result = git_command
        .stderr(Stdio::null())
        .output()
        .map_err(|start_failure| TaskFailure::ToolNotStarted {
            tool_name: "git",
            start_failure,
        })?;
    if git_result.status.success() {
        Ok(String::from_utf8_lossy(&git_result.stdout)
            .trim()
            .to_owned())
    } else {
        Err(TaskFailure::ToolFailed {
            tool_name: "git",
            exit_status: git_result.status,
        })
    }
}

fn published_screenshots_tree(staging_directory: &Path) -> Option<String> {
    run_git(git_in(staging_directory).args([
        "fetch",
        "--quiet",
        "--depth",
        "1",
        "origin",
        SCREENSHOTS_BRANCH,
    ]))
    .ok()?;
    git_output(git_in(staging_directory).args(["rev-parse", "FETCH_HEAD^{tree}"])).ok()
}

fn copy_screenshots(
    screenshots_directory: &Path,
    staging_directory: &Path,
) -> Result<(), TaskFailure> {
    fs::read_dir(screenshots_directory)?.try_for_each(|directory_entry| {
        let entry_path = directory_entry?.path();
        if entry_path.is_file() {
            let copied_path = staging_directory.join(entry_path.file_name().unwrap_or_default());
            fs::write(&copied_path, fs::read(&entry_path)?)?;
        }
        Ok(())
    })
}

pub fn publish_screenshots(screenshots_directory: &Path) -> Result<(), TaskFailure> {
    let bot_token = required_variable("CODEBERG_TOKEN")?;
    let repository_name = required_variable("CI_REPO")?;
    let commit_hash = required_variable("CI_COMMIT_SHA")?;
    let staging_root = tempfile::tempdir()?;
    let staging_directory = staging_root.path();
    copy_screenshots(screenshots_directory, staging_directory)?;
    run_git(git_in(staging_directory).args([
        "init",
        "--quiet",
        "--initial-branch",
        SCREENSHOTS_BRANCH,
    ]))?;
    run_git(git_in(staging_directory).args(["add", "--all"]))?;
    run_git(git_in(staging_directory).args([
        "-c",
        &format!("user.name={PUBLISHING_BOT_NAME}"),
        "-c",
        &format!("user.email={PUBLISHING_COMMITTER_EMAIL}"),
        "commit",
        "--quiet",
        "--message",
        &format!("docs: screenshots of {commit_hash}"),
    ]))?;
    run_git(git_in(staging_directory).args([
        "remote",
        "add",
        "origin",
        &format!(
            "https://{PUBLISHING_BOT_NAME}:{bot_token}@{PUBLISHING_HOST}/{repository_name}.git"
        ),
    ]))?;
    let staged_tree = git_output(git_in(staging_directory).args(["rev-parse", "HEAD^{tree}"]))?;
    if published_screenshots_tree(staging_directory).as_deref() == Some(staged_tree.as_str()) {
        eprintln!("xtask: screenshots unchanged");
        return Ok(());
    }
    run_git(git_in(staging_directory).args([
        "push",
        "--quiet",
        "--force",
        "origin",
        SCREENSHOTS_BRANCH,
    ]))
}
