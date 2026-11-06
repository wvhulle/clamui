use std::process::Command;

use crate::{
    codeberg_bot_account::{
        BOT_ACCOUNT_NAME, MAIN_BRANCH, TEA_LOGIN_NAME, bot_commit_identity_arguments,
        log_tea_into_bot_account, point_origin_at_bot_account,
    },
    task_failure::TaskFailure,
    tool_commands::{required_variable, run_tool, tool_stdout},
};

const UPDATE_BRANCH: &str = "bot/dependency-updates";
const UPDATE_COMMIT_MESSAGE: &str = "chore(deps): update lock files";
const PULL_REQUEST_DESCRIPTION: &str = "Opened by the weekly dependency update job. The checks on \
                                        this pull request are the trial build. Commits pushed to \
                                        this branch by hand stop further automatic updates until \
                                        it is merged.";

fn open_pull_request_branches(repository_name: &str) -> Result<Vec<String>, TaskFailure> {
    let listed_heads = tool_stdout(
        "tea",
        Command::new("tea").args([
            "pulls",
            "list",
            "--login",
            TEA_LOGIN_NAME,
            "--repo",
            repository_name,
            "--state",
            "open",
            "--fields",
            "head",
            "--output",
            "simple",
        ]),
    )?;
    Ok(listed_heads
        .lines()
        .map(str::trim)
        .filter(|head_branch| !head_branch.is_empty())
        .map(str::to_owned)
        .collect())
}

fn remote_update_branch_commit() -> Result<Option<String>, TaskFailure> {
    let listed_references = tool_stdout(
        "git",
        Command::new("git").args([
            "ls-remote",
            "--heads",
            "origin",
            &format!("refs/heads/{UPDATE_BRANCH}"),
        ]),
    )?;
    Ok(listed_references
        .split_whitespace()
        .next()
        .map(str::to_owned))
}

fn has_hand_written_commits(commit_authors: &str) -> bool {
    commit_authors
        .lines()
        .any(|commit_author| commit_author != BOT_ACCOUNT_NAME)
}

fn update_branch_has_hand_written_commits() -> Result<bool, TaskFailure> {
    run_tool(
        "git",
        Command::new("git").args([
            "fetch",
            "--quiet",
            "origin",
            &format!("+refs/heads/{UPDATE_BRANCH}:refs/remotes/origin/{UPDATE_BRANCH}"),
        ]),
    )?;
    let commit_authors = tool_stdout(
        "git",
        Command::new("git").args([
            "log",
            "--format=%an",
            &format!("origin/{MAIN_BRANCH}..origin/{UPDATE_BRANCH}"),
        ]),
    )?;
    Ok(has_hand_written_commits(&commit_authors))
}

pub fn open_dependency_update_pull_request() -> Result<(), TaskFailure> {
    let repository_name = required_variable("CI_REPO")?;
    point_origin_at_bot_account()?;
    log_tea_into_bot_account()?;
    run_tool(
        "git",
        Command::new("git").args([
            "fetch",
            "--quiet",
            "origin",
            &format!("+refs/heads/{MAIN_BRANCH}:refs/remotes/origin/{MAIN_BRANCH}"),
        ]),
    )?;
    let remote_commit = remote_update_branch_commit()?;
    let pull_request_is_open =
        open_pull_request_branches(&repository_name)?.contains(&UPDATE_BRANCH.to_owned());
    if remote_commit.is_some() && pull_request_is_open && update_branch_has_hand_written_commits()?
    {
        eprintln!("xtask: leaving {UPDATE_BRANCH} alone because it has hand-written commits");
        return Ok(());
    }
    run_tool(
        "git",
        Command::new("git").args([
            "checkout",
            "-B",
            UPDATE_BRANCH,
            &format!("origin/{MAIN_BRANCH}"),
        ]),
    )?;
    run_tool("cargo", Command::new("cargo").arg("update"))?;
    run_tool("nix", Command::new("nix").args(["flake", "update"]))?;
    let changed_files = tool_stdout("git", Command::new("git").args(["diff", "--name-only"]))?;
    if changed_files.trim().is_empty() {
        eprintln!("xtask: dependencies are up to date");
        return Ok(());
    }
    run_tool(
        "git",
        Command::new("git")
            .args(bot_commit_identity_arguments())
            .args(["commit", "--all", "--message", UPDATE_COMMIT_MESSAGE]),
    )?;
    run_tool(
        "git",
        Command::new("git").args([
            "push",
            &format!(
                "--force-with-lease={UPDATE_BRANCH}:{}",
                remote_commit.unwrap_or_default()
            ),
            "origin",
            UPDATE_BRANCH,
        ]),
    )?;
    if pull_request_is_open {
        eprintln!("xtask: updated the open pull request from {UPDATE_BRANCH}");
        return Ok(());
    }
    run_tool(
        "tea",
        Command::new("tea").args([
            "pulls",
            "create",
            "--login",
            TEA_LOGIN_NAME,
            "--repo",
            &repository_name,
            "--head",
            UPDATE_BRANCH,
            "--base",
            MAIN_BRANCH,
            "--title",
            UPDATE_COMMIT_MESSAGE,
            "--description",
            PULL_REQUEST_DESCRIPTION,
        ]),
    )
}

#[cfg(test)]
mod dependency_update_pull_request_tests {
    use super::*;

    #[test]
    fn only_bot_commits_allow_another_automatic_update() {
        assert!(!has_hand_written_commits("wvhulle-bot\nwvhulle-bot\n"));
        assert!(has_hand_written_commits("wvhulle-bot\nWillem Vanhulle\n"));
    }
}
