use std::process::Command;

use crate::{
    task_failure::TaskFailure,
    tool_commands::{required_variable, run_tool},
};

pub const BOT_ACCOUNT_NAME: &str = "wvhulle-bot";
pub const BOT_ACCOUNT_EMAIL: &str = "willemvanhulle@protonmail.com";
pub const CODEBERG_HOST: &str = "codeberg.org";
pub const TEA_LOGIN_NAME: &str = "codeberg";
pub const MAIN_BRANCH: &str = "main";

pub fn authenticated_remote_url(bot_token: &str, repository_name: &str) -> String {
    format!("https://{BOT_ACCOUNT_NAME}:{bot_token}@{CODEBERG_HOST}/{repository_name}.git")
}

pub fn bot_commit_identity_arguments() -> [String; 4] {
    [
        "-c".to_owned(),
        format!("user.name={BOT_ACCOUNT_NAME}"),
        "-c".to_owned(),
        format!("user.email={BOT_ACCOUNT_EMAIL}"),
    ]
}

pub fn point_origin_at_bot_account() -> Result<(), TaskFailure> {
    let bot_token = required_variable("CODEBERG_TOKEN")?;
    let repository_name = required_variable("CI_REPO")?;
    run_tool(
        "git",
        Command::new("git").args([
            "remote",
            "set-url",
            "origin",
            &authenticated_remote_url(&bot_token, &repository_name),
        ]),
    )
}

pub fn log_tea_into_bot_account() -> Result<(), TaskFailure> {
    let bot_token = required_variable("CODEBERG_TOKEN")?;
    let forge_url = required_variable("CI_FORGE_URL")?;
    run_tool(
        "tea",
        Command::new("tea").args([
            "login",
            "add",
            "--name",
            TEA_LOGIN_NAME,
            "--url",
            &forge_url,
            "--token",
            &bot_token,
        ]),
    )
}

#[cfg(test)]
mod codeberg_bot_account_tests {
    use super::*;

    #[test]
    fn pushes_authenticate_as_the_bot_account() {
        assert_eq!(
            authenticated_remote_url("secret", "wvhulle/lazaret"),
            "https://wvhulle-bot:secret@codeberg.org/wvhulle/lazaret.git"
        );
    }
}
