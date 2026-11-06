use std::{
    env, io,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    metainfo_release_stamp::{APPLICATION_ID, stamp_metainfo_for_ci_release},
    task_failure::TaskFailure,
    tool_commands::run_tool,
};

const FLATPAK_MANIFEST_PATH: &str = "page.codeberg.wvhulle.Lazaret.json";
const FLATPAK_BUILD_DIRECTORY: &str = "flatpak-build";
const FLATPAK_REPO_DIRECTORY: &str = "flatpak-repo";
const FLATPAK_USER_DIRECTORY: &str = "flatpak-user";
const BUNDLE_FILE_NAME: &str = "lazaret-x86_64.flatpak";
const FLATHUB_REMOTE_NAME: &str = "flathub";
const FLATHUB_REPO_URL: &str = "https://flathub.org/repo/flathub.flatpakrepo";

fn flatpak_user_directory() -> io::Result<PathBuf> {
    match env::var_os("FLATPAK_USER_DIR") {
        Some(configured_directory) => Ok(PathBuf::from(configured_directory)),
        None => Ok(env::current_dir()?.join(FLATPAK_USER_DIRECTORY)),
    }
}

fn flatpak_builder(user_directory: &Path) -> Command {
    let mut builder_command = Command::new("flatpak-builder");
    builder_command
        .env("FLATPAK_USER_DIR", user_directory)
        .args(["--user", "--disable-rofiles-fuse", "--force-clean"]);
    builder_command
}

pub fn download_flatpak_dependencies() -> Result<(), TaskFailure> {
    let user_directory = flatpak_user_directory()?;
    run_tool(
        "flatpak",
        Command::new("flatpak")
            .env("FLATPAK_USER_DIR", &user_directory)
            .args([
                "remote-add",
                "--user",
                "--if-not-exists",
                FLATHUB_REMOTE_NAME,
                FLATHUB_REPO_URL,
            ]),
    )?;
    run_tool(
        "flatpak-builder",
        flatpak_builder(&user_directory).args([
            "--install-deps-from",
            FLATHUB_REMOTE_NAME,
            "--install-deps-only",
            FLATPAK_BUILD_DIRECTORY,
            FLATPAK_MANIFEST_PATH,
        ]),
    )?;
    run_tool(
        "flatpak-builder",
        flatpak_builder(&user_directory).args([
            "--download-only",
            FLATPAK_BUILD_DIRECTORY,
            FLATPAK_MANIFEST_PATH,
        ]),
    )
}

pub fn build_flatpak_bundle(
    output_directory: &Path,
    skip_downloads: bool,
) -> Result<(), TaskFailure> {
    if !skip_downloads {
        download_flatpak_dependencies()?;
    }
    stamp_metainfo_for_ci_release()?;
    let user_directory = flatpak_user_directory()?;
    run_tool(
        "flatpak-builder",
        flatpak_builder(&user_directory).args([
            "--disable-download",
            "--disable-updates",
            "--repo",
            FLATPAK_REPO_DIRECTORY,
            FLATPAK_BUILD_DIRECTORY,
            FLATPAK_MANIFEST_PATH,
        ]),
    )?;
    std::fs::create_dir_all(output_directory)?;
    run_tool(
        "flatpak",
        Command::new("flatpak")
            .env("FLATPAK_USER_DIR", &user_directory)
            .args(["build-bundle", FLATPAK_REPO_DIRECTORY])
            .arg(output_directory.join(BUNDLE_FILE_NAME))
            .args([APPLICATION_ID, "--runtime-repo", FLATHUB_REPO_URL]),
    )
}
