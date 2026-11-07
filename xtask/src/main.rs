mod cachix_closure_push;
mod ci_tool_preparation;
mod codeberg_bot_account;
mod debian_package;
mod dependency_update_pull_request;
mod fixture_clamav_programs;
mod fixture_systemd_service;
mod flatpak_bundle;
mod metainfo_release_stamp;
mod page_screenshots;
mod release_publishing;
mod screenshot_fixtures;
mod screenshot_publishing;
mod task_failure;
mod tool_commands;

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

use crate::{
    cachix_closure_push::push_build_closure,
    ci_tool_preparation::{check_commit_messages, download_tools, prepare_ci_tools},
    debian_package::{build_debian_package, check_debian_package_install, ci_build_debian_package},
    dependency_update_pull_request::open_dependency_update_pull_request,
    fixture_clamav_programs::{invoked_as_fixture_program, run_fixture_program},
    flatpak_bundle::{build_flatpak_bundle, download_flatpak_dependencies},
    page_screenshots::{list_visible_widgets, render_page_screenshots},
    release_publishing::{ReleasePlzCommand, run_release_plz, upload_release_assets},
    screenshot_publishing::publish_screenshots,
    task_failure::TaskFailure,
};

#[derive(Parser)]
struct XtaskCli {
    #[command(subcommand)]
    repository_task: RepositoryTask,
}

#[derive(Subcommand)]
enum RepositoryTask {
    RenderScreenshots {
        #[arg(default_value = "dist/screenshots")]
        output_directory: PathBuf,
    },
    ListWidgets {
        #[arg(default_value = "--page=manual-scan")]
        page_argument: String,
    },
    PublishScreenshots {
        screenshots_directory: PathBuf,
    },
    PushToCachix {
        #[arg(required = true)]
        installables: Vec<String>,
    },
    CheckCommits {
        #[arg(long)]
        fetch_target_branch: bool,
        revision_ranges: Vec<String>,
    },
    ReleasePlz {
        #[arg(value_enum)]
        release_plz_command: ReleasePlzCommand,
    },
    UploadReleaseAssets {
        assets_directory: PathBuf,
    },
    DownloadTools {
        binary_cache_url: String,
        #[arg(required = true)]
        tool_installables: Vec<String>,
    },
    PrepareCiTools,
    OpenDependencyUpdatePr,
    BuildDebianPackage {
        #[arg(default_value = "dist")]
        output_directory: PathBuf,
    },
    CiBuildDebianPackage {
        #[arg(default_value = "dist")]
        output_directory: PathBuf,
    },
    CheckDebianPackageInstall {
        #[arg(default_value = "dist")]
        packages_directory: PathBuf,
    },
    DownloadFlatpakDependencies,
    BuildFlatpakBundle {
        #[arg(long)]
        skip_downloads: bool,
        #[arg(default_value = "dist")]
        output_directory: PathBuf,
    },
}

fn run_repository_task(repository_task: RepositoryTask) -> Result<(), TaskFailure> {
    match repository_task {
        RepositoryTask::RenderScreenshots { output_directory } => {
            render_page_screenshots(&output_directory)
        }
        RepositoryTask::PushToCachix { installables } => push_build_closure(&installables),
        RepositoryTask::CheckCommits {
            fetch_target_branch,
            revision_ranges,
        } => check_commit_messages(fetch_target_branch, &revision_ranges),
        RepositoryTask::ReleasePlz {
            release_plz_command,
        } => run_release_plz(release_plz_command),
        RepositoryTask::UploadReleaseAssets { assets_directory } => {
            upload_release_assets(&assets_directory)
        }
        RepositoryTask::DownloadTools {
            binary_cache_url,
            tool_installables,
        } => download_tools(&binary_cache_url, &tool_installables),
        RepositoryTask::PrepareCiTools => prepare_ci_tools(),
        RepositoryTask::OpenDependencyUpdatePr => open_dependency_update_pull_request(),
        RepositoryTask::BuildDebianPackage { output_directory } => {
            build_debian_package(&output_directory)
        }
        RepositoryTask::CiBuildDebianPackage { output_directory } => {
            ci_build_debian_package(&output_directory)
        }
        RepositoryTask::CheckDebianPackageInstall { packages_directory } => {
            check_debian_package_install(&packages_directory)
        }
        RepositoryTask::DownloadFlatpakDependencies => download_flatpak_dependencies(),
        RepositoryTask::BuildFlatpakBundle {
            skip_downloads,
            output_directory,
        } => build_flatpak_bundle(&output_directory, skip_downloads),
        RepositoryTask::PublishScreenshots {
            screenshots_directory,
        } => publish_screenshots(&screenshots_directory),
        RepositoryTask::ListWidgets { page_argument } => {
            list_visible_widgets(&page_argument).map(|widget_descriptions| {
                widget_descriptions
                    .iter()
                    .for_each(|widget_description| println!("{widget_description}"));
            })
        }
    }
}

fn main() -> ExitCode {
    if invoked_as_fixture_program() {
        return run_fixture_program();
    }
    match run_repository_task(XtaskCli::parse().repository_task) {
        Ok(()) => ExitCode::SUCCESS,
        Err(task_failure) => {
            eprintln!("{task_failure}");
            ExitCode::FAILURE
        }
    }
}
