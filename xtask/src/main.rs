mod fixture_clamav_programs;
mod fixture_systemd_service;
mod headless_sway_session;
mod page_screenshots;
mod screenshot_fixtures;
mod task_failure;
mod virtual_pointer_input;

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

use crate::{
    fixture_clamav_programs::{invoked_as_fixture_program, run_fixture_program},
    page_screenshots::render_page_screenshots,
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
}

fn run_repository_task(repository_task: RepositoryTask) -> Result<(), TaskFailure> {
    match repository_task {
        RepositoryTask::RenderScreenshots { output_directory } => {
            render_page_screenshots(&output_directory)
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
