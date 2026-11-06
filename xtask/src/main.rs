mod fixture_clamav_programs;
mod fixture_systemd_service;
mod page_screenshots;
mod screenshot_fixtures;
mod screenshot_publishing;
mod task_failure;

use std::{path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};

use crate::{
    fixture_clamav_programs::{invoked_as_fixture_program, run_fixture_program},
    page_screenshots::{list_visible_widgets, render_page_screenshots},
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
        #[arg(default_value = "--page=scan")]
        page_argument: String,
    },
    PublishScreenshots {
        screenshots_directory: PathBuf,
    },
}

fn run_repository_task(repository_task: RepositoryTask) -> Result<(), TaskFailure> {
    match repository_task {
        RepositoryTask::RenderScreenshots { output_directory } => {
            render_page_screenshots(&output_directory)
        }
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
