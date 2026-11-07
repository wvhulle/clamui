use std::{path::PathBuf, time::Instant};

use futures::{StreamExt, future::ready, stream};
use gettextrs::gettext;
use jiff::Timestamp;
use relm4::{
    Component, ComponentSender,
    gtk::{gio::prelude::SettingsExt, glib},
};

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityRecord, FoundThreatCount, NewActivityEntry, ScanActivityStatus, ScanOrigin,
        },
        clamav_config::detection_options::read_host_clamscan_detection_arguments,
        clamav_scanner::{
            scan_exclusion_rules::{ExclusionEntry, ScanExclusions},
            scan_progress_events::{ScanProgressEvent, ScanRequest, scan_progress_events},
            scanner_command_builder::{ScannerProgramPaths, choose_scanner_backend},
            scanner_process_events::ScanStartFailure,
        },
        desktop::{
            desktop_notifications::notify_outside_the_window,
            stored_settings::{
                SHOW_LIVE_PROGRESS_KEY, application_settings, read_exclusion_entries,
                scanner_backend_preference,
            },
        },
    },
    shared_widgets::{
        component_streams::run_stream_then,
        scan_runs::{
            scan_outcome_text::{
                problem_path_groups, results_status, scan_summary_text, unlisted_notice_lines,
            },
            scan_results_section::scan_results_state::{ScanResultsStatus, ScanResultsView},
            scan_run_progress::{
                CurrentFileDisplay, FinishedScan, LiveProgress, RunningScan, ScanEnding, ScanRun,
                ScanRunNumber, TemporaryScanTarget,
            },
        },
    },
};

const PROGRESS_BATCH_SIZE: usize = 256;

pub struct ScanRunRequest {
    pub scan_run_number: ScanRunNumber,
    pub scan_targets: Vec<PathBuf>,
    pub extra_exclusion_entries: Vec<ExclusionEntry>,
    pub file_list_directory: PathBuf,
    pub temporary_scan_target: TemporaryScanTarget,
}

pub struct ScanRunCommands<PageCommand> {
    pub progress_command: fn(ScanRunNumber, Vec<ScanProgressEvent>) -> PageCommand,
    pub finished_command: fn(ScanRunNumber) -> PageCommand,
}

pub fn start_scan_run<Page>(
    sender: &ComponentSender<Page>,
    run_request: ScanRunRequest,
    run_commands: ScanRunCommands<Page::CommandOutput>,
) -> RunningScan
where
    Page: Component,
    Page::CommandOutput: Send,
{
    let ScanRunRequest {
        scan_run_number,
        scan_targets,
        extra_exclusion_entries,
        file_list_directory,
        temporary_scan_target,
    } = run_request;
    let settings = application_settings();
    let current_file_display = if settings.boolean(SHOW_LIVE_PROGRESS_KEY) {
        CurrentFileDisplay::ShowCurrentFile
    } else {
        CurrentFileDisplay::HideCurrentFile
    };
    let scan_exclusions = ScanExclusions::from_entries(
        &read_exclusion_entries(&settings)
            .into_iter()
            .chain(extra_exclusion_entries)
            .collect::<Vec<_>>(),
        &glib::home_dir(),
    );
    let backend_preference = scanner_backend_preference(&settings);
    let started_instant = Instant::now();
    let scan_run = ScanRun::starting(
        scan_run_number,
        scan_targets.clone(),
        Timestamp::now(),
        started_instant,
    );
    let scan_events = stream::once(async move {
        let scanner_programs = ScannerProgramPaths::locate_trusted_programs_in_background().await?;
        let scanner_backend = choose_scanner_backend(backend_preference, &scanner_programs).await;
        let detection_arguments = read_host_clamscan_detection_arguments().await?;
        Ok::<ScanRequest, ScanStartFailure>(ScanRequest {
            scan_exclusions,
            scan_targets,
            scanner_backend,
            scanner_programs,
            file_list_directory,
            detection_arguments,
        })
    })
    .flat_map(|scan_request| match scan_request {
        Ok(scan_request) => scan_progress_events(scan_request).left_stream(),
        Err(start_failure) => stream::once(ready(ScanProgressEvent::ScanPhaseUnstartable(
            start_failure,
        )))
        .right_stream(),
    });
    let progress_command = run_commands.progress_command;
    let scan_stream = run_stream_then(
        sender,
        scan_events
            .ready_chunks(PROGRESS_BATCH_SIZE)
            .map(move |progress_batch| progress_command(scan_run_number, progress_batch)),
        (run_commands.finished_command)(scan_run_number),
    );
    RunningScan::started(
        scan_run,
        scan_stream,
        LiveProgress::starting(current_file_display, started_instant),
        temporary_scan_target,
    )
}

pub fn finished_results_view(finished_scan: &FinishedScan) -> ScanResultsView {
    let scan_outcome = &finished_scan.scan_run.scan_outcome;
    ScanResultsView {
        results_status: results_status(scan_outcome, finished_scan.scan_ending),
        inspected_file_count: scan_outcome.inspected_file_count,
        planned_file_count: scan_outcome.planned_file_count,
        scanned_directory_count: scan_outcome.scanned_directory_count,
        excluded_entry_count: scan_outcome.excluded_entry_count,
        elapsed_time: finished_scan.elapsed_time,
        detected_threats: scan_outcome.threat_findings.attributed_threats().to_vec(),
        problem_path_groups: problem_path_groups(scan_outcome),
        notice_lines: unlisted_notice_lines(scan_outcome),
        noteworthy_output: scan_outcome.noteworthy_output.clone(),
    }
}

pub fn finished_results_status(finished_scan: &FinishedScan) -> ScanResultsStatus {
    results_status(
        &finished_scan.scan_run.scan_outcome,
        finished_scan.scan_ending,
    )
}

pub fn notify_finished_scan(finished_scan: &FinishedScan) {
    let notification_title = match finished_results_status(finished_scan) {
        ScanResultsStatus::ThreatsDetected => gettext("Threats Detected"),
        ScanResultsStatus::NoThreatsDetected => gettext("No threats found"),
        ScanResultsStatus::FinishedWithProblems => gettext("The scan did not finish cleanly"),
        ScanResultsStatus::ScanCancelled => return,
    };
    notify_outside_the_window(
        "scan-finished",
        &notification_title,
        &scan_summary_text(&finished_scan.scan_run.scan_outcome),
    );
}

pub fn finished_scan_activity(
    finished_scan: &FinishedScan,
    scan_origin: ScanOrigin,
) -> NewActivityEntry {
    let scan_run = &finished_scan.scan_run;
    let scan_outcome = &scan_run.scan_outcome;
    let scan_status = match FoundThreatCount::from_findings(&scan_outcome.threat_findings) {
        Some(found_threats) => ScanActivityStatus::ScanInfected { found_threats },
        None => match finished_scan.scan_ending {
            ScanEnding::ScanCancelled => ScanActivityStatus::ScanCancelled,
            ScanEnding::ScanCompleted if scan_outcome.scan_problems.is_empty() => {
                ScanActivityStatus::ScanClean
            }
            ScanEnding::ScanCompleted => ScanActivityStatus::ScanFailed,
        },
    };
    NewActivityEntry {
        started_at: scan_run.started_at,
        activity_record: ActivityRecord::ScanActivity {
            scan_targets: scan_run.scan_targets.clone(),
            inspected_file_count: scan_outcome.inspected_file_count,
            scan_status,
            scan_origin,
        },
        duration_millis: finished_scan.elapsed_time.as_millis() as u64,
        activity_output: scan_run.scan_outcome.noteworthy_output.clone(),
    }
}
