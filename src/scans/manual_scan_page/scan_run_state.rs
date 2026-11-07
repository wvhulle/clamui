use std::path::Path;

use gettextrs::{gettext, ngettext};

use crate::{
    host_services::{
        clamav_programs::trusted_program_lookup::ProgramLocation,
        clamav_scanner::{
            scan_progress_events::{
                CompletedScanOutcome, ScanProblem, ThreatFindings, UnscannedFileCause,
            },
            scan_target_enumeration::ScanTargetFailure,
            scanner_command_builder::ScannerProgramPaths,
            scanner_output_parser::{
                ScanFailureReason, ScanNotice, sanitize_scanner_line, sanitize_scanner_text,
            },
        },
    },
    scans::manual_scan_page::{
        scan_page_state::ScanEnding,
        scan_results_section::scan_results_state::{ProblemPathGroup, ScanResultsStatus},
    },
    shared_widgets::{
        scanner_exit_text::abnormal_scanner_exit_text,
        scanner_start_failure_text::describe_start_failure,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerProgramTrust {
    ProgramsTrusted,
    ReplaceableProgramRefused,
}

pub fn scanner_program_trust(scanner_programs: &ScannerProgramPaths) -> ScannerProgramTrust {
    let program_refused = [
        &scanner_programs.clamdscan_program,
        &scanner_programs.clamscan_program,
    ]
    .into_iter()
    .any(|program_location| {
        matches!(
            program_location,
            ProgramLocation::OnlyReplaceableCandidates { .. }
        )
    });
    if program_refused {
        ScannerProgramTrust::ReplaceableProgramRefused
    } else {
        ScannerProgramTrust::ProgramsTrusted
    }
}

fn describe_target_failure(target_failure: &ScanTargetFailure) -> String {
    match target_failure {
        ScanTargetFailure::TargetMissing => {
            gettext("Scan target does not exist or contains an invalid NUL byte")
        }
        ScanTargetFailure::TargetNotScannable => {
            gettext("Scan target is not a regular file or directory")
        }
        ScanTargetFailure::TargetDirectoryUnreadable {
            target_path,
            directory_failure,
        } => gettext("Unable to enumerate scan target {path}: {error}")
            .replace("{error}", &directory_failure.to_string())
            .replace(
                "{path}",
                &sanitize_scanner_line(&target_path.to_string_lossy()),
            ),
        ScanTargetFailure::FileListUnwritable(list_failure) => {
            gettext("Unable to write private clamd file list: {error}")
                .replace("{error}", &list_failure.to_string())
        }
        ScanTargetFailure::EnumerationInterrupted => {
            gettext("Listing the scan target stopped unexpectedly.")
        }
    }
}

fn describe_scan_problem(scan_problem: &ScanProblem) -> String {
    match scan_problem {
        ScanProblem::ScannerFailed(ScanFailureReason::NoFilesScanned) => {
            gettext("No files could be scanned")
        }
        ScanProblem::ScannerFailed(ScanFailureReason::ScannerReported { scanner_message }) => {
            sanitize_scanner_text(scanner_message)
        }
        ScanProblem::ScannerFailed(ScanFailureReason::ScannerExitedAbnormally(abnormal_exit)) => {
            abnormal_scanner_exit_text(abnormal_exit)
        }
        ScanProblem::FilesNotScanned {
            unscanned_paths,
            unscanned_cause,
        } => format!(
            "{} {}",
            unscanned_files_title(unscanned_paths.len()),
            describe_unscanned_cause(*unscanned_cause)
        ),
        ScanProblem::ScanPhaseUnstartable(start_failure) => describe_start_failure(start_failure),
        ScanProblem::TargetRejected(target_failure) => describe_target_failure(target_failure),
    }
}

fn unscanned_files_title(unscanned_count: usize) -> String {
    ngettext(
        "{count} file was not scanned",
        "{count} files were not scanned",
        u32::try_from(unscanned_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &unscanned_count.to_string())
}

fn describe_unscanned_cause(unscanned_cause: UnscannedFileCause) -> String {
    match unscanned_cause {
        UnscannedFileCause::ClamdConnectionLost => {
            gettext("The connection to clamd was lost during the scan.")
        }
        UnscannedFileCause::ScannerStoppedReporting => {
            gettext("The scanner did not report a result for these files.")
        }
    }
}

fn is_listed_as_path_group(scan_problem: &ScanProblem) -> bool {
    matches!(scan_problem, ScanProblem::FilesNotScanned { .. })
}

pub fn scan_target_name(scan_target: &Path) -> String {
    sanitize_scanner_line(
        &scan_target
            .file_name()
            .unwrap_or(scan_target.as_os_str())
            .to_string_lossy(),
    )
}

fn describe_scan_notice(scan_notice: &ScanNotice) -> String {
    match scan_notice {
        ScanNotice::NoNotice => String::new(),
        ScanNotice::FilesInaccessible { file_count } => ngettext(
            "{count} file could not be accessed",
            "{count} files could not be accessed",
            u32::try_from(*file_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &file_count.to_string()),
        ScanNotice::FilesUnreadable { file_count } => ngettext(
            "{count} file could not be read",
            "{count} files could not be read",
            u32::try_from(*file_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &file_count.to_string()),
        ScanNotice::NonfatalWarnings { warning_count } => ngettext(
            "{count} non-fatal warning during scan; some files may have been only partially \
             scanned",
            "{count} non-fatal warnings during scan; some files may have been only partially \
             scanned",
            u32::try_from(*warning_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &warning_count.to_string()),
    }
}

pub fn scan_summary_text(scan_outcome: &CompletedScanOutcome) -> String {
    let threat_summary =
        (!scan_outcome.threat_findings.attributed_threats().is_empty()).then(|| {
            let threat_count = scan_outcome.threat_findings.attributed_threats().len();
            ngettext(
                "{count} threat found",
                "{count} threats found",
                u32::try_from(threat_count).unwrap_or(u32::MAX),
            )
            .replace("{count}", &threat_count.to_string())
        });
    let inspected_summary = ngettext(
        "{count} file scanned",
        "{count} files scanned",
        u32::try_from(scan_outcome.inspected_file_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &scan_outcome.inspected_file_count.to_string());
    [inspected_summary]
        .into_iter()
        .chain(threat_summary)
        .chain(scan_notice_lines(scan_outcome))
        .collect::<Vec<_>>()
        .join("\n")
}

fn scan_notice_lines(scan_outcome: &CompletedScanOutcome) -> Vec<String> {
    notice_lines_where(scan_outcome, |_scan_problem| true, |_scan_notice| true)
}

pub fn unlisted_notice_lines(scan_outcome: &CompletedScanOutcome) -> Vec<String> {
    notice_lines_where(
        scan_outcome,
        |scan_problem| !is_listed_as_path_group(scan_problem),
        |scan_notice| {
            !matches!(
                scan_notice,
                ScanNotice::FilesInaccessible { .. } | ScanNotice::FilesUnreadable { .. }
            )
        },
    )
}

fn unlisted_skipped_paths(scan_outcome: &CompletedScanOutcome) -> Vec<String> {
    scan_outcome
        .skipped_paths
        .iter()
        .filter(|skipped_path| {
            !scan_outcome
                .threat_findings
                .attributed_threats()
                .iter()
                .any(|detected_threat| detected_threat.file_path == Path::new(skipped_path))
        })
        .cloned()
        .collect()
}

pub fn problem_path_groups(scan_outcome: &CompletedScanOutcome) -> Vec<ProblemPathGroup> {
    let unscanned_groups = scan_outcome
        .scan_problems
        .iter()
        .filter_map(|scan_problem| match scan_problem {
            ScanProblem::FilesNotScanned {
                unscanned_paths,
                unscanned_cause,
            } => Some(ProblemPathGroup {
                group_title: unscanned_files_title(unscanned_paths.len()),
                group_explanation: describe_unscanned_cause(*unscanned_cause),
                listed_paths: unscanned_paths
                    .iter()
                    .map(|unscanned_path| unscanned_path.to_string_lossy().into_owned())
                    .collect(),
            }),
            _other_problem => None,
        });
    let skipped_paths = unlisted_skipped_paths(scan_outcome);
    let skipped_group = (!skipped_paths.is_empty()).then(|| ProblemPathGroup {
        group_title: ngettext(
            "{count} file could not be accessed",
            "{count} files could not be accessed",
            u32::try_from(skipped_paths.len()).unwrap_or(u32::MAX),
        )
        .replace("{count}", &skipped_paths.len().to_string()),
        group_explanation: gettext("ClamAV could not open these files."),
        listed_paths: skipped_paths,
    });
    unscanned_groups.chain(skipped_group).collect()
}

fn notice_lines_where(
    scan_outcome: &CompletedScanOutcome,
    include_problem: impl Fn(&ScanProblem) -> bool,
    include_notice: impl Fn(&ScanNotice) -> bool,
) -> Vec<String> {
    let unattributed_notice = match scan_outcome.threat_findings {
        ThreatFindings::UnattributedThreatsOnly => Some(gettext(
            "The scanner reported a threat without naming the file.",
        )),
        ThreatFindings::NoThreatsFound | ThreatFindings::AttributedThreats(_) => None,
    };
    unattributed_notice
        .into_iter()
        .chain(
            scan_outcome
                .scan_problems
                .iter()
                .filter(|scan_problem| include_problem(scan_problem))
                .map(describe_scan_problem),
        )
        .chain(
            scan_outcome
                .scan_notices
                .iter()
                .filter(|scan_notice| include_notice(scan_notice))
                .map(describe_scan_notice),
        )
        .chain(
            scan_outcome
                .nonfatal_warnings
                .iter()
                .map(|nonfatal_warning| sanitize_scanner_line(nonfatal_warning)),
        )
        .collect()
}

pub fn results_status(
    scan_outcome: &CompletedScanOutcome,
    scan_ending: ScanEnding,
) -> ScanResultsStatus {
    match scan_ending {
        _any_ending if scan_outcome.threats_were_found() => ScanResultsStatus::ThreatsDetected,
        ScanEnding::ScanCancelled => ScanResultsStatus::ScanCancelled,
        ScanEnding::ScanCompleted if scan_outcome.scan_problems.is_empty() => {
            ScanResultsStatus::NoThreatsDetected
        }
        ScanEnding::ScanCompleted => ScanResultsStatus::FinishedWithProblems,
    }
}
