use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures::{
    StreamExt,
    future::{AbortHandle, ready},
    stream,
};
use gettextrs::{gettext, ngettext};
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, RelmWidgetExt,
    adw,
    adw::prelude::*,
    gtk,
    gtk::{gdk, gio, glib},
    prelude::{DynamicIndex, FactoryVecDeque},
};
use tempfile::NamedTempFile;

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityHistory, ActivityHistoryFailure, ActivityStatus, NewActivityEntry,
        },
        clamav_programs::trusted_program_lookup::ProgramLocation,
        clamav_scanner::{
            scan_exclusion_rules::{ExclusionEntry, ScanExclusions},
            scan_progress_estimates::{RefreshThrottle, file_progress_text},
            scan_progress_events::{
                CompletedScanOutcome, ScanProblem, ScanProgressEvent, ScanRequest,
                UnscannedFileCause, scan_progress_events,
            },
            scan_target_enumeration::ScanTargetFailure,
            scanner_command_builder::{
                ScannerBackend, ScannerProgramPaths, choose_scanner_backend,
            },
            scanner_output_parser::{
                ScanFailureReason, ScanNotice, sanitize_scanner_line, sanitize_scanner_text,
            },
            scanner_process_events::ScanStartFailure,
        },
        desktop::{
            desktop_notifications::notify_outside_the_window,
            stored_settings::{
                SHOW_LIVE_PROGRESS_KEY, application_settings, read_exclusion_entries,
                scanner_backend_preference,
            },
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
    },
    scan_page::{
        eicar_test_file::write_eicar_test_file,
        scan_profiles_dialog::{
            profile_manager_dialog::{ProfileManagerDialog, ProfileManagerDialogOutput},
            scan_profile_store::{ScanProfile, ScanProfileStore},
        },
        scan_progress_display::{ScanProgressDisplay, ScanningSnapshot},
        scan_results_section::scan_results_component::{
            ProblemPathGroup, ScanResultsSection, ScanResultsSectionInit, ScanResultsSectionInput,
            ScanResultsSectionOutput, ScanResultsStatus, ScanResultsView,
        },
        scan_settings::scan_settings_sections,
        scan_target_row::{ScanTargetRow, ScanTargetRowOutput},
    },
};

const PROGRESS_BATCH_SIZE: usize = 256;
const DISPLAY_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisplayedScanPhase {
    PreparingScan,
    FindingFiles,
    ScanningFiles,
}

enum ScanPageState {
    WaitingForTargets,
    ScanInProgress { scan_abort_handle: AbortHandle },
    ScanCancelling,
    ScanCancelled,
    ScanCompleted,
}

enum SelectedScanProfile {
    ManualTargets,
    ProfileChosen(ScanProfile),
}

enum ProfileManagerView {
    ManagerClosed,
    ManagerOpen {
        _profile_manager: Controller<ProfileManagerDialog>,
    },
}

enum ResultsPanelView {
    NoResultsYet,
    ResultsShown(Controller<ScanResultsSection>),
}

enum ScannerBackendView {
    DetectingBackend,
    BackendDetected(ScannerBackend),
}

pub struct ScanPageInit {
    pub quarantine_vault: QuarantineVault,
    pub activity_history: ActivityHistory,
    pub profile_store: ScanProfileStore,
    pub file_list_directory: PathBuf,
}

pub struct ScanPage {
    quarantine_vault: QuarantineVault,
    activity_history: ActivityHistory,
    profile_store: ScanProfileStore,
    known_profiles: Vec<ScanProfile>,
    selected_profile: SelectedScanProfile,
    profile_manager_view: ProfileManagerView,
    profile_names: gtk::StringList,
    scan_started_at: SystemTime,
    scan_started_instant: Instant,
    active_scan_targets: Vec<PathBuf>,
    file_list_directory: PathBuf,
    scan_page_state: ScanPageState,
    scan_outcome: CompletedScanOutcome,
    current_file_label: String,
    show_live_progress: bool,
    progress_display: ScanProgressDisplay,
    display_throttle: RefreshThrottle,
    displayed_phase: DisplayedScanPhase,
    results_panel_view: ResultsPanelView,
    results_container: gtk::Box,
    scan_target_rows: FactoryVecDeque<ScanTargetRow>,
    scanner_backend_view: ScannerBackendView,
    scanner_program_trust: ScannerProgramTrust,
    eicar_test_files: Vec<NamedTempFile>,
    page_notice: String,
}

#[derive(Debug)]
pub enum ScanPageInput {
    ChooseFilesRequested,
    ChooseFolderRequested,
    ScanTargetsChosen(Vec<PathBuf>),
    ScanTargetsAdded(Vec<PathBuf>),
    QuickScanRequested,
    DeviceMounted(PathBuf),
    ProfileRowSelected { row_position: usize },
    ManageProfilesRequested,
    ProfilesChanged,
    RunProfileRequested(ScanProfile),
    RemoveTargetRequested(DynamicIndex),
    StartScanRequested,
    EicarTestRequested,
    CancelScanRequested,
    NewScanRequested,
    CopyResultsRequested,
    ExportResultsRequested,
    ToastRequested(String),
    QuarantineEntriesChanged,
}

#[derive(Debug)]
pub enum ScanPageOutput {
    QuarantineEntriesChanged,
    ActivityRecorded,
}

#[derive(Debug)]
pub enum ScanPageCommand {
    ProgressBatchArrived(Vec<ScanProgressEvent>),
    ScanStreamFinished,
    ScannerBackendDetected {
        scanner_backend: ScannerBackend,
        scanner_program_trust: ScannerProgramTrust,
    },
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
}

const PROTECTION_PAGE_NAME: &str = "protection";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerProgramTrust {
    ProgramsTrusted,
    ReplaceableProgramRefused,
}

fn scanner_program_trust(scanner_programs: &ScannerProgramPaths) -> ScannerProgramTrust {
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

fn describe_start_failure(start_failure: &ScanStartFailure) -> String {
    match start_failure {
        ScanStartFailure::ScannerProgramMissing => {
            gettext("The ClamAV scanner is not installed or not on the search path.")
        }
        ScanStartFailure::ScannerProgramReplaceable {
            candidate_path,
            replaceable_path,
        } => gettext(
            "Lazaret refused to run {program}, because your account can replace {replaceable}. \
             Install ClamAV system-wide so a program planted by malware can't fake clean results.",
        )
        .replace(
            "{replaceable}",
            &sanitize_scanner_line(&replaceable_path.to_string_lossy()),
        )
        .replace(
            "{program}",
            &sanitize_scanner_line(&candidate_path.to_string_lossy()),
        ),
        ScanStartFailure::ScannerSpawnFailed(spawn_failure) => {
            gettext("The scanner could not be started: {error}")
                .replace("{error}", &spawn_failure.to_string())
        }
        ScanStartFailure::ScannerWorkDirectoryUnavailable(work_directory_failure) => {
            gettext("Unable to create the private scanner work directory: {error}")
                .replace("{error}", &work_directory_failure.to_string())
        }
        ScanStartFailure::ScannerOutputUncaptured => {
            gettext("The scanner output could not be captured.")
        }
        ScanStartFailure::ScanInputUnavailable {
            input_path,
            input_failure,
        } => gettext("Unable to safely open scan input {path}: {error}")
            .replace("{error}", &input_failure.to_string())
            .replace(
                "{path}",
                &sanitize_scanner_line(&input_path.to_string_lossy()),
            ),
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
        ScanProblem::ScannerFailed(ScanFailureReason::UnexplainedScannerFailure { exit_code }) => {
            gettext("The scanner stopped with exit code {code}.")
                .replace("{code}", &exit_code.to_string())
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

fn close_enclosing_popover(clicked_button: &gtk::Button) {
    if let Some(enclosing_popover) = clicked_button
        .ancestor(gtk::Popover::static_type())
        .and_downcast::<gtk::Popover>()
    {
        enclosing_popover.popdown();
    }
}

fn scan_target_name(scan_target: &Path) -> String {
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

fn dropped_file_paths(dropped_value: &glib::Value) -> Vec<PathBuf> {
    dropped_value
        .get::<gdk::FileList>()
        .map(|dropped_files| {
            dropped_files
                .files()
                .iter()
                .filter_map(gio::prelude::FileExt::path)
                .collect()
        })
        .unwrap_or_default()
}

fn chosen_file_paths(chosen_files: &gio::ListModel) -> Vec<PathBuf> {
    (0..chosen_files.n_items())
        .filter_map(|file_position| chosen_files.item(file_position))
        .filter_map(|chosen_file| chosen_file.downcast::<gio::File>().ok())
        .filter_map(|chosen_file| chosen_file.path())
        .collect()
}

impl ScanPage {
    fn scan_is_running(&self) -> bool {
        matches!(
            self.scan_page_state,
            ScanPageState::ScanInProgress { .. } | ScanPageState::ScanCancelling
        )
    }

    fn chosen_scan_targets(&self) -> Vec<PathBuf> {
        self.scan_target_rows
            .iter()
            .map(|target_row| target_row.target_path.clone())
            .collect()
    }

    fn add_scan_targets(&mut self, added_targets: Vec<PathBuf>) {
        let known_targets = self.chosen_scan_targets();
        let mut target_rows_guard = self.scan_target_rows.guard();
        added_targets
            .into_iter()
            .filter(|added_target| !known_targets.contains(added_target))
            .for_each(|added_target| {
                target_rows_guard.push_back(added_target);
            });
    }

    fn scanner_backend_text(&self) -> String {
        match self.scanner_backend_view {
            ScannerBackendView::DetectingBackend => gettext("Checking…"),
            ScannerBackendView::BackendDetected(ScannerBackend::ClamdDaemon) => {
                gettext("Backend: clamd (daemon)")
            }
            ScannerBackendView::BackendDetected(ScannerBackend::StandaloneClamscan) => {
                gettext("Backend: clamscan (standalone)")
            }
        }
    }

    fn start_eicar_test(&mut self, sender: &ComponentSender<Self>) {
        self.page_notice.clear();
        match write_eicar_test_file(&self.file_list_directory) {
            Ok(eicar_file) => {
                let eicar_path = eicar_file.path().to_path_buf();
                self.eicar_test_files.clear();
                self.eicar_test_files.push(eicar_file);
                self.start_scan(vec![eicar_path], sender);
            }
            Err(write_failure) => {
                self.page_notice = gettext("Could not create the EICAR test file: {error}")
                    .replace("{error}", &write_failure.to_string());
            }
        }
    }

    fn header_subtitle(&self) -> String {
        match self.scan_page_state {
            ScanPageState::WaitingForTargets => self.scanner_backend_text(),
            ScanPageState::ScanInProgress { .. } if self.scan_outcome.planned_file_count > 0 => {
                format!(
                    "{} · {}",
                    self.scan_status_title(),
                    file_progress_text(
                        self.scan_outcome.inspected_file_count,
                        self.scan_outcome.planned_file_count
                    )
                )
            }
            ScanPageState::ScanInProgress { .. } | ScanPageState::ScanCancelling => {
                self.scan_status_title()
            }
            ScanPageState::ScanCancelled | ScanPageState::ScanCompleted => String::new(),
        }
    }

    fn scan_status_title(&self) -> String {
        match self.scan_page_state {
            ScanPageState::WaitingForTargets => gettext("Scan"),
            ScanPageState::ScanInProgress { .. } => match self.active_scan_targets.as_slice() {
                [single_target] => {
                    gettext("Scanning {name}").replace("{name}", &scan_target_name(single_target))
                }
                several_targets => ngettext(
                    "Scanning {count} location",
                    "Scanning {count} locations",
                    u32::try_from(several_targets.len()).unwrap_or(u32::MAX),
                )
                .replace("{count}", &several_targets.len().to_string()),
            },
            ScanPageState::ScanCancelling => gettext("Cancelling…"),
            ScanPageState::ScanCancelled => gettext("Scan cancelled by user"),
            ScanPageState::ScanCompleted if self.scan_outcome.threats_were_found() => {
                gettext("Threats found")
            }
            ScanPageState::ScanCompleted if !self.scan_outcome.scan_problems.is_empty() => {
                gettext("The scan did not finish cleanly")
            }
            ScanPageState::ScanCompleted => gettext("No threats found"),
        }
    }

    fn scan_summary_text(&self) -> String {
        let threat_summary = (!self.scan_outcome.detected_threats.is_empty()).then(|| {
            let threat_count = self.scan_outcome.detected_threats.len();
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
            u32::try_from(self.scan_outcome.inspected_file_count).unwrap_or(u32::MAX),
        )
        .replace(
            "{count}",
            &self.scan_outcome.inspected_file_count.to_string(),
        );
        [inspected_summary]
            .into_iter()
            .chain(threat_summary)
            .chain(self.scan_notice_lines())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn scan_notice_lines(&self) -> Vec<String> {
        self.notice_lines_where(|_scan_problem| true, |_scan_notice| true)
    }

    fn unlisted_notice_lines(&self) -> Vec<String> {
        self.notice_lines_where(
            |scan_problem| !is_listed_as_path_group(scan_problem),
            |scan_notice| {
                !matches!(
                    scan_notice,
                    ScanNotice::FilesInaccessible { .. } | ScanNotice::FilesUnreadable { .. }
                )
            },
        )
    }

    fn unlisted_skipped_paths(&self) -> Vec<String> {
        self.scan_outcome
            .skipped_paths
            .iter()
            .filter(|skipped_path| {
                !self
                    .scan_outcome
                    .detected_threats
                    .iter()
                    .any(|detected_threat| detected_threat.file_path == Path::new(skipped_path))
            })
            .cloned()
            .collect()
    }

    fn problem_path_groups(&self) -> Vec<ProblemPathGroup> {
        let unscanned_groups = self
            .scan_outcome
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
        let skipped_paths = self.unlisted_skipped_paths();
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
        &self,
        include_problem: impl Fn(&ScanProblem) -> bool,
        include_notice: impl Fn(&ScanNotice) -> bool,
    ) -> Vec<String> {
        let unattributed_notice = (self.scan_outcome.unattributed_threats_reported
            && self.scan_outcome.detected_threats.is_empty())
        .then(|| gettext("The scanner reported a threat without naming the file."));
        unattributed_notice
            .into_iter()
            .chain(
                self.scan_outcome
                    .scan_problems
                    .iter()
                    .filter(|scan_problem| include_problem(scan_problem))
                    .map(describe_scan_problem),
            )
            .chain(
                self.scan_outcome
                    .scan_notices
                    .iter()
                    .filter(|scan_notice| include_notice(scan_notice))
                    .map(describe_scan_notice),
            )
            .chain(
                self.scan_outcome
                    .nonfatal_warnings
                    .iter()
                    .map(|nonfatal_warning| sanitize_scanner_line(nonfatal_warning)),
            )
            .collect()
    }

    fn results_status(&self) -> ScanResultsStatus {
        if self.scan_outcome.threats_were_found() {
            ScanResultsStatus::ThreatsDetected
        } else if matches!(self.scan_page_state, ScanPageState::ScanCancelled) {
            ScanResultsStatus::ScanCancelled
        } else if self.scan_outcome.scan_problems.is_empty() {
            ScanResultsStatus::NoThreatsDetected
        } else {
            ScanResultsStatus::FinishedWithProblems
        }
    }

    fn results_view(&self) -> ScanResultsView {
        ScanResultsView {
            results_status: self.results_status(),
            inspected_file_count: self.scan_outcome.inspected_file_count,
            planned_file_count: self.scan_outcome.planned_file_count,
            scanned_directory_count: self.scan_outcome.scanned_directory_count,
            elapsed_time: self.scan_started_instant.elapsed(),
            detected_threats: self.scan_outcome.detected_threats.clone(),
            problem_path_groups: self.problem_path_groups(),
            notice_lines: self.unlisted_notice_lines(),
            noteworthy_output: self.scan_outcome.noteworthy_output.clone(),
        }
    }

    fn reload_known_profiles(&mut self) {
        match self.profile_store.load_profiles() {
            Ok(known_profiles) => {
                let profile_labels = std::iter::once(gettext("No Profile (Manual)"))
                    .chain(known_profiles.iter().map(|known_profile| {
                        sanitize_scanner_line(&known_profile.displayed_name())
                    }))
                    .collect::<Vec<_>>();
                self.known_profiles = known_profiles;
                self.profile_names.splice(
                    0,
                    self.profile_names.n_items(),
                    &profile_labels
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                );
            }
            Err(load_failure) => self.page_notice = load_failure.to_string(),
        }
    }

    fn apply_profile(&mut self, chosen_profile: ScanProfile) {
        let profile_targets = chosen_profile.expanded_targets(&glib::home_dir());
        self.scan_target_rows.guard().clear();
        self.add_scan_targets(profile_targets);
        self.selected_profile = SelectedScanProfile::ProfileChosen(chosen_profile);
    }

    fn profile_exclusion_entries(&self) -> Vec<ExclusionEntry> {
        match &self.selected_profile {
            SelectedScanProfile::ManualTargets => Vec::new(),
            SelectedScanProfile::ProfileChosen(chosen_profile) => {
                chosen_profile.exclusion_entries()
            }
        }
    }

    fn open_profile_manager(&mut self, root: &adw::ToastOverlay, sender: &ComponentSender<Self>) {
        let profile_manager = ProfileManagerDialog::builder()
            .launch(self.profile_store.clone())
            .forward(
                sender.input_sender(),
                |manager_output| match manager_output {
                    ProfileManagerDialogOutput::ProfilesChanged => ScanPageInput::ProfilesChanged,
                    ProfileManagerDialogOutput::RunProfile(run_profile) => {
                        ScanPageInput::RunProfileRequested(run_profile)
                    }
                },
            );
        profile_manager.widget().present(Some(root));
        self.profile_manager_view = ProfileManagerView::ManagerOpen {
            _profile_manager: profile_manager,
        };
    }

    fn notify_finished_scan(&self) {
        let notification_title = match self.results_status() {
            ScanResultsStatus::ThreatsDetected => gettext("Threats Detected"),
            ScanResultsStatus::NoThreatsDetected => gettext("No threats found"),
            ScanResultsStatus::FinishedWithProblems => gettext("The scan did not finish cleanly"),
            ScanResultsStatus::ScanCancelled => return,
        };
        notify_outside_the_window(
            "scan-finished",
            &notification_title,
            &self.scan_summary_text(),
        );
    }

    fn record_finished_scan(&self, sender: &ComponentSender<Self>) {
        let activity_status = match self.results_status() {
            ScanResultsStatus::ThreatsDetected => ActivityStatus::ScanInfected,
            ScanResultsStatus::NoThreatsDetected => ActivityStatus::ScanClean,
            ScanResultsStatus::FinishedWithProblems => ActivityStatus::ScanFailed,
            ScanResultsStatus::ScanCancelled => ActivityStatus::ScanCancelled,
        };
        let new_entry = NewActivityEntry {
            started_at_unix: self
                .scan_started_at
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed_time| elapsed_time.as_secs() as i64),
            activity_status,
            activity_targets: self
                .active_scan_targets
                .iter()
                .map(|scan_target| sanitize_scanner_line(&scan_target.to_string_lossy()))
                .collect::<Vec<_>>()
                .join("\n"),
            inspected_file_count: self.scan_outcome.inspected_file_count,
            threat_count: self.scan_outcome.detected_threats.len() as u64,
            duration_millis: self.scan_started_instant.elapsed().as_millis() as u64,
            activity_output: self.scan_outcome.noteworthy_output.clone(),
        };
        let activity_history = self.activity_history.clone();
        let command_sender = sender.command_sender().clone();
        relm4::spawn(async move {
            let _page_closed = command_sender.send(ScanPageCommand::ActivityRecordingFinished(
                activity_history.record_activity(new_entry).await,
            ));
        });
    }

    fn show_results_panel(&mut self, sender: &ComponentSender<Self>) {
        self.clear_results_panel();
        let results_panel = ScanResultsSection::builder()
            .launch(ScanResultsSectionInit {
                results_view: self.results_view(),
                quarantine_vault: self.quarantine_vault.clone(),
            })
            .forward(sender.input_sender(), |panel_output| match panel_output {
                ScanResultsSectionOutput::QuarantineEntriesChanged => {
                    ScanPageInput::QuarantineEntriesChanged
                }
                ScanResultsSectionOutput::NewScanRequested => ScanPageInput::NewScanRequested,
                ScanResultsSectionOutput::ToastRequested(toast_message) => {
                    ScanPageInput::ToastRequested(toast_message)
                }
            });
        self.results_container.append(results_panel.widget());
        self.results_panel_view = ResultsPanelView::ResultsShown(results_panel);
    }

    fn clear_results_panel(&mut self) {
        if let ResultsPanelView::ResultsShown(results_panel) = &self.results_panel_view {
            self.results_container.remove(results_panel.widget());
        }
        self.results_panel_view = ResultsPanelView::NoResultsYet;
    }

    fn shows_results(&self) -> bool {
        matches!(
            self.scan_page_state,
            ScanPageState::ScanCompleted | ScanPageState::ScanCancelled
        )
    }

    fn shows_scan_settings(&self) -> bool {
        matches!(self.scan_page_state, ScanPageState::WaitingForTargets)
    }

    fn start_scan(&mut self, scan_targets: Vec<PathBuf>, sender: &ComponentSender<Self>) {
        self.page_notice.clear();
        self.scan_started_at = SystemTime::now();
        self.scan_started_instant = Instant::now();
        self.active_scan_targets.clone_from(&scan_targets);
        self.scan_outcome = CompletedScanOutcome::default();
        self.current_file_label.clear();
        self.display_throttle =
            RefreshThrottle::starting_at(DISPLAY_REFRESH_INTERVAL, Instant::now());
        self.displayed_phase = DisplayedScanPhase::PreparingScan;
        self.progress_display.show_preparation();
        self.clear_results_panel();
        let settings = application_settings();
        self.show_live_progress = settings.boolean(SHOW_LIVE_PROGRESS_KEY);
        let scan_exclusions = ScanExclusions::from_entries(
            &read_exclusion_entries(&settings)
                .into_iter()
                .chain(self.profile_exclusion_entries())
                .collect::<Vec<_>>(),
            &glib::home_dir(),
        );
        let backend_preference = scanner_backend_preference(&settings);
        let scanner_programs = ScannerProgramPaths::locate_trusted_programs();
        let file_list_directory = self.file_list_directory.clone();
        let scan_events = stream::once(async move {
            let scanner_backend =
                choose_scanner_backend(backend_preference, &scanner_programs).await;
            ScanRequest {
                scan_exclusions,
                scan_targets,
                scanner_backend,
                scanner_programs,
                file_list_directory,
            }
        })
        .flat_map(scan_progress_events);
        let (abortable_events, scan_abort_handle) = stream::abortable(scan_events);
        self.scan_page_state = ScanPageState::ScanInProgress { scan_abort_handle };
        sender.command(move |command_output, shutdown| {
            shutdown
                .register(async move {
                    abortable_events
                        .ready_chunks(PROGRESS_BATCH_SIZE)
                        .for_each(|progress_batch| {
                            command_output
                                .emit(ScanPageCommand::ProgressBatchArrived(progress_batch));
                            ready(())
                        })
                        .await;
                    command_output.emit(ScanPageCommand::ScanStreamFinished);
                })
                .drop_on_shutdown()
        });
    }

    fn absorb_progress_batch(&mut self, progress_batch: Vec<ScanProgressEvent>) {
        let mut target_enumerated = false;
        let mut latest_enumeration = None;
        progress_batch.into_iter().for_each(|progress_event| {
            match &progress_event {
                ScanProgressEvent::EnumerationProgressed(enumeration_progress) => {
                    self.displayed_phase = DisplayedScanPhase::FindingFiles;
                    latest_enumeration = Some(enumeration_progress.clone());
                }
                ScanProgressEvent::TargetEnumerated { .. } => {
                    self.displayed_phase = DisplayedScanPhase::ScanningFiles;
                    target_enumerated = true;
                }
                ScanProgressEvent::ThreatDetected(detected_threat) => {
                    self.progress_display.add_found_threat(detected_threat);
                }
                ScanProgressEvent::FileInspected { file_path } => {
                    self.current_file_label = sanitize_scanner_line(&file_path.to_string_lossy());
                }
                _other_event => {}
            }
            self.scan_outcome.absorb_progress_event(progress_event);
        });
        match self.displayed_phase {
            DisplayedScanPhase::PreparingScan => {}
            DisplayedScanPhase::FindingFiles => {
                if let Some(enumeration_progress) = latest_enumeration {
                    self.progress_display
                        .show_finding_files(&enumeration_progress);
                }
            }
            DisplayedScanPhase::ScanningFiles => {
                if self.display_throttle.allows_refresh(Instant::now()) || target_enumerated {
                    self.show_scanning_progress();
                }
            }
        }
    }

    fn show_scanning_progress(&self) {
        self.progress_display.show_scanning(&ScanningSnapshot {
            inspected_file_count: self.scan_outcome.inspected_file_count,
            planned_file_count: self.scan_outcome.planned_file_count,
            elapsed_time: self.scan_started_instant.elapsed(),
            current_file_text: if self.show_live_progress {
                &self.current_file_label
            } else {
                ""
            },
        });
    }
}

#[relm4::component(pub)]
impl Component for ScanPage {
    type Init = ScanPageInit;
    type Input = ScanPageInput;
    type Output = ScanPageOutput;
    type CommandOutput = ScanPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
            add_top_bar = &adw::HeaderBar {
                #[wrap(Some)]
                set_title_widget = &adw::WindowTitle {
                    set_title: &gettext("Scan"),
                    #[watch]
                    set_subtitle: &model.header_subtitle(),
                },

                pack_start = &gtk::Button {
                    set_icon_name: "document-new-symbolic",
                    set_tooltip_text: Some(&gettext("Add Files")),
                    #[watch]
                    set_visible: model.shows_scan_settings(),
                    connect_clicked => ScanPageInput::ChooseFilesRequested,
                },

                pack_start = &gtk::Button {
                    set_icon_name: "folder-new-symbolic",
                    set_tooltip_text: Some(&gettext("Add Folder")),
                    #[watch]
                    set_visible: model.shows_scan_settings(),
                    connect_clicked => ScanPageInput::ChooseFolderRequested,
                },

                pack_end = &gtk::MenuButton {
                    set_icon_name: "view-more-symbolic",
                    set_tooltip_text: Some(&gettext("More")),
                    #[watch]
                    set_visible: !model.scan_is_running(),
                    #[wrap(Some)]
                    set_popover = &gtk::Popover {
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,

                            gtk::Button {
                                set_label: &gettext("Run EICAR Test"),
                                add_css_class: "flat",
                                #[watch]
                                set_visible: model.shows_scan_settings(),
                                connect_clicked[sender] => move |clicked_button| {
                                    close_enclosing_popover(clicked_button);
                                    sender.input(ScanPageInput::EicarTestRequested);
                                },
                            },

                            gtk::Button {
                                set_label: &gettext("Copy Results"),
                                add_css_class: "flat",
                                #[watch]
                                set_visible: model.shows_results(),
                                connect_clicked[sender] => move |clicked_button| {
                                    close_enclosing_popover(clicked_button);
                                    sender.input(ScanPageInput::CopyResultsRequested);
                                },
                            },

                            gtk::Button {
                                set_label: &gettext("Export Results…"),
                                add_css_class: "flat",
                                #[watch]
                                set_visible: model.shows_results(),
                                connect_clicked[sender] => move |clicked_button| {
                                    close_enclosing_popover(clicked_button);
                                    sender.input(ScanPageInput::ExportResultsRequested);
                                },
                            },
                        },
                    },
                },

                pack_end = &gtk::Button {
                    set_label: &gettext("Start Scan"),
                    add_css_class: "suggested-action",
                    #[watch]
                    set_visible: model.shows_scan_settings(),
                    #[watch]
                    set_sensitive: !model.scan_target_rows.is_empty(),
                    connect_clicked => ScanPageInput::StartScanRequested,
                },

                pack_end = &gtk::Button {
                    set_label: &gettext("Cancel"),
                    add_css_class: "destructive-action",
                    #[watch]
                    set_visible: model.scan_is_running(),
                    #[watch]
                    set_sensitive: matches!(model.scan_page_state, ScanPageState::ScanInProgress { .. }),
                    connect_clicked => ScanPageInput::CancelScanRequested,
                },
            },

            add_top_bar = &adw::Banner {
                set_title: &gettext("Lazaret refuses a ClamAV program that your account could replace"),
                set_button_label: Some(&gettext("Details")),
                set_action_name: Some("win.show-page"),
                set_action_target_value: Some(&PROTECTION_PAGE_NAME.to_variant()),
                #[watch]
                set_revealed: model.scanner_program_trust == ScannerProgramTrust::ReplaceableProgramRefused,
            },

            #[wrap(Some)]
            set_content = &gtk::ScrolledWindow {
                set_propagate_natural_height: true,
                set_vexpand: true,

                adw::Clamp {
                    set_maximum_size: 720,
                    set_margin_all: 24,

                    gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 18,

                        #[local_ref]
                        scan_progress_box -> gtk::Box {
                            #[watch]
                            set_visible: model.scan_is_running(),
                        },

                        adw::PreferencesGroup {
                            set_title: &gettext("Scan Profile"),
                            #[watch]
                            set_visible: model.shows_scan_settings(),

                            adw::ComboRow {
                                set_title: &gettext("Profile"),
                                set_model: Some(&model.profile_names),
                                connect_selected_notify[sender] => move |profile_row| {
                                    sender.input(ScanPageInput::ProfileRowSelected {
                                        row_position: profile_row.selected() as usize,
                                    });
                                },

                                add_suffix = &gtk::Button {
                                    set_icon_name: "emblem-system-symbolic",
                                    set_tooltip_text: Some(&gettext("Manage Profiles")),
                                    set_valign: gtk::Align::Center,
                                    add_css_class: "flat",
                                    connect_clicked => ScanPageInput::ManageProfilesRequested,
                                },
                            },
                        },

                        adw::PreferencesGroup {
                            set_title: &gettext("Scan Targets"),
                            #[watch]
                            set_visible: model.shows_scan_settings(),

                            #[local_ref]
                            scan_target_list -> gtk::ListBox {
                                add_css_class: "boxed-list",
                                set_selection_mode: gtk::SelectionMode::None,
                                #[wrap(Some)]
                                set_placeholder = &gtk::Box {
                                    set_orientation: gtk::Orientation::Vertical,
                                    set_spacing: 12,
                                    set_margin_top: 36,
                                    set_margin_bottom: 36,
                                    set_halign: gtk::Align::Center,

                                    gtk::Image {
                                        set_icon_name: Some("folder-open-symbolic"),
                                        set_pixel_size: 48,
                                        add_css_class: "dim-label",
                                    },

                                    gtk::Label {
                                        set_label: &gettext("Drop files or folders to scan"),
                                        add_css_class: "title-4",
                                    },

                                    gtk::Box {
                                        set_spacing: 12,
                                        set_halign: gtk::Align::Center,

                                        gtk::Button {
                                            set_label: &gettext("Add Files…"),
                                            add_css_class: "pill",
                                            connect_clicked => ScanPageInput::ChooseFilesRequested,
                                        },

                                        gtk::Button {
                                            set_label: &gettext("Add Folder…"),
                                            add_css_class: "pill",
                                            connect_clicked => ScanPageInput::ChooseFolderRequested,
                                        },
                                    },
                                },
                            },
                        },

                        #[local_ref]
                        found_threat_group -> adw::PreferencesGroup {
                            #[watch]
                            set_visible: model.scan_is_running() && model.scan_outcome.threats_were_found(),
                        },

                        gtk::Label {
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "error",
                            #[watch]
                            set_visible: !model.page_notice.is_empty(),
                            #[watch]
                            set_label: &model.page_notice,
                        },

                        #[local_ref]
                        results_container -> gtk::Box {
                            #[watch]
                            set_visible: model.shows_results(),
                        },

                        #[local_ref]
                        scan_settings -> gtk::Box {
                            #[watch]
                            set_visible: model.shows_scan_settings(),
                        },
                    },
                },
            },
            },
        }
    }

    fn init(
        page_init: ScanPageInit,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let scan_target_rows = FactoryVecDeque::builder()
            .launch(gtk::ListBox::default())
            .forward(sender.input_sender(), |row_output| match row_output {
                ScanTargetRowOutput::RemoveRequested(row_index) => {
                    ScanPageInput::RemoveTargetRequested(row_index)
                }
            });
        let drop_target = gtk::DropTarget::new(gdk::FileList::static_type(), gdk::DragAction::COPY);
        let drop_input_sender = sender.input_sender().clone();
        drop_target.connect_drop(move |_drop_target, dropped_value, _horizontal, _vertical| {
            drop_input_sender.emit(ScanPageInput::ScanTargetsAdded(dropped_file_paths(
                dropped_value,
            )));
            true
        });
        root.add_controller(drop_target);
        let startup_backend_preference = scanner_backend_preference(&application_settings());
        sender.oneshot_command(async move {
            let scanner_programs =
                tokio::task::spawn_blocking(ScannerProgramPaths::locate_trusted_programs)
                    .await
                    .unwrap_or_else(|_interrupted_lookup| ScannerProgramPaths::nothing_found());
            ScanPageCommand::ScannerBackendDetected {
                scanner_backend: choose_scanner_backend(
                    startup_backend_preference,
                    &scanner_programs,
                )
                .await,
                scanner_program_trust: scanner_program_trust(&scanner_programs),
            }
        });
        let mut model = Self {
            profile_store: page_init.profile_store,
            known_profiles: Vec::new(),
            selected_profile: SelectedScanProfile::ManualTargets,
            profile_manager_view: ProfileManagerView::ManagerClosed,
            profile_names: gtk::StringList::new(&[]),
            quarantine_vault: page_init.quarantine_vault,
            activity_history: page_init.activity_history,
            scan_started_at: SystemTime::now(),
            scan_started_instant: Instant::now(),
            active_scan_targets: Vec::new(),
            file_list_directory: page_init.file_list_directory,
            scan_page_state: ScanPageState::WaitingForTargets,
            scan_outcome: CompletedScanOutcome::default(),
            current_file_label: String::new(),
            show_live_progress: true,
            progress_display: ScanProgressDisplay::new(),
            display_throttle: RefreshThrottle::starting_at(
                DISPLAY_REFRESH_INTERVAL,
                Instant::now(),
            ),
            displayed_phase: DisplayedScanPhase::PreparingScan,
            results_panel_view: ResultsPanelView::NoResultsYet,
            results_container: gtk::Box::new(gtk::Orientation::Vertical, 0),
            scan_target_rows,
            scanner_backend_view: ScannerBackendView::DetectingBackend,
            scanner_program_trust: ScannerProgramTrust::ProgramsTrusted,
            eicar_test_files: Vec::new(),
            page_notice: String::new(),
        };
        model.reload_known_profiles();
        let scan_target_list = model.scan_target_rows.widget();
        let scan_progress_box = &model.progress_display.progress_widget().clone();
        let found_threat_group = &model.progress_display.found_threat_widget().clone();
        let results_container = &model.results_container.clone();
        let scan_settings = &scan_settings_sections(&application_settings());
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScanPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match page_input {
            ScanPageInput::ChooseFilesRequested => {
                let input_sender = sender.input_sender().clone();
                relm4::spawn_local(async move {
                    let chosen_files = gtk::FileDialog::builder()
                        .title(gettext("Choose Files to Scan"))
                        .build()
                        .open_multiple_future(relm4::main_application().active_window().as_ref())
                        .await;
                    if let Ok(chosen_files) = chosen_files {
                        input_sender.emit(ScanPageInput::ScanTargetsAdded(chosen_file_paths(
                            &chosen_files,
                        )));
                    }
                });
            }
            ScanPageInput::ChooseFolderRequested => {
                let input_sender = sender.input_sender().clone();
                relm4::spawn_local(async move {
                    let chosen_folder = gtk::FileDialog::builder()
                        .title(gettext("Choose a Folder to Scan"))
                        .build()
                        .select_folder_future(relm4::main_application().active_window().as_ref())
                        .await;
                    if let Some(folder_path) = chosen_folder
                        .ok()
                        .and_then(|chosen_folder| chosen_folder.path())
                    {
                        input_sender.emit(ScanPageInput::ScanTargetsAdded(vec![folder_path]));
                    }
                });
            }
            ScanPageInput::ScanTargetsChosen(scan_targets) => {
                self.add_scan_targets(scan_targets);
                if !self.scan_target_rows.is_empty() && !self.scan_is_running() {
                    self.start_scan(self.chosen_scan_targets(), &sender);
                }
            }
            ScanPageInput::ScanTargetsAdded(added_targets) => {
                self.add_scan_targets(added_targets);
                if self.shows_results() {
                    self.scan_page_state = ScanPageState::WaitingForTargets;
                }
            }
            ScanPageInput::ProfileRowSelected { row_position } => {
                match row_position
                    .checked_sub(1)
                    .and_then(|profile_position| self.known_profiles.get(profile_position))
                {
                    Some(chosen_profile) => self.apply_profile(chosen_profile.clone()),
                    None => self.selected_profile = SelectedScanProfile::ManualTargets,
                }
            }
            ScanPageInput::ManageProfilesRequested => {
                self.open_profile_manager(root, &sender);
            }
            ScanPageInput::ProfilesChanged => self.reload_known_profiles(),
            ScanPageInput::RunProfileRequested(run_profile) => {
                self.apply_profile(run_profile);
                if !self.scan_target_rows.is_empty() && !self.scan_is_running() {
                    self.start_scan(self.chosen_scan_targets(), &sender);
                }
            }
            ScanPageInput::DeviceMounted(mount_path) => {
                if self.scan_is_running() {
                    notify_outside_the_window(
                        "device-scan-skipped",
                        &gettext("Device Auto-Scan"),
                        &gettext(
                            "A device was connected during another scan, so it was not scanned.",
                        ),
                    );
                } else {
                    self.start_scan(vec![mount_path], &sender);
                }
            }
            ScanPageInput::QuickScanRequested => {
                if !self.scan_is_running() {
                    self.start_scan(
                        vec![
                            glib::user_special_dir(glib::UserDirectory::Downloads)
                                .unwrap_or_else(|| glib::home_dir().join("Downloads")),
                        ],
                        &sender,
                    );
                }
            }
            ScanPageInput::RemoveTargetRequested(row_index) => {
                self.scan_target_rows
                    .guard()
                    .remove(row_index.current_index());
            }
            ScanPageInput::StartScanRequested => {
                if !self.scan_target_rows.is_empty() && !self.scan_is_running() {
                    self.start_scan(self.chosen_scan_targets(), &sender);
                }
            }
            ScanPageInput::EicarTestRequested => {
                if !self.scan_is_running() {
                    self.start_eicar_test(&sender);
                }
            }
            ScanPageInput::CancelScanRequested => {
                if let ScanPageState::ScanInProgress { scan_abort_handle } = &self.scan_page_state {
                    scan_abort_handle.abort();
                    self.scan_page_state = ScanPageState::ScanCancelling;
                }
            }
            ScanPageInput::NewScanRequested => {
                if self.shows_results() {
                    self.scan_page_state = ScanPageState::WaitingForTargets;
                }
            }
            ScanPageInput::CopyResultsRequested => {
                if let ResultsPanelView::ResultsShown(results_panel) = &self.results_panel_view {
                    results_panel.emit(ScanResultsSectionInput::CopyReportRequested);
                }
            }
            ScanPageInput::ExportResultsRequested => {
                if let ResultsPanelView::ResultsShown(results_panel) = &self.results_panel_view {
                    results_panel.emit(ScanResultsSectionInput::ExportReportRequested);
                }
            }
            ScanPageInput::ToastRequested(toast_message) => {
                root.add_toast(adw::Toast::new(&toast_message));
            }
            ScanPageInput::QuarantineEntriesChanged => {
                let _shell_closed = sender.output(ScanPageOutput::QuarantineEntriesChanged);
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ScanPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            ScanPageCommand::ProgressBatchArrived(progress_batch) => {
                self.absorb_progress_batch(progress_batch);
            }
            ScanPageCommand::ScanStreamFinished => {
                self.scan_page_state = match &self.scan_page_state {
                    ScanPageState::ScanCancelling => ScanPageState::ScanCancelled,
                    _other_state => ScanPageState::ScanCompleted,
                };
                self.show_results_panel(&sender);
                self.record_finished_scan(&sender);
                self.notify_finished_scan();
            }
            ScanPageCommand::ScannerBackendDetected {
                scanner_backend,
                scanner_program_trust,
            } => {
                self.scanner_backend_view = ScannerBackendView::BackendDetected(scanner_backend);
                self.scanner_program_trust = scanner_program_trust;
            }
            ScanPageCommand::ActivityRecordingFinished(Ok(())) => {
                let _shell_closed = sender.output(ScanPageOutput::ActivityRecorded);
            }
            ScanPageCommand::ActivityRecordingFinished(Err(recording_failure)) => {
                self.page_notice = gettext("The scan could not be added to the history: {error}")
                    .replace("{error}", &recording_failure.to_string());
            }
        }
    }
}
