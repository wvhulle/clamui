use std::{path::PathBuf, time::Instant};

use futures::{StreamExt, future::ready, stream};
use gettextrs::{gettext, ngettext};
use jiff::Timestamp;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller, RelmWidgetExt,
    abstractions::Toaster,
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
            ActivityHistory, ActivityHistoryFailure, ActivityRecord, FoundThreatCount,
            NewActivityEntry, ScanActivityStatus,
        },
        clamav_config::detection_options::read_host_clamscan_detection_arguments,
        clamav_scanner::{
            scan_exclusion_rules::ScanExclusions,
            scan_progress_estimates::file_progress_text,
            scan_progress_events::{ScanProgressEvent, ScanRequest, scan_progress_events},
            scanner_command_builder::{
                ProgramLookupFailure, ScannerBackend, ScannerProgramPaths, choose_scanner_backend,
            },
            scanner_output_parser::sanitize_scanner_line,
            scanner_process_events::ScanStartFailure,
        },
        desktop::{
            desktop_notifications::notify_outside_the_window,
            stored_settings::{
                SHOW_LIVE_PROGRESS_KEY, application_settings, read_exclusion_entries,
                scanner_backend_preference,
            },
            stored_settings_watch::forward_setting_changes,
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
    },
    scans::manual_scan_page::{
        device_auto_scan_page::device_mount_scans::{
            DEVICE_SCAN_SETTING_KEYS, DeviceAutoScanSettings, MountedDevice,
            device_qualifies_for_scan, mounted_device_of, settled_device_passes_limits,
        },
        eicar_test_file::{EicarTestFileFailure, written_eicar_test_file},
        found_threat_row::FoundThreatRow,
        scan_options_section::ScanOptionsSection,
        scan_page_state::{
            CancelRequest, CurrentFileDisplay, FinishedScan, LiveProgress, RunningScan, ScanEnding,
            ScanPageState, ScanRun, ScanRunNumber, ScanStartPermission, ScanStartPermit,
            ScanStreamEnding, TemporaryScanTarget,
        },
        scan_profile_selection::{ProfileChoiceRow, ScanProfileChoice, TargetRowsChange},
        scan_profiles_dialog::{
            profile_display_text::{describe_profile_store_failure, displayed_profile_name},
            profile_manager_dialog::{ProfileManagerDialog, ProfileManagerDialogOutput},
            scan_profile_store::{
                ProfileStoreFailure, ScanProfile, ScanProfileStore, expanded_profile_targets,
                run_blocking_profile_task,
            },
        },
        scan_progress_view::ScanProgressBar,
        scan_results_section::{
            scan_results_component::{
                ScanResultsSection, ScanResultsSectionInput, ScanResultsSectionOutput,
            },
            scan_results_state::{ScanResultsStatus, ScanResultsView},
        },
        scan_run_state::{
            ScannerProgramTrust, problem_path_groups, results_status, scan_summary_text,
            scan_target_name, scanner_program_trust, unlisted_notice_lines,
        },
        scan_target_row::{ScanTargetRow, ScanTargetRowOutput},
    },
    shared_widgets::{
        awaited_dialogs::{chosen_files_to_open, chosen_folders_to_open, deliver_local_outcome},
        component_streams::run_stream_then,
    },
};

const PROGRESS_BATCH_SIZE: usize = 256;

enum ProfileManagerView {
    ManagerClosed,
    ManagerOpen {
        _profile_manager: Controller<ProfileManagerDialog>,
    },
}

enum ScannerBackendView {
    DetectingBackend,
    BackendDetected(ScannerBackend),
    BackendUndetermined(ProgramLookupFailure),
}

pub struct ScanPageInit {
    pub quarantine_vault: QuarantineVault,
    pub activity_history: ActivityHistory,
    pub profile_store: ScanProfileStore,
    pub file_list_directory: PathBuf,
}

#[derive(Debug)]
enum ScanPageNotice {
    NoNoticeShown,
    ProfilesUnloadable(ProfileStoreFailure),
    EicarTestFileUnwritable(EicarTestFileFailure),
    ScanNotRecorded(ActivityHistoryFailure),
}

fn describe_page_notice(page_notice: &ScanPageNotice) -> String {
    match page_notice {
        ScanPageNotice::NoNoticeShown => String::new(),
        ScanPageNotice::ProfilesUnloadable(load_failure) => {
            describe_profile_store_failure(load_failure)
        }
        ScanPageNotice::EicarTestFileUnwritable(eicar_failure) => eicar_failure_text(eicar_failure),
        ScanPageNotice::ScanNotRecorded(recording_failure) => {
            gettext("The scan could not be added to the history: {error}")
                .replace("{error}", &recording_failure.to_string())
        }
    }
}

const fn shows_page_notice(page_notice: &ScanPageNotice) -> bool {
    !matches!(page_notice, ScanPageNotice::NoNoticeShown)
}

pub struct ScanPage {
    activity_history: ActivityHistory,
    profile_store: ScanProfileStore,
    profile_choice: ScanProfileChoice,
    profile_manager_view: ProfileManagerView,
    profile_list_reloaded: bool,
    file_list_directory: PathBuf,
    scan_page_state: ScanPageState,
    next_scan_run_number: ScanRunNumber,
    found_threat_rows: FactoryVecDeque<FoundThreatRow>,
    scan_results_section: Controller<ScanResultsSection>,
    scan_target_rows: FactoryVecDeque<ScanTargetRow>,
    scanner_backend_view: ScannerBackendView,
    scanner_program_trust: ScannerProgramTrust,
    page_notice: ScanPageNotice,
    scan_options_section: Controller<ScanOptionsSection>,
    stored_settings: gio::Settings,
    device_auto_scan_settings: DeviceAutoScanSettings,
    _device_monitor: gio::VolumeMonitor,
    toaster: Toaster,
}

#[derive(Debug)]
pub enum ScanPageInput {
    ChooseFilesRequested,
    ChooseFolderRequested,
    ScanTargetsChosen(Vec<PathBuf>),
    ScanTargetsAdded(Vec<PathBuf>),
    QuickScanRequested,
    DeviceMountAdded(MountedDevice),
    DeviceAutoScanSettingsChanged,
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
    ProgressBatchArrived {
        scan_run_number: ScanRunNumber,
        progress_batch: Vec<ScanProgressEvent>,
    },
    ScanStreamFinished {
        scan_run_number: ScanRunNumber,
    },
    ScannerLookupFailed(ProgramLookupFailure),
    ScannerBackendDetected {
        scanner_backend: ScannerBackend,
        scanner_program_trust: ScannerProgramTrust,
    },
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
    ProfilesLoaded(Result<Vec<ScanProfile>, ProfileStoreFailure>),
    EicarTestFileWritten(Result<NamedTempFile, EicarTestFileFailure>),
    DeviceSettled {
        mount_path: PathBuf,
        passes_limits: bool,
    },
}

const PROTECTION_PAGE_NAME: &str = "protection";

fn close_enclosing_popover(clicked_button: &gtk::Button) {
    if let Some(enclosing_popover) = clicked_button
        .ancestor(gtk::Popover::static_type())
        .and_downcast::<gtk::Popover>()
    {
        enclosing_popover.popdown();
    }
}

fn profile_choice_label(choice_row: &ProfileChoiceRow) -> String {
    match choice_row {
        ProfileChoiceRow::ManualTargetsRow => gettext("No Profile (Manual)"),
        ProfileChoiceRow::StoredProfileRow(stored_profile) => {
            sanitize_scanner_line(&displayed_profile_name(stored_profile))
        }
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

impl ScanPage {
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
        match &self.scanner_backend_view {
            ScannerBackendView::DetectingBackend => gettext("Checking…"),
            ScannerBackendView::BackendUndetermined(lookup_failure) => {
                gettext("Backend: unknown, the scanner programs could not be looked up: {error}")
                    .replace("{error}", &lookup_failure.to_string())
            }
            ScannerBackendView::BackendDetected(ScannerBackend::ClamdDaemon) => {
                gettext("Backend: clamd (daemon)")
            }
            ScannerBackendView::BackendDetected(ScannerBackend::StandaloneClamscan) => {
                gettext("Backend: clamscan (standalone)")
            }
        }
    }

    fn start_eicar_test(&mut self, start_permit: ScanStartPermit, sender: &ComponentSender<Self>) {
        self.page_notice = ScanPageNotice::NoNoticeShown;
        self.scan_page_state.begin_writing_eicar_file(start_permit);
        let file_list_directory = self.file_list_directory.clone();
        sender.oneshot_command(async move {
            ScanPageCommand::EicarTestFileWritten(
                written_eicar_test_file(file_list_directory).await,
            )
        });
    }

    fn header_subtitle(&self) -> String {
        match &self.scan_page_state {
            ScanPageState::WaitingForTargets => self.scanner_backend_text(),
            ScanPageState::ScanRunning(RunningScan {
                scan_run,
                cancel_request: CancelRequest::CancelNotRequested,
                ..
            }) if scan_run.scan_outcome.planned_file_count > 0 => format!(
                "{} · {}",
                self.scan_status_title(),
                file_progress_text(
                    scan_run.scan_outcome.inspected_file_count,
                    scan_run.scan_outcome.planned_file_count
                )
            ),
            ScanPageState::WritingEicarFile | ScanPageState::ScanRunning(_) => {
                self.scan_status_title()
            }
            ScanPageState::ScanFinished(_) => String::new(),
        }
    }

    fn scan_status_title(&self) -> String {
        match &self.scan_page_state {
            ScanPageState::WaitingForTargets => gettext("Scan"),
            ScanPageState::WritingEicarFile => gettext("Preparing…"),
            ScanPageState::ScanRunning(RunningScan {
                cancel_request: CancelRequest::CancelRequested,
                ..
            }) => gettext("Cancelling…"),
            ScanPageState::ScanRunning(RunningScan {
                scan_run,
                cancel_request: CancelRequest::CancelNotRequested,
                ..
            }) => match scan_run.scan_targets.as_slice() {
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
            ScanPageState::ScanFinished(FinishedScan {
                scan_ending: ScanEnding::ScanCancelled,
                ..
            }) => gettext("Scan cancelled by user"),
            ScanPageState::ScanFinished(FinishedScan { scan_run, .. })
                if scan_run.scan_outcome.threats_were_found() =>
            {
                gettext("Threats found")
            }
            ScanPageState::ScanFinished(FinishedScan { scan_run, .. })
                if !scan_run.scan_outcome.scan_problems.is_empty() =>
            {
                gettext("The scan did not finish cleanly")
            }
            ScanPageState::ScanFinished(_) => gettext("No threats found"),
        }
    }

    fn reload_known_profiles(&self, sender: &ComponentSender<Self>) {
        let profile_store = self.profile_store.clone();
        sender.oneshot_command(async move {
            ScanPageCommand::ProfilesLoaded(
                run_blocking_profile_task(move || profile_store.load_profiles()).await,
            )
        });
    }

    fn profile_choice_labels(&self) -> gtk::StringList {
        let choice_labels = self
            .profile_choice
            .choice_rows()
            .iter()
            .map(profile_choice_label)
            .collect::<Vec<_>>();
        gtk::StringList::new(&choice_labels.iter().map(String::as_str).collect::<Vec<_>>())
    }

    fn change_target_rows(&mut self, target_rows_change: TargetRowsChange) {
        match target_rows_change {
            TargetRowsChange::KeepTargetRows => {}
            TargetRowsChange::ClearTargetRows => self.scan_target_rows.guard().clear(),
            TargetRowsChange::ReplaceTargetRows { profile_targets } => {
                self.scan_target_rows.guard().clear();
                self.add_scan_targets(expanded_profile_targets(
                    &profile_targets,
                    &glib::home_dir(),
                ));
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
                    ProfileManagerDialogOutput::ProfileRunRequested(run_profile) => {
                        ScanPageInput::RunProfileRequested(run_profile)
                    }
                },
            );
        profile_manager.widget().present(Some(root));
        self.profile_manager_view = ProfileManagerView::ManagerOpen {
            _profile_manager: profile_manager,
        };
    }

    fn start_chosen_targets_scan(&mut self, sender: &ComponentSender<Self>) {
        if self.scan_target_rows.is_empty() {
            return;
        }
        if let ScanStartPermission::ScanMayStart(start_permit) =
            self.scan_page_state.new_scan_permission()
        {
            self.start_scan(
                start_permit,
                self.chosen_scan_targets(),
                TemporaryScanTarget::NoTemporaryTarget,
                sender,
            );
        }
    }

    fn start_scan(
        &mut self,
        start_permit: ScanStartPermit,
        scan_targets: Vec<PathBuf>,
        temporary_scan_target: TemporaryScanTarget,
        sender: &ComponentSender<Self>,
    ) {
        self.page_notice = ScanPageNotice::NoNoticeShown;
        let scan_run_number = self.next_scan_run_number;
        self.next_scan_run_number = scan_run_number.following_run();
        self.found_threat_rows.guard().clear();
        let settings = application_settings();
        let current_file_display = if settings.boolean(SHOW_LIVE_PROGRESS_KEY) {
            CurrentFileDisplay::ShowCurrentFile
        } else {
            CurrentFileDisplay::HideCurrentFile
        };
        let scan_exclusions = ScanExclusions::from_entries(
            &read_exclusion_entries(&settings)
                .into_iter()
                .chain(self.profile_choice.selected_exclusion_entries())
                .collect::<Vec<_>>(),
            &glib::home_dir(),
        );
        let backend_preference = scanner_backend_preference(&settings);
        let file_list_directory = self.file_list_directory.clone();
        let started_instant = Instant::now();
        let scan_run = ScanRun::starting(
            scan_run_number,
            scan_targets.clone(),
            Timestamp::now(),
            started_instant,
        );
        let scan_events = stream::once(async move {
            let scanner_programs =
                ScannerProgramPaths::locate_trusted_programs_in_background().await?;
            let scanner_backend =
                choose_scanner_backend(backend_preference, &scanner_programs).await;
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
        let scan_stream = run_stream_then(
            sender,
            scan_events
                .ready_chunks(PROGRESS_BATCH_SIZE)
                .map(
                    move |progress_batch| ScanPageCommand::ProgressBatchArrived {
                        scan_run_number,
                        progress_batch,
                    },
                ),
            ScanPageCommand::ScanStreamFinished { scan_run_number },
        );
        self.scan_page_state.begin_scan_run(
            start_permit,
            RunningScan::started(
                scan_run,
                scan_stream,
                LiveProgress::starting(current_file_display, started_instant),
                temporary_scan_target,
            ),
        );
    }
}

fn finished_results_view(finished_scan: &FinishedScan) -> ScanResultsView {
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

fn notify_finished_scan(finished_scan: &FinishedScan) {
    let scan_outcome = &finished_scan.scan_run.scan_outcome;
    let notification_title = match results_status(scan_outcome, finished_scan.scan_ending) {
        ScanResultsStatus::ThreatsDetected => gettext("Threats Detected"),
        ScanResultsStatus::NoThreatsDetected => gettext("No threats found"),
        ScanResultsStatus::FinishedWithProblems => gettext("The scan did not finish cleanly"),
        ScanResultsStatus::ScanCancelled => return,
    };
    notify_outside_the_window(
        "scan-finished",
        &notification_title,
        &scan_summary_text(scan_outcome),
    );
}

fn finished_scan_activity(finished_scan: &FinishedScan) -> NewActivityEntry {
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
        },
        duration_millis: finished_scan.elapsed_time.as_millis() as u64,
        activity_output: scan_run.scan_outcome.noteworthy_output.clone(),
    }
}

fn eicar_failure_text(eicar_failure: &EicarTestFileFailure) -> String {
    let failure_detail = match eicar_failure {
        EicarTestFileFailure::WritingInterrupted(interrupted_writing) => {
            interrupted_writing.to_string()
        }
        EicarTestFileFailure::FileUnwritable(write_failure) => write_failure.to_string(),
    };
    gettext("Could not create the EICAR test file: {error}").replace("{error}", &failure_detail)
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
                    set_visible: model.scan_page_state.shows_scan_settings(),
                    connect_clicked => ScanPageInput::ChooseFilesRequested,
                },

                pack_start = &gtk::Button {
                    set_icon_name: "folder-new-symbolic",
                    set_tooltip_text: Some(&gettext("Add Folder")),
                    #[watch]
                    set_visible: model.scan_page_state.shows_scan_settings(),
                    connect_clicked => ScanPageInput::ChooseFolderRequested,
                },

                pack_end = &gtk::MenuButton {
                    set_icon_name: "view-more-symbolic",
                    set_tooltip_text: Some(&gettext("More")),
                    #[watch]
                    set_visible: !model.scan_page_state.scan_is_active(),
                    #[wrap(Some)]
                    set_popover = &gtk::Popover {
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,

                            gtk::Button {
                                set_label: &gettext("Run EICAR Test"),
                                add_css_class: "flat",
                                #[watch]
                                set_visible: model.scan_page_state.shows_scan_settings(),
                                connect_clicked[sender] => move |clicked_button| {
                                    close_enclosing_popover(clicked_button);
                                    sender.input(ScanPageInput::EicarTestRequested);
                                },
                            },

                            gtk::Button {
                                set_label: &gettext("Copy Results"),
                                add_css_class: "flat",
                                #[watch]
                                set_visible: model.scan_page_state.shows_results(),
                                connect_clicked[sender] => move |clicked_button| {
                                    close_enclosing_popover(clicked_button);
                                    sender.input(ScanPageInput::CopyResultsRequested);
                                },
                            },

                            gtk::Button {
                                set_label: &gettext("Export Results…"),
                                add_css_class: "flat",
                                #[watch]
                                set_visible: model.scan_page_state.shows_results(),
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
                    set_visible: model.scan_page_state.shows_scan_settings(),
                    #[watch]
                    set_sensitive: !model.scan_target_rows.is_empty(),
                    connect_clicked => ScanPageInput::StartScanRequested,
                },

                pack_end = &gtk::Button {
                    set_label: &gettext("Cancel"),
                    add_css_class: "destructive-action",
                    #[watch]
                    set_visible: model.scan_page_state.scan_is_active(),
                    #[watch]
                    set_sensitive: model.scan_page_state.accepts_cancel(),
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

                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_spacing: 6,
                            #[watch]
                            set_visible: model.scan_page_state.scan_is_active(),

                            gtk::ProgressBar {
                                set_show_text: true,
                                #[watch]
                                show_scan_progress: model.scan_page_state.scan_progress_view(),
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_use_markup: false,
                                set_ellipsize: gtk::pango::EllipsizeMode::Middle,
                                add_css_class: "dim-label",
                                add_css_class: "caption",
                                #[watch]
                                set_label: &model.scan_page_state.scan_progress_view().detail_text(),
                            },
                        },

                        adw::PreferencesGroup {
                            set_title: &gettext("Scan Profile"),
                            #[watch]
                            set_visible: model.scan_page_state.shows_scan_settings(),

                            adw::ComboRow {
                                set_title: &gettext("Profile"),
                                #[track(model.profile_list_reloaded)]
                                #[block_signal(profile_selection_handler)]
                                set_model: Some(&model.profile_choice_labels()),
                                #[watch]
                                #[block_signal(profile_selection_handler)]
                                set_selected: model.profile_choice.selected_row_position(),
                                connect_selected_notify[sender] => move |profile_row| {
                                    sender.input(ScanPageInput::ProfileRowSelected {
                                        row_position: profile_row.selected() as usize,
                                    });
                                } @profile_selection_handler,

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
                            set_visible: model.scan_page_state.shows_scan_settings(),

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

                        adw::PreferencesGroup {
                            set_title: &gettext("Found so far"),
                            set_margin_top: 12,
                            #[watch]
                            set_visible: model.scan_page_state.scan_is_active() && !model.found_threat_rows.is_empty(),

                            #[local_ref]
                            found_threat_list -> gtk::ListBox {
                                add_css_class: "boxed-list",
                                set_selection_mode: gtk::SelectionMode::None,
                            },
                        },

                        gtk::Label {
                            set_xalign: 0.0,
                            set_wrap: true,
                            add_css_class: "error",
                            #[watch]
                            set_visible: shows_page_notice(&model.page_notice),
                            #[watch]
                            set_label: &describe_page_notice(&model.page_notice),
                        },

                        #[local_ref]
                        scan_results_widget -> gtk::Box {
                            #[watch]
                            set_visible: model.scan_page_state.shows_results(),
                        },

                        #[local_ref]
                        scan_options_widget -> gtk::Box {
                            #[watch]
                            set_visible: model.scan_page_state.shows_scan_settings(),
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
            match ScannerProgramPaths::locate_trusted_programs_in_background().await {
                Ok(scanner_programs) => ScanPageCommand::ScannerBackendDetected {
                    scanner_backend: choose_scanner_backend(
                        startup_backend_preference,
                        &scanner_programs,
                    )
                    .await,
                    scanner_program_trust: scanner_program_trust(&scanner_programs),
                },
                Err(lookup_failure) => ScanPageCommand::ScannerLookupFailed(lookup_failure),
            }
        });
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &DEVICE_SCAN_SETTING_KEYS,
            sender.input_sender(),
            |_changed_settings, _changed_key| ScanPageInput::DeviceAutoScanSettingsChanged,
        );
        let device_monitor = gio::VolumeMonitor::get();
        let mount_sender = sender.input_sender().clone();
        device_monitor.connect_mount_added(move |_volume_monitor, added_mount| {
            if let Some(mounted_device) = mounted_device_of(added_mount) {
                mount_sender.emit(ScanPageInput::DeviceMountAdded(mounted_device));
            }
        });
        let model = Self {
            profile_store: page_init.profile_store,
            profile_choice: ScanProfileChoice::without_profiles(),
            profile_manager_view: ProfileManagerView::ManagerClosed,
            profile_list_reloaded: false,
            activity_history: page_init.activity_history,
            file_list_directory: page_init.file_list_directory,
            scan_page_state: ScanPageState::WaitingForTargets,
            next_scan_run_number: ScanRunNumber::FIRST_RUN,
            found_threat_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            scan_results_section: ScanResultsSection::builder()
                .launch(page_init.quarantine_vault)
                .forward(
                    sender.input_sender(),
                    |section_output| match section_output {
                        ScanResultsSectionOutput::QuarantineEntriesChanged => {
                            ScanPageInput::QuarantineEntriesChanged
                        }
                        ScanResultsSectionOutput::NewScanRequested => {
                            ScanPageInput::NewScanRequested
                        }
                        ScanResultsSectionOutput::ToastRequested(toast_message) => {
                            ScanPageInput::ToastRequested(toast_message)
                        }
                    },
                ),
            scan_target_rows,
            scanner_backend_view: ScannerBackendView::DetectingBackend,
            scanner_program_trust: ScannerProgramTrust::ProgramsTrusted,
            scan_options_section: ScanOptionsSection::builder().launch(()).detach(),
            device_auto_scan_settings: DeviceAutoScanSettings::read_from(&stored_settings),
            stored_settings,
            _device_monitor: device_monitor,
            toaster: Toaster::new(&root),
            page_notice: ScanPageNotice::NoNoticeShown,
        };
        model.reload_known_profiles(&sender);
        let scan_target_list = model.scan_target_rows.widget();
        let found_threat_list = model.found_threat_rows.widget();
        let scan_results_widget = model.scan_results_section.widget();
        let scan_options_widget = model.scan_options_section.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScanPageInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        self.profile_list_reloaded = false;
        match page_input {
            ScanPageInput::ChooseFilesRequested => deliver_local_outcome(
                sender.input_sender().clone(),
                chosen_files_to_open(gettext("Choose Files to Scan")),
                |chosen_paths| {
                    (!chosen_paths.is_empty())
                        .then_some(ScanPageInput::ScanTargetsAdded(chosen_paths))
                },
            ),
            ScanPageInput::ChooseFolderRequested => deliver_local_outcome(
                sender.input_sender().clone(),
                chosen_folders_to_open(gettext("Choose a Folder to Scan")),
                |chosen_paths| {
                    (!chosen_paths.is_empty())
                        .then_some(ScanPageInput::ScanTargetsAdded(chosen_paths))
                },
            ),
            ScanPageInput::ScanTargetsChosen(scan_targets) => {
                self.add_scan_targets(scan_targets);
                self.start_chosen_targets_scan(&sender);
            }
            ScanPageInput::ScanTargetsAdded(added_targets) => {
                self.add_scan_targets(added_targets);
                self.scan_page_state.return_to_targets();
            }
            ScanPageInput::ProfileRowSelected { row_position } => {
                let target_rows_change = self.profile_choice.choose_row(row_position);
                self.change_target_rows(target_rows_change);
            }
            ScanPageInput::ManageProfilesRequested => {
                self.open_profile_manager(root, &sender);
            }
            ScanPageInput::ProfilesChanged => self.reload_known_profiles(&sender),
            ScanPageInput::RunProfileRequested(run_profile) => {
                let target_rows_change = self.profile_choice.run_profile(run_profile);
                self.profile_list_reloaded = true;
                self.change_target_rows(target_rows_change);
                self.start_chosen_targets_scan(&sender);
            }
            ScanPageInput::DeviceMountAdded(mounted_device) => {
                if self.device_auto_scan_settings.auto_scan_enabled
                    && device_qualifies_for_scan(mounted_device.device_traits)
                {
                    let auto_scan_settings = self.device_auto_scan_settings;
                    sender.oneshot_command(async move {
                        let passes_limits = settled_device_passes_limits(
                            mounted_device.mount_path.clone(),
                            auto_scan_settings,
                        )
                        .await;
                        ScanPageCommand::DeviceSettled {
                            mount_path: mounted_device.mount_path,
                            passes_limits,
                        }
                    });
                }
            }
            ScanPageInput::DeviceAutoScanSettingsChanged => {
                self.device_auto_scan_settings =
                    DeviceAutoScanSettings::read_from(&self.stored_settings);
            }
            ScanPageInput::DeviceMounted(mount_path) => {
                match self.scan_page_state.new_scan_permission() {
                    ScanStartPermission::ScanMayStart(start_permit) => self.start_scan(
                        start_permit,
                        vec![mount_path],
                        TemporaryScanTarget::NoTemporaryTarget,
                        &sender,
                    ),
                    ScanStartPermission::ScanAlreadyActive => notify_outside_the_window(
                        "device-scan-skipped",
                        &gettext("Device Auto-Scan"),
                        &gettext(
                            "A device was connected during another scan, so it was not scanned.",
                        ),
                    ),
                }
            }
            ScanPageInput::QuickScanRequested => {
                if let ScanStartPermission::ScanMayStart(start_permit) =
                    self.scan_page_state.new_scan_permission()
                {
                    self.start_scan(
                        start_permit,
                        vec![
                            glib::user_special_dir(glib::UserDirectory::Downloads)
                                .unwrap_or_else(|| glib::home_dir().join("Downloads")),
                        ],
                        TemporaryScanTarget::NoTemporaryTarget,
                        &sender,
                    );
                }
            }
            ScanPageInput::RemoveTargetRequested(row_index) => {
                self.scan_target_rows
                    .guard()
                    .remove(row_index.current_index());
            }
            ScanPageInput::StartScanRequested => self.start_chosen_targets_scan(&sender),
            ScanPageInput::EicarTestRequested => {
                if let ScanStartPermission::ScanMayStart(start_permit) =
                    self.scan_page_state.new_scan_permission()
                {
                    self.start_eicar_test(start_permit, &sender);
                }
            }
            ScanPageInput::CancelScanRequested => self.scan_page_state.request_cancel(),
            ScanPageInput::NewScanRequested => self.scan_page_state.return_to_targets(),
            ScanPageInput::CopyResultsRequested => {
                self.scan_results_section
                    .emit(ScanResultsSectionInput::CopyReportRequested);
            }
            ScanPageInput::ExportResultsRequested => {
                self.scan_results_section
                    .emit(ScanResultsSectionInput::ExportReportRequested);
            }
            ScanPageInput::ToastRequested(toast_message) => self.toaster.toast(&toast_message),
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
        self.profile_list_reloaded = false;
        match page_command {
            ScanPageCommand::ProfilesLoaded(Ok(reloaded_profiles)) => {
                let target_rows_change = self
                    .profile_choice
                    .replace_known_profiles(reloaded_profiles);
                self.profile_list_reloaded = true;
                self.change_target_rows(target_rows_change);
            }
            ScanPageCommand::ProfilesLoaded(Err(load_failure)) => {
                self.page_notice = ScanPageNotice::ProfilesUnloadable(load_failure);
            }
            ScanPageCommand::EicarTestFileWritten(write_outcome) => {
                if let ScanStartPermission::ScanMayStart(start_permit) =
                    self.scan_page_state.written_eicar_file_permission()
                {
                    match write_outcome {
                        Ok(eicar_file) => {
                            let eicar_path = eicar_file.path().to_path_buf();
                            self.start_scan(
                                start_permit,
                                vec![eicar_path],
                                TemporaryScanTarget::EicarTestFile {
                                    _eicar_file_kept: eicar_file,
                                },
                                &sender,
                            );
                        }
                        Err(eicar_failure) => {
                            self.scan_page_state.abandon_scan_start(start_permit);
                            self.page_notice =
                                ScanPageNotice::EicarTestFileUnwritable(eicar_failure);
                        }
                    }
                }
            }
            ScanPageCommand::DeviceSettled {
                mount_path,
                passes_limits: true,
            } => sender.input(ScanPageInput::DeviceMounted(mount_path)),
            ScanPageCommand::DeviceSettled {
                passes_limits: false,
                ..
            } => {}
            ScanPageCommand::ProgressBatchArrived {
                scan_run_number,
                progress_batch,
            } => {
                let newly_found_threats = self.scan_page_state.absorb_progress_batch(
                    scan_run_number,
                    progress_batch,
                    Instant::now(),
                );
                let mut threat_rows_guard = self.found_threat_rows.guard();
                newly_found_threats.into_iter().for_each(|detected_threat| {
                    threat_rows_guard.push_back(detected_threat);
                });
            }
            ScanPageCommand::ScanStreamFinished { scan_run_number } => {
                match self
                    .scan_page_state
                    .finish_scan_stream(scan_run_number, Instant::now())
                {
                    ScanStreamEnding::ScanRunFinished(finished_scan) => {
                        self.scan_results_section
                            .emit(ScanResultsSectionInput::ResultsShown(
                                finished_results_view(finished_scan),
                            ));
                        let new_entry = finished_scan_activity(finished_scan);
                        notify_finished_scan(finished_scan);
                        let activity_history = self.activity_history.clone();
                        sender.oneshot_command(async move {
                            ScanPageCommand::ActivityRecordingFinished(
                                activity_history.record_activity(new_entry).await,
                            )
                        });
                    }
                    ScanStreamEnding::StaleStreamIgnored => {}
                }
            }
            ScanPageCommand::ScannerBackendDetected {
                scanner_backend,
                scanner_program_trust,
            } => {
                self.scanner_backend_view = ScannerBackendView::BackendDetected(scanner_backend);
                self.scanner_program_trust = scanner_program_trust;
            }
            ScanPageCommand::ScannerLookupFailed(lookup_failure) => {
                self.scanner_backend_view = ScannerBackendView::BackendUndetermined(lookup_failure);
            }
            ScanPageCommand::ActivityRecordingFinished(Ok(())) => {
                let _shell_closed = sender.output(ScanPageOutput::ActivityRecorded);
            }
            ScanPageCommand::ActivityRecordingFinished(Err(recording_failure)) => {
                self.page_notice = ScanPageNotice::ScanNotRecorded(recording_failure);
            }
        }
    }
}
