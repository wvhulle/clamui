use std::{
    path::PathBuf,
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
            ActivityHistory, ActivityHistoryFailure, ActivityStatus, NewActivityEntry,
        },
        clamav_config::detection_options::host_clamscan_detection_arguments,
        clamav_scanner::{
            scan_exclusion_rules::{ExclusionEntry, ScanExclusions},
            scan_progress_estimates::{RefreshThrottle, file_progress_text},
            scan_progress_events::{
                CompletedScanOutcome, ScanProgressEvent, ScanRequest, scan_progress_events,
            },
            scanner_command_builder::{
                ScannerBackend, ScannerProgramPaths, choose_scanner_backend,
            },
            scanner_output_parser::sanitize_scanner_line,
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
    scan_page::{
        device_auto_scan_page::device_mount_scans::{
            DEVICE_SCAN_SETTING_KEYS, DeviceAutoScanSettings, MountedDevice,
            device_qualifies_for_scan, mounted_device_of, settled_device_passes_limits,
        },
        eicar_test_file::write_eicar_test_file,
        found_threat_row::FoundThreatRow,
        scan_options_section::ScanOptionsSection,
        scan_profiles_dialog::{
            profile_manager_dialog::{ProfileManagerDialog, ProfileManagerDialogOutput},
            scan_profile_store::{ScanProfile, ScanProfileStore},
        },
        scan_progress_view::{ScanProgressBar, ScanProgressView},
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
    shared_widgets::file_dialog_requests::{request_files_to_open, request_folder_to_open},
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
    activity_history: ActivityHistory,
    profile_store: ScanProfileStore,
    known_profiles: Vec<ScanProfile>,
    selected_profile: SelectedScanProfile,
    profile_manager_view: ProfileManagerView,
    profile_names: Vec<String>,
    profile_names_replaced: bool,
    scan_started_at: SystemTime,
    scan_started_instant: Instant,
    active_scan_targets: Vec<PathBuf>,
    file_list_directory: PathBuf,
    scan_page_state: ScanPageState,
    scan_outcome: CompletedScanOutcome,
    current_file_label: String,
    show_live_progress: bool,
    scan_progress_view: ScanProgressView,
    found_threat_rows: FactoryVecDeque<FoundThreatRow>,
    display_throttle: RefreshThrottle,
    displayed_phase: DisplayedScanPhase,
    scan_results_section: Controller<ScanResultsSection>,
    scan_target_rows: FactoryVecDeque<ScanTargetRow>,
    scanner_backend_view: ScannerBackendView,
    scanner_program_trust: ScannerProgramTrust,
    eicar_test_files: Vec<NamedTempFile>,
    page_notice: String,
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
    ProgressBatchArrived(Vec<ScanProgressEvent>),
    ScanStreamFinished,
    ScannerBackendDetected {
        scanner_backend: ScannerBackend,
        scanner_program_trust: ScannerProgramTrust,
    },
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
    ProfilesLoaded(Result<Vec<ScanProfile>, String>),
    EicarTestFileWritten(Result<NamedTempFile, String>),
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
        let file_list_directory = self.file_list_directory.clone();
        sender.oneshot_command(async move {
            ScanPageCommand::EicarTestFileWritten(
                tokio::task::spawn_blocking(move || write_eicar_test_file(&file_list_directory))
                    .await
                    .map_err(|interrupted_writing| interrupted_writing.to_string())
                    .and_then(|write_outcome| {
                        write_outcome.map_err(|write_failure| write_failure.to_string())
                    }),
            )
        });
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

    fn results_status(&self) -> ScanResultsStatus {
        results_status(
            &self.scan_outcome,
            matches!(self.scan_page_state, ScanPageState::ScanCancelled),
        )
    }

    fn results_view(&self) -> ScanResultsView {
        ScanResultsView {
            results_status: self.results_status(),
            inspected_file_count: self.scan_outcome.inspected_file_count,
            planned_file_count: self.scan_outcome.planned_file_count,
            scanned_directory_count: self.scan_outcome.scanned_directory_count,
            excluded_entry_count: self.scan_outcome.excluded_entry_count,
            elapsed_time: self.scan_started_instant.elapsed(),
            detected_threats: self.scan_outcome.detected_threats.clone(),
            problem_path_groups: problem_path_groups(&self.scan_outcome),
            notice_lines: unlisted_notice_lines(&self.scan_outcome),
            noteworthy_output: self.scan_outcome.noteworthy_output.clone(),
        }
    }

    fn reload_known_profiles(&self, sender: &ComponentSender<Self>) {
        let profile_store = self.profile_store.clone();
        sender.oneshot_command(async move {
            ScanPageCommand::ProfilesLoaded(
                tokio::task::spawn_blocking(move || profile_store.load_profiles())
                    .await
                    .map_err(|interrupted_loading| interrupted_loading.to_string())
                    .and_then(|load_outcome| {
                        load_outcome.map_err(|load_failure| load_failure.to_string())
                    }),
            )
        });
    }

    fn show_known_profiles(&mut self, known_profiles: Vec<ScanProfile>) {
        self.profile_names = std::iter::once(gettext("No Profile (Manual)"))
            .chain(
                known_profiles
                    .iter()
                    .map(|known_profile| sanitize_scanner_line(&known_profile.displayed_name())),
            )
            .collect();
        self.profile_names_replaced = true;
        self.known_profiles = known_profiles;
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
            &scan_summary_text(&self.scan_outcome),
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
        sender.oneshot_command(async move {
            ScanPageCommand::ActivityRecordingFinished(
                activity_history.record_activity(new_entry).await,
            )
        });
    }

    fn show_scan_results(&self) {
        self.scan_results_section
            .emit(ScanResultsSectionInput::ResultsShown(self.results_view()));
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
        self.scan_progress_view = ScanProgressView::PreparingScan;
        self.found_threat_rows.guard().clear();
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
        let file_list_directory = self.file_list_directory.clone();
        let scan_events = stream::once(async move {
            let scanner_programs =
                tokio::task::spawn_blocking(ScannerProgramPaths::locate_trusted_programs)
                    .await
                    .unwrap_or_else(|_interrupted_lookup| ScannerProgramPaths::nothing_found());
            let scanner_backend =
                choose_scanner_backend(backend_preference, &scanner_programs).await;
            let detection_arguments =
                tokio::task::spawn_blocking(host_clamscan_detection_arguments)
                    .await
                    .unwrap_or_default();
            ScanRequest {
                scan_exclusions,
                scan_targets,
                scanner_backend,
                scanner_programs,
                file_list_directory,
                detection_arguments,
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
                    self.found_threat_rows
                        .guard()
                        .push_back(detected_threat.clone());
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
                    self.scan_progress_view =
                        ScanProgressView::finding_files(&enumeration_progress);
                }
            }
            DisplayedScanPhase::ScanningFiles => {
                if self.display_throttle.allows_refresh(Instant::now()) || target_enumerated {
                    self.show_scanning_progress();
                }
            }
        }
    }

    fn show_scanning_progress(&mut self) {
        self.scan_progress_view = ScanProgressView::ScanningFiles {
            inspected_file_count: self.scan_outcome.inspected_file_count,
            planned_file_count: self.scan_outcome.planned_file_count,
            elapsed_time: self.scan_started_instant.elapsed(),
            current_file_text: if self.show_live_progress {
                self.current_file_label.clone()
            } else {
                String::new()
            },
        };
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

                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_spacing: 6,
                            #[watch]
                            set_visible: model.scan_is_running(),

                            gtk::ProgressBar {
                                set_show_text: true,
                                #[watch]
                                show_scan_progress: &model.scan_progress_view,
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_use_markup: false,
                                set_ellipsize: gtk::pango::EllipsizeMode::Middle,
                                add_css_class: "dim-label",
                                add_css_class: "caption",
                                #[watch]
                                set_label: &model.scan_progress_view.detail_text(),
                            },
                        },

                        adw::PreferencesGroup {
                            set_title: &gettext("Scan Profile"),
                            #[watch]
                            set_visible: model.shows_scan_settings(),

                            adw::ComboRow {
                                set_title: &gettext("Profile"),
                                #[track(model.profile_names_replaced)]
                                set_model: Some(&gtk::StringList::new(
                                    &model.profile_names.iter().map(String::as_str).collect::<Vec<_>>(),
                                )),
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

                        adw::PreferencesGroup {
                            set_title: &gettext("Found so far"),
                            set_margin_top: 12,
                            #[watch]
                            set_visible: model.scan_is_running() && !model.found_threat_rows.is_empty(),

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
                            set_visible: !model.page_notice.is_empty(),
                            #[watch]
                            set_label: &model.page_notice,
                        },

                        #[local_ref]
                        scan_results_widget -> gtk::Box {
                            #[watch]
                            set_visible: model.shows_results(),
                        },

                        #[local_ref]
                        scan_options_widget -> gtk::Box {
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
            known_profiles: Vec::new(),
            selected_profile: SelectedScanProfile::ManualTargets,
            profile_manager_view: ProfileManagerView::ManagerClosed,
            profile_names: Vec::new(),
            profile_names_replaced: false,
            activity_history: page_init.activity_history,
            scan_started_at: SystemTime::now(),
            scan_started_instant: Instant::now(),
            active_scan_targets: Vec::new(),
            file_list_directory: page_init.file_list_directory,
            scan_page_state: ScanPageState::WaitingForTargets,
            scan_outcome: CompletedScanOutcome::default(),
            current_file_label: String::new(),
            show_live_progress: true,
            scan_progress_view: ScanProgressView::PreparingScan,
            found_threat_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            display_throttle: RefreshThrottle::starting_at(
                DISPLAY_REFRESH_INTERVAL,
                Instant::now(),
            ),
            displayed_phase: DisplayedScanPhase::PreparingScan,
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
            eicar_test_files: Vec::new(),
            scan_options_section: ScanOptionsSection::builder().launch(()).detach(),
            device_auto_scan_settings: DeviceAutoScanSettings::read_from(&stored_settings),
            stored_settings,
            _device_monitor: device_monitor,
            toaster: Toaster::new(&root),
            page_notice: String::new(),
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
        self.profile_names_replaced = false;
        match page_input {
            ScanPageInput::ChooseFilesRequested => request_files_to_open(
                gettext("Choose Files to Scan"),
                sender.input_sender().clone(),
                ScanPageInput::ScanTargetsAdded,
            ),
            ScanPageInput::ChooseFolderRequested => request_folder_to_open(
                gettext("Choose a Folder to Scan"),
                sender.input_sender().clone(),
                |folder_path| ScanPageInput::ScanTargetsAdded(vec![folder_path]),
            ),
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
            ScanPageInput::ProfilesChanged => self.reload_known_profiles(&sender),
            ScanPageInput::RunProfileRequested(run_profile) => {
                self.apply_profile(run_profile);
                if !self.scan_target_rows.is_empty() && !self.scan_is_running() {
                    self.start_scan(self.chosen_scan_targets(), &sender);
                }
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
        self.profile_names_replaced = false;
        match page_command {
            ScanPageCommand::ProfilesLoaded(Ok(known_profiles)) => {
                self.show_known_profiles(known_profiles);
            }
            ScanPageCommand::ProfilesLoaded(Err(load_failure)) => self.page_notice = load_failure,
            ScanPageCommand::EicarTestFileWritten(Ok(eicar_file)) => {
                let eicar_path = eicar_file.path().to_path_buf();
                self.eicar_test_files.clear();
                self.eicar_test_files.push(eicar_file);
                self.start_scan(vec![eicar_path], &sender);
            }
            ScanPageCommand::EicarTestFileWritten(Err(write_failure)) => {
                self.page_notice = gettext("Could not create the EICAR test file: {error}")
                    .replace("{error}", &write_failure);
            }
            ScanPageCommand::DeviceSettled {
                mount_path,
                passes_limits: true,
            } => sender.input(ScanPageInput::DeviceMounted(mount_path)),
            ScanPageCommand::DeviceSettled {
                passes_limits: false,
                ..
            } => {}
            ScanPageCommand::ProgressBatchArrived(progress_batch) => {
                self.absorb_progress_batch(progress_batch);
            }
            ScanPageCommand::ScanStreamFinished => {
                self.scan_page_state = match &self.scan_page_state {
                    ScanPageState::ScanCancelling => ScanPageState::ScanCancelled,
                    _other_state => ScanPageState::ScanCompleted,
                };
                self.show_scan_results();
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
