use std::{path::PathBuf, time::Instant};

use gettextrs::gettext;
use jiff::Timestamp;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, adw, adw::prelude::*, gtk, gtk::gio, prelude::FactoryVecDeque,
};

use crate::{
    host_services::{
        activity_history::activity_history_database::{
            ActivityHistory, ActivityHistoryFailure, ScanOrigin,
        },
        clamav_scanner::{
            scan_progress_estimates::file_progress_text, scan_progress_events::ScanProgressEvent,
        },
        desktop::{
            desktop_notifications::notify_outside_the_window, stored_settings::application_settings,
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
    },
    scans::removable_drives_page::{
        device_auto_scan_section::{DeviceAutoScanSection, DeviceAutoScanSectionOutput},
        drive_event_row::DriveEventRow,
        drive_mount_checks::{
            DeviceAutoScanSettings, DriveScanDecision, MountedDevice, SettledDriveCheck,
            SettledDriveFacts, classify_settled_drive, device_qualifies_for_scan,
            mounted_device_of, mounted_drive_decision, settled_drive_facts,
        },
        removable_drives_presentation::{device_scan_title, shown_drive_name},
        removable_drives_state::{
            DeviceScanEnding, DeviceScanFlow, DriveEventLog, DriveEventNumber, DriveScanTarget,
            GrantedSlotUse, ReadyDriveOutcome, RemovableDrivesPageOutput, RemovableDrivesStatus,
            WithdrawnDrive, skipped_while_scanning,
        },
    },
    shared_widgets::{
        activity_entries::{
            activity_history_filter::ActivityHistoryFilter,
            activity_history_group::{
                ActivityHistoryGroup, ActivityHistoryGroupInit, ActivityHistoryGroupInput,
            },
        },
        scan_runs::{
            found_threat_row::FoundThreatRow,
            scan_progress_view::{ScanProgressBar, ScanProgressView},
            scan_results_section::scan_results_component::{
                ScanResultsSection, ScanResultsSectionInit, ScanResultsSectionInput,
                ScanResultsSectionOutput,
            },
            scan_run_progress::{ScanRunNumber, TemporaryScanTarget},
            scan_run_start::{
                ScanRunCommands, ScanRunRequest, finished_results_status, finished_results_view,
                finished_scan_activity, notify_finished_scan, start_scan_run,
            },
        },
    },
};

pub struct RemovableDrivesPageInit {
    pub quarantine_vault: QuarantineVault,
    pub activity_history: ActivityHistory,
    pub file_list_directory: PathBuf,
}

#[derive(Debug)]
enum DrivesPageNotice {
    NoNoticeShown,
    ScanNotRecorded(ActivityHistoryFailure),
}

fn describe_page_notice(page_notice: &DrivesPageNotice) -> String {
    match page_notice {
        DrivesPageNotice::NoNoticeShown => String::new(),
        DrivesPageNotice::ScanNotRecorded(recording_failure) => {
            gettext("The drive scan could not be added to the history: {error}")
                .replace("{error}", &recording_failure.to_string())
        }
    }
}

const fn shows_page_notice(page_notice: &DrivesPageNotice) -> bool {
    !matches!(page_notice, DrivesPageNotice::NoNoticeShown)
}

pub struct RemovableDrivesPage {
    toaster: Toaster,
    activity_history: ActivityHistory,
    file_list_directory: PathBuf,
    auto_scan_settings: DeviceAutoScanSettings,
    drive_event_log: DriveEventLog,
    drive_event_rows: FactoryVecDeque<DriveEventRow>,
    device_scan_flow: DeviceScanFlow,
    next_scan_run_number: ScanRunNumber,
    found_threat_rows: FactoryVecDeque<FoundThreatRow>,
    scan_results_section: Controller<ScanResultsSection>,
    settings_section: Controller<DeviceAutoScanSection>,
    history_group: Controller<ActivityHistoryGroup>,
    page_notice: DrivesPageNotice,
    reported_status: RemovableDrivesStatus,
    _volume_monitor: gio::VolumeMonitor,
}

#[derive(Debug)]
pub enum RemovableDrivesPageInput {
    DriveMountAdded(MountedDevice),
    AutoScanSettingsChanged(DeviceAutoScanSettings),
    ScanSlotGranted,
    ScanSlotRefused,
    ScanSlotRevoked,
    CancelScanRequested,
    ResultsDismissed,
    ToastRequested(String),
    QuarantineEntriesChanged,
    HistoryReloadRequested,
}

#[derive(Debug)]
pub enum RemovableDrivesPageCommand {
    DriveSettled {
        scan_target: DriveScanTarget,
        settled_facts: SettledDriveFacts,
    },
    ProgressBatchArrived {
        scan_run_number: ScanRunNumber,
        progress_batch: Vec<ScanProgressEvent>,
    },
    ScanStreamFinished {
        scan_run_number: ScanRunNumber,
    },
    ActivityRecordingFinished(Result<(), ActivityHistoryFailure>),
}

fn notify_drive_skipped_during_scan() {
    notify_outside_the_window(
        "device-scan-skipped",
        &gettext("Device Auto-Scan"),
        &gettext("A device was connected during another scan, so it was not scanned."),
    );
}

impl RemovableDrivesPage {
    fn current_status(&self) -> RemovableDrivesStatus {
        RemovableDrivesStatus {
            auto_scan_settings: self.auto_scan_settings,
            device_scan_status: self.device_scan_flow.device_scan_status(),
        }
    }

    fn report_status_change(&mut self, sender: &ComponentSender<Self>) {
        let current_status = self.current_status();
        if current_status != self.reported_status {
            self.reported_status = current_status.clone();
            let _shell_closed =
                sender.output(RemovableDrivesPageOutput::StatusChanged(current_status));
        }
    }

    fn show_drive_events(&mut self) {
        let mut event_rows_guard = self.drive_event_rows.guard();
        event_rows_guard.clear();
        self.drive_event_log
            .newest_first_events()
            .iter()
            .cloned()
            .for_each(|drive_event| {
                event_rows_guard.push_back(drive_event);
            });
    }

    fn decide_drive(
        &mut self,
        drive_event_number: DriveEventNumber,
        drive_decision: DriveScanDecision,
    ) {
        self.drive_event_log
            .decide_drive(drive_event_number, drive_decision);
        self.show_drive_events();
    }

    fn withdraw_drive(&mut self, withdrawn_drive: WithdrawnDrive) {
        match withdrawn_drive {
            WithdrawnDrive::DriveWithdrawn(drive_event_number) => {
                self.decide_drive(drive_event_number, skipped_while_scanning());
                notify_drive_skipped_during_scan();
            }
            WithdrawnDrive::NoDriveWithdrawn => {}
        }
    }

    fn record_mounted_drive(
        &mut self,
        mounted_device: MountedDevice,
        sender: &ComponentSender<Self>,
    ) {
        if !device_qualifies_for_scan(mounted_device.device_traits) {
            return;
        }
        let drive_name = shown_drive_name(&mounted_device.drive_name, &mounted_device.mount_path);
        let drive_decision = mounted_drive_decision(self.auto_scan_settings);
        let drive_event_number = self.drive_event_log.record_seen_drive(
            drive_name.clone(),
            mounted_device.mount_path.clone(),
            Timestamp::now(),
            drive_decision,
        );
        self.show_drive_events();
        match drive_decision {
            DriveScanDecision::DriveSettling => {
                let scan_target = DriveScanTarget {
                    drive_event_number,
                    drive_name,
                    mount_path: mounted_device.mount_path,
                };
                sender.oneshot_command(async move {
                    let settled_facts = settled_drive_facts(scan_target.mount_path.clone()).await;
                    RemovableDrivesPageCommand::DriveSettled {
                        scan_target,
                        settled_facts,
                    }
                });
            }
            DriveScanDecision::DriveScanning
            | DriveScanDecision::ScannedDrive { .. }
            | DriveScanDecision::DriveSkipped(_) => {}
        }
    }

    fn settled_drive(
        &mut self,
        scan_target: DriveScanTarget,
        settled_facts: SettledDriveFacts,
        sender: &ComponentSender<Self>,
    ) {
        let drive_event_number = scan_target.drive_event_number;
        match classify_settled_drive(self.auto_scan_settings, settled_facts) {
            SettledDriveCheck::DriveNotScanned(skip_reason) => {
                self.decide_drive(
                    drive_event_number,
                    DriveScanDecision::DriveSkipped(skip_reason),
                );
            }
            SettledDriveCheck::DriveMayBeScanned => {
                match self.device_scan_flow.drive_ready_to_scan(scan_target) {
                    ReadyDriveOutcome::ScanSlotNeeded { drive_name } => {
                        let _shell_closed = sender
                            .output(RemovableDrivesPageOutput::ScanSlotRequested { drive_name });
                    }
                    ReadyDriveOutcome::SkippedWhileBusy => {
                        self.withdraw_drive(WithdrawnDrive::DriveWithdrawn(drive_event_number));
                    }
                }
            }
        }
    }

    fn start_granted_scan(&mut self, sender: &ComponentSender<Self>) {
        let scan_target = match self.device_scan_flow.scan_slot_granted() {
            GrantedSlotUse::ScanGrantedDrive(scan_target) => scan_target,
            GrantedSlotUse::ReleaseUnusedSlot => {
                let _shell_closed = sender.output(RemovableDrivesPageOutput::DeviceScanEnded);
                return;
            }
        };
        self.page_notice = DrivesPageNotice::NoNoticeShown;
        let scan_run_number = self.next_scan_run_number;
        self.next_scan_run_number = scan_run_number.following_run();
        self.found_threat_rows.guard().clear();
        let running_scan = start_scan_run(
            sender,
            ScanRunRequest {
                scan_run_number,
                scan_targets: vec![scan_target.mount_path.clone()],
                extra_exclusion_entries: Vec::new(),
                file_list_directory: self.file_list_directory.clone(),
                temporary_scan_target: TemporaryScanTarget::NoTemporaryTarget,
            },
            ScanRunCommands {
                progress_command: |scan_run_number, progress_batch| {
                    RemovableDrivesPageCommand::ProgressBatchArrived {
                        scan_run_number,
                        progress_batch,
                    }
                },
                finished_command: |scan_run_number| {
                    RemovableDrivesPageCommand::ScanStreamFinished { scan_run_number }
                },
            },
        );
        self.decide_drive(
            scan_target.drive_event_number,
            DriveScanDecision::DriveScanning,
        );
        self.device_scan_flow
            .begin_device_scan(scan_target, running_scan);
    }

    fn finish_scan_stream(
        &mut self,
        scan_run_number: ScanRunNumber,
        sender: &ComponentSender<Self>,
    ) {
        let (drive_event_number, scan_result, new_entry) = match self
            .device_scan_flow
            .finish_scan_stream(scan_run_number, Instant::now())
        {
            DeviceScanEnding::DeviceScanFinished(finished_device_scan) => {
                let finished_scan = finished_device_scan.finished_scan;
                self.scan_results_section
                    .emit(ScanResultsSectionInput::ResultsShown(
                        finished_results_view(finished_scan),
                    ));
                notify_finished_scan(finished_scan);
                (
                    finished_device_scan.scan_target.drive_event_number,
                    finished_results_status(finished_scan),
                    finished_scan_activity(finished_scan, ScanOrigin::DeviceScan),
                )
            }
            DeviceScanEnding::StaleDeviceStreamIgnored => return,
        };
        self.decide_drive(
            drive_event_number,
            DriveScanDecision::ScannedDrive { scan_result },
        );
        let _shell_closed = sender.output(RemovableDrivesPageOutput::DeviceScanEnded);
        let activity_history = self.activity_history.clone();
        sender.oneshot_command(async move {
            RemovableDrivesPageCommand::ActivityRecordingFinished(
                activity_history.record_activity(new_entry).await,
            )
        });
    }

    fn header_subtitle(&self) -> String {
        match self.device_scan_flow.scan_progress_view() {
            ScanProgressView::ScanningFiles {
                inspected_file_count,
                planned_file_count,
                ..
            } if self.device_scan_flow.scan_is_running() && *planned_file_count > 0 => {
                file_progress_text(*inspected_file_count, *planned_file_count)
            }
            ScanProgressView::PreparingScan
            | ScanProgressView::FindingFiles { .. }
            | ScanProgressView::ScanningFiles { .. } => String::new(),
        }
    }
}

#[relm4::component(pub)]
impl Component for RemovableDrivesPage {
    type Init = RemovableDrivesPageInit;
    type Input = RemovableDrivesPageInput;
    type Output = RemovableDrivesPageOutput;
    type CommandOutput = RemovableDrivesPageCommand;

    view! {
        adw::ToastOverlay {
            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {
                    #[wrap(Some)]
                    set_title_widget = &adw::WindowTitle {
                        set_title: &gettext("Removable Drives"),
                        #[watch]
                        set_subtitle: &model.header_subtitle(),
                    },

                    pack_end = &gtk::Button {
                        set_label: &gettext("Cancel"),
                        add_css_class: "destructive-action",
                        #[watch]
                        set_visible: model.device_scan_flow.scan_is_running(),
                        #[watch]
                        set_sensitive: model.device_scan_flow.accepts_cancel(),
                        connect_clicked => RemovableDrivesPageInput::CancelScanRequested,
                    },
                },

                #[wrap(Some)]
                set_content = &adw::PreferencesPage {
                    add = &adw::PreferencesGroup {
                        #[watch]
                        set_title: &device_scan_title(&model.device_scan_flow.device_scan_status()),
                        #[watch]
                        set_visible: model.device_scan_flow.scan_is_running(),

                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_spacing: 6,

                            gtk::ProgressBar {
                                set_show_text: true,
                                #[watch]
                                show_scan_progress: model.device_scan_flow.scan_progress_view(),
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_use_markup: false,
                                set_ellipsize: gtk::pango::EllipsizeMode::Middle,
                                add_css_class: "dim-label",
                                add_css_class: "caption",
                                #[watch]
                                set_label: &model.device_scan_flow.scan_progress_view().detail_text(),
                            },
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Found so far"),
                        #[watch]
                        set_visible: model.device_scan_flow.scan_is_running() && !model.found_threat_rows.is_empty(),

                        #[local_ref]
                        found_threat_list -> gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                        },
                    },

                    add = &adw::PreferencesGroup {
                        #[watch]
                        set_visible: shows_page_notice(&model.page_notice) || model.device_scan_flow.shows_results(),

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
                            set_visible: model.device_scan_flow.shows_results(),
                        },
                    },

                    add = &adw::PreferencesGroup {
                        set_title: &gettext("Drives this session"),
                        set_description: Some(&gettext(
                            "Drives connected since Lazaret started, newest first, and what \
                             happened to each. This list is kept only until Lazaret quits.",
                        )),

                        #[local_ref]
                        drive_event_list -> gtk::ListBox {
                            add_css_class: "boxed-list",
                            set_selection_mode: gtk::SelectionMode::None,
                            #[wrap(Some)]
                            set_placeholder = &adw::ActionRow {
                                set_title: &gettext("No drive was connected yet"),
                                add_css_class: "dim-label",
                            },
                        },
                    },

                    add: model.settings_section.widget(),
                    add: model.history_group.widget(),
                },
            },
        }
    }

    fn init(
        page_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let volume_monitor = gio::VolumeMonitor::get();
        let mount_sender = sender.input_sender().clone();
        volume_monitor.connect_mount_added(move |_volume_monitor, added_mount| {
            if let Some(mounted_device) = mounted_device_of(added_mount) {
                mount_sender.emit(RemovableDrivesPageInput::DriveMountAdded(mounted_device));
            }
        });
        let auto_scan_settings = DeviceAutoScanSettings::read_from(&application_settings());
        let device_scan_flow = DeviceScanFlow::idle_flow();
        let reported_status = RemovableDrivesStatus {
            auto_scan_settings,
            device_scan_status: device_scan_flow.device_scan_status(),
        };
        let model = Self {
            toaster: Toaster::new(&root),
            activity_history: page_init.activity_history.clone(),
            file_list_directory: page_init.file_list_directory,
            auto_scan_settings,
            drive_event_log: DriveEventLog::empty_session(),
            drive_event_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            device_scan_flow,
            next_scan_run_number: ScanRunNumber::FIRST_RUN,
            found_threat_rows: FactoryVecDeque::builder()
                .launch(gtk::ListBox::default())
                .detach(),
            scan_results_section: ScanResultsSection::builder()
                .launch(ScanResultsSectionInit {
                    quarantine_vault: page_init.quarantine_vault,
                    activity_history: page_init.activity_history.clone(),
                    dismiss_label: gettext("Close Results"),
                })
                .forward(
                    sender.input_sender(),
                    |section_output| match section_output {
                        ScanResultsSectionOutput::QuarantineEntriesChanged => {
                            RemovableDrivesPageInput::QuarantineEntriesChanged
                        }
                        ScanResultsSectionOutput::ResultsDismissRequested => {
                            RemovableDrivesPageInput::ResultsDismissed
                        }
                        ScanResultsSectionOutput::ToastRequested(toast_message) => {
                            RemovableDrivesPageInput::ToastRequested(toast_message)
                        }
                    },
                ),
            settings_section: DeviceAutoScanSection::builder().launch(()).forward(
                sender.input_sender(),
                |section_output| match section_output {
                    DeviceAutoScanSectionOutput::SettingsChanged(auto_scan_settings) => {
                        RemovableDrivesPageInput::AutoScanSettingsChanged(auto_scan_settings)
                    }
                },
            ),
            history_group: ActivityHistoryGroup::builder()
                .launch(ActivityHistoryGroupInit {
                    activity_history: page_init.activity_history,
                    history_filter: ActivityHistoryFilter::DeviceScans,
                    group_title: gettext("Drive scans"),
                    group_description: gettext(
                        "Drives Lazaret scanned when they were connected, newest first. Select \
                         one to read its transcript.",
                    ),
                    empty_title: gettext("No drive was scanned yet"),
                    empty_icon_name: "drive-removable-media-symbolic",
                })
                .detach(),
            page_notice: DrivesPageNotice::NoNoticeShown,
            reported_status,
            _volume_monitor: volume_monitor,
        };
        let found_threat_list = model.found_threat_rows.widget();
        let drive_event_list = model.drive_event_rows.widget();
        let scan_results_widget = model.scan_results_section.widget();
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: RemovableDrivesPageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_input {
            RemovableDrivesPageInput::DriveMountAdded(mounted_device) => {
                self.record_mounted_drive(mounted_device, &sender);
            }
            RemovableDrivesPageInput::AutoScanSettingsChanged(auto_scan_settings) => {
                self.auto_scan_settings = auto_scan_settings;
            }
            RemovableDrivesPageInput::ScanSlotGranted => self.start_granted_scan(&sender),
            RemovableDrivesPageInput::ScanSlotRefused => {
                let withdrawn_drive = self.device_scan_flow.scan_slot_refused();
                self.withdraw_drive(withdrawn_drive);
            }
            RemovableDrivesPageInput::ScanSlotRevoked => {
                let withdrawn_drive = self.device_scan_flow.scan_slot_revoked();
                self.withdraw_drive(withdrawn_drive);
            }
            RemovableDrivesPageInput::CancelScanRequested => {
                self.device_scan_flow.request_cancel();
            }
            RemovableDrivesPageInput::ResultsDismissed => self.device_scan_flow.dismiss_results(),
            RemovableDrivesPageInput::ToastRequested(toast_message) => {
                self.toaster.toast(&toast_message);
            }
            RemovableDrivesPageInput::QuarantineEntriesChanged => {
                let _shell_closed =
                    sender.output(RemovableDrivesPageOutput::QuarantineEntriesChanged);
            }
            RemovableDrivesPageInput::HistoryReloadRequested => {
                self.history_group
                    .emit(ActivityHistoryGroupInput::ReloadRequested);
            }
        }
        self.report_status_change(&sender);
    }

    fn update_cmd(
        &mut self,
        page_command: RemovableDrivesPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            RemovableDrivesPageCommand::DriveSettled {
                scan_target,
                settled_facts,
            } => self.settled_drive(scan_target, settled_facts, &sender),
            RemovableDrivesPageCommand::ProgressBatchArrived {
                scan_run_number,
                progress_batch,
            } => {
                let newly_found_threats = self.device_scan_flow.absorb_progress_batch(
                    scan_run_number,
                    progress_batch,
                    Instant::now(),
                );
                let mut threat_rows_guard = self.found_threat_rows.guard();
                newly_found_threats.into_iter().for_each(|detected_threat| {
                    threat_rows_guard.push_back(detected_threat);
                });
            }
            RemovableDrivesPageCommand::ScanStreamFinished { scan_run_number } => {
                self.finish_scan_stream(scan_run_number, &sender);
            }
            RemovableDrivesPageCommand::ActivityRecordingFinished(Ok(())) => {
                self.history_group
                    .emit(ActivityHistoryGroupInput::ReloadRequested);
                let _shell_closed = sender.output(RemovableDrivesPageOutput::ActivityRecorded);
            }
            RemovableDrivesPageCommand::ActivityRecordingFinished(Err(recording_failure)) => {
                self.page_notice = DrivesPageNotice::ScanNotRecorded(recording_failure);
            }
        }
        self.report_status_change(&sender);
    }
}
