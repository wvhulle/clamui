use std::path::PathBuf;

use futures::StreamExt;
use gettextrs::gettext;
use jiff::Timestamp;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster, actions::RelmAction, adw, adw::prelude::*, gtk, gtk::glib,
};

use crate::{
    application_window::{
        application_actions::{
            ClearHistoryAction, ExportHistoryAction, OpenDetectionAction, OpenDetectionsAction,
            QuickScanAction, ScanFilesAction, ScanPathsAction, ShowPageAction,
            UpdateDefinitionsAction, register_application_action, register_window_action,
        },
        application_pages::{ALL_APPLICATION_PAGES, ApplicationPage},
        history_menu_actions::{
            ClearHistoryChoice, HistoryExportChoice, HistoryExportFormat, clear_history_dialog,
            exported_history_file, history_export_dialog,
        },
        protection_evidence_refresh::{
            EvidenceRefresh, EvidenceRefreshTransition, EvidenceRefreshTrigger, GatheredEvidence,
            GatheringStart,
        },
        scan_slot_arbiter::{ScanSlot, ScanSlotEvent, ScanSlotReply, ScanSlotTransition},
        sidebar_area_status::{AreaSummaryContext, SidebarAreaSummary, all_area_summaries},
        sidebar_navigation::sidebar_navigation_column::{
            SidebarNavigationColumn, SidebarNavigationColumnInput,
        },
        start_page_choice::{
            StartPageRequest, StartPageState, StartPageTransition, initial_start_page,
            start_page_after_evidence,
        },
    },
    findings::{
        detections_page::{
            alert_delivery_presentation::AlertReadiness,
            background_detections_page::{
                BackgroundDetectionsPage, BackgroundDetectionsPageInit,
                BackgroundDetectionsPageInput, BackgroundDetectionsPageOutput,
            },
        },
        quarantine_page::{
            quarantine_entries_page::{
                QuarantineEntriesPage, QuarantineEntriesPageInit, QuarantineEntriesPageInput,
                QuarantineEntriesPageOutput,
            },
            quarantine_page_state::QuarantineEntryCount,
        },
        trusted_detections_page::trusted_detections_component::{
            TrustedDetectionsPage, TrustedDetectionsPageInput, TrustedDetectionsPageOutput,
        },
    },
    host_services::{
        activity_history::activity_history_database::{
            ActivityEntryRecord, ActivityHistory, ActivityHistoryFailure,
        },
        clamav_programs::clamav_report_submission::ClamavReportRequest,
        desktop::{
            application_directories::application_config_directory,
            locale_formatting::host_moment_formatters,
            running_instance_forwarding::paths_from_bytes, stored_settings::application_settings,
        },
        detection_journal::detection_journal_follower::JournalAccess,
        lazaret_database::locked_database_connection::lazaret_database_path,
        protection_evidence::host_protection_evidence::{
            ProtectionEvidence, WATCHED_SERVICE_UNITS, detection_notifications_are_enabled,
            gather_protection_evidence, lazaret_schedule_is_enabled,
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
        systemd_bus::host_systemd_units::watched_unit_changes,
    },
    scans::{
        manual_scan_page::{
            scan_page_component::{ScanPage, ScanPageInit, ScanPageInput, ScanPageOutput},
            scan_profiles_dialog::scan_profile_store::ScanProfileStore,
        },
        on_access_page::{
            on_access_component::{OnAccessPage, OnAccessPageInput},
            on_access_state::OnAccessPageOutput,
        },
        removable_drives_page::{
            drive_mount_checks::DeviceAutoScanSettings,
            removable_drives_component::{
                RemovableDrivesPage, RemovableDrivesPageInit, RemovableDrivesPageInput,
            },
            removable_drives_state::{
                DeviceScanStatus, RemovableDrivesPageOutput, RemovableDrivesStatus,
            },
        },
        scan_engine_page::{
            scan_engine_component::{ScanEnginePage, ScanEnginePageInput},
            scan_engine_state::ScanEnginePageOutput,
        },
        scheduled_scans_page::{
            scheduled_scans_component::{ScheduledScansPage, ScheduledScansPageInput},
            scheduled_scans_state::ScheduledScansPageOutput,
        },
    },
    shared_widgets::{
        awaited_dialogs::{
            TextExportOutcome, alert_choice, deliver_local_outcome, describe_export_failure,
            exported_text,
        },
        component_streams::{RunningStream, run_stream},
        database_migration_failure_text::describe_history_failure,
        scan_runs::scan_run_progress::PageScanActivity,
    },
    sharing::{
        online_lookups_page::{
            online_lookups_component::{OnlineLookupsPage, OnlineLookupsPageInput},
            online_lookups_state::OnlineLookupsPageOutput,
        },
        submissions_page::{
            submissions_component::{SubmissionsPage, SubmissionsPageInit, SubmissionsPageInput},
            submissions_state::{SubmissionTally, SubmissionsPageOutput},
        },
    },
    signatures::{
        database_updates_page::{
            database_updates_component::{DatabaseUpdatesPage, DatabaseUpdatesPageInput},
            database_updates_state::DatabaseUpdatesPageOutput,
        },
        signature_sources_page::signature_sources_component::{
            SignatureSourcesPage, SignatureSourcesPageInput, SignatureSourcesPageOutput,
        },
    },
};

pub struct PageNavigationInit {
    pub quarantine_vault: QuarantineVault,
    pub data_directory: PathBuf,
    pub window_root: adw::ApplicationWindow,
    pub startup_page: StartPageRequest,
    pub startup_scan_targets: Vec<PathBuf>,
}

enum AreaSummaries {
    SummariesPending,
    SummariesComputed(Vec<SidebarAreaSummary>),
}

pub struct PageNavigation {
    visible_page: ApplicationPage,
    sidebar_column: Controller<SidebarNavigationColumn>,
    start_page_state: StartPageState,
    shows_content_when_narrow: bool,
    scan_page: Controller<ScanPage>,
    removable_drives_page: Controller<RemovableDrivesPage>,
    scan_slot: ScanSlot,
    removable_drives_status: RemovableDrivesStatus,
    toaster: Toaster,
    quarantine_page: Controller<QuarantineEntriesPage>,
    activity_history: ActivityHistory,
    signature_sources_page: Controller<SignatureSourcesPage>,
    database_updates_page: Controller<DatabaseUpdatesPage>,
    scan_engine_page: Controller<ScanEnginePage>,
    on_access_page: Controller<OnAccessPage>,
    scheduled_scans_page: Controller<ScheduledScansPage>,
    detections_page: Controller<BackgroundDetectionsPage>,
    trusted_detections_page: Controller<TrustedDetectionsPage>,
    online_lookups_page: Controller<OnlineLookupsPage>,
    submissions_page: Controller<SubmissionsPage>,
    submission_tally: SubmissionTally,
    evidence_refresh: EvidenceRefresh,
    gathered_evidence: GatheredEvidence,
    journal_access: JournalAccess,
    unresolved_detections: usize,
    quarantine_entry_count: QuarantineEntryCount,
    area_summaries: AreaSummaries,
    _unit_watch: RunningStream,
}

#[derive(Debug)]
pub enum PageNavigationInput {
    PageShown(ApplicationPage),
    NarrowContentToggled(bool),
    QuickScanRequested,
    SignatureUpdateRequested,
    ScanTargetsReceived(Vec<PathBuf>),
    ScanPathsForwarded(Vec<PathBuf>),
    DetectionsListRequested,
    DetectionRequestedForFile(PathBuf),
    QuarantineEntriesChanged,
    ActivityRecorded,
    SignaturesUpdated,
    JournalAccessChanged(JournalAccess),
    UnresolvedDetectionsChanged(usize),
    QuarantineEntriesCounted(QuarantineEntryCount),
    EvidenceRefreshRequested,
    ManualScanActivityChanged(PageScanActivity),
    DeviceScanSlotRequested { drive_name: String },
    DeviceScanEnded,
    RemovableDrivesStatusChanged(RemovableDrivesStatus),
    SubmissionsChanged,
    SubmissionsTallied(SubmissionTally),
    ClamavReportConfirmed(ClamavReportRequest),
    UploadNoticeReceived(String),
    EntrySubmissionRequested { entry_id: i64 },
    QuarantinedFileSubmissionRequested(PathBuf),
    ScanFilesRequested,
    HistoryExportRequested,
    HistoryExportFormatChosen(HistoryExportFormat),
    HistoryClearRequested,
    HistoryClearConfirmed,
}

#[derive(Debug)]
pub enum PageNavigationCommand {
    EvidenceGathered {
        protection_evidence: Box<ProtectionEvidence>,
        gathered_at: Timestamp,
    },
    WatchedUnitChanged,
    HistoryLoadedForExport {
        export_format: HistoryExportFormat,
        load_outcome: Result<Vec<ActivityEntryRecord>, ActivityHistoryFailure>,
    },
    HistoryExportFinished(TextExportOutcome),
    HistoryCleared(Result<(), ActivityHistoryFailure>),
}

#[derive(Debug)]
pub enum PageNavigationOutput {
    WindowPresentRequested,
    UnresolvedDetectionsChanged(usize),
}

fn page_root(
    application_page: ApplicationPage,
    page_widget: &impl IsA<gtk::Widget>,
) -> adw::NavigationPage {
    adw::NavigationPage::builder()
        .title(application_page.page_title())
        .tag(application_page.page_name())
        .child(page_widget)
        .build()
}

fn narrow_layout_breakpoint(split_view: &adw::NavigationSplitView) -> adw::Breakpoint {
    let narrow_breakpoint = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
        adw::BreakpointConditionLengthType::MaxWidth,
        640.0,
        adw::LengthUnit::Sp,
    ));
    narrow_breakpoint.add_setter(split_view, "collapsed", Some(&true.to_value()));
    narrow_breakpoint
}

fn forwarded_scan_output(scan_output: ScanPageOutput) -> PageNavigationInput {
    match scan_output {
        ScanPageOutput::ScanActivityChanged(scan_activity) => {
            PageNavigationInput::ManualScanActivityChanged(scan_activity)
        }
        ScanPageOutput::QuarantineEntriesChanged => PageNavigationInput::QuarantineEntriesChanged,
        ScanPageOutput::ActivityRecorded => PageNavigationInput::ActivityRecorded,
        ScanPageOutput::ClamavReportConfirmed(report_request) => {
            PageNavigationInput::ClamavReportConfirmed(report_request)
        }
    }
}

fn forwarded_removable_drives_output(
    removable_drives_output: RemovableDrivesPageOutput,
) -> PageNavigationInput {
    match removable_drives_output {
        RemovableDrivesPageOutput::ScanSlotRequested { drive_name } => {
            PageNavigationInput::DeviceScanSlotRequested { drive_name }
        }
        RemovableDrivesPageOutput::DeviceScanEnded => PageNavigationInput::DeviceScanEnded,
        RemovableDrivesPageOutput::StatusChanged(removable_drives_status) => {
            PageNavigationInput::RemovableDrivesStatusChanged(removable_drives_status)
        }
        RemovableDrivesPageOutput::QuarantineEntriesChanged => {
            PageNavigationInput::QuarantineEntriesChanged
        }
        RemovableDrivesPageOutput::ActivityRecorded => PageNavigationInput::ActivityRecorded,
        RemovableDrivesPageOutput::ClamavReportConfirmed(report_request) => {
            PageNavigationInput::ClamavReportConfirmed(report_request)
        }
    }
}

fn device_scan_started_toast(drive_name: &str) -> adw::Toast {
    let started_toast = adw::Toast::builder()
        .title(gettext("Scanning {drive}").replace("{drive}", drive_name))
        .use_markup(false)
        .build();
    started_toast.set_button_label(Some(&gettext("Open Removable Drives")));
    started_toast.set_action_name(Some("win.show-page"));
    started_toast.set_action_target_value(Some(
        &ApplicationPage::RemovableDrives.page_name().to_variant(),
    ));
    started_toast
}

fn forwarded_detections_output(
    detections_output: BackgroundDetectionsPageOutput,
) -> PageNavigationInput {
    match detections_output {
        BackgroundDetectionsPageOutput::UnresolvedCountChanged(unresolved_detections) => {
            PageNavigationInput::UnresolvedDetectionsChanged(unresolved_detections)
        }
        BackgroundDetectionsPageOutput::QuarantineReloadNeeded => {
            PageNavigationInput::QuarantineEntriesChanged
        }
        BackgroundDetectionsPageOutput::JournalAccessChanged(journal_access) => {
            PageNavigationInput::JournalAccessChanged(journal_access)
        }
        BackgroundDetectionsPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
        BackgroundDetectionsPageOutput::SubmissionRequestedForFile(original_path) => {
            PageNavigationInput::QuarantinedFileSubmissionRequested(original_path)
        }
    }
}

const fn forwarded_database_updates_output(
    database_updates_output: DatabaseUpdatesPageOutput,
) -> PageNavigationInput {
    match database_updates_output {
        DatabaseUpdatesPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
        DatabaseUpdatesPageOutput::SignaturesUpdated => PageNavigationInput::SignaturesUpdated,
        DatabaseUpdatesPageOutput::ActivityRecorded => PageNavigationInput::ActivityRecorded,
    }
}

fn forwarded_submissions_output(submissions_output: SubmissionsPageOutput) -> PageNavigationInput {
    match submissions_output {
        SubmissionsPageOutput::TallyChanged(submission_tally) => {
            PageNavigationInput::SubmissionsTallied(submission_tally)
        }
        SubmissionsPageOutput::UploadNoticeReady(notice_text) => {
            PageNavigationInput::UploadNoticeReceived(notice_text)
        }
        SubmissionsPageOutput::StoredKeyChanged => PageNavigationInput::EvidenceRefreshRequested,
    }
}

const fn forwarded_trusted_detections_output(
    trusted_detections_output: TrustedDetectionsPageOutput,
) -> PageNavigationInput {
    match trusted_detections_output {
        TrustedDetectionsPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
    }
}

const fn forwarded_online_lookups_output(
    online_lookups_output: OnlineLookupsPageOutput,
) -> PageNavigationInput {
    match online_lookups_output {
        OnlineLookupsPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
    }
}

const fn forwarded_signature_sources_output(
    signature_sources_output: SignatureSourcesPageOutput,
) -> PageNavigationInput {
    match signature_sources_output {
        SignatureSourcesPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
    }
}

const fn forwarded_scan_engine_output(
    scan_engine_output: ScanEnginePageOutput,
) -> PageNavigationInput {
    match scan_engine_output {
        ScanEnginePageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
    }
}

const fn forwarded_on_access_output(on_access_output: OnAccessPageOutput) -> PageNavigationInput {
    match on_access_output {
        OnAccessPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
    }
}

const fn forwarded_scheduled_scans_output(
    scheduled_scans_output: ScheduledScansPageOutput,
) -> PageNavigationInput {
    match scheduled_scans_output {
        ScheduledScansPageOutput::EvidenceRefreshRequested => {
            PageNavigationInput::EvidenceRefreshRequested
        }
    }
}

fn register_page_actions(
    window_root: &adw::ApplicationWindow,
    sender: &ComponentSender<PageNavigation>,
) {
    let page_sender = sender.clone();
    register_window_action(
        window_root,
        RelmAction::<ShowPageAction>::new_with_target_value(move |_action, page_name: String| {
            if let Some(application_page) = ApplicationPage::from_page_name(&page_name) {
                page_sender.input(PageNavigationInput::PageShown(application_page));
            }
        }),
    );
    let export_sender = sender.clone();
    register_window_action(
        window_root,
        RelmAction::<ExportHistoryAction>::new_stateless(move |_action| {
            export_sender.input(PageNavigationInput::HistoryExportRequested);
        }),
    );
    let clear_sender = sender.clone();
    register_window_action(
        window_root,
        RelmAction::<ClearHistoryAction>::new_stateless(move |_action| {
            clear_sender.input(PageNavigationInput::HistoryClearRequested);
        }),
    );
    let scan_files_sender = sender.clone();
    register_window_action(
        window_root,
        RelmAction::<ScanFilesAction>::new_stateless(move |_action| {
            scan_files_sender.input(PageNavigationInput::ScanFilesRequested);
        }),
    );
    let quick_scan_sender = sender.clone();
    register_application_action(RelmAction::<QuickScanAction>::new_stateless(
        move |_action| {
            quick_scan_sender.input(PageNavigationInput::QuickScanRequested);
        },
    ));
    let update_sender = sender.clone();
    register_application_action(RelmAction::<UpdateDefinitionsAction>::new_stateless(
        move |_action| update_sender.input(PageNavigationInput::SignatureUpdateRequested),
    ));
    let scan_paths_sender = sender.clone();
    register_application_action(RelmAction::<ScanPathsAction>::new_with_target_value(
        move |_action, forwarded_paths: Vec<Vec<u8>>| {
            scan_paths_sender.input(PageNavigationInput::ScanPathsForwarded(paths_from_bytes(
                forwarded_paths,
            )));
        },
    ));
    let detections_sender = sender.clone();
    register_application_action(RelmAction::<OpenDetectionsAction>::new_stateless(
        move |_action| detections_sender.input(PageNavigationInput::DetectionsListRequested),
    ));
    let detection_sender = sender.clone();
    register_application_action(RelmAction::<OpenDetectionAction>::new_with_target_value(
        move |_action, path_bytes: Vec<u8>| {
            if let Some(detected_path) = paths_from_bytes(vec![path_bytes]).pop() {
                detection_sender.input(PageNavigationInput::DetectionRequestedForFile(
                    detected_path,
                ));
            }
        },
    ));
    ALL_APPLICATION_PAGES
        .into_iter()
        .for_each(|application_page| {
            relm4::main_application().set_accels_for_action(
                &format!("win.show-page::{}", application_page.page_name()),
                application_page.keyboard_accelerators(),
            );
        });
}

impl PageNavigation {
    fn refresh_area_summaries(&mut self) {
        let GatheredEvidence::Gathered {
            protection_evidence,
            gathered_at,
        } = &self.gathered_evidence
        else {
            return;
        };
        self.area_summaries = AreaSummaries::SummariesComputed(all_area_summaries(
            protection_evidence,
            &AreaSummaryContext {
                alert_readiness: AlertReadiness {
                    journal_access: self.journal_access.clone(),
                    notifications_enabled: detection_notifications_are_enabled(),
                },
                unresolved_detections: self.unresolved_detections,
                quarantine_entry_count: self.quarantine_entry_count,
                removable_drives_status: self.removable_drives_status.clone(),
                submission_tally: self.submission_tally,
                home_directory: glib::home_dir().to_string_lossy().into_owned(),
                moment_formatters: host_moment_formatters(),
                reference_moment: *gathered_at,
            },
        ));
        self.sidebar_column
            .emit(SidebarNavigationColumnInput::AreaSummariesChanged(
                self.computed_area_summaries().to_vec(),
            ));
    }

    fn select_visible_page(&mut self, application_page: ApplicationPage) {
        self.visible_page = application_page;
        self.sidebar_column
            .emit(SidebarNavigationColumnInput::SelectedPageChanged(
                application_page,
            ));
    }

    fn apply_start_page_choice(&mut self) {
        let StartPageTransition {
            shown_page,
            next_state,
        } = start_page_after_evidence(
            self.start_page_state,
            self.visible_page,
            self.computed_area_summaries(),
        );
        self.select_visible_page(shown_page);
        self.start_page_state = next_state;
    }

    fn computed_area_summaries(&self) -> &[SidebarAreaSummary] {
        match &self.area_summaries {
            AreaSummaries::SummariesPending => &[],
            AreaSummaries::SummariesComputed(area_summaries) => area_summaries,
        }
    }

    fn advance_evidence_refresh(
        &mut self,
        refresh_trigger: EvidenceRefreshTrigger,
        sender: &ComponentSender<Self>,
    ) {
        let EvidenceRefreshTransition {
            next_refresh,
            gathering_start,
        } = self.evidence_refresh.after_trigger(refresh_trigger);
        self.evidence_refresh = next_refresh;
        self.signature_sources_page
            .emit(SignatureSourcesPageInput::EvidenceRefreshChanged(
                next_refresh,
            ));
        self.database_updates_page
            .emit(DatabaseUpdatesPageInput::EvidenceRefreshChanged(
                next_refresh,
            ));
        self.scan_engine_page
            .emit(ScanEnginePageInput::EvidenceRefreshChanged(next_refresh));
        self.on_access_page
            .emit(OnAccessPageInput::EvidenceRefreshChanged(next_refresh));
        self.scheduled_scans_page
            .emit(ScheduledScansPageInput::EvidenceRefreshChanged(
                next_refresh,
            ));
        self.detections_page
            .emit(BackgroundDetectionsPageInput::EvidenceRefreshChanged(
                next_refresh,
            ));
        self.trusted_detections_page
            .emit(TrustedDetectionsPageInput::EvidenceRefreshChanged(
                next_refresh,
            ));
        self.online_lookups_page
            .emit(OnlineLookupsPageInput::EvidenceRefreshChanged(next_refresh));
        match gathering_start {
            GatheringStart::StartGathering => {
                let lazaret_schedule_enabled = lazaret_schedule_is_enabled();
                sender.oneshot_command(async move {
                    let protection_evidence =
                        Box::new(gather_protection_evidence(lazaret_schedule_enabled).await);
                    PageNavigationCommand::EvidenceGathered {
                        protection_evidence,
                        gathered_at: Timestamp::now(),
                    }
                });
            }
            GatheringStart::KeepWaiting => {}
        }
    }

    fn show_plain_toast(&self, toast_text: String) {
        self.toaster.add_toast(
            adw::Toast::builder()
                .title(toast_text)
                .use_markup(false)
                .build(),
        );
    }

    fn reload_every_history(&self) {
        self.scan_page.emit(ScanPageInput::HistoryReloadRequested);
        self.database_updates_page
            .emit(DatabaseUpdatesPageInput::HistoryReloadRequested);
        self.scheduled_scans_page
            .emit(ScheduledScansPageInput::HistoryReloadRequested);
        self.removable_drives_page
            .emit(RemovableDrivesPageInput::HistoryReloadRequested);
    }

    fn show_page(&mut self, application_page: ApplicationPage) {
        self.select_visible_page(application_page);
        self.start_page_state = StartPageState::UserNavigated;
        self.shows_content_when_narrow = true;
    }

    fn apply_scan_slot_event(&mut self, slot_event: ScanSlotEvent) -> ScanSlotReply {
        let previous_activity = self.scan_slot.device_scan_activity();
        let ScanSlotTransition {
            next_slot,
            slot_reply,
        } = self.scan_slot.after_event(slot_event);
        self.scan_slot = next_slot;
        match slot_reply {
            ScanSlotReply::DeviceScanGranted => self
                .removable_drives_page
                .emit(RemovableDrivesPageInput::ScanSlotGranted),
            ScanSlotReply::DeviceScanRefused => self
                .removable_drives_page
                .emit(RemovableDrivesPageInput::ScanSlotRefused),
            ScanSlotReply::DeviceScanRevoked => self
                .removable_drives_page
                .emit(RemovableDrivesPageInput::ScanSlotRevoked),
            ScanSlotReply::NoReplyNeeded => {}
        }
        let next_activity = next_slot.device_scan_activity();
        if next_activity != previous_activity {
            self.scan_page
                .emit(ScanPageInput::DeviceScanActivityChanged(next_activity));
        }
        slot_reply
    }
}

#[relm4::component(pub)]
impl Component for PageNavigation {
    type Init = PageNavigationInit;
    type Input = PageNavigationInput;
    type Output = PageNavigationOutput;
    type CommandOutput = PageNavigationCommand;

    view! {
        adw::BreakpointBin {
            set_width_request: 360,
            set_height_request: 500,
            add_breakpoint: narrow_layout_breakpoint(&split_view),

            #[wrap(Some)]
            #[local_ref]
            set_child = page_toast_overlay -> adw::ToastOverlay {
                #[name = "split_view"]
                adw::NavigationSplitView {
                    set_sidebar_width_fraction: 0.22,
                    #[watch]
                    #[block_signal(narrow_content_handler)]
                    set_show_content: model.shows_content_when_narrow,
                    connect_show_content_notify[sender] => move |split_view| {
                        sender.input(PageNavigationInput::NarrowContentToggled(split_view.shows_content()));
                    } @narrow_content_handler,

                    set_sidebar: Some(model.sidebar_column.widget()),

                    #[wrap(Some)]
                    set_content = &adw::NavigationPage {
                        #[watch]
                        set_title: &model.visible_page.page_title(),

                        #[name = "page_stack"]
                        gtk::Stack {

                            add_titled[Some(ApplicationPage::Detections.page_name()), &ApplicationPage::Detections.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Detections, model.detections_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::ManualScan.page_name()), &ApplicationPage::ManualScan.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::ManualScan, model.scan_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::RemovableDrives.page_name()), &ApplicationPage::RemovableDrives.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::RemovableDrives, model.removable_drives_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Quarantine.page_name()), &ApplicationPage::Quarantine.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Quarantine, model.quarantine_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::TrustedDetections.page_name()), &ApplicationPage::TrustedDetections.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::TrustedDetections, model.trusted_detections_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::OnlineLookups.page_name()), &ApplicationPage::OnlineLookups.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::OnlineLookups, model.online_lookups_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Submissions.page_name()), &ApplicationPage::Submissions.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Submissions, model.submissions_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::SignatureSources.page_name()), &ApplicationPage::SignatureSources.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::SignatureSources, model.signature_sources_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::DatabaseUpdates.page_name()), &ApplicationPage::DatabaseUpdates.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::DatabaseUpdates, model.database_updates_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::ScanEngine.page_name()), &ApplicationPage::ScanEngine.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::ScanEngine, model.scan_engine_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::OnAccessScanning.page_name()), &ApplicationPage::OnAccessScanning.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::OnAccessScanning, model.on_access_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::ScheduledScans.page_name()), &ApplicationPage::ScheduledScans.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::ScheduledScans, model.scheduled_scans_page.widget()),
                            },

                            #[watch]
                            #[block_signal(visible_page_handler)]
                            set_visible_child_name: model.visible_page.page_name(),
                            connect_visible_child_name_notify[sender] => move |changed_stack| {
                                if let Some(application_page) = changed_stack
                                    .visible_child_name()
                                    .and_then(|page_name| ApplicationPage::from_page_name(&page_name))
                                {
                                    sender.input(PageNavigationInput::PageShown(application_page));
                                }
                            } @visible_page_handler,
                        },
                    },
                },
            },
        }
    }

    fn init(
        navigation_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let quarantine_vault = navigation_init.quarantine_vault;
        let data_directory = navigation_init.data_directory;
        let activity_history =
            ActivityHistory::at_database_path(lazaret_database_path(&data_directory));
        let quarantine_page = QuarantineEntriesPage::builder()
            .launch(QuarantineEntriesPageInit {
                quarantine_vault: quarantine_vault.clone(),
                activity_history: activity_history.clone(),
            })
            .forward(
                sender.input_sender(),
                |quarantine_output| match quarantine_output {
                    QuarantineEntriesPageOutput::EntriesCounted(quarantine_entry_count) => {
                        PageNavigationInput::QuarantineEntriesCounted(quarantine_entry_count)
                    }
                    QuarantineEntriesPageOutput::SubmissionsChanged => {
                        PageNavigationInput::SubmissionsChanged
                    }
                    QuarantineEntriesPageOutput::ClamavReportConfirmed(report_request) => {
                        PageNavigationInput::ClamavReportConfirmed(report_request)
                    }
                    QuarantineEntriesPageOutput::SubmissionRequested { entry_id } => {
                        PageNavigationInput::EntrySubmissionRequested { entry_id }
                    }
                },
            );
        let scan_page = ScanPage::builder()
            .launch(ScanPageInit {
                quarantine_vault: quarantine_vault.clone(),
                activity_history: activity_history.clone(),
                profile_store: ScanProfileStore::at_path(
                    application_config_directory().join("profiles.json"),
                    glib::user_special_dir(glib::UserDirectory::Downloads)
                        .unwrap_or_else(|| glib::home_dir().join("Downloads"))
                        .to_string_lossy()
                        .into_owned(),
                ),
                file_list_directory: data_directory.clone(),
            })
            .forward(sender.input_sender(), forwarded_scan_output);
        let removable_drives_page = RemovableDrivesPage::builder()
            .launch(RemovableDrivesPageInit {
                quarantine_vault: quarantine_vault.clone(),
                activity_history: activity_history.clone(),
                file_list_directory: data_directory,
            })
            .forward(sender.input_sender(), forwarded_removable_drives_output);
        let database_updates_page = DatabaseUpdatesPage::builder()
            .launch(activity_history.clone())
            .forward(sender.input_sender(), forwarded_database_updates_output);
        let scan_engine_page = ScanEnginePage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_scan_engine_output);
        let on_access_page = OnAccessPage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_on_access_output);
        let scheduled_scans_page = ScheduledScansPage::builder()
            .launch(activity_history.clone())
            .forward(sender.input_sender(), forwarded_scheduled_scans_output);
        let submissions_page = SubmissionsPage::builder()
            .launch(SubmissionsPageInit {
                activity_history: activity_history.clone(),
                quarantine_vault: quarantine_vault.clone(),
            })
            .forward(sender.input_sender(), forwarded_submissions_output);
        let detections_page = BackgroundDetectionsPage::builder()
            .launch(BackgroundDetectionsPageInit {
                activity_history: activity_history.clone(),
                quarantine_vault,
            })
            .forward(sender.input_sender(), forwarded_detections_output);
        let trusted_detections_page = TrustedDetectionsPage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_trusted_detections_output);
        let online_lookups_page = OnlineLookupsPage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_online_lookups_output);
        let signature_sources_page = SignatureSourcesPage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_signature_sources_output);
        let StartPageTransition {
            shown_page: initial_page,
            next_state: initial_start_state,
        } = initial_start_page(navigation_init.startup_page);
        let mut model = Self {
            visible_page: initial_page,
            sidebar_column: SidebarNavigationColumn::builder()
                .launch(initial_page)
                .detach(),
            start_page_state: initial_start_state,
            shows_content_when_narrow: false,
            scan_page,
            removable_drives_page,
            scan_slot: ScanSlot::SlotFree,
            removable_drives_status: RemovableDrivesStatus {
                auto_scan_settings: DeviceAutoScanSettings::read_from(&application_settings()),
                device_scan_status: DeviceScanStatus::NoDeviceScanYet,
            },
            toaster: Toaster::default(),
            quarantine_page,
            activity_history,
            signature_sources_page,
            database_updates_page,
            scan_engine_page,
            on_access_page,
            scheduled_scans_page,
            detections_page,
            trusted_detections_page,
            online_lookups_page,
            submissions_page,
            submission_tally: SubmissionTally::TallyLoading,
            evidence_refresh: EvidenceRefresh::NothingRunning,
            gathered_evidence: GatheredEvidence::NotGatheredYet,
            journal_access: JournalAccess::FollowingJournal,
            unresolved_detections: 0,
            quarantine_entry_count: QuarantineEntryCount::CountLoading,
            area_summaries: AreaSummaries::SummariesPending,
            _unit_watch: run_stream(
                &sender,
                watched_unit_changes(&WATCHED_SERVICE_UNITS)
                    .map(|()| PageNavigationCommand::WatchedUnitChanged),
            ),
        };
        model.advance_evidence_refresh(EvidenceRefreshTrigger::RefreshRequested, &sender);
        let page_toast_overlay = model.toaster.overlay_widget();
        let widgets = view_output!();
        register_page_actions(&navigation_init.window_root, &sender);
        if !navigation_init.startup_scan_targets.is_empty() {
            sender.input(PageNavigationInput::ScanTargetsReceived(
                navigation_init.startup_scan_targets,
            ));
        }
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        navigation_input: PageNavigationInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match navigation_input {
            PageNavigationInput::PageShown(application_page) => self.show_page(application_page),
            PageNavigationInput::NarrowContentToggled(shows_content) => {
                self.shows_content_when_narrow = shows_content;
            }
            PageNavigationInput::QuickScanRequested => {
                self.show_page(ApplicationPage::ManualScan);
                self.scan_page.emit(ScanPageInput::QuickScanRequested);
            }
            PageNavigationInput::SignatureUpdateRequested => {
                self.show_page(ApplicationPage::DatabaseUpdates);
                self.database_updates_page
                    .emit(DatabaseUpdatesPageInput::SignatureUpdateRequested);
            }
            PageNavigationInput::ScanTargetsReceived(scan_targets) => {
                self.show_page(ApplicationPage::ManualScan);
                self.scan_page
                    .emit(ScanPageInput::ScanTargetsChosen(scan_targets));
            }
            PageNavigationInput::ScanPathsForwarded(scan_targets) => {
                let _window_closed = sender.output(PageNavigationOutput::WindowPresentRequested);
                sender.input(PageNavigationInput::ScanTargetsReceived(scan_targets));
            }
            PageNavigationInput::DetectionsListRequested => {
                self.detections_page
                    .emit(BackgroundDetectionsPageInput::BackToListRequested);
                self.show_page(ApplicationPage::Detections);
                let _window_closed = sender.output(PageNavigationOutput::WindowPresentRequested);
            }
            PageNavigationInput::DetectionRequestedForFile(detected_path) => {
                self.show_page(ApplicationPage::Detections);
                let _window_closed = sender.output(PageNavigationOutput::WindowPresentRequested);
                self.detections_page
                    .emit(BackgroundDetectionsPageInput::IncidentRequestedForFile(
                        detected_path,
                    ));
            }
            PageNavigationInput::QuarantineEntriesChanged => {
                self.quarantine_page
                    .emit(QuarantineEntriesPageInput::ReloadEntriesRequested);
                self.submissions_page
                    .emit(SubmissionsPageInput::QuarantineEntriesChanged);
            }
            PageNavigationInput::SignaturesUpdated => {
                self.quarantine_page
                    .emit(QuarantineEntriesPageInput::RecheckAllRequested);
            }
            PageNavigationInput::ActivityRecorded => {
                self.scheduled_scans_page
                    .emit(ScheduledScansPageInput::HistoryReloadRequested);
                self.removable_drives_page
                    .emit(RemovableDrivesPageInput::HistoryReloadRequested);
            }
            PageNavigationInput::JournalAccessChanged(journal_access) => {
                self.journal_access = journal_access.clone();
                self.refresh_area_summaries();
            }
            PageNavigationInput::QuarantineEntriesCounted(quarantine_entry_count) => {
                self.quarantine_entry_count = quarantine_entry_count;
                self.submissions_page
                    .emit(SubmissionsPageInput::QuarantineEntriesChanged);
                self.refresh_area_summaries();
            }
            PageNavigationInput::UnresolvedDetectionsChanged(unresolved_detections) => {
                self.unresolved_detections = unresolved_detections;
                self.refresh_area_summaries();
                let _window_closed = sender.output(
                    PageNavigationOutput::UnresolvedDetectionsChanged(unresolved_detections),
                );
            }
            PageNavigationInput::EvidenceRefreshRequested => {
                self.advance_evidence_refresh(EvidenceRefreshTrigger::RefreshRequested, &sender);
            }
            PageNavigationInput::ManualScanActivityChanged(scan_activity) => {
                let _slot_reply = self.apply_scan_slot_event(match scan_activity {
                    PageScanActivity::PageScanActive => ScanSlotEvent::ManualScanStarted,
                    PageScanActivity::PageScanIdle => ScanSlotEvent::ManualScanEnded,
                });
            }
            PageNavigationInput::DeviceScanSlotRequested { drive_name } => {
                let slot_reply = self.apply_scan_slot_event(ScanSlotEvent::DeviceScanRequested);
                if slot_reply == ScanSlotReply::DeviceScanGranted
                    && self.visible_page != ApplicationPage::RemovableDrives
                {
                    self.toaster
                        .add_toast(device_scan_started_toast(&drive_name));
                }
            }
            PageNavigationInput::DeviceScanEnded => {
                let _slot_reply = self.apply_scan_slot_event(ScanSlotEvent::DeviceScanEnded);
            }
            PageNavigationInput::RemovableDrivesStatusChanged(removable_drives_status) => {
                self.removable_drives_status = removable_drives_status;
                self.refresh_area_summaries();
            }
            PageNavigationInput::SubmissionsChanged => {
                self.submissions_page
                    .emit(SubmissionsPageInput::SubmissionsChanged);
            }
            PageNavigationInput::SubmissionsTallied(submission_tally) => {
                self.submission_tally = submission_tally;
                self.refresh_area_summaries();
            }
            PageNavigationInput::EntrySubmissionRequested { entry_id } => {
                self.show_page(ApplicationPage::Submissions);
                self.submissions_page
                    .emit(SubmissionsPageInput::EntrySubmissionRequested { entry_id });
            }
            PageNavigationInput::ClamavReportConfirmed(report_request) => {
                self.submissions_page
                    .emit(SubmissionsPageInput::ClamavReportConfirmed(report_request));
            }
            PageNavigationInput::UploadNoticeReceived(notice_text) => {
                self.show_plain_toast(notice_text);
            }
            PageNavigationInput::ScanFilesRequested => {
                self.show_page(ApplicationPage::ManualScan);
                self.scan_page.emit(ScanPageInput::ChooseFilesRequested);
            }
            PageNavigationInput::HistoryExportRequested => {
                deliver_local_outcome(
                    sender.input_sender().clone(),
                    alert_choice(history_export_dialog(), root.clone().upcast()),
                    |export_choice| match export_choice {
                        HistoryExportChoice::FormatChosen(export_format) => Some(
                            PageNavigationInput::HistoryExportFormatChosen(export_format),
                        ),
                        HistoryExportChoice::ExportDismissed => None,
                    },
                );
            }
            PageNavigationInput::HistoryExportFormatChosen(export_format) => {
                let activity_history = self.activity_history.clone();
                sender.oneshot_command(async move {
                    PageNavigationCommand::HistoryLoadedForExport {
                        export_format,
                        load_outcome: activity_history.list_recent_entries().await,
                    }
                });
            }
            PageNavigationInput::HistoryClearRequested => {
                deliver_local_outcome(
                    sender.input_sender().clone(),
                    alert_choice(clear_history_dialog(), root.clone().upcast()),
                    |clear_choice| match clear_choice {
                        ClearHistoryChoice::ClearAllChosen => {
                            Some(PageNavigationInput::HistoryClearConfirmed)
                        }
                        ClearHistoryChoice::ClearCancelled => None,
                    },
                );
            }
            PageNavigationInput::HistoryClearConfirmed => {
                let activity_history = self.activity_history.clone();
                sender.oneshot_command(async move {
                    PageNavigationCommand::HistoryCleared(
                        activity_history.clear_all_entries().await,
                    )
                });
            }
            PageNavigationInput::QuarantinedFileSubmissionRequested(original_path) => {
                self.show_page(ApplicationPage::Submissions);
                self.submissions_page.emit(
                    SubmissionsPageInput::QuarantinedFileSubmissionRequested { original_path },
                );
            }
        }
    }

    fn update_cmd(
        &mut self,
        navigation_command: PageNavigationCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match navigation_command {
            PageNavigationCommand::EvidenceGathered {
                protection_evidence,
                gathered_at,
            } => {
                self.gathered_evidence = GatheredEvidence::Gathered {
                    protection_evidence,
                    gathered_at,
                };
                self.refresh_area_summaries();
                self.apply_start_page_choice();
                self.signature_sources_page
                    .emit(SignatureSourcesPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.database_updates_page
                    .emit(DatabaseUpdatesPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.scan_engine_page
                    .emit(ScanEnginePageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.on_access_page
                    .emit(OnAccessPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.scheduled_scans_page
                    .emit(ScheduledScansPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.detections_page
                    .emit(BackgroundDetectionsPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.trusted_detections_page
                    .emit(TrustedDetectionsPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.online_lookups_page
                    .emit(OnlineLookupsPageInput::EvidenceGathered(
                        self.gathered_evidence.clone(),
                    ));
                self.advance_evidence_refresh(EvidenceRefreshTrigger::GatheringFinished, &sender);
            }
            PageNavigationCommand::WatchedUnitChanged => {
                self.advance_evidence_refresh(EvidenceRefreshTrigger::WatchedUnitChanged, &sender);
            }
            PageNavigationCommand::HistoryLoadedForExport {
                export_format,
                load_outcome,
            } => match load_outcome
                .map_err(|load_failure| describe_history_failure(&load_failure))
                .and_then(|activity_entries| {
                    exported_history_file(export_format, &activity_entries)
                        .map_err(|json_failure| json_failure.to_string())
                }) {
                Ok(history_file) => deliver_local_outcome(
                    sender.command_sender().clone(),
                    exported_text(
                        history_file.suggested_name.to_owned(),
                        history_file.exported_text,
                    ),
                    |export_outcome| {
                        Some(PageNavigationCommand::HistoryExportFinished(export_outcome))
                    },
                ),
                Err(failure_text) => self.show_plain_toast(
                    gettext("Could not export the history: {error}")
                        .replace("{error}", &failure_text),
                ),
            },
            PageNavigationCommand::HistoryExportFinished(TextExportOutcome::TextSaved) => {
                self.show_plain_toast(gettext("History exported"));
            }
            PageNavigationCommand::HistoryExportFinished(TextExportOutcome::ExportCancelled) => {}
            PageNavigationCommand::HistoryExportFinished(TextExportOutcome::ExportFailed(
                export_failure,
            )) => self.show_plain_toast(describe_export_failure(&export_failure)),
            PageNavigationCommand::HistoryCleared(Ok(())) => {
                self.show_plain_toast(gettext("History cleared"));
                self.reload_every_history();
            }
            PageNavigationCommand::HistoryCleared(Err(clear_failure)) => {
                self.show_plain_toast(
                    gettext("Could not clear the history: {error}")
                        .replace("{error}", &describe_history_failure(&clear_failure)),
                );
            }
        }
    }
}

#[cfg(test)]
mod page_navigation_tests {
    use super::*;
    use crate::host_services::clamav_programs::clamav_report_submission::{
        ClamavReport, ClamavReportKind, ReporterContact, SubmittedContent,
    };

    fn false_positive_request() -> ClamavReportRequest {
        ClamavReportRequest {
            clamav_report: ClamavReport {
                reporter_contact: ReporterContact {
                    reporter_name: "Alex Doe".to_owned(),
                    reporter_email: "alex@example.org".to_owned(),
                },
                report_kind: ClamavReportKind::FalsePositive {
                    detection_name: "Win.Trojan.Agent".to_owned(),
                },
            },
            submitted_content: SubmittedContent::QuarantinedEntry { entry_id: 7 },
        }
    }

    #[test]
    fn scan_result_reports_go_to_the_submissions_page_that_guards_uploads() {
        assert!(matches!(
            forwarded_scan_output(ScanPageOutput::ClamavReportConfirmed(false_positive_request())),
            PageNavigationInput::ClamavReportConfirmed(report_request)
                if report_request == false_positive_request()
        ));
        assert!(matches!(
            forwarded_removable_drives_output(RemovableDrivesPageOutput::ClamavReportConfirmed(
                false_positive_request()
            )),
            PageNavigationInput::ClamavReportConfirmed(report_request)
                if report_request == false_positive_request()
        ));
    }

    #[test]
    fn upload_notices_reach_the_window_toasts() {
        assert!(matches!(
            forwarded_submissions_output(SubmissionsPageOutput::UploadNoticeReady(
                "Already being sent".to_owned()
            )),
            PageNavigationInput::UploadNoticeReceived(notice_text)
                if notice_text == "Already being sent"
        ));
    }
}
