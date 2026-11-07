use std::path::PathBuf;

use futures::StreamExt;
use gettextrs::gettext;
use jiff::Timestamp;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
    abstractions::Toaster,
    actions::RelmAction,
    adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, glib},
};

use crate::{
    APPLICATION_DATA_NAME,
    application_window::{
        application_actions::{
            OpenDetectionAction, OpenDetectionsAction, QuickScanAction, ScanPathsAction,
            ShowPageAction, UpdateDefinitionsAction, register_application_action,
            register_window_action,
        },
        application_pages::{ALL_APPLICATION_PAGES, ApplicationPage},
        protection_evidence_refresh::{
            EvidenceRefresh, EvidenceRefreshTransition, EvidenceRefreshTrigger, GatheredEvidence,
            GatheringStart,
        },
        scan_slot_arbiter::{ScanSlot, ScanSlotEvent, ScanSlotReply, ScanSlotTransition},
        sidebar_area_status::{
            AreaSummaryContext, SidebarAreaSummary, StatusIndicator, all_area_summaries,
            attention_summary_text, worst_area_status,
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
        activity_history::activity_history_database::ActivityHistory,
        clamav_programs::clamav_report_submission::ClamavReportRequest,
        desktop::{
            locale_formatting::host_moment_formatters,
            running_instance_forwarding::paths_from_bytes, stored_settings::application_settings,
        },
        detection_journal::detection_journal_follower::JournalAccess,
        protection_evidence::host_protection_evidence::{
            ProtectionEvidence, WATCHED_SERVICE_UNITS, detection_notifications_are_enabled,
            gather_protection_evidence, lazaret_schedule_is_enabled,
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
        systemd_bus::host_systemd_units::watched_unit_changes,
    },
    logs_page::activity_logs_page::{ActivityLogsPage, ActivityLogsPageInput},
    protection_page::protection_timeline_page::{
        ProtectionTimelinePage, ProtectionTimelinePageInput, ProtectionTimelinePageOutput,
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
        audit_sections::{
            audit_check_results::{HARDENING_AUDIT_CATEGORIES, SIGNATURE_AUDIT_CATEGORIES},
            audit_sections_page::{AuditSectionsPage, AuditSectionsPageInit},
        },
        component_streams::{RunningStream, run_stream},
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
    signatures::database_updates_page::{
        database_updates_component::{DatabaseUpdatesPage, DatabaseUpdatesPageInput},
        database_updates_state::DatabaseUpdatesPageOutput,
    },
};

pub struct PageNavigationInit {
    pub quarantine_vault: QuarantineVault,
    pub data_directory: PathBuf,
    pub window_root: adw::ApplicationWindow,
    pub startup_page: ApplicationPage,
    pub startup_scan_targets: Vec<PathBuf>,
}

enum AreaSummaries {
    SummariesPending,
    SummariesComputed(Vec<SidebarAreaSummary>),
}

pub struct PageNavigation {
    visible_page: ApplicationPage,
    shows_content_when_narrow: bool,
    scan_page: Controller<ScanPage>,
    removable_drives_page: Controller<RemovableDrivesPage>,
    scan_slot: ScanSlot,
    removable_drives_status: RemovableDrivesStatus,
    toaster: Toaster,
    quarantine_page: Controller<QuarantineEntriesPage>,
    logs_page: Controller<ActivityLogsPage>,
    signatures_page: Controller<AuditSectionsPage>,
    hardening_page: Controller<AuditSectionsPage>,
    protection_page: Controller<ProtectionTimelinePage>,
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
}

#[derive(Debug)]
pub enum PageNavigationCommand {
    EvidenceGathered {
        protection_evidence: Box<ProtectionEvidence>,
        gathered_at: Timestamp,
    },
    WatchedUnitChanged,
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

fn navigation_row(application_page: ApplicationPage) -> gtk::ListBoxRow {
    let row_content = gtk::Box::builder().spacing(12).build();
    row_content.append(&gtk::Image::from_icon_name(application_page.page_icon()));
    row_content.append(&gtk::Label::new(Some(&application_page.page_title())));
    let navigation_row = gtk::ListBoxRow::builder().child(&row_content).build();
    navigation_row.set_widget_name(application_page.page_name());
    navigation_row
}

fn primary_menu() -> gio::Menu {
    let primary_menu = gio::Menu::new();
    primary_menu.append(Some(&gettext("Preferences")), Some("app.preferences"));
    primary_menu.append(Some(&gettext("About Lazaret")), Some("app.about"));
    primary_menu.append(Some(&gettext("Quit")), Some("app.quit"));
    primary_menu
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
        ScanPageOutput::EvidenceRefreshRequested => PageNavigationInput::EvidenceRefreshRequested,
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
    }

    fn computed_area_summaries(&self) -> &[SidebarAreaSummary] {
        match &self.area_summaries {
            AreaSummaries::SummariesPending => &[],
            AreaSummaries::SummariesComputed(area_summaries) => area_summaries,
        }
    }

    fn protection_status_indicator(&self) -> StatusIndicator {
        worst_area_status(self.computed_area_summaries()).status_indicator()
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
        self.protection_page
            .emit(ProtectionTimelinePageInput::EvidenceRefreshChanged(
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

    fn show_page(&mut self, application_page: ApplicationPage) {
        self.visible_page = application_page;
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

                    #[wrap(Some)]
                    set_sidebar = &adw::NavigationPage {
                        set_title: "Lazaret",

                        #[wrap(Some)]
                        set_child = &adw::ToolbarView {
                            add_top_bar = &adw::HeaderBar {
                                pack_end = &gtk::MenuButton {
                                    set_icon_name: "open-menu-symbolic",
                                    set_tooltip_text: Some(&gettext("Menu")),
                                    set_menu_model: Some(&primary_menu()),
                                    set_primary: true,
                                },
                            },

                            #[wrap(Some)]
                            set_content = &gtk::ScrolledWindow {
                                set_hscrollbar_policy: gtk::PolicyType::Never,

                                #[name = "sidebar_list"]
                                gtk::ListBox {
                                    set_selection_mode: gtk::SelectionMode::Single,
                                    add_css_class: "navigation-sidebar",
                                    #[watch]
                                    select_row: sidebar_list
                                        .row_at_index(model.visible_page.sidebar_position())
                                        .as_ref(),
                                    connect_row_activated[sender] => move |_sidebar_list, activated_row| {
                                        if let Some(application_page) =
                                            ApplicationPage::from_page_name(&activated_row.widget_name())
                                        {
                                            sender.input(PageNavigationInput::PageShown(application_page));
                                        }
                                    },

                                    append = &gtk::ListBoxRow {
                                        set_widget_name: ApplicationPage::Protection.page_name(),

                                        #[wrap(Some)]
                                        set_child = &gtk::Box {
                                            set_spacing: 12,

                                            gtk::Image {
                                                set_icon_name: Some(ApplicationPage::Protection.page_icon()),
                                            },
                                            gtk::Label {
                                                set_label: &ApplicationPage::Protection.page_title(),
                                            },
                                            gtk::Image {
                                                set_hexpand: true,
                                                set_halign: gtk::Align::End,
                                                #[watch]
                                                set_visible: model.protection_status_indicator().is_shown(),
                                                #[watch]
                                                set_icon_name: Some(model.protection_status_indicator().icon_name()),
                                                #[watch]
                                                set_css_classes: model.protection_status_indicator().css_classes(),
                                                #[watch]
                                                set_tooltip_text: Some(&attention_summary_text(model.computed_area_summaries())),
                                            },
                                        },
                                    },
                                    append: &navigation_row(ApplicationPage::Detections),
                                    append: &navigation_row(ApplicationPage::Scan),
                                    append: &navigation_row(ApplicationPage::RemovableDrives),
                                    append: &navigation_row(ApplicationPage::Logs),
                                    append: &navigation_row(ApplicationPage::Quarantine),
                                    append: &navigation_row(ApplicationPage::TrustedDetections),
                                    append: &navigation_row(ApplicationPage::OnlineLookups),
                                    append: &navigation_row(ApplicationPage::Submissions),
                                    append: &navigation_row(ApplicationPage::Signatures),
                                    append: &navigation_row(ApplicationPage::DatabaseUpdates),
                                    append: &navigation_row(ApplicationPage::ScanEngine),
                                    append: &navigation_row(ApplicationPage::OnAccessScanning),
                                    append: &navigation_row(ApplicationPage::ScheduledScans),
                                    append: &navigation_row(ApplicationPage::Hardening),
                                },
                            },
                        },
                    },

                    #[wrap(Some)]
                    set_content = &adw::NavigationPage {
                        #[watch]
                        set_title: &model.visible_page.page_title(),

                        #[name = "page_stack"]
                        gtk::Stack {

                            add_titled[Some(ApplicationPage::Protection.page_name()), &ApplicationPage::Protection.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Protection, model.protection_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Detections.page_name()), &ApplicationPage::Detections.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Detections, model.detections_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Scan.page_name()), &ApplicationPage::Scan.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Scan, model.scan_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::RemovableDrives.page_name()), &ApplicationPage::RemovableDrives.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::RemovableDrives, model.removable_drives_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Logs.page_name()), &ApplicationPage::Logs.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Logs, model.logs_page.widget()),
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
                            add_titled[Some(ApplicationPage::Signatures.page_name()), &ApplicationPage::Signatures.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Signatures, model.signatures_page.widget()),
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
                            add_titled[Some(ApplicationPage::Hardening.page_name()), &ApplicationPage::Hardening.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Hardening, model.hardening_page.widget()),
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
        let activity_history = ActivityHistory::at_database_path(data_directory.join("history.db"));
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
        let logs_page = ActivityLogsPage::builder()
            .launch(activity_history.clone())
            .detach();
        let scan_page = ScanPage::builder()
            .launch(ScanPageInit {
                quarantine_vault: quarantine_vault.clone(),
                activity_history: activity_history.clone(),
                profile_store: ScanProfileStore::at_path(
                    glib::user_config_dir()
                        .join(APPLICATION_DATA_NAME)
                        .join("profiles.json"),
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
        let protection_page = ProtectionTimelinePage::builder().launch(()).forward(
            sender.input_sender(),
            |protection_output| match protection_output {
                ProtectionTimelinePageOutput::EvidenceRefreshRequested => {
                    PageNavigationInput::EvidenceRefreshRequested
                }
            },
        );
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
                activity_history,
                quarantine_vault,
            })
            .forward(sender.input_sender(), forwarded_detections_output);
        let trusted_detections_page = TrustedDetectionsPage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_trusted_detections_output);
        let online_lookups_page = OnlineLookupsPage::builder()
            .launch(())
            .forward(sender.input_sender(), forwarded_online_lookups_output);
        let signatures_page = AuditSectionsPage::builder()
            .launch(AuditSectionsPageInit {
                page_title: gettext("Signatures"),
                page_description: gettext(
                    "Where ClamAV's malware signatures come from, and which other sources you \
                     could add.",
                ),
                audited_categories: &SIGNATURE_AUDIT_CATEGORIES,
                linked_pages: &[ApplicationPage::DatabaseUpdates],
            })
            .detach();
        let hardening_page = AuditSectionsPage::builder()
            .launch(AuditSectionsPageInit {
                page_title: gettext("Hardening"),
                page_description: gettext(
                    "Protections outside ClamAV that make exploits harder. They are listed for \
                     reference and don't affect the Protection summary.",
                ),
                audited_categories: &HARDENING_AUDIT_CATEGORIES,
                linked_pages: &[],
            })
            .detach();
        let mut model = Self {
            visible_page: navigation_init.startup_page,
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
            logs_page,
            signatures_page,
            hardening_page,
            protection_page,
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
        widgets.sidebar_list.select_row(
            widgets
                .sidebar_list
                .row_at_index(model.visible_page.sidebar_position())
                .as_ref(),
        );
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
        _root: &Self::Root,
    ) {
        match navigation_input {
            PageNavigationInput::PageShown(application_page) => self.show_page(application_page),
            PageNavigationInput::NarrowContentToggled(shows_content) => {
                self.shows_content_when_narrow = shows_content;
            }
            PageNavigationInput::QuickScanRequested => {
                self.show_page(ApplicationPage::Scan);
                self.scan_page.emit(ScanPageInput::QuickScanRequested);
            }
            PageNavigationInput::SignatureUpdateRequested => {
                self.show_page(ApplicationPage::DatabaseUpdates);
                self.database_updates_page
                    .emit(DatabaseUpdatesPageInput::SignatureUpdateRequested);
            }
            PageNavigationInput::ScanTargetsReceived(scan_targets) => {
                self.show_page(ApplicationPage::Scan);
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
                self.logs_page
                    .emit(ActivityLogsPageInput::ReloadEntriesRequested);
                self.scheduled_scans_page
                    .emit(ScheduledScansPageInput::HistoryReloadRequested);
                self.removable_drives_page
                    .emit(RemovableDrivesPageInput::HistoryReloadRequested);
            }
            PageNavigationInput::JournalAccessChanged(journal_access) => {
                self.journal_access = journal_access.clone();
                self.refresh_area_summaries();
                self.protection_page
                    .emit(ProtectionTimelinePageInput::JournalAccessChanged(
                        journal_access,
                    ));
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
                self.protection_page.emit(
                    ProtectionTimelinePageInput::UnresolvedDetectionsChanged(unresolved_detections),
                );
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
                self.toaster.add_toast(
                    adw::Toast::builder()
                        .title(notice_text)
                        .use_markup(false)
                        .build(),
                );
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
                self.protection_page
                    .emit(ProtectionTimelinePageInput::EvidenceGathered(
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
                self.scan_page.emit(ScanPageInput::EvidenceGathered(
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
