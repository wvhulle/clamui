use std::path::PathBuf;

use futures::StreamExt;
use gettextrs::gettext;
use jiff::Timestamp;
use relm4::{
    Component, ComponentController, ComponentParts, ComponentSender, Controller,
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
            OpenDetectionAction, OpenDetectionsAction, OpenSettingsAction, QuickScanAction,
            ScanPathsAction, ShowPageAction, UpdateDefinitionsAction, register_application_action,
            register_window_action,
        },
        application_pages::{ALL_APPLICATION_PAGES, ApplicationPage},
        protection_evidence_refresh::{
            EvidenceRefresh, EvidenceRefreshTransition, EvidenceRefreshTrigger, GatheredEvidence,
            GatheringStart,
        },
        settings_navigation::{SettingsSubpage, SubpagePlacement, settings_subpage_frame},
        sidebar_area_status::{
            AreaSummaryContext, SidebarAreaSummary, StatusIndicator, all_area_summaries,
            attention_summary_text, worst_area_status,
        },
    },
    findings::{
        detections_page::background_detections_page::{
            BackgroundDetectionsPage, BackgroundDetectionsPageInit, BackgroundDetectionsPageInput,
            BackgroundDetectionsPageOutput,
        },
        quarantine_page::{
            quarantine_entries_page::{
                QuarantineEntriesPage, QuarantineEntriesPageInput, QuarantineEntriesPageOutput,
            },
            quarantine_page_state::QuarantineEntryCount,
        },
    },
    host_services::{
        activity_history::activity_history_database::ActivityHistory,
        desktop::{
            locale_formatting::host_moment_formatters,
            running_instance_forwarding::paths_from_bytes,
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
    protection_page::{
        protection_timeline_page::{
            ProtectionTimelinePage, ProtectionTimelinePageInput, ProtectionTimelinePageOutput,
        },
        protection_timeline_presentation::AlertReadiness,
    },
    scans::{
        manual_scan_page::{
            device_auto_scan_page::device_scan_page::DeviceScanPage,
            exclusions_page::scan_exclusions_page::ScanExclusionsPage,
            scan_page_component::{ScanPage, ScanPageInit, ScanPageInput, ScanPageOutput},
            scan_profiles_dialog::scan_profile_store::ScanProfileStore,
        },
        scan_engine_page::{
            scan_engine_component::{ScanEnginePage, ScanEnginePageInput},
            scan_engine_state::ScanEnginePageOutput,
        },
        scheduled_scans_page::scan_schedule_component::ScanSchedulePage,
    },
    shared_widgets::{
        audit_sections::{
            audit_check_results::{HARDENING_AUDIT_CATEGORIES, SIGNATURE_AUDIT_CATEGORIES},
            audit_sections_page::{AuditSectionsPage, AuditSectionsPageInit},
        },
        component_streams::{RunningStream, run_stream},
        engine_settings::{
            engine_settings_sections::EngineSettingsSection,
            engine_settings_subpage::EngineSettingsSubpage,
        },
    },
    sharing::analysis_page::trusted_detections_page::trusted_detections_component::TrustedDetectionsPage,
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

enum SettingsSubpageContent {
    EngineSettings(Controller<EngineSettingsSubpage>),
    ScanExclusions(Controller<ScanExclusionsPage>),
    DeviceAutoScan(Controller<DeviceScanPage>),
    ScanSchedule(Controller<ScanSchedulePage>),
    TrustedDetections(Controller<TrustedDetectionsPage>),
}

impl SettingsSubpageContent {
    fn launched_for(settings_subpage: SettingsSubpage) -> Self {
        match settings_subpage {
            SettingsSubpage::ScannerEngine => Self::EngineSettings(
                EngineSettingsSubpage::builder()
                    .launch(EngineSettingsSection::ScannerEngine)
                    .detach(),
            ),
            SettingsSubpage::DetectionChoices => Self::EngineSettings(
                EngineSettingsSubpage::builder()
                    .launch(EngineSettingsSection::DetectionChoices)
                    .detach(),
            ),
            SettingsSubpage::OnAccessScanning => Self::EngineSettings(
                EngineSettingsSubpage::builder()
                    .launch(EngineSettingsSection::OnAccessScanning)
                    .detach(),
            ),
            SettingsSubpage::SignatureUpdates => Self::EngineSettings(
                EngineSettingsSubpage::builder()
                    .launch(EngineSettingsSection::SignatureUpdates)
                    .detach(),
            ),
            SettingsSubpage::ScanExclusions => {
                Self::ScanExclusions(ScanExclusionsPage::builder().launch(()).detach())
            }
            SettingsSubpage::DeviceAutoScan => {
                Self::DeviceAutoScan(DeviceScanPage::builder().launch(()).detach())
            }
            SettingsSubpage::ScanSchedule => {
                Self::ScanSchedule(ScanSchedulePage::builder().launch(()).detach())
            }
            SettingsSubpage::TrustedDetections => {
                Self::TrustedDetections(TrustedDetectionsPage::builder().launch(()).detach())
            }
        }
    }

    fn content_widget(&self) -> gtk::Widget {
        match self {
            Self::EngineSettings(engine_subpage) => engine_subpage.widget().clone().upcast(),
            Self::ScanExclusions(exclusions_page) => exclusions_page.widget().clone().upcast(),
            Self::DeviceAutoScan(device_page) => device_page.widget().clone().upcast(),
            Self::ScanSchedule(schedule_page) => schedule_page.widget().clone().upcast(),
            Self::TrustedDetections(trusted_page) => trusted_page.widget().clone().upcast(),
        }
    }
}

enum AreaSummaries {
    SummariesPending,
    SummariesComputed(Vec<SidebarAreaSummary>),
}

struct OpenedSettingsSubpage {
    settings_subpage: SettingsSubpage,
    subpage_frame: adw::NavigationPage,
    _subpage_content: SettingsSubpageContent,
}

impl OpenedSettingsSubpage {
    fn opened(settings_subpage: SettingsSubpage) -> Self {
        let subpage_content = SettingsSubpageContent::launched_for(settings_subpage);
        Self {
            settings_subpage,
            subpage_frame: settings_subpage_frame(
                settings_subpage,
                &subpage_content.content_widget(),
            ),
            _subpage_content: subpage_content,
        }
    }
}

pub struct PageNavigation {
    visible_page: ApplicationPage,
    shows_content_when_narrow: bool,
    opened_settings_subpages: Vec<OpenedSettingsSubpage>,
    scan_page: Controller<ScanPage>,
    quarantine_page: Controller<QuarantineEntriesPage>,
    logs_page: Controller<ActivityLogsPage>,
    signatures_page: Controller<AuditSectionsPage>,
    hardening_page: Controller<AuditSectionsPage>,
    protection_page: Controller<ProtectionTimelinePage>,
    database_updates_page: Controller<DatabaseUpdatesPage>,
    scan_engine_page: Controller<ScanEnginePage>,
    detections_page: Controller<BackgroundDetectionsPage>,
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
    SettingsSubpageOpened(SettingsSubpage),
    SettingsSubpagePopped(String),
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

trait SettingsSubpageStack {
    fn show_settings_subpages(&self, root_tag: &str, subpage_frames: &[adw::NavigationPage]);
}

impl SettingsSubpageStack for adw::NavigationView {
    fn show_settings_subpages(&self, root_tag: &str, subpage_frames: &[adw::NavigationPage]) {
        let shown_frames = (0..self.navigation_stack().n_items())
            .filter_map(|stack_position| self.navigation_stack().item(stack_position))
            .filter_map(|stack_item| stack_item.downcast::<adw::NavigationPage>().ok())
            .skip(1)
            .collect::<Vec<_>>();
        let kept_frames = shown_frames
            .iter()
            .zip(subpage_frames)
            .take_while(|(shown_frame, wanted_frame)| shown_frame == wanted_frame)
            .count();
        if kept_frames < shown_frames.len() {
            let _popped = match kept_frames
                .checked_sub(1)
                .and_then(|kept_position| shown_frames.get(kept_position))
            {
                Some(newest_kept_frame) => self.pop_to_page(newest_kept_frame),
                None => self.pop_to_tag(root_tag),
            };
        }
        subpage_frames
            .iter()
            .skip(kept_frames)
            .for_each(|subpage_frame| self.push(subpage_frame));
    }
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
        ScanPageOutput::QuarantineEntriesChanged => PageNavigationInput::QuarantineEntriesChanged,
        ScanPageOutput::ActivityRecorded => PageNavigationInput::ActivityRecorded,
    }
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

const fn forwarded_scan_engine_output(
    scan_engine_output: ScanEnginePageOutput,
) -> PageNavigationInput {
    match scan_engine_output {
        ScanEnginePageOutput::EvidenceRefreshRequested => {
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
    let settings_sender = sender.clone();
    register_window_action(
        window_root,
        RelmAction::<OpenSettingsAction>::new_with_target_value(
            move |_action, action_target: String| {
                if let Some(settings_subpage) = SettingsSubpage::from_action_target(&action_target)
                {
                    settings_sender
                        .input(PageNavigationInput::SettingsSubpageOpened(settings_subpage));
                }
            },
        ),
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

    fn subpage_frames_of(&self, application_page: ApplicationPage) -> Vec<adw::NavigationPage> {
        self.opened_settings_subpages
            .iter()
            .filter(|opened_subpage| {
                opened_subpage.settings_subpage.owning_page() == application_page
            })
            .map(|opened_subpage| opened_subpage.subpage_frame.clone())
            .collect()
    }

    fn show_page(&mut self, application_page: ApplicationPage) {
        self.visible_page = application_page;
        self.shows_content_when_narrow = true;
    }

    fn open_settings_subpage(&mut self, settings_subpage: SettingsSubpage) {
        let owning_page = match settings_subpage.subpage_placement() {
            SubpagePlacement::StackedOnPage(owning_page) => owning_page,
            SubpagePlacement::EmbeddedInPage(embedding_page) => {
                self.show_page(embedding_page);
                return;
            }
        };
        self.show_page(owning_page);
        let newest_subpage_of_page = self
            .opened_settings_subpages
            .iter()
            .rev()
            .find(|opened_subpage| opened_subpage.settings_subpage.owning_page() == owning_page)
            .map(|opened_subpage| opened_subpage.settings_subpage);
        if newest_subpage_of_page != Some(settings_subpage) {
            self.opened_settings_subpages
                .push(OpenedSettingsSubpage::opened(settings_subpage));
        }
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
            set_child = &adw::ToastOverlay {
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
                                    append: &navigation_row(ApplicationPage::Logs),
                                    append: &navigation_row(ApplicationPage::Quarantine),
                                    append: &navigation_row(ApplicationPage::Signatures),
                                    append: &navigation_row(ApplicationPage::DatabaseUpdates),
                                    append: &navigation_row(ApplicationPage::ScanEngine),
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
                                #[watch]
                                show_settings_subpages: (ApplicationPage::Protection.page_name(), &model.subpage_frames_of(ApplicationPage::Protection)),
                                connect_popped[sender] => move |_navigation_view, popped_page| {
                                    if let Some(popped_tag) = popped_page.tag() {
                                        sender.input(PageNavigationInput::SettingsSubpagePopped(popped_tag.to_string()));
                                    }
                                },
                            },
                            add_titled[Some(ApplicationPage::Detections.page_name()), &ApplicationPage::Detections.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Detections, model.detections_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Scan.page_name()), &ApplicationPage::Scan.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Scan, model.scan_page.widget()),
                                #[watch]
                                show_settings_subpages: (ApplicationPage::Scan.page_name(), &model.subpage_frames_of(ApplicationPage::Scan)),
                                connect_popped[sender] => move |_navigation_view, popped_page| {
                                    if let Some(popped_tag) = popped_page.tag() {
                                        sender.input(PageNavigationInput::SettingsSubpagePopped(popped_tag.to_string()));
                                    }
                                },
                            },
                            add_titled[Some(ApplicationPage::Logs.page_name()), &ApplicationPage::Logs.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Logs, model.logs_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Quarantine.page_name()), &ApplicationPage::Quarantine.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Quarantine, model.quarantine_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::Signatures.page_name()), &ApplicationPage::Signatures.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::Signatures, model.signatures_page.widget()),
                                #[watch]
                                show_settings_subpages: (ApplicationPage::Signatures.page_name(), &model.subpage_frames_of(ApplicationPage::Signatures)),
                                connect_popped[sender] => move |_navigation_view, popped_page| {
                                    if let Some(popped_tag) = popped_page.tag() {
                                        sender.input(PageNavigationInput::SettingsSubpagePopped(popped_tag.to_string()));
                                    }
                                },
                            },
                            add_titled[Some(ApplicationPage::DatabaseUpdates.page_name()), &ApplicationPage::DatabaseUpdates.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::DatabaseUpdates, model.database_updates_page.widget()),
                            },
                            add_titled[Some(ApplicationPage::ScanEngine.page_name()), &ApplicationPage::ScanEngine.page_title()] = &adw::NavigationView {
                                add: &page_root(ApplicationPage::ScanEngine, model.scan_engine_page.widget()),
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
            .launch(quarantine_vault.clone())
            .forward(
                sender.input_sender(),
                |quarantine_output| match quarantine_output {
                    QuarantineEntriesPageOutput::EntriesCounted(quarantine_entry_count) => {
                        PageNavigationInput::QuarantineEntriesCounted(quarantine_entry_count)
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
                file_list_directory: data_directory,
            })
            .forward(sender.input_sender(), forwarded_scan_output);
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
        let detections_page = BackgroundDetectionsPage::builder()
            .launch(BackgroundDetectionsPageInit {
                activity_history,
                quarantine_vault,
            })
            .forward(sender.input_sender(), forwarded_detections_output);
        let signatures_page = AuditSectionsPage::builder()
            .launch(AuditSectionsPageInit {
                page_title: gettext("Signatures"),
                page_description: gettext(
                    "Where ClamAV's malware signatures come from, and which other sources you \
                     could add.",
                ),
                audited_categories: &SIGNATURE_AUDIT_CATEGORIES,
                settings_subpages: &[SettingsSubpage::SignatureUpdates],
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
                settings_subpages: &[],
            })
            .detach();
        let mut model = Self {
            visible_page: navigation_init.startup_page,
            shows_content_when_narrow: false,
            opened_settings_subpages: Vec::new(),
            scan_page,
            quarantine_page,
            logs_page,
            signatures_page,
            hardening_page,
            protection_page,
            database_updates_page,
            scan_engine_page,
            detections_page,
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
            PageNavigationInput::SettingsSubpageOpened(settings_subpage) => {
                self.open_settings_subpage(settings_subpage);
            }
            PageNavigationInput::SettingsSubpagePopped(popped_tag) => {
                if let Some(popped_position) =
                    self.opened_settings_subpages
                        .iter()
                        .rposition(|opened_subpage| {
                            opened_subpage.settings_subpage.action_target() == popped_tag
                        })
                {
                    self.opened_settings_subpages.remove(popped_position);
                }
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
            }
            PageNavigationInput::SignaturesUpdated => {
                self.quarantine_page
                    .emit(QuarantineEntriesPageInput::RecheckAllRequested);
            }
            PageNavigationInput::ActivityRecorded => {
                self.logs_page
                    .emit(ActivityLogsPageInput::ReloadEntriesRequested);
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
                self.advance_evidence_refresh(EvidenceRefreshTrigger::GatheringFinished, &sender);
            }
            PageNavigationCommand::WatchedUnitChanged => {
                self.advance_evidence_refresh(EvidenceRefreshTrigger::WatchedUnitChanged, &sender);
            }
        }
    }
}
