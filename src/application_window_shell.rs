use std::{
    cell::OnceCell, collections::HashMap, os::unix::ffi::OsStringExt, path::PathBuf, rc::Rc,
};

use gettextrs::gettext;
use relm4::{
    AsyncComponentSender, Component, ComponentController, Controller, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, glib},
    prelude::{AsyncComponent, AsyncComponentParts},
};

use crate::{
    APPLICATION_DATA_NAME, APPLICATION_ICON_NAME,
    activity_history::{
        activity_history_database::ActivityHistory,
        activity_logs_page::{ActivityLogsPage, ActivityLogsPageInput},
    },
    application_data_directory,
    application_settings::{
        clamav_host_settings::{
            EngineSettingsSection, current_live_tuning_state, engine_settings_page,
        },
        preferences_dialog::{PreferencesPageName, present_preferences_dialog},
        stored_settings::{CLOSE_ACTION_KEY, application_settings},
    },
    background_detections::{
        background_detections_page::{
            BackgroundDetectionsPage, BackgroundDetectionsPageInit, BackgroundDetectionsPageInput,
            BackgroundDetectionsPageOutput,
        },
        detection_alerts::{OPEN_DETECTION_ACTION, OPEN_DETECTIONS_ACTION},
    },
    desktop_integration::{
        device_mount_scans::watch_device_mounts,
        running_instance_forwarding::{
            SCAN_PATHS_ACTION, SHOW_WINDOW_ACTION, paths_from_variant, scan_paths_action_type,
        },
        system_tray_menu::{SystemTrayMenu, spawn_system_tray},
    },
    file_process_lock::{ProcessFileLock, wait_for_file_lock},
    file_quarantine::{
        quarantine_entries_page::{
            QuarantineEntriesPage, QuarantineEntriesPageInput, describe_quarantine_failure,
        },
        quarantine_entry_database::QuarantineVault,
        quarantine_file_moves::QuarantineMoveFailure,
    },
    malware_scan::{
        scan_progress_page::{
            ScanProgressPage, ScanProgressPageInit, ScanProgressPageInput, ScanProgressPageOutput,
        },
        scan_settings::{device_scan_page, exclusions_page},
    },
    protection_status::protection_timeline_page::{
        ProtectionTimelinePage, ProtectionTimelinePageInput, ProtectionTimelinePageOutput,
    },
    scan_profiles::scan_profile_store::ScanProfileStore,
    scheduled_scans::schedule_preferences_page::SchedulePreferencesPage,
    settings_navigation::{OPEN_SETTINGS_ACTION_NAME, SettingsSubpage, settings_subpage_frame},
    startup_arguments::StartupRequest,
    system_audit::{
        audit_report_model::{HARDENING_AUDIT_CATEGORIES, SIGNATURE_AUDIT_CATEGORIES},
        audit_sections_page::{AuditSectionsPage, AuditSectionsPageInit},
    },
    virus_database::database_update_page::{
        DatabaseUpdatePage, DatabaseUpdatePageInput, DatabaseUpdatePageOutput,
    },
};

const PREFERENCES_STARTUP_PAGE: &str = "preferences";
const DATABASE_STARTUP_PAGE: &str = "database";
const SCAN_PAGE_NAME: &str = "scan";
const DETECTIONS_PAGE_NAME: &str = "detections";

struct ApplicationPages {
    _device_monitor: gio::VolumeMonitor,
    _vault_lock: ProcessFileLock,
    _scan_page: Controller<ScanProgressPage>,
    _quarantine_page: Controller<QuarantineEntriesPage>,
    _database_page: Controller<DatabaseUpdatePage>,
    _logs_page: Controller<ActivityLogsPage>,
    _signatures_page: Controller<AuditSectionsPage>,
    _hardening_page: Controller<AuditSectionsPage>,
    _protection_page: Controller<ProtectionTimelinePage>,
    _detections_page: Controller<BackgroundDetectionsPage>,
    _database_dialog: adw::Dialog,
}

enum ShellContent {
    VaultReady {
        _application_pages: Box<ApplicationPages>,
    },
    VaultUnavailable,
}

pub struct ApplicationWindowShell {
    _shell_content: ShellContent,
}

fn vault_unavailable_page(vault_failure: &QuarantineMoveFailure) -> adw::StatusPage {
    adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title(gettext("The quarantine database could not be opened"))
        .description(glib::markup_escape_text(&describe_quarantine_failure(
            vault_failure,
        )))
        .build()
}

struct NavigationPage<'page> {
    page_name: &'static str,
    page_title: String,
    page_icon: &'static str,
    page_widget: &'page gtk::Widget,
    keyboard_accelerator: &'static str,
}

type PageNavigationViews = Rc<HashMap<&'static str, adw::NavigationView>>;

fn page_navigation_view(navigation_page: &NavigationPage<'_>) -> adw::NavigationView {
    let navigation_view = adw::NavigationView::new();
    navigation_view.add(
        &adw::NavigationPage::builder()
            .title(&navigation_page.page_title)
            .tag(navigation_page.page_name)
            .child(navigation_page.page_widget)
            .build(),
    );
    navigation_view
}

fn navigation_stack(navigation_pages: &[NavigationPage<'_>]) -> (gtk::Stack, PageNavigationViews) {
    let page_stack = gtk::Stack::new();
    let mut navigation_views = HashMap::new();
    navigation_pages.iter().for_each(|navigation_page| {
        let navigation_view = page_navigation_view(navigation_page);
        page_stack.add_titled(
            &navigation_view,
            Some(navigation_page.page_name),
            &navigation_page.page_title,
        );
        navigation_views.insert(navigation_page.page_name, navigation_view);
        relm4::main_application().set_accels_for_action(
            &format!("win.show-page::{}", navigation_page.page_name),
            &[navigation_page.keyboard_accelerator],
        );
    });
    (page_stack, Rc::new(navigation_views))
}

fn settings_subpage_content(settings_subpage: SettingsSubpage) -> gtk::Widget {
    match settings_subpage {
        SettingsSubpage::ScanExclusions => exclusions_page(&application_settings()).upcast(),
        SettingsSubpage::DeviceAutoScan => device_scan_page(&application_settings()).upcast(),
        SettingsSubpage::ScanSchedule => {
            let mut schedule_page = SchedulePreferencesPage::builder().launch(()).detach();
            schedule_page.detach_runtime();
            schedule_page.widget().clone().upcast()
        }
        SettingsSubpage::ScannerEngine
        | SettingsSubpage::OnAccessScanning
        | SettingsSubpage::SignatureUpdates => adw::Spinner::new().upcast(),
    }
}

const fn engine_section(settings_subpage: SettingsSubpage) -> Option<EngineSettingsSection> {
    match settings_subpage {
        SettingsSubpage::ScannerEngine => Some(EngineSettingsSection::ScannerEngine),
        SettingsSubpage::OnAccessScanning => Some(EngineSettingsSection::OnAccessScanning),
        SettingsSubpage::SignatureUpdates => Some(EngineSettingsSection::SignatureUpdates),
        SettingsSubpage::ScanExclusions
        | SettingsSubpage::ScanSchedule
        | SettingsSubpage::DeviceAutoScan => None,
    }
}

fn push_settings_subpage(navigation_view: &adw::NavigationView, settings_subpage: SettingsSubpage) {
    if navigation_view
        .visible_page()
        .and_then(|visible_page| visible_page.tag())
        .is_some_and(|visible_tag| visible_tag == settings_subpage.action_target())
    {
        return;
    }
    let pushed_subpage = settings_subpage_frame(
        settings_subpage,
        &settings_subpage_content(settings_subpage),
    );
    navigation_view.push(&pushed_subpage);
    if let Some(engine_section) = engine_section(settings_subpage) {
        let loading_subpage = pushed_subpage.clone();
        relm4::spawn_local(async move {
            let engine_page =
                engine_settings_page(engine_section, current_live_tuning_state().await);
            if let Some(subpage_view) = loading_subpage.child().and_downcast::<adw::ToolbarView>() {
                subpage_view.set_content(Some(&engine_page));
            }
        });
    }
}

fn register_settings_action(
    window_root: &adw::ApplicationWindow,
    page_stack: &gtk::Stack,
    navigation_views: PageNavigationViews,
) {
    let settings_action =
        gio::SimpleAction::new(OPEN_SETTINGS_ACTION_NAME, Some(glib::VariantTy::STRING));
    let settings_stack = page_stack.clone();
    settings_action.connect_activate(move |_activated_action, action_target| {
        let Some(settings_subpage) = action_target
            .and_then(|target_variant| target_variant.str().map(str::to_owned))
            .and_then(|target_text| SettingsSubpage::from_action_target(&target_text))
        else {
            return;
        };
        let owning_page_name = settings_subpage.owning_page_name();
        settings_stack.set_visible_child_name(owning_page_name);
        if let Some(navigation_view) = navigation_views.get(owning_page_name) {
            push_settings_subpage(navigation_view, settings_subpage);
        }
    });
    window_root.add_action(&settings_action);
}

fn navigation_row(navigation_page: &NavigationPage<'_>) -> gtk::ListBoxRow {
    let row_content = gtk::Box::builder().spacing(12).build();
    row_content.append(&gtk::Image::from_icon_name(navigation_page.page_icon));
    row_content.append(&gtk::Label::new(Some(&navigation_page.page_title)));
    let navigation_row = gtk::ListBoxRow::builder().child(&row_content).build();
    navigation_row.set_widget_name(navigation_page.page_name);
    navigation_row
}

fn navigation_sidebar(
    navigation_pages: &[NavigationPage<'_>],
    page_stack: &gtk::Stack,
) -> gtk::ListBox {
    let sidebar_list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .css_classes(["navigation-sidebar"])
        .build();
    let navigation_rows = navigation_pages
        .iter()
        .map(navigation_row)
        .collect::<Vec<_>>();
    navigation_rows
        .iter()
        .for_each(|navigation_row| sidebar_list.append(navigation_row));
    let activated_stack = page_stack.clone();
    sidebar_list.connect_row_activated(move |_sidebar_list, activated_row| {
        activated_stack.set_visible_child_name(&activated_row.widget_name());
    });
    let selection_list = sidebar_list.clone();
    let select_visible_page = move |changed_stack: &gtk::Stack| {
        let visible_page = changed_stack.visible_child_name().unwrap_or_default();
        selection_list.select_row(
            navigation_rows
                .iter()
                .find(|navigation_row| navigation_row.widget_name() == visible_page),
        );
    };
    select_visible_page(page_stack);
    page_stack.connect_visible_child_name_notify(select_visible_page);
    sidebar_list
}

fn signature_update_dialog(database_page: &Controller<DatabaseUpdatePage>) -> adw::Dialog {
    adw::Dialog::builder()
        .title(gettext("Update signatures"))
        .content_width(560)
        .content_height(640)
        .child(&{
            let dialog_view = adw::ToolbarView::new();
            dialog_view.add_top_bar(&adw::HeaderBar::new());
            dialog_view.set_content(Some(database_page.widget()));
            dialog_view
        })
        .build()
}

fn primary_menu_button() -> gtk::MenuButton {
    let primary_menu = gio::Menu::new();
    primary_menu.append(Some(&gettext("Preferences")), Some("app.preferences"));
    primary_menu.append(Some(&gettext("About Lazaret")), Some("app.about"));
    primary_menu.append(Some(&gettext("Quit")), Some("app.quit"));
    gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .tooltip_text(gettext("Menu"))
        .menu_model(&primary_menu)
        .primary(true)
        .build()
}

fn present_about_dialog() {
    adw::AboutDialog::builder()
        .application_name("Lazaret")
        .application_icon(APPLICATION_ICON_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .license_type(gtk::License::MitX11)
        .website("https://codeberg.org/wvhulle/lazaret")
        .developers(
            include_str!("../AUTHORS")
                .lines()
                .filter(|author_line| !author_line.starts_with('#'))
                .collect::<Vec<_>>(),
        )
        .translator_credits(gettext("translator-credits"))
        .build()
        .present(relm4::main_application().active_window().as_ref());
}

fn register_application_actions(window_root: &adw::ApplicationWindow, page_stack: &gtk::Stack) {
    window_root.add_action(&gio::PropertyAction::new(
        "show-page",
        page_stack,
        "visible-child-name",
    ));
    let main_application = relm4::main_application();
    let about_action = gio::SimpleAction::new("about", None);
    about_action.connect_activate(|_activated_action, _parameter| present_about_dialog());
    main_application.add_action(&about_action);
    let preferences_action = gio::SimpleAction::new("preferences", None);
    preferences_action.connect_activate(|_activated_action, _parameter| {
        present_preferences_dialog(PreferencesPageName::GeneralPreferences)
    });
    main_application.add_action(&preferences_action);
    main_application.set_accels_for_action("app.preferences", &["<Control>comma"]);
    let quit_action = gio::SimpleAction::new("quit", None);
    quit_action.connect_activate(|_activated_action, _parameter| {
        relm4::main_application().quit();
    });
    main_application.add_action(&quit_action);
    main_application.set_accels_for_action("app.quit", &["<Control>q"]);
    main_application.set_accels_for_action("window.close", &["<Control>w"]);
}

fn visible_page_title(page_stack: &gtk::Stack) -> String {
    page_stack
        .visible_child()
        .and_then(|visible_child| page_stack.page(&visible_child).title())
        .map(|page_title| page_title.to_string())
        .unwrap_or_default()
}

fn adaptive_navigation_layout(
    sidebar_list: &gtk::ListBox,
    page_stack: &gtk::Stack,
    window_root: &adw::ApplicationWindow,
) -> adw::ToastOverlay {
    let sidebar_header = adw::HeaderBar::new();
    sidebar_header.pack_end(&primary_menu_button());
    let sidebar_view = adw::ToolbarView::new();
    sidebar_view.add_top_bar(&sidebar_header);
    sidebar_view.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(sidebar_list)
            .build(),
    ));
    let content_page = adw::NavigationPage::builder()
        .title(visible_page_title(page_stack))
        .child(page_stack)
        .build();
    let split_view = adw::NavigationSplitView::builder()
        .sidebar(
            &adw::NavigationPage::builder()
                .title("Lazaret")
                .child(&sidebar_view)
                .build(),
        )
        .content(&content_page)
        .sidebar_width_fraction(0.22)
        .build();
    let titled_content_page = content_page.clone();
    page_stack.connect_visible_child_notify(move |changed_stack| {
        titled_content_page.set_title(&visible_page_title(changed_stack));
    });
    let activated_split_view = split_view.clone();
    sidebar_list.connect_row_activated(move |_sidebar_list, _activated_row| {
        activated_split_view.set_show_content(true);
    });
    if let Ok(narrow_condition) = adw::BreakpointCondition::parse("max-width: 640sp") {
        let narrow_breakpoint = adw::Breakpoint::new(narrow_condition);
        narrow_breakpoint.add_setter(&split_view, "collapsed", Some(&true.to_value()));
        window_root.add_breakpoint(narrow_breakpoint);
    }
    let window_toast_overlay = adw::ToastOverlay::new();
    window_toast_overlay.set_child(Some(&split_view));
    window_toast_overlay
}

fn application_pages(
    vault_lock: ProcessFileLock,
    quarantine_vault: QuarantineVault,
    data_directory: PathBuf,
    window_root: &adw::ApplicationWindow,
    startup_request: StartupRequest,
    running_tray: RunningTray,
) -> ShellContent {
    let quarantine_page = QuarantineEntriesPage::builder()
        .launch(quarantine_vault.clone())
        .detach();
    let quarantine_input_sender = quarantine_page.sender().clone();
    let detection_quarantine_sender = quarantine_page.sender().clone();
    let activity_history = ActivityHistory::at_database_path(data_directory.join("history.db"));
    let detections_history = activity_history.clone();
    let detections_vault = quarantine_vault.clone();
    let logs_page = ActivityLogsPage::builder()
        .launch(activity_history.clone())
        .detach();
    let logs_input_sender = logs_page.sender().clone();
    let reload_activity_views: Rc<dyn Fn()> = Rc::new(move || {
        logs_input_sender.emit(ActivityLogsPageInput::ReloadEntriesRequested);
    });
    let scan_activity_reload = Rc::clone(&reload_activity_views);
    let scan_page = ScanProgressPage::builder()
        .launch(ScanProgressPageInit {
            quarantine_vault,
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
        .connect_receiver(
            move |_scan_page_sender, scan_page_output| match scan_page_output {
                ScanProgressPageOutput::QuarantineEntriesChanged => {
                    quarantine_input_sender
                        .emit(QuarantineEntriesPageInput::ReloadEntriesRequested);
                }
                ScanProgressPageOutput::ActivityRecorded => scan_activity_reload(),
            },
        );
    let database_page = DatabaseUpdatePage::builder()
        .launch(activity_history)
        .connect_receiver(
            move |_database_sender, database_output| match database_output {
                DatabaseUpdatePageOutput::ActivityRecorded => reload_activity_views(),
            },
        );
    let database_dialog = signature_update_dialog(&database_page);
    let requested_dialog = database_dialog.clone();
    let requesting_window = window_root.clone();
    let protection_page = ProtectionTimelinePage::builder()
        .launch(())
        .connect_receiver(
            move |_protection_sender, protection_output| match protection_output {
                ProtectionTimelinePageOutput::UpdateSignaturesRequested => {
                    requested_dialog.present(Some(&requesting_window));
                }
            },
        );
    let protection_input_sender = protection_page.sender().clone();
    let journal_access_sender = protection_page.sender().clone();
    let detections_page = BackgroundDetectionsPage::builder()
        .launch(BackgroundDetectionsPageInit {
            activity_history: detections_history,
            quarantine_vault: detections_vault,
        })
        .connect_receiver(
            move |_detections_sender, detections_output| match detections_output {
                BackgroundDetectionsPageOutput::JournalAccessChanged(journal_access) => {
                    journal_access_sender.emit(ProtectionTimelinePageInput::JournalAccessChanged(
                        journal_access,
                    ));
                }
                BackgroundDetectionsPageOutput::UnresolvedCountChanged(unresolved_detections) => {
                    show_unresolved_detections_in_tray(&running_tray, unresolved_detections);
                    protection_input_sender.emit(
                        ProtectionTimelinePageInput::UnresolvedDetectionsChanged(
                            unresolved_detections,
                        ),
                    );
                }
                BackgroundDetectionsPageOutput::QuarantineReloadNeeded => {
                    detection_quarantine_sender
                        .emit(QuarantineEntriesPageInput::ReloadEntriesRequested);
                }
            },
        );

    let signatures_page = AuditSectionsPage::builder()
        .launch(AuditSectionsPageInit {
            page_title: gettext("Signatures"),
            page_description: gettext(
                "Where ClamAV's malware signatures come from, and which other sources you could \
                 add.",
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

    let navigation_pages = [
        NavigationPage {
            page_name: "protection",
            page_title: gettext("Protection"),
            page_icon: "security-high-symbolic",
            page_widget: protection_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>1",
        },
        NavigationPage {
            page_name: DETECTIONS_PAGE_NAME,
            page_title: gettext("Detections"),
            page_icon: "dialog-warning-symbolic",
            page_widget: detections_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>2",
        },
        NavigationPage {
            page_name: SCAN_PAGE_NAME,
            page_title: gettext("Scan"),
            page_icon: "system-search-symbolic",
            page_widget: scan_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>3",
        },
        NavigationPage {
            page_name: "logs",
            page_title: gettext("Logs"),
            page_icon: "document-open-recent-symbolic",
            page_widget: logs_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>4",
        },
        NavigationPage {
            page_name: "quarantine",
            page_title: gettext("Quarantine"),
            page_icon: "folder-symbolic",
            page_widget: quarantine_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>5",
        },
        NavigationPage {
            page_name: "signatures",
            page_title: gettext("Signatures"),
            page_icon: "drive-harddisk-symbolic",
            page_widget: signatures_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>6",
        },
        NavigationPage {
            page_name: "hardening",
            page_title: gettext("Hardening"),
            page_icon: "channel-secure-symbolic",
            page_widget: hardening_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>7",
        },
    ];
    let (page_stack, navigation_views) = navigation_stack(&navigation_pages);
    register_settings_action(window_root, &page_stack, navigation_views);
    match startup_request.startup_page.as_str() {
        PREFERENCES_STARTUP_PAGE => {
            present_preferences_dialog(PreferencesPageName::GeneralPreferences)
        }
        DATABASE_STARTUP_PAGE => database_dialog.present(Some(window_root)),
        startup_page => page_stack.set_visible_child_name(startup_page),
    }
    let sidebar_list = navigation_sidebar(&navigation_pages, &page_stack);
    if !startup_request.scan_targets.is_empty() {
        page_stack.set_visible_child_name(SCAN_PAGE_NAME);
        scan_page.emit(ScanProgressPageInput::ScanTargetsChosen(
            startup_request.scan_targets,
        ));
    }
    register_application_actions(window_root, &page_stack);
    let device_monitor = watch_device_mounts(&scan_page);
    let main_application = relm4::main_application();
    let quick_scan_action = gio::SimpleAction::new("quick-scan", None);
    let quick_scan_sender = scan_page.sender().clone();
    let quick_scan_stack = page_stack.clone();
    quick_scan_action.connect_activate(move |_activated_action, _parameter| {
        quick_scan_stack.set_visible_child_name("scan");
        quick_scan_sender.emit(ScanProgressPageInput::QuickScanRequested);
    });
    main_application.add_action(&quick_scan_action);
    let update_action = gio::SimpleAction::new("update-definitions", None);
    let update_sender = database_page.sender().clone();
    let update_dialog = database_dialog.clone();
    let update_window = window_root.clone();
    update_action.connect_activate(move |_activated_action, _parameter| {
        update_dialog.present(Some(&update_window));
        update_sender.emit(DatabaseUpdatePageInput::StartUpdate);
    });
    main_application.add_action(&update_action);
    let scan_paths_action =
        gio::SimpleAction::new(SCAN_PATHS_ACTION, Some(scan_paths_action_type()));
    let scan_paths_sender = scan_page.sender().clone();
    let scan_paths_stack = page_stack.clone();
    let scan_paths_window = window_root.clone();
    scan_paths_action.connect_activate(move |_activated_action, forwarded_paths| {
        if let Some(forwarded_paths) = forwarded_paths {
            scan_paths_stack.set_visible_child_name("scan");
            scan_paths_window.present();
            scan_paths_sender.emit(ScanProgressPageInput::ScanTargetsChosen(
                paths_from_variant(forwarded_paths),
            ));
        }
    });
    main_application.add_action(&scan_paths_action);
    let open_detections_action = gio::SimpleAction::new(OPEN_DETECTIONS_ACTION, None);
    let open_detections_stack = page_stack.clone();
    let open_detections_window = window_root.clone();
    let open_detections_sender = detections_page.sender().clone();
    open_detections_action.connect_activate(move |_activated_action, _parameter| {
        open_detections_sender.emit(BackgroundDetectionsPageInput::BackToListRequested);
        open_detections_stack.set_visible_child_name(DETECTIONS_PAGE_NAME);
        open_detections_window.present();
    });
    main_application.add_action(&open_detections_action);
    let open_detection_action =
        gio::SimpleAction::new(OPEN_DETECTION_ACTION, Some(glib::VariantTy::BYTE_STRING));
    let open_detection_stack = page_stack.clone();
    let open_detection_window = window_root.clone();
    let open_detection_sender = detections_page.sender().clone();
    open_detection_action.connect_activate(move |_activated_action, detected_path| {
        open_detection_stack.set_visible_child_name(DETECTIONS_PAGE_NAME);
        open_detection_window.present();
        if let Some(path_bytes) =
            detected_path.and_then(|path_variant| path_variant.get::<Vec<u8>>())
        {
            open_detection_sender.emit(BackgroundDetectionsPageInput::IncidentRequestedForFile(
                PathBuf::from(std::ffi::OsString::from_vec(path_bytes)),
            ));
        }
    });
    main_application.add_action(&open_detection_action);
    let show_window_action = gio::SimpleAction::new(SHOW_WINDOW_ACTION, None);
    let shown_window = window_root.clone();
    show_window_action.connect_activate(move |_activated_action, _parameter| {
        shown_window.present();
    });
    main_application.add_action(&show_window_action);
    window_root.set_content(Some(&adaptive_navigation_layout(
        &sidebar_list,
        &page_stack,
        window_root,
    )));
    ShellContent::VaultReady {
        _application_pages: Box::new(ApplicationPages {
            _vault_lock: vault_lock,
            _device_monitor: device_monitor,
            _scan_page: scan_page,
            _quarantine_page: quarantine_page,
            _database_page: database_page,
            _logs_page: logs_page,
            _signatures_page: signatures_page,
            _hardening_page: hardening_page,
            _protection_page: protection_page,
            _detections_page: detections_page,
            _database_dialog: database_dialog,
        }),
    }
}

type RunningTray = Rc<OnceCell<ksni::Handle<SystemTrayMenu>>>;

fn show_unresolved_detections_in_tray(running_tray: &RunningTray, unresolved_detections: usize) {
    if let Some(tray_handle) = running_tray.get().cloned() {
        relm4::spawn(async move {
            let _tray_stopped = tray_handle
                .update(move |tray_menu: &mut SystemTrayMenu| {
                    tray_menu.unresolved_detections = unresolved_detections;
                })
                .await;
        });
    }
}

fn start_system_tray(
    window_root: &adw::ApplicationWindow,
    running_tray: RunningTray,
    start_in_background: bool,
) {
    let hidden_window = window_root.clone();
    relm4::spawn_local(async move {
        let tray_outcome = relm4::spawn(spawn_system_tray()).await;
        match tray_outcome {
            Ok(Ok(tray_handle)) => {
                let _tray_started_once = running_tray.set(tray_handle);
            }
            Ok(Err(tray_failure)) => {
                eprintln!("the system tray is unavailable: {tray_failure}");
                if !start_in_background {
                    hidden_window.present();
                }
            }
            Err(join_failure) => {
                eprintln!("the system tray could not start: {join_failure}");
                if !start_in_background {
                    hidden_window.present();
                }
            }
        }
    });
}

fn confirm_close_action(window_root: &adw::ApplicationWindow) {
    let close_dialog = adw::AlertDialog::new(
        Some(&gettext("Close Lazaret?")),
        Some(&gettext(
            "Detection alerts stop while Lazaret isn't running. Keep it running in the \
             background, or quit completely?",
        )),
    );
    close_dialog.add_response("cancel", &gettext("Cancel"));
    close_dialog.add_response("quit", &gettext("Quit"));
    close_dialog.add_response("minimize", &gettext("Keep Running"));
    close_dialog.set_default_response(Some("minimize"));
    close_dialog.set_close_response("cancel");
    let answered_window = window_root.clone();
    close_dialog.connect_response(None, move |_dialog, close_response| match close_response {
        "quit" => relm4::main_application().quit(),
        "minimize" => answered_window.set_visible(false),
        _cancelled => {}
    });
    close_dialog.present(Some(window_root));
}

fn handle_window_close(window_root: &adw::ApplicationWindow) {
    window_root.connect_close_request(move |closed_window| {
        match application_settings().string(CLOSE_ACTION_KEY).as_str() {
            "minimize" => {
                closed_window.set_visible(false);
                glib::Propagation::Stop
            }
            "ask" => {
                confirm_close_action(closed_window);
                glib::Propagation::Stop
            }
            _quit => glib::Propagation::Proceed,
        }
    });
}

impl AsyncComponent for ApplicationWindowShell {
    type Init = StartupRequest;
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type Root = adw::ApplicationWindow;
    type Widgets = ();

    fn init_root() -> Self::Root {
        adw::ApplicationWindow::builder()
            .title("Lazaret")
            .width_request(360)
            .height_request(500)
            .default_width(900)
            .default_height(700)
            .build()
    }

    async fn init(
        startup_request: Self::Init,
        root: Self::Root,
        _sender: AsyncComponentSender<Self>,
    ) -> AsyncComponentParts<Self> {
        let running_tray = RunningTray::default();
        let start_in_background = startup_request.start_in_background;
        let data_directory = application_data_directory();
        let lock_path = data_directory.join("quarantine.lock");
        let vault_lock = relm4::spawn(async move {
            tokio::task::spawn_blocking(move || wait_for_file_lock(&lock_path)).await
        })
        .await;
        let opened_vault = QuarantineVault::open_vault(
            data_directory.join("quarantine.db"),
            data_directory.join("quarantine"),
        )
        .await;
        let shell_content = match (vault_lock, opened_vault) {
            (Ok(Ok(Ok(vault_lock))), Ok(quarantine_vault)) => application_pages(
                vault_lock,
                quarantine_vault,
                data_directory,
                &root,
                startup_request,
                Rc::clone(&running_tray),
            ),
            (_lock_outcome, Err(vault_failure)) => {
                let unavailable_page = vault_unavailable_page(&vault_failure);
                let toolbar_view = adw::ToolbarView::new();
                toolbar_view.add_top_bar(&adw::HeaderBar::new());
                toolbar_view.set_content(Some(&unavailable_page));
                root.set_content(Some(&toolbar_view));
                ShellContent::VaultUnavailable
            }
            (_lock_failure, Ok(_quarantine_vault)) => {
                let unavailable_page = adw::StatusPage::builder()
                    .icon_name("dialog-error-symbolic")
                    .title(gettext("The quarantine database could not be locked"))
                    .build();
                let toolbar_view = adw::ToolbarView::new();
                toolbar_view.add_top_bar(&adw::HeaderBar::new());
                toolbar_view.set_content(Some(&unavailable_page));
                root.set_content(Some(&toolbar_view));
                ShellContent::VaultUnavailable
            }
        };
        start_system_tray(&root, running_tray, start_in_background);
        handle_window_close(&root);
        AsyncComponentParts {
            model: Self {
                _shell_content: shell_content,
            },
            widgets: (),
        }
    }
}
