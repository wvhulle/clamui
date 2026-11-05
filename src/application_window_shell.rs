use std::{cell::OnceCell, path::PathBuf, rc::Rc};

use gettextrs::gettext;
use ksni::TrayMethods;
use relm4::{
    AsyncComponentSender, Component, ComponentController, Controller, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, glib},
    prelude::{AsyncComponent, AsyncComponentParts},
};

use crate::{
    APPLICATION_DATA_NAME, APPLICATION_ID,
    activity_history::{
        activity_history_database::ActivityHistory,
        activity_logs_page::{ActivityLogsPage, ActivityLogsPageInput},
    },
    application_data_directory,
    application_settings::preferences_dialog::{
        CLOSE_ACTION_KEY, application_settings, present_preferences_dialog,
    },
    background_detections::background_detections_page::{
        BackgroundDetectionsPage, BackgroundDetectionsPageInit, BackgroundDetectionsPageOutput,
    },
    clamav_components::component_status_page::ComponentStatusPage,
    desktop_integration::{
        device_mount_scans::watch_device_mounts,
        running_instance_forwarding::{
            SCAN_PATHS_ACTION, SHOW_WINDOW_ACTION, paths_from_variant, scan_paths_action_type,
        },
        system_tray_menu::SystemTrayMenu,
    },
    file_process_lock::{ProcessFileLock, wait_for_file_lock},
    file_quarantine::{
        quarantine_entries_page::{
            QuarantineEntriesPage, QuarantineEntriesPageInput, describe_quarantine_failure,
        },
        quarantine_entry_database::QuarantineVault,
        quarantine_file_moves::QuarantineMoveFailure,
    },
    malware_scan::scan_progress_page::{
        ScanProgressPage, ScanProgressPageInit, ScanProgressPageInput, ScanProgressPageOutput,
    },
    protection_status::protection_timeline_page::{
        ProtectionTimelinePage, ProtectionTimelinePageInput, ProtectionTimelinePageOutput,
    },
    scan_profiles::scan_profile_store::ScanProfileStore,
    startup_arguments::StartupRequest,
    virus_database::database_update_page::{
        DatabaseUpdatePage, DatabaseUpdatePageInput, DatabaseUpdatePageOutput,
    },
};

const PREFERENCES_STARTUP_PAGE: &str = "preferences";
const DATABASE_STARTUP_PAGE: &str = "database";
const SCAN_PAGE_NAME: &str = "scan";

struct ApplicationPages {
    _device_monitor: gio::VolumeMonitor,
    _vault_lock: ProcessFileLock,
    _scan_page: Controller<ScanProgressPage>,
    _quarantine_page: Controller<QuarantineEntriesPage>,
    _database_page: Controller<DatabaseUpdatePage>,
    _component_page: Controller<ComponentStatusPage>,
    _logs_page: Controller<ActivityLogsPage>,
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

fn navigation_stack(navigation_pages: &[NavigationPage<'_>]) -> gtk::Stack {
    let page_stack = gtk::Stack::builder()
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();
    navigation_pages.iter().for_each(|navigation_page| {
        page_stack.add_titled(
            navigation_page.page_widget,
            Some(navigation_page.page_name),
            &navigation_page.page_title,
        );
        relm4::main_application().set_accels_for_action(
            &format!("win.show-page::{}", navigation_page.page_name),
            &[navigation_page.keyboard_accelerator],
        );
    });
    page_stack
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
    primary_menu.append(Some(&gettext("About ClamUI")), Some("app.about"));
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
        .application_name("ClamUI")
        .application_icon(APPLICATION_ID)
        .version(env!("CARGO_PKG_VERSION"))
        .license_type(gtk::License::MitX11)
        .website("https://github.com/linx-systems/clamui")
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
    preferences_action
        .connect_activate(|_activated_action, _parameter| present_preferences_dialog());
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

fn adaptive_navigation_layout(
    sidebar_list: &gtk::ListBox,
    page_stack: &gtk::Stack,
    window_root: &adw::ApplicationWindow,
) -> adw::OverlaySplitView {
    let sidebar_header = adw::HeaderBar::builder()
        .title_widget(&adw::WindowTitle::new("ClamUI", ""))
        .build();
    sidebar_header.pack_end(&primary_menu_button());
    let sidebar_view = adw::ToolbarView::new();
    sidebar_view.add_top_bar(&sidebar_header);
    sidebar_view.set_content(Some(
        &gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(sidebar_list)
            .build(),
    ));

    let split_view = adw::OverlaySplitView::builder()
        .sidebar(&sidebar_view)
        .sidebar_width_fraction(0.22)
        .build();
    let activated_split_view = split_view.clone();
    sidebar_list.connect_row_activated(move |_sidebar_list, _activated_row| {
        if activated_split_view.is_collapsed() {
            activated_split_view.set_show_sidebar(false);
        }
    });
    let sidebar_toggle = gtk::ToggleButton::builder()
        .icon_name("sidebar-show-symbolic")
        .tooltip_text(gettext("Toggle sidebar"))
        .build();
    split_view
        .bind_property("show-sidebar", &sidebar_toggle, "active")
        .bidirectional()
        .sync_create()
        .build();
    split_view
        .bind_property("collapsed", &sidebar_toggle, "visible")
        .sync_create()
        .build();
    let content_header = adw::HeaderBar::builder().show_title(false).build();
    content_header.pack_start(&sidebar_toggle);
    let content_view = adw::ToolbarView::new();
    content_view.add_top_bar(&content_header);
    content_view.set_content(Some(page_stack));
    split_view.set_content(Some(&content_view));

    if let Ok(narrow_condition) = adw::BreakpointCondition::parse("max-width: 640sp") {
        let narrow_breakpoint = adw::Breakpoint::new(narrow_condition);
        narrow_breakpoint.add_setter(&split_view, "collapsed", Some(&true.to_value()));
        window_root.add_breakpoint(narrow_breakpoint);
    }
    split_view
}

fn application_pages(
    vault_lock: ProcessFileLock,
    quarantine_vault: QuarantineVault,
    data_directory: PathBuf,
    window_root: &adw::ApplicationWindow,
    startup_request: StartupRequest,
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
    let component_page = ComponentStatusPage::builder().launch(()).detach();
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
    let detections_page = BackgroundDetectionsPage::builder()
        .launch(BackgroundDetectionsPageInit {
            activity_history: detections_history,
            quarantine_vault: detections_vault,
        })
        .connect_receiver(
            move |_detections_sender, detections_output| match detections_output {
                BackgroundDetectionsPageOutput::UnresolvedCountChanged(unresolved_detections) => {
                    protection_input_sender.emit(
                        ProtectionTimelinePageInput::UnresolvedDetectionsChanged(
                            unresolved_detections,
                        ),
                    );
                }
                BackgroundDetectionsPageOutput::QuarantineEntriesChanged => {
                    detection_quarantine_sender
                        .emit(QuarantineEntriesPageInput::ReloadEntriesRequested);
                }
                BackgroundDetectionsPageOutput::DetectionsOpened(_opened_detections) => {}
            },
        );

    let navigation_pages = [
        NavigationPage {
            page_name: "protection",
            page_title: gettext("Protection"),
            page_icon: "security-high-symbolic",
            page_widget: protection_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>1",
        },
        NavigationPage {
            page_name: "detections",
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
            page_name: "components",
            page_title: gettext("Components"),
            page_icon: "emblem-system-symbolic",
            page_widget: component_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>5",
        },
        NavigationPage {
            page_name: "quarantine",
            page_title: gettext("Quarantine"),
            page_icon: "folder-symbolic",
            page_widget: quarantine_page.widget().upcast_ref(),
            keyboard_accelerator: "<Control>6",
        },
    ];
    let page_stack = navigation_stack(&navigation_pages);
    match startup_request.startup_page.as_str() {
        PREFERENCES_STARTUP_PAGE => present_preferences_dialog(),
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
            _component_page: component_page,
            _logs_page: logs_page,
            _protection_page: protection_page,
            _detections_page: detections_page,
            _database_dialog: database_dialog,
        }),
    }
}

type RunningTray = Rc<OnceCell<ksni::Handle<SystemTrayMenu>>>;

fn start_system_tray(window_root: &adw::ApplicationWindow, running_tray: RunningTray) {
    let hidden_window = window_root.clone();
    relm4::spawn_local(async move {
        let tray_outcome = relm4::spawn(async { SystemTrayMenu.spawn().await }).await;
        match tray_outcome {
            Ok(Ok(tray_handle)) => {
                let _tray_started_once = running_tray.set(tray_handle);
            }
            _tray_unavailable => hidden_window.present(),
        }
    });
}

fn confirm_close_action(window_root: &adw::ApplicationWindow) {
    let close_dialog = adw::AlertDialog::new(
        Some(&gettext("Close ClamUI?")),
        Some(&gettext(
            "Keep ClamUI running in the system tray, or quit completely?",
        )),
    );
    close_dialog.add_response("cancel", &gettext("Cancel"));
    close_dialog.add_response("quit", &gettext("Quit"));
    close_dialog.add_response("minimize", &gettext("Minimize to tray"));
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

fn handle_window_close(window_root: &adw::ApplicationWindow, running_tray: RunningTray) {
    window_root.connect_close_request(move |closed_window| {
        if running_tray.get().is_none() {
            return glib::Propagation::Proceed;
        }
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
            .title("ClamUI")
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
        let running_tray = RunningTray::default();
        start_system_tray(&root, Rc::clone(&running_tray));
        handle_window_close(&root, running_tray);
        AsyncComponentParts {
            model: Self {
                _shell_content: shell_content,
            },
            widgets: (),
        }
    }
}
