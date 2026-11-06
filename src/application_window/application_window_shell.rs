use gettextrs::gettext;
use relm4::{
    AsyncComponentSender, Component, ComponentController, Controller,
    actions::RelmAction,
    adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, glib},
    prelude::{AsyncComponent, AsyncComponentParts},
};

use crate::{
    APPLICATION_ICON_NAME, application_data_directory,
    application_window::{
        application_actions::{
            AboutAction, PreferencesAction, PreferencesPageAction, QuitAction, ShowWindowAction,
            register_application_action,
        },
        application_pages::ApplicationPage,
        page_navigation::{
            PageNavigation, PageNavigationInit, PageNavigationOutput, StartupDestination,
        },
        startup_arguments::StartupRequest,
        system_tray_connection::{
            RunningTrayHandle, TrayConnection, show_unresolved_detections, start_system_tray,
        },
        window_close_behavior::{CloseAction, CloseAnswer, present_close_confirmation},
    },
    host_services::{
        desktop::{
            file_process_lock::{ProcessFileLock, wait_for_file_lock},
            stored_settings::{CLOSE_ACTION_KEY, application_settings},
            stored_settings_watch::forward_setting_changes,
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
    },
    preferences_dialog::preferences_dialog_component::{
        PreferencesDialog, PreferencesDialogInput, PreferencesPageName,
    },
    quarantine_page::quarantine_entries_page::describe_quarantine_failure,
};

const PREFERENCES_STARTUP_PAGE: &str = "preferences";
const DATABASE_STARTUP_PAGE: &str = "database";

enum WindowContent {
    PagesShown {
        page_navigation: Controller<PageNavigation>,
        _vault_lock: ProcessFileLock,
    },
    VaultUnavailable {
        failure_title: String,
        failure_description: String,
    },
}

pub struct ApplicationWindowShell {
    window_content: WindowContent,
    tray_connection: TrayConnection,
    close_action: CloseAction,
    stored_settings: gio::Settings,
    start_in_background: bool,
    preferences_dialog: Controller<PreferencesDialog>,
}

#[derive(Debug)]
pub enum ApplicationWindowShellInput {
    WindowShowRequested,
    AboutRequested,
    PreferencesRequested(PreferencesPageName),
    QuitRequested,
    WindowCloseRequested,
    CloseAnswered(CloseAnswer),
    CloseActionChanged,
    UnresolvedDetectionsChanged(usize),
}

#[derive(Debug)]
pub enum ApplicationWindowShellCommand {
    TrayStartFinished(Result<RunningTrayHandle, String>),
    TrayUpdated,
}

fn present_about_dialog(parent_window: &adw::ApplicationWindow) {
    adw::AboutDialog::builder()
        .application_name("Lazaret")
        .application_icon(APPLICATION_ICON_NAME)
        .version(env!("CARGO_PKG_VERSION"))
        .license_type(gtk::License::MitX11)
        .website("https://codeberg.org/wvhulle/lazaret")
        .developers(
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/AUTHORS"))
                .lines()
                .filter(|author_line| !author_line.starts_with('#'))
                .collect::<Vec<_>>(),
        )
        .translator_credits(gettext("translator-credits"))
        .build()
        .present(Some(parent_window));
}

fn startup_destination(startup_page: &str) -> StartupDestination {
    match startup_page {
        DATABASE_STARTUP_PAGE => StartupDestination::ShowPage(ApplicationPage::Protection),
        startup_page => StartupDestination::ShowPage(
            ApplicationPage::from_page_name(startup_page).unwrap_or(ApplicationPage::Protection),
        ),
    }
}

fn register_window_actions(sender: &AsyncComponentSender<ApplicationWindowShell>) {
    let about_sender = sender.input_sender().clone();
    register_application_action(RelmAction::<AboutAction>::new_stateless(move |_action| {
        about_sender.emit(ApplicationWindowShellInput::AboutRequested);
    }));
    let preferences_sender = sender.input_sender().clone();
    register_application_action(RelmAction::<PreferencesAction>::new_stateless(
        move |_action| {
            preferences_sender.emit(ApplicationWindowShellInput::PreferencesRequested(
                PreferencesPageName::GeneralPreferences,
            ));
        },
    ));
    let preferences_page_sender = sender.input_sender().clone();
    register_application_action(RelmAction::<PreferencesPageAction>::new_with_target_value(
        move |_action, page_name: String| {
            if let Some(preferences_page) = PreferencesPageName::from_page_name(&page_name) {
                preferences_page_sender.emit(ApplicationWindowShellInput::PreferencesRequested(
                    preferences_page,
                ));
            }
        },
    ));
    let quit_sender = sender.input_sender().clone();
    register_application_action(RelmAction::<QuitAction>::new_stateless(move |_action| {
        quit_sender.emit(ApplicationWindowShellInput::QuitRequested);
    }));
    let show_sender = sender.input_sender().clone();
    register_application_action(RelmAction::<ShowWindowAction>::new_stateless(
        move |_action| show_sender.emit(ApplicationWindowShellInput::WindowShowRequested),
    ));
    let main_application = relm4::main_application();
    main_application.set_accels_for_action("app.preferences", &["<Control>comma"]);
    main_application.set_accels_for_action("app.quit", &["<Control>q"]);
    main_application.set_accels_for_action("window.close", &["<Control>w"]);
}

async fn opened_window_content(
    window_root: &adw::ApplicationWindow,
    startup_request: StartupRequest,
    sender: &AsyncComponentSender<ApplicationWindowShell>,
) -> WindowContent {
    let data_directory = application_data_directory();
    let lock_path = data_directory.join("quarantine.lock");
    let vault_lock = relm4::spawn_blocking(move || wait_for_file_lock(&lock_path)).await;
    let opened_vault = QuarantineVault::open_vault(
        data_directory.join("quarantine.db"),
        data_directory.join("quarantine"),
    )
    .await;
    match (vault_lock, opened_vault) {
        (Ok(Ok(vault_lock)), Ok(quarantine_vault)) => WindowContent::PagesShown {
            page_navigation: PageNavigation::builder()
                .launch(PageNavigationInit {
                    quarantine_vault,
                    data_directory,
                    window_root: window_root.clone(),
                    startup_destination: startup_destination(&startup_request.startup_page),
                    startup_scan_targets: startup_request.scan_targets,
                })
                .forward(
                    sender.input_sender(),
                    |navigation_output| match navigation_output {
                        PageNavigationOutput::WindowPresentRequested => {
                            ApplicationWindowShellInput::WindowShowRequested
                        }
                        PageNavigationOutput::UnresolvedDetectionsChanged(
                            unresolved_detections,
                        ) => ApplicationWindowShellInput::UnresolvedDetectionsChanged(
                            unresolved_detections,
                        ),
                    },
                ),
            _vault_lock: vault_lock,
        },
        (_lock_outcome, Err(vault_failure)) => WindowContent::VaultUnavailable {
            failure_title: gettext("The quarantine database could not be opened"),
            failure_description: describe_quarantine_failure(&vault_failure),
        },
        (_lock_failure, Ok(_quarantine_vault)) => WindowContent::VaultUnavailable {
            failure_title: gettext("The quarantine database could not be locked"),
            failure_description: String::new(),
        },
    }
}

impl WindowContent {
    fn content_widget(&self) -> gtk::Widget {
        match self {
            Self::PagesShown {
                page_navigation, ..
            } => page_navigation.widget().clone().upcast(),
            Self::VaultUnavailable {
                failure_title,
                failure_description,
            } => {
                let toolbar_view = adw::ToolbarView::new();
                toolbar_view.add_top_bar(&adw::HeaderBar::new());
                toolbar_view.set_content(Some(
                    &adw::StatusPage::builder()
                        .icon_name("dialog-error-symbolic")
                        .title(failure_title)
                        .description(glib::markup_escape_text(failure_description))
                        .build(),
                ));
                toolbar_view.upcast()
            }
        }
    }
}

#[relm4::component(async, pub)]
impl AsyncComponent for ApplicationWindowShell {
    type Init = StartupRequest;
    type Input = ApplicationWindowShellInput;
    type Output = ();
    type CommandOutput = ApplicationWindowShellCommand;

    view! {
        adw::ApplicationWindow {
            set_title: Some("Lazaret"),
            set_default_width: 900,
            set_default_height: 700,
            set_content: Some(&content_widget),
            connect_close_request[sender] => move |_closed_window| {
                sender.input(ApplicationWindowShellInput::WindowCloseRequested);
                glib::Propagation::Stop
            },
        }
    }

    async fn init(
        startup_request: Self::Init,
        root: Self::Root,
        sender: AsyncComponentSender<Self>,
    ) -> AsyncComponentParts<Self> {
        let start_in_background = startup_request.start_in_background;
        let presents_preferences = startup_request.startup_page == PREFERENCES_STARTUP_PAGE;
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &[CLOSE_ACTION_KEY],
            sender.input_sender(),
            |_changed_settings, _changed_key| ApplicationWindowShellInput::CloseActionChanged,
        );
        register_window_actions(&sender);
        let model = Self {
            window_content: opened_window_content(&root, startup_request, &sender).await,
            tray_connection: TrayConnection::Starting,
            close_action: CloseAction::read_from(&stored_settings),
            stored_settings,
            start_in_background,
            preferences_dialog: PreferencesDialog::builder().launch(()).detach(),
        };
        let content_widget = model.window_content.content_widget();
        let widgets = view_output!();
        sender.oneshot_command(async {
            ApplicationWindowShellCommand::TrayStartFinished(start_system_tray().await)
        });
        if presents_preferences {
            sender.input(ApplicationWindowShellInput::PreferencesRequested(
                PreferencesPageName::GeneralPreferences,
            ));
        }
        AsyncComponentParts { model, widgets }
    }

    async fn update(
        &mut self,
        shell_input: ApplicationWindowShellInput,
        sender: AsyncComponentSender<Self>,
        root: &Self::Root,
    ) {
        match shell_input {
            ApplicationWindowShellInput::WindowShowRequested => root.present(),
            ApplicationWindowShellInput::AboutRequested => present_about_dialog(root),
            ApplicationWindowShellInput::PreferencesRequested(preferences_page) => {
                self.preferences_dialog
                    .emit(PreferencesDialogInput::PageShown(preferences_page));
                self.preferences_dialog.widget().present(Some(root));
            }
            ApplicationWindowShellInput::QuitRequested
            | ApplicationWindowShellInput::CloseAnswered(CloseAnswer::QuitChosen) => {
                relm4::main_application().quit();
            }
            ApplicationWindowShellInput::CloseAnswered(CloseAnswer::KeepRunningChosen) => {
                root.set_visible(false);
            }
            ApplicationWindowShellInput::CloseAnswered(CloseAnswer::CloseCancelled) => {}
            ApplicationWindowShellInput::WindowCloseRequested => match self.close_action {
                CloseAction::QuitCompletely => relm4::main_application().quit(),
                CloseAction::HideToTray => root.set_visible(false),
                CloseAction::AskEachTime => present_close_confirmation(
                    root,
                    sender.input_sender().clone(),
                    ApplicationWindowShellInput::CloseAnswered,
                ),
            },
            ApplicationWindowShellInput::CloseActionChanged => {
                self.close_action = CloseAction::read_from(&self.stored_settings);
            }
            ApplicationWindowShellInput::UnresolvedDetectionsChanged(unresolved_detections) => {
                if let TrayConnection::Running(tray_handle) = &self.tray_connection {
                    let tray_handle = tray_handle.clone();
                    sender.oneshot_command(async move {
                        show_unresolved_detections(tray_handle, unresolved_detections).await;
                        ApplicationWindowShellCommand::TrayUpdated
                    });
                }
            }
        }
    }

    async fn update_cmd(
        &mut self,
        shell_command: ApplicationWindowShellCommand,
        _sender: AsyncComponentSender<Self>,
        root: &Self::Root,
    ) {
        match shell_command {
            ApplicationWindowShellCommand::TrayStartFinished(Ok(tray_handle)) => {
                self.tray_connection = TrayConnection::Running(tray_handle);
            }
            ApplicationWindowShellCommand::TrayStartFinished(Err(tray_failure)) => {
                eprintln!("the system tray is unavailable: {tray_failure}");
                self.tray_connection = TrayConnection::Unavailable;
                if !self.start_in_background {
                    root.present();
                }
            }
            ApplicationWindowShellCommand::TrayUpdated => {}
        }
    }
}
