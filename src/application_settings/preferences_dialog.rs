use gettextrs::gettext;
use relm4::{
    adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, glib},
};

use crate::{
    application_settings::stored_settings::{
        CLOSE_ACTION_CHOICES, CLOSE_ACTION_KEY, application_settings,
    },
    desktop_integration::{
        file_manager_actions::{
            SUPPORTED_FILE_MANAGERS, file_manager_action_installed, install_file_manager_action,
            remove_file_manager_action,
        },
        flatpak_sandbox::{request_background_autostart, running_in_flatpak},
    },
    scheduled_scans::scan_schedule_units::current_launcher_path,
    threat_intel_lookup::online_lookup_preferences::{
        ONLINE_LOOKUPS_PAGE_NAME, online_lookups_page,
    },
};

const GENERAL_PAGE_NAME: &str = "general";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreferencesPageName {
    GeneralPreferences,
    OnlineLookups,
}

impl PreferencesPageName {
    const fn page_name(self) -> &'static str {
        match self {
            Self::GeneralPreferences => GENERAL_PAGE_NAME,
            Self::OnlineLookups => ONLINE_LOOKUPS_PAGE_NAME,
        }
    }
}

fn file_manager_group() -> adw::PreferencesGroup {
    let integration_group = adw::PreferencesGroup::builder()
        .title(gettext("File Manager Integration"))
        .description(gettext(
            "Add context menu actions for supported file managers.",
        ))
        .build();
    SUPPORTED_FILE_MANAGERS.iter().for_each(|file_manager| {
        let file_manager = *file_manager;
        let data_directory = glib::user_data_dir();
        let manager_row = adw::SwitchRow::builder()
            .title(file_manager.displayed_name())
            .active(file_manager_action_installed(file_manager, &data_directory))
            .build();
        manager_row.connect_active_notify(move |changed_row| {
            let change_outcome = if changed_row.is_active() {
                current_launcher_path().and_then(|launcher_path| {
                    install_file_manager_action(file_manager, &data_directory, &launcher_path)
                })
            } else {
                remove_file_manager_action(file_manager, &data_directory)
            };
            changed_row.set_subtitle(&change_outcome.map_or_else(
                |change_failure| change_failure.to_string(),
                |()| String::new(),
            ));
        });
        integration_group.add(&manager_row);
    });
    integration_group
}

fn window_group(settings: &gio::Settings) -> adw::PreferencesGroup {
    let window_group = adw::PreferencesGroup::builder()
        .title(gettext("Window Behavior"))
        .description(gettext(
            "Detection alerts only work while Lazaret is running.",
        ))
        .build();
    let close_labels = [
        gettext("Quit completely"),
        gettext("Minimize to tray"),
        gettext("Always ask"),
    ];
    let close_row = adw::ComboRow::builder()
        .title(gettext("When closing window"))
        .model(&gtk::StringList::new(
            &close_labels.iter().map(String::as_str).collect::<Vec<_>>(),
        ))
        .selected(
            CLOSE_ACTION_CHOICES
                .iter()
                .position(|close_choice| *close_choice == settings.string(CLOSE_ACTION_KEY))
                .unwrap_or(0) as u32,
        )
        .build();
    let close_settings = settings.clone();
    close_row.connect_selected_notify(move |changed_row| {
        if let Some(close_choice) = CLOSE_ACTION_CHOICES.get(changed_row.selected() as usize) {
            let _read_only_settings = close_settings.set_string(CLOSE_ACTION_KEY, close_choice);
        }
    });
    window_group.add(&close_row);
    let background_row = adw::SwitchRow::builder()
        .title(gettext("Start in the Background"))
        .subtitle(gettext(
            "Launch in the background without opening a window.",
        ))
        .build();
    settings
        .bind("start-in-background", &background_row, "active")
        .build();
    if running_in_flatpak() {
        background_row.connect_active_notify(|changed_row| {
            let autostart_enabled = changed_row.is_active();
            relm4::spawn(async move {
                if let Err(portal_failure) = request_background_autostart(autostart_enabled).await {
                    eprintln!("lazaret: the Background portal refused autostart: {portal_failure}");
                }
            });
        });
    }
    window_group.add(&background_row);
    let notifications_row = adw::SwitchRow::builder()
        .title(gettext("Desktop Notifications"))
        .subtitle(gettext(
            "Notify about detections, and about finished scans and updates while the window is \
             not in focus.",
        ))
        .build();
    settings
        .bind("notifications-enabled", &notifications_row, "active")
        .build();
    window_group.add(&notifications_row);
    window_group
}

fn general_page(settings: &gio::Settings) -> adw::PreferencesPage {
    let general_page = adw::PreferencesPage::builder()
        .title(gettext("General"))
        .icon_name("preferences-system-symbolic")
        .name(GENERAL_PAGE_NAME)
        .build();
    general_page.add(&window_group(settings));
    if !running_in_flatpak() {
        general_page.add(&file_manager_group());
    }
    general_page
}

pub fn present_preferences_dialog(shown_page: PreferencesPageName) {
    let preferences_dialog = adw::PreferencesDialog::builder()
        .title(gettext("Preferences"))
        .search_enabled(true)
        .build();
    preferences_dialog.add(&general_page(&application_settings()));
    let lookups_page = online_lookups_page();
    preferences_dialog.add(&lookups_page.lookups_page);
    preferences_dialog.set_visible_page_name(shown_page.page_name());
    let key_groups = lookups_page.key_groups;
    preferences_dialog.connect_closed(move |_closed_dialog| {
        let _keep_groups_until_closed = &key_groups;
    });
    preferences_dialog.present(relm4::main_application().active_window().as_ref());
}
