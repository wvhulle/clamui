use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual},
};

use crate::host_services::{
    clamav_scanner::scanner_command_builder::ScannerBackendPreference,
    desktop::{
        stored_settings::{
            SCAN_BACKEND_CHOICES, SCAN_BACKEND_KEY, SHOW_LIVE_PROGRESS_KEY, application_settings,
            scanner_backend_preference,
        },
        stored_settings_watch::forward_setting_changes,
    },
};

pub struct ScanOptionsSection {
    stored_settings: gio::Settings,
    backend_preference: ScannerBackendPreference,
    shows_live_progress: bool,
}

#[derive(Debug)]
pub enum ScanOptionsSectionInput {
    BackendChosen(u32),
    LiveProgressToggled(bool),
    StoredSettingChanged,
}

fn backend_choice_label(backend_preference: ScannerBackendPreference) -> String {
    match backend_preference {
        ScannerBackendPreference::PreferClamdWhenAvailable => gettext("Automatic"),
        ScannerBackendPreference::AlwaysClamd => gettext("clamd (daemon)"),
        ScannerBackendPreference::AlwaysClamscan => gettext("clamscan (standalone)"),
    }
}

fn backend_labels() -> gtk::StringList {
    let backend_labels = SCAN_BACKEND_CHOICES.map(backend_choice_label);
    gtk::StringList::new(
        &backend_labels
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
}

impl ScanOptionsSection {
    fn read_stored_settings(&mut self) {
        self.backend_preference = scanner_backend_preference(&self.stored_settings);
        self.shows_live_progress = self.stored_settings.boolean(SHOW_LIVE_PROGRESS_KEY);
    }
}

#[relm4::component(pub)]
impl Component for ScanOptionsSection {
    type Init = ();
    type Input = ScanOptionsSectionInput;
    type Output = ();
    type CommandOutput = ();

    view! {
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_spacing: 18,
            set_margin_top: 12,

            adw::PreferencesGroup {
                set_title: &gettext("Options"),

                adw::ComboRow {
                    set_title: &gettext("Scan Backend"),
                    set_subtitle: &gettext(
                        "Automatic uses the daemon when it answers and clamscan otherwise.",
                    ),
                    set_model: Some(&backend_labels()),
                    #[watch]
                    #[block_signal(backend_selected_handler)]
                    set_selected: model.backend_preference.choice_position(),
                    connect_selected_notify[sender] => move |changed_row| {
                        sender.input(ScanOptionsSectionInput::BackendChosen(changed_row.selected()));
                    } @backend_selected_handler,
                },

                adw::SwitchRow {
                    set_title: &gettext("Show Live Scan Progress"),
                    set_subtitle: &gettext("Display files being scanned in real time."),
                    #[watch]
                    #[block_signal(live_progress_handler)]
                    set_active: model.shows_live_progress,
                    connect_active_notify[sender] => move |changed_row| {
                        sender.input(ScanOptionsSectionInput::LiveProgressToggled(
                            changed_row.is_active(),
                        ));
                    } @live_progress_handler,
                },
            },

        }
    }

    fn init(
        _section_init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &[SCAN_BACKEND_KEY, SHOW_LIVE_PROGRESS_KEY],
            sender.input_sender(),
            |_changed_settings, _changed_key| ScanOptionsSectionInput::StoredSettingChanged,
        );
        let model = Self {
            backend_preference: scanner_backend_preference(&stored_settings),
            shows_live_progress: stored_settings.boolean(SHOW_LIVE_PROGRESS_KEY),
            stored_settings,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        section_input: ScanOptionsSectionInput,
        _sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match section_input {
            ScanOptionsSectionInput::BackendChosen(choice_position) => {
                if let Some(backend_preference) =
                    ScannerBackendPreference::from_choice_position(choice_position)
                {
                    self.backend_preference = backend_preference;
                    backend_preference.store_into(&self.stored_settings);
                }
            }
            ScanOptionsSectionInput::LiveProgressToggled(shows_live_progress) => {
                self.shows_live_progress = shows_live_progress;
                let _read_only_settings = self
                    .stored_settings
                    .set(SHOW_LIVE_PROGRESS_KEY, shows_live_progress);
            }
            ScanOptionsSectionInput::StoredSettingChanged => self.read_stored_settings(),
        }
    }
}
