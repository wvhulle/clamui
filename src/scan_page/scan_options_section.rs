use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual},
};

use crate::{
    application_window::settings_navigation::{
        SettingsSubpage, settings_link_group, system_settings_group,
    },
    host_services::desktop::{
        stored_settings::{
            SCAN_BACKEND_CHOICES, SCAN_BACKEND_KEY, SHOW_LIVE_PROGRESS_KEY, application_settings,
        },
        stored_settings_watch::forward_setting_changes,
    },
};

pub struct ScanOptionsSection {
    stored_settings: gio::Settings,
    backend_position: u32,
    shows_live_progress: bool,
}

#[derive(Debug)]
pub enum ScanOptionsSectionInput {
    BackendChosen(u32),
    LiveProgressToggled(bool),
    StoredSettingChanged,
}

fn stored_backend_position(stored_settings: &gio::Settings) -> u32 {
    let stored_backend = stored_settings.string(SCAN_BACKEND_KEY);
    SCAN_BACKEND_CHOICES
        .iter()
        .position(|backend_choice| *backend_choice == stored_backend)
        .and_then(|backend_position| u32::try_from(backend_position).ok())
        .unwrap_or(0)
}

fn backend_labels() -> gtk::StringList {
    let backend_labels = [
        gettext("Automatic"),
        gettext("clamd (daemon)"),
        gettext("clamscan (standalone)"),
    ];
    gtk::StringList::new(
        &backend_labels
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )
}

impl ScanOptionsSection {
    fn read_stored_settings(&mut self) {
        self.backend_position = stored_backend_position(&self.stored_settings);
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
                    set_selected: model.backend_position,
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

            append: &settings_link_group(
                gettext("More"),
                &[
                    SettingsSubpage::ScanExclusions,
                    SettingsSubpage::ScanSchedule,
                    SettingsSubpage::DeviceAutoScan,
                ],
            ),
            append: &system_settings_group(&[
                SettingsSubpage::DetectionChoices,
                SettingsSubpage::ScannerEngine,
            ]),
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
        let mut model = Self {
            stored_settings,
            backend_position: 0,
            shows_live_progress: false,
        };
        model.read_stored_settings();
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
            ScanOptionsSectionInput::BackendChosen(backend_position) => {
                if let Some(backend_choice) = usize::try_from(backend_position)
                    .ok()
                    .and_then(|backend_position| SCAN_BACKEND_CHOICES.get(backend_position))
                {
                    self.backend_position = backend_position;
                    let _read_only_settings = self
                        .stored_settings
                        .set_string(SCAN_BACKEND_KEY, backend_choice);
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
