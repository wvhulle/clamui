use gettextrs::gettext;
use relm4::{
    FactorySender, adw,
    adw::prelude::*,
    prelude::{DynamicIndex, FactoryComponent},
};

use crate::{
    host_services::clamav_config::detection_options::DetectionOption,
    shared_widgets::engine_settings::config_setting_row::RowChangeActivity,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchAvailability {
    ChangeableNow,
    LockedUntilUnlocked,
    NotAllowedAtRuntime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectionSwitchState {
    pub detection_option: DetectionOption,
    pub switched_on: bool,
    pub switch_availability: SwitchAvailability,
    pub change_activity: RowChangeActivity,
}

pub struct DetectionSwitchRow {
    switch_state: DetectionSwitchState,
}

#[derive(Debug)]
pub enum DetectionSwitchRowInput {
    SwitchStateChanged(DetectionSwitchState),
    ToggleRequested(bool),
}

#[derive(Debug)]
pub enum DetectionSwitchRowOutput {
    SwitchChangeRequested {
        detection_option: DetectionOption,
        switched_on: bool,
    },
}

fn option_title(detection_option: DetectionOption) -> String {
    match detection_option {
        DetectionOption::PotentiallyUnwantedPrograms => {
            gettext("Detect Potentially Unwanted Programs")
        }
        DetectionOption::HeuristicAlerts => gettext("Heuristic Detections"),
        DetectionOption::OfficeMacros => gettext("Flag Office Files With Macros"),
        DetectionOption::EncryptedContent => gettext("Flag Encrypted Archives and Documents"),
        DetectionOption::ArchiveContents => gettext("Look Inside Archives"),
        DetectionOption::OversizedFiles => gettext("Flag Files Too Large to Check Fully"),
    }
}

fn option_description(detection_option: DetectionOption) -> String {
    match detection_option {
        DetectionOption::PotentiallyUnwantedPrograms => {
            gettext("Adware, hacking tools and remote-access tools. Expect more false positives.")
        }
        DetectionOption::HeuristicAlerts => gettext(
            "Suspicious files that no signature names, such as broken executables and phishing \
             tricks.",
        ),
        DetectionOption::OfficeMacros => gettext(
            "Macros are a common way to deliver malware, but many legitimate documents use them.",
        ),
        DetectionOption::EncryptedContent => {
            gettext("ClamAV can't look inside them, so they could hide malware.")
        }
        DetectionOption::ArchiveContents => {
            gettext("Checks the files inside zip, rar and other archives.")
        }
        DetectionOption::OversizedFiles => gettext(
            "Otherwise files above the size and recursion limits pass unchecked without notice.",
        ),
    }
}

impl DetectionSwitchRow {
    fn availability_note(&self) -> String {
        match self.switch_state.switch_availability {
            SwitchAvailability::ChangeableNow => String::new(),
            SwitchAvailability::LockedUntilUnlocked => gettext("Unlock to change this setting."),
            SwitchAvailability::NotAllowedAtRuntime => {
                gettext("Your administrator doesn't allow changing this setting from Lazaret.")
            }
        }
    }

    fn row_subtitle(&self) -> String {
        [
            option_description(self.switch_state.detection_option),
            self.availability_note(),
        ]
        .into_iter()
        .filter(|subtitle_part| !subtitle_part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
    }

    fn accepts_toggles(&self) -> bool {
        self.switch_state.switch_availability == SwitchAvailability::ChangeableNow
            && self.switch_state.change_activity.accepts_changes()
    }
}

#[relm4::factory(pub)]
impl FactoryComponent for DetectionSwitchRow {
    type Init = DetectionSwitchState;
    type Input = DetectionSwitchRowInput;
    type Output = DetectionSwitchRowOutput;
    type CommandOutput = ();
    type ParentWidget = adw::PreferencesGroup;

    view! {
        adw::SwitchRow {
            set_title: &option_title(self.switch_state.detection_option),
            set_subtitle_lines: 0,
            #[watch]
            set_subtitle: &self.row_subtitle(),
            #[watch]
            set_sensitive: self.accepts_toggles(),
            #[watch]
            #[block_signal(switch_toggled_handler)]
            set_active: self.switch_state.switched_on,
            connect_active_notify[sender] => move |toggled_row| {
                sender.input(DetectionSwitchRowInput::ToggleRequested(toggled_row.is_active()));
            } @switch_toggled_handler,
        }
    }

    fn init_model(
        switch_state: DetectionSwitchState,
        _row_index: &DynamicIndex,
        _sender: FactorySender<Self>,
    ) -> Self {
        Self { switch_state }
    }

    fn update(&mut self, row_input: DetectionSwitchRowInput, sender: FactorySender<Self>) {
        match row_input {
            DetectionSwitchRowInput::SwitchStateChanged(switch_state) => {
                self.switch_state = switch_state;
            }
            DetectionSwitchRowInput::ToggleRequested(switched_on) => {
                if switched_on != self.switch_state.switched_on {
                    let _page_closed =
                        sender.output(DetectionSwitchRowOutput::SwitchChangeRequested {
                            detection_option: self.switch_state.detection_option,
                            switched_on,
                        });
                }
            }
        }
    }
}
