use std::path::PathBuf;

use gettextrs::gettext;
use relm4::{
    Component, ComponentParts, ComponentSender, adw,
    adw::prelude::*,
    gtk,
    gtk::{gio, gio::prelude::SettingsExtManual, glib},
};

use crate::{
    activity_history::activity_entry_row::formatted_local_time,
    application_settings::preferences_dialog::application_settings,
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    scheduled_scans::scan_schedule_units::{
        ScanSchedule, ScheduleApplyFailure, ScheduleFrequency, ScheduleTimerState,
        disable_scan_schedule, enable_scan_schedule, parse_schedule_time,
        read_schedule_timer_state,
    },
    systemd_bus::host_systemd_units::{
        TimerUnitSnapshot, UnitState, UnitTimestamp, timer_unit_snapshot,
    },
};

const ENABLED_KEY: &str = "schedule-enabled";
const SYSTEM_SCAN_TIMER: &str = "clamdscan.timer";
const FREQUENCY_KEY: &str = "schedule-frequency";
const TIME_KEY: &str = "schedule-time";
const WEEKDAY_KEY: &str = "schedule-day-of-week";
const MONTH_DAY_KEY: &str = "schedule-day-of-month";
const TARGETS_KEY: &str = "schedule-targets";
const SKIP_ON_BATTERY_KEY: &str = "schedule-skip-on-battery";
const AUTO_QUARANTINE_KEY: &str = "schedule-auto-quarantine";
const FREQUENCY_CHOICES: [ScheduleFrequency; 4] = [
    ScheduleFrequency::Hourly,
    ScheduleFrequency::Daily,
    ScheduleFrequency::Weekly,
    ScheduleFrequency::Monthly,
];

pub struct SchedulePreferencesPage {
    settings: gio::Settings,
    timer_state_text: String,
    system_schedule_owner: SystemScheduleOwner,
    page_notice: String,
}

#[derive(Debug)]
pub enum SchedulePreferencesPageInput {
    ApplyRequested,
}

#[derive(Debug)]
pub enum SchedulePreferencesPageCommand {
    TimerStateLoaded(ScheduleTimerState),
    SystemTimerInspected(SystemScheduleOwner),
    ScheduleApplied(Result<(), ScheduleApplyFailure>),
}

fn systemd_user_unit_directory() -> PathBuf {
    glib::user_config_dir().join("systemd/user")
}

fn scan_schedule_from_settings(settings: &gio::Settings) -> Option<ScanSchedule> {
    let clock_time = parse_schedule_time(&settings.string(TIME_KEY))?;
    Some(ScanSchedule {
        schedule_frequency: ScheduleFrequency::from_stored_text(&settings.string(FREQUENCY_KEY)),
        scan_hour: clock_time.scan_hour,
        scan_minute: clock_time.scan_minute,
        weekday_position: u8::try_from(settings.int(WEEKDAY_KEY)).unwrap_or(0),
        month_day: u8::try_from(settings.int(MONTH_DAY_KEY)).unwrap_or(1),
        scan_targets: settings
            .strv(TARGETS_KEY)
            .iter()
            .map(ToString::to_string)
            .collect(),
        skip_on_battery: settings.boolean(SKIP_ON_BATTERY_KEY),
        auto_quarantine: settings.boolean(AUTO_QUARANTINE_KEY),
    })
}

fn describe_timer_state(timer_state: &ScheduleTimerState) -> String {
    match timer_state {
        ScheduleTimerState::TimerInactive => gettext("Not scheduled"),
        ScheduleTimerState::TimerActive { next_run_text } => {
            gettext("Next run: {time}").replace("{time}", &sanitize_scanner_line(next_run_text))
        }
        ScheduleTimerState::SystemdUnavailable => {
            gettext("Scheduled scans need a systemd user session, which is not available.")
        }
    }
}

fn describe_system_schedule(next_run: UnitTimestamp) -> String {
    match next_run {
        UnitTimestamp::RecordedAt { unix_seconds } => gettext(
            "Your system already runs scheduled scans, so these settings are locked to avoid a \
             second schedule. Next scan: {time}. Change it in your system configuration.",
        )
        .replace("{time}", &formatted_local_time(unix_seconds)),
        UnitTimestamp::NeverRecorded => gettext(
            "Your system has a scan timer, so these settings are locked to avoid a second \
             schedule. Change it in your system configuration.",
        ),
    }
}

fn describe_apply_failure(apply_failure: &ScheduleApplyFailure) -> String {
    match apply_failure {
        ScheduleApplyFailure::UnitFilesUnwritable(unit_failure) => {
            gettext("Error creating systemd files: {error}")
                .replace("{error}", &unit_failure.to_string())
        }
        ScheduleApplyFailure::UserManagerFailed(manager_failure) => {
            gettext("The timer could not be applied: {error}")
                .replace("{error}", &manager_failure.to_string())
        }
    }
}

fn frequency_labels() -> gtk::StringList {
    let labels = [
        gettext("Hourly"),
        gettext("Daily"),
        gettext("Weekly"),
        gettext("Monthly"),
    ];
    gtk::StringList::new(&labels.iter().map(String::as_str).collect::<Vec<_>>())
}

fn weekday_labels() -> gtk::StringList {
    let labels = [
        gettext("Monday"),
        gettext("Tuesday"),
        gettext("Wednesday"),
        gettext("Thursday"),
        gettext("Friday"),
        gettext("Saturday"),
        gettext("Sunday"),
    ];
    gtk::StringList::new(&labels.iter().map(String::as_str).collect::<Vec<_>>())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemScheduleOwner {
    NoSystemTimer,
    SystemTimerExists { next_run: UnitTimestamp },
}

pub fn system_schedule_owner(timer_snapshot: TimerUnitSnapshot) -> SystemScheduleOwner {
    match timer_snapshot.unit_state {
        UnitState::UnitActive | UnitState::UnitInactive => SystemScheduleOwner::SystemTimerExists {
            next_run: timer_snapshot.next_run,
        },
        UnitState::UnitNotFound | UnitState::SystemdUnavailable => {
            SystemScheduleOwner::NoSystemTimer
        }
    }
}

impl SchedulePreferencesPage {
    fn refresh_timer_state(&self, sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            SchedulePreferencesPageCommand::SystemTimerInspected(system_schedule_owner(
                timer_unit_snapshot(SYSTEM_SCAN_TIMER).await,
            ))
        });
        sender.oneshot_command(async {
            SchedulePreferencesPageCommand::TimerStateLoaded(read_schedule_timer_state().await)
        });
    }
}

#[relm4::component(pub)]
impl Component for SchedulePreferencesPage {
    type Init = ();
    type Input = SchedulePreferencesPageInput;
    type Output = ();
    type CommandOutput = SchedulePreferencesPageCommand;

    view! {
        adw::PreferencesPage {
            set_title: &gettext("Scheduled"),
            set_icon_name: Some("alarm-symbolic"),

            add = &adw::PreferencesGroup {
                set_title: &gettext("Scheduled Scans"),
                #[watch]
                set_sensitive: model.system_schedule_owner == SystemScheduleOwner::NoSystemTimer,
                #[watch]
                set_description: Some(&model.timer_state_text),
                #[wrap(Some)]
                set_header_suffix = &gtk::Button {
                    set_label: &gettext("Apply"),
                    set_valign: gtk::Align::Center,
                    add_css_class: "suggested-action",
                    connect_clicked => SchedulePreferencesPageInput::ApplyRequested,
                },

                #[name = "enabled_row"]
                adw::SwitchRow {
                    set_title: &gettext("Enable Scheduled Scans"),
                },

                #[name = "frequency_row"]
                adw::ComboRow {
                    set_title: &gettext("Scan Frequency"),
                    set_model: Some(&frequency_labels()),
                },

                #[name = "time_row"]
                adw::EntryRow {
                    set_title: &gettext("Scan Time (24-hour)"),
                },

                #[name = "weekday_row"]
                adw::ComboRow {
                    set_title: &gettext("Day of Week"),
                    set_subtitle: &gettext("Used for weekly scans."),
                    set_model: Some(&weekday_labels()),
                },

                #[name = "month_day_row"]
                adw::SpinRow {
                    set_title: &gettext("Day of Month"),
                    set_subtitle: &gettext("Used for monthly scans."),
                    set_adjustment: Some(&gtk::Adjustment::new(1.0, 1.0, 28.0, 1.0, 7.0, 0.0)),
                },

                #[name = "targets_row"]
                adw::EntryRow {
                    set_title: &gettext("Scan Targets (separated by commas; empty scans your home folder)"),
                },

                #[name = "battery_row"]
                adw::SwitchRow {
                    set_title: &gettext("Skip on Battery"),
                    set_subtitle: &gettext("Do not start scheduled scans while on battery power."),
                },

                #[name = "quarantine_row"]
                adw::SwitchRow {
                    set_title: &gettext("Auto-Quarantine"),
                    set_subtitle: &gettext("Automatically quarantine threats found by scheduled scans. While ClamUI is open, threats are only reported."),
                },
            },

            add = &adw::PreferencesGroup {
                gtk::Label {
                    set_xalign: 0.0,
                    set_wrap: true,
                    add_css_class: "error",
                    #[watch]
                    set_visible: !model.page_notice.is_empty(),
                    #[watch]
                    set_label: &model.page_notice,
                },
            },
        }
    }

    fn init((): (), root: Self::Root, sender: ComponentSender<Self>) -> ComponentParts<Self> {
        let model = Self {
            settings: application_settings(),
            timer_state_text: gettext("Checking…"),
            system_schedule_owner: SystemScheduleOwner::NoSystemTimer,
            page_notice: String::new(),
        };
        let widgets = view_output!();
        let settings = &model.settings;
        settings
            .bind(ENABLED_KEY, &widgets.enabled_row, "active")
            .build();
        settings.bind(TIME_KEY, &widgets.time_row, "text").build();
        settings
            .bind(SKIP_ON_BATTERY_KEY, &widgets.battery_row, "active")
            .build();
        settings
            .bind(AUTO_QUARANTINE_KEY, &widgets.quarantine_row, "active")
            .build();
        settings
            .bind(WEEKDAY_KEY, &widgets.weekday_row, "selected")
            .mapping(|stored_value, _value_type| {
                stored_value
                    .get::<i32>()
                    .map(|weekday| (weekday.max(0) as u32).to_value())
            })
            .set_mapping(|selected_value, _variant_type| {
                selected_value
                    .get::<u32>()
                    .ok()
                    .map(|weekday| (weekday as i32).to_variant())
            })
            .build();
        settings
            .bind(MONTH_DAY_KEY, &widgets.month_day_row, "value")
            .mapping(|stored_value, _value_type| {
                stored_value
                    .get::<i32>()
                    .map(|month_day| f64::from(month_day).to_value())
            })
            .set_mapping(|spin_value, _variant_type| {
                spin_value
                    .get::<f64>()
                    .ok()
                    .map(|month_day| (month_day as i32).to_variant())
            })
            .build();
        widgets.frequency_row.set_selected(
            FREQUENCY_CHOICES
                .iter()
                .position(|frequency_choice| {
                    frequency_choice.stored_text() == settings.string(FREQUENCY_KEY).as_str()
                })
                .unwrap_or(1) as u32,
        );
        let frequency_settings = settings.clone();
        widgets
            .frequency_row
            .connect_selected_notify(move |changed_row| {
                if let Some(frequency_choice) =
                    FREQUENCY_CHOICES.get(changed_row.selected() as usize)
                {
                    let _read_only_settings = frequency_settings
                        .set_string(FREQUENCY_KEY, frequency_choice.stored_text());
                }
            });
        widgets.targets_row.set_text(
            &settings
                .strv(TARGETS_KEY)
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
        let targets_settings = settings.clone();
        widgets.targets_row.connect_changed(move |changed_row| {
            let target_text = changed_row.text();
            let listed_targets = target_text
                .split(',')
                .map(str::trim)
                .filter(|listed_target| !listed_target.is_empty())
                .collect::<Vec<_>>();
            let _read_only_settings = targets_settings.set_strv(TARGETS_KEY, listed_targets);
        });
        model.refresh_timer_state(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: SchedulePreferencesPageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_input {
            SchedulePreferencesPageInput::ApplyRequested => {
                self.page_notice.clear();
                if !self.settings.boolean(ENABLED_KEY) {
                    sender.oneshot_command(async {
                        SchedulePreferencesPageCommand::ScheduleApplied(
                            disable_scan_schedule(systemd_user_unit_directory()).await,
                        )
                    });
                    return;
                }
                let Some(scan_schedule) = scan_schedule_from_settings(&self.settings) else {
                    self.page_notice = gettext("Enter the scan time as HH:MM, for example 02:00.");
                    return;
                };
                sender.oneshot_command(async move {
                    SchedulePreferencesPageCommand::ScheduleApplied(
                        enable_scan_schedule(systemd_user_unit_directory(), scan_schedule).await,
                    )
                });
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: SchedulePreferencesPageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        match page_command {
            SchedulePreferencesPageCommand::TimerStateLoaded(timer_state) => {
                if self.system_schedule_owner == SystemScheduleOwner::NoSystemTimer {
                    self.timer_state_text = describe_timer_state(&timer_state);
                }
            }
            SchedulePreferencesPageCommand::SystemTimerInspected(system_schedule_owner) => {
                self.system_schedule_owner = system_schedule_owner;
                if let SystemScheduleOwner::SystemTimerExists { next_run } = system_schedule_owner {
                    self.timer_state_text = describe_system_schedule(next_run);
                }
            }
            SchedulePreferencesPageCommand::ScheduleApplied(apply_outcome) => {
                if let Err(apply_failure) = apply_outcome {
                    self.page_notice = describe_apply_failure(&apply_failure);
                }
                self.refresh_timer_state(&sender);
            }
        }
    }
}

#[cfg(test)]
mod schedule_preferences_page_tests {
    use super::*;

    fn timer_snapshot_with(unit_state: UnitState) -> TimerUnitSnapshot {
        TimerUnitSnapshot {
            unit_state,
            next_run: UnitTimestamp::NeverRecorded,
            last_trigger: UnitTimestamp::NeverRecorded,
        }
    }

    #[test]
    fn an_installed_system_timer_locks_the_schedule_even_when_stopped() {
        [UnitState::UnitActive, UnitState::UnitInactive]
            .into_iter()
            .for_each(|unit_state| {
                assert!(matches!(
                    system_schedule_owner(timer_snapshot_with(unit_state)),
                    SystemScheduleOwner::SystemTimerExists { .. }
                ));
            });
    }

    #[test]
    fn hosts_without_a_system_timer_keep_their_own_schedule() {
        [UnitState::UnitNotFound, UnitState::SystemdUnavailable]
            .into_iter()
            .for_each(|unit_state| {
                assert_eq!(
                    system_schedule_owner(timer_snapshot_with(unit_state)),
                    SystemScheduleOwner::NoSystemTimer
                );
            });
    }
}
