use gettextrs::gettext;
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk, gtk::gio};

use crate::{
    host_services::{
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::{
            locale_formatting::exact_local_time_text, stored_settings::application_settings,
            stored_settings_watch::forward_setting_changes,
        },
        systemd_bus::host_systemd_units::{
            TimerUnitSnapshot, UnitState, UnitTimestamp, timer_unit_snapshot,
        },
    },
    scan_page::scan_schedule_page::{
        scan_schedule_settings::{
            SCHEDULE_SETTING_KEYS, StoredScheduleSettings, frequency_at, frequency_position,
            joined_scan_targets, listed_scan_targets,
        },
        scan_schedule_units::{
            ScheduleApplyFailure, ScheduleTimerState, disable_scan_schedule, enable_scan_schedule,
            read_schedule_timer_state, systemd_user_unit_directory,
        },
    },
};

const SYSTEM_SCAN_TIMER: &str = "clamdscan.timer";

pub struct ScanSchedulePage {
    stored_settings: gio::Settings,
    schedule_settings: StoredScheduleSettings,
    scan_targets_text: String,
    entry_texts_replaced: bool,
    timer_state_text: String,
    system_schedule_owner: SystemScheduleOwner,
    page_notice: String,
}

#[derive(Debug)]
pub enum ScanSchedulePageInput {
    ScheduleToggled(bool),
    FrequencyChosen(u32),
    TimeTextChanged(String),
    WeekdayChosen(u32),
    MonthDayChanged(f64),
    TargetsTextChanged(String),
    BatterySkipToggled(bool),
    AutoQuarantineToggled(bool),
    StoredSettingChanged,
    ApplyRequested,
}

#[derive(Debug)]
pub enum ScanSchedulePageCommand {
    TimerStateLoaded(ScheduleTimerState),
    SystemTimerInspected(SystemScheduleOwner),
    ScheduleApplied(Result<(), ScheduleApplyFailure>),
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
        UnitTimestamp::RecordedAt { recorded_at } => gettext(
            "Your system already runs scheduled scans, so these settings are locked to avoid a \
             second schedule. Next scan: {time}. Change it in your system configuration.",
        )
        .replace("{time}", &exact_local_time_text(recorded_at)),
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

impl ScanSchedulePage {
    fn refresh_timer_state(&self, sender: &ComponentSender<Self>) {
        sender.oneshot_command(async {
            ScanSchedulePageCommand::SystemTimerInspected(system_schedule_owner(
                timer_unit_snapshot(SYSTEM_SCAN_TIMER).await,
            ))
        });
        sender.oneshot_command(async {
            ScanSchedulePageCommand::TimerStateLoaded(read_schedule_timer_state().await)
        });
    }

    fn change_schedule_settings(&mut self, apply_change: impl FnOnce(&mut StoredScheduleSettings)) {
        apply_change(&mut self.schedule_settings);
        self.schedule_settings.write_to(&self.stored_settings);
    }

    fn show_stored_settings(&mut self) {
        let stored_schedule = StoredScheduleSettings::read_from(&self.stored_settings);
        if stored_schedule == self.schedule_settings {
            return;
        }
        if stored_schedule.schedule_time_text != self.schedule_settings.schedule_time_text
            || stored_schedule.scan_targets != listed_scan_targets(&self.scan_targets_text)
        {
            self.scan_targets_text = joined_scan_targets(&stored_schedule.scan_targets);
            self.entry_texts_replaced = true;
        }
        self.schedule_settings = stored_schedule;
    }
}

#[relm4::component(pub)]
impl Component for ScanSchedulePage {
    type Init = ();
    type Input = ScanSchedulePageInput;
    type Output = ();
    type CommandOutput = ScanSchedulePageCommand;

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
                    connect_clicked => ScanSchedulePageInput::ApplyRequested,
                },

                adw::SwitchRow {
                    set_title: &gettext("Enable Scheduled Scans"),
                    #[watch]
                    #[block_signal(schedule_toggled_handler)]
                    set_active: model.schedule_settings.schedule_enabled,
                    connect_active_notify[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::ScheduleToggled(changed_row.is_active()));
                    } @schedule_toggled_handler,
                },

                adw::ComboRow {
                    set_title: &gettext("Scan Frequency"),
                    set_model: Some(&frequency_labels()),
                    #[watch]
                    #[block_signal(frequency_chosen_handler)]
                    set_selected: frequency_position(model.schedule_settings.schedule_frequency),
                    connect_selected_notify[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::FrequencyChosen(changed_row.selected()));
                    } @frequency_chosen_handler,
                },

                adw::EntryRow {
                    set_title: &gettext("Scan Time (24-hour)"),
                    #[track(model.entry_texts_replaced)]
                    #[block_signal(time_changed_handler)]
                    set_text: &model.schedule_settings.schedule_time_text,
                    connect_changed[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::TimeTextChanged(changed_row.text().to_string()));
                    } @time_changed_handler,
                },

                adw::ComboRow {
                    set_title: &gettext("Day of Week"),
                    set_subtitle: &gettext("Used for weekly scans."),
                    set_model: Some(&weekday_labels()),
                    #[watch]
                    #[block_signal(weekday_chosen_handler)]
                    set_selected: model.schedule_settings.weekday_position,
                    connect_selected_notify[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::WeekdayChosen(changed_row.selected()));
                    } @weekday_chosen_handler,
                },

                adw::SpinRow {
                    set_title: &gettext("Day of Month"),
                    set_subtitle: &gettext("Used for monthly scans."),
                    set_adjustment: Some(&gtk::Adjustment::new(1.0, 1.0, 28.0, 1.0, 7.0, 0.0)),
                    #[watch]
                    #[block_signal(month_day_handler)]
                    set_value: f64::from(model.schedule_settings.month_day),
                    connect_value_notify[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::MonthDayChanged(changed_row.value()));
                    } @month_day_handler,
                },

                adw::EntryRow {
                    set_title: &gettext("Scan Targets (separated by commas; empty scans your home folder)"),
                    #[track(model.entry_texts_replaced)]
                    #[block_signal(targets_changed_handler)]
                    set_text: &model.scan_targets_text,
                    connect_changed[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::TargetsTextChanged(changed_row.text().to_string()));
                    } @targets_changed_handler,
                },

                adw::SwitchRow {
                    set_title: &gettext("Skip on Battery"),
                    set_subtitle: &gettext("Do not start scheduled scans while on battery power."),
                    #[watch]
                    #[block_signal(battery_skip_handler)]
                    set_active: model.schedule_settings.skip_on_battery,
                    connect_active_notify[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::BatterySkipToggled(changed_row.is_active()));
                    } @battery_skip_handler,
                },

                adw::SwitchRow {
                    set_title: &gettext("Auto-Quarantine"),
                    set_subtitle: &gettext("Automatically quarantine threats found by scheduled scans. While Lazaret is open, threats are only reported."),
                    #[watch]
                    #[block_signal(auto_quarantine_handler)]
                    set_active: model.schedule_settings.auto_quarantine,
                    connect_active_notify[sender] => move |changed_row| {
                        sender.input(ScanSchedulePageInput::AutoQuarantineToggled(changed_row.is_active()));
                    } @auto_quarantine_handler,
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
        let stored_settings = application_settings();
        forward_setting_changes(
            &stored_settings,
            &SCHEDULE_SETTING_KEYS,
            sender.input_sender(),
            |_changed_settings, _changed_key| ScanSchedulePageInput::StoredSettingChanged,
        );
        let schedule_settings = StoredScheduleSettings::read_from(&stored_settings);
        let model = Self {
            scan_targets_text: joined_scan_targets(&schedule_settings.scan_targets),
            entry_texts_replaced: true,
            schedule_settings,
            stored_settings,
            timer_state_text: gettext("Checking…"),
            system_schedule_owner: SystemScheduleOwner::NoSystemTimer,
            page_notice: String::new(),
        };
        let widgets = view_output!();
        model.refresh_timer_state(&sender);
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        page_input: ScanSchedulePageInput,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.entry_texts_replaced = false;
        match page_input {
            ScanSchedulePageInput::ScheduleToggled(schedule_enabled) => {
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.schedule_enabled = schedule_enabled;
                });
            }
            ScanSchedulePageInput::FrequencyChosen(chosen_position) => {
                if let Some(schedule_frequency) = frequency_at(chosen_position) {
                    self.change_schedule_settings(|schedule_settings| {
                        schedule_settings.schedule_frequency = schedule_frequency;
                    });
                }
            }
            ScanSchedulePageInput::TimeTextChanged(schedule_time_text) => {
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.schedule_time_text = schedule_time_text;
                });
            }
            ScanSchedulePageInput::WeekdayChosen(weekday_position) => {
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.weekday_position = weekday_position;
                });
            }
            ScanSchedulePageInput::MonthDayChanged(spin_value) => {
                let month_day = spin_value.clamp(1.0, 28.0) as u32;
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.month_day = month_day;
                });
            }
            ScanSchedulePageInput::TargetsTextChanged(scan_targets_text) => {
                let scan_targets = listed_scan_targets(&scan_targets_text);
                self.scan_targets_text = scan_targets_text;
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.scan_targets = scan_targets;
                });
            }
            ScanSchedulePageInput::BatterySkipToggled(skip_on_battery) => {
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.skip_on_battery = skip_on_battery;
                });
            }
            ScanSchedulePageInput::AutoQuarantineToggled(auto_quarantine) => {
                self.change_schedule_settings(|schedule_settings| {
                    schedule_settings.auto_quarantine = auto_quarantine;
                });
            }
            ScanSchedulePageInput::StoredSettingChanged => self.show_stored_settings(),
            ScanSchedulePageInput::ApplyRequested => {
                self.page_notice.clear();
                if !self.schedule_settings.schedule_enabled {
                    sender.oneshot_command(async {
                        ScanSchedulePageCommand::ScheduleApplied(
                            disable_scan_schedule(systemd_user_unit_directory()).await,
                        )
                    });
                    return;
                }
                let Some(scan_schedule) = self.schedule_settings.scan_schedule() else {
                    self.page_notice = gettext("Enter the scan time as HH:MM, for example 02:00.");
                    return;
                };
                sender.oneshot_command(async move {
                    ScanSchedulePageCommand::ScheduleApplied(
                        enable_scan_schedule(systemd_user_unit_directory(), scan_schedule).await,
                    )
                });
            }
        }
    }

    fn update_cmd(
        &mut self,
        page_command: ScanSchedulePageCommand,
        sender: ComponentSender<Self>,
        _root: &Self::Root,
    ) {
        self.entry_texts_replaced = false;
        match page_command {
            ScanSchedulePageCommand::TimerStateLoaded(timer_state) => {
                if self.system_schedule_owner == SystemScheduleOwner::NoSystemTimer {
                    self.timer_state_text = describe_timer_state(&timer_state);
                }
            }
            ScanSchedulePageCommand::SystemTimerInspected(system_schedule_owner) => {
                self.system_schedule_owner = system_schedule_owner;
                if let SystemScheduleOwner::SystemTimerExists { next_run } = system_schedule_owner {
                    self.timer_state_text = describe_system_schedule(next_run);
                }
            }
            ScanSchedulePageCommand::ScheduleApplied(apply_outcome) => {
                if let Err(apply_failure) = apply_outcome {
                    self.page_notice = describe_apply_failure(&apply_failure);
                }
                self.refresh_timer_state(&sender);
            }
        }
    }
}

#[cfg(test)]
mod scan_schedule_component_tests {
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
