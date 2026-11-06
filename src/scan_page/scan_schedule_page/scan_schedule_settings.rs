use jiff::civil::Weekday;
use relm4::gtk::{gio, gio::prelude::*};

use crate::scan_page::scan_schedule_page::scan_schedule_units::{
    ScanSchedule, ScheduleClockTime, ScheduleFrequency, ScheduleFrequencyChoice,
    parse_schedule_time,
};

pub const ENABLED_KEY: &str = "schedule-enabled";
pub const FREQUENCY_KEY: &str = "schedule-frequency";
pub const TIME_KEY: &str = "schedule-time";
pub const WEEKDAY_KEY: &str = "schedule-day-of-week";
pub const MONTH_DAY_KEY: &str = "schedule-day-of-month";
pub const TARGETS_KEY: &str = "schedule-targets";
pub const SKIP_ON_BATTERY_KEY: &str = "schedule-skip-on-battery";
pub const AUTO_QUARANTINE_KEY: &str = "schedule-auto-quarantine";
pub const SCHEDULE_SETTING_KEYS: [&str; 8] = [
    ENABLED_KEY,
    FREQUENCY_KEY,
    TIME_KEY,
    WEEKDAY_KEY,
    MONTH_DAY_KEY,
    TARGETS_KEY,
    SKIP_ON_BATTERY_KEY,
    AUTO_QUARANTINE_KEY,
];
pub const FREQUENCY_CHOICES: [ScheduleFrequencyChoice; 4] = [
    ScheduleFrequencyChoice::Hourly,
    ScheduleFrequencyChoice::Daily,
    ScheduleFrequencyChoice::Weekly,
    ScheduleFrequencyChoice::Monthly,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredScheduleSettings {
    pub schedule_enabled: bool,
    pub frequency_choice: ScheduleFrequencyChoice,
    pub schedule_time_text: String,
    pub weekday_position: u32,
    pub month_day: u32,
    pub scan_targets: Vec<String>,
    pub skip_on_battery: bool,
    pub auto_quarantine: bool,
}

pub fn listed_scan_targets(targets_text: &str) -> Vec<String> {
    targets_text
        .split(',')
        .map(str::trim)
        .filter(|listed_target| !listed_target.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn joined_scan_targets(scan_targets: &[String]) -> String {
    scan_targets.join(", ")
}

pub fn frequency_position(schedule_frequency: ScheduleFrequencyChoice) -> u32 {
    FREQUENCY_CHOICES
        .iter()
        .position(|frequency_choice| *frequency_choice == schedule_frequency)
        .and_then(|frequency_position| u32::try_from(frequency_position).ok())
        .unwrap_or(1)
}

pub fn frequency_at(frequency_position: u32) -> Option<ScheduleFrequencyChoice> {
    usize::try_from(frequency_position)
        .ok()
        .and_then(|frequency_position| FREQUENCY_CHOICES.get(frequency_position))
        .copied()
}

impl StoredScheduleSettings {
    pub fn read_from(stored_settings: &gio::Settings) -> Self {
        Self {
            schedule_enabled: stored_settings.boolean(ENABLED_KEY),
            frequency_choice: ScheduleFrequencyChoice::from_stored_text(
                &stored_settings.string(FREQUENCY_KEY),
            ),
            schedule_time_text: stored_settings.string(TIME_KEY).to_string(),
            weekday_position: u32::try_from(stored_settings.int(WEEKDAY_KEY)).unwrap_or(0),
            month_day: u32::try_from(stored_settings.int(MONTH_DAY_KEY)).unwrap_or(1),
            scan_targets: stored_settings
                .strv(TARGETS_KEY)
                .iter()
                .map(ToString::to_string)
                .collect(),
            skip_on_battery: stored_settings.boolean(SKIP_ON_BATTERY_KEY),
            auto_quarantine: stored_settings.boolean(AUTO_QUARANTINE_KEY),
        }
    }

    pub fn write_to(&self, stored_settings: &gio::Settings) {
        let _enabled_stored = stored_settings.set_boolean(ENABLED_KEY, self.schedule_enabled);
        let _frequency_stored =
            stored_settings.set_string(FREQUENCY_KEY, self.frequency_choice.stored_text());
        let _time_stored = stored_settings.set_string(TIME_KEY, &self.schedule_time_text);
        let _weekday_stored = stored_settings.set_int(
            WEEKDAY_KEY,
            i32::try_from(self.weekday_position).unwrap_or(0),
        );
        let _month_day_stored =
            stored_settings.set_int(MONTH_DAY_KEY, i32::try_from(self.month_day).unwrap_or(1));
        let _targets_stored = stored_settings.set_strv(
            TARGETS_KEY,
            self.scan_targets
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let _battery_stored =
            stored_settings.set_boolean(SKIP_ON_BATTERY_KEY, self.skip_on_battery);
        let _quarantine_stored =
            stored_settings.set_boolean(AUTO_QUARANTINE_KEY, self.auto_quarantine);
    }

    fn stored_weekday(&self) -> Weekday {
        Weekday::Monday.wrapping_add(u8::try_from(self.weekday_position).unwrap_or(0))
    }

    fn stored_month_day(&self) -> u8 {
        u8::try_from(self.month_day).unwrap_or(1)
    }

    fn scan_time(&self) -> Option<ScheduleClockTime> {
        parse_schedule_time(&self.schedule_time_text)
    }

    fn schedule_frequency(&self) -> Option<ScheduleFrequency> {
        match self.frequency_choice {
            ScheduleFrequencyChoice::Hourly => Some(ScheduleFrequency::Hourly),
            ScheduleFrequencyChoice::Daily => self
                .scan_time()
                .map(|scan_time| ScheduleFrequency::Daily { scan_time }),
            ScheduleFrequencyChoice::Weekly => {
                self.scan_time().map(|scan_time| ScheduleFrequency::Weekly {
                    scan_weekday: self.stored_weekday(),
                    scan_time,
                })
            }
            ScheduleFrequencyChoice::Monthly => {
                self.scan_time()
                    .map(|scan_time| ScheduleFrequency::Monthly {
                        month_day: self.stored_month_day(),
                        scan_time,
                    })
            }
        }
    }

    pub fn scan_schedule(&self) -> Option<ScanSchedule> {
        Some(ScanSchedule {
            schedule_frequency: self.schedule_frequency()?,
            scan_targets: self.scan_targets.clone(),
            skip_on_battery: self.skip_on_battery,
            auto_quarantine: self.auto_quarantine,
        })
    }
}

#[cfg(test)]
mod scan_schedule_settings_tests {
    use super::*;
    use crate::scan_page::scan_schedule_page::scan_schedule_units::on_calendar_expression;

    fn daily_schedule_settings() -> StoredScheduleSettings {
        StoredScheduleSettings {
            schedule_enabled: true,
            frequency_choice: ScheduleFrequencyChoice::Daily,
            schedule_time_text: "02:30".to_owned(),
            weekday_position: 0,
            month_day: 1,
            scan_targets: vec!["/home".to_owned()],
            skip_on_battery: true,
            auto_quarantine: false,
        }
    }

    #[test]
    fn listed_targets_drop_blank_entries_and_surrounding_spaces() {
        assert_eq!(
            listed_scan_targets(" /home , ,/srv,"),
            vec!["/home".to_owned(), "/srv".to_owned()]
        );
        assert!(listed_scan_targets("").is_empty());
    }

    #[test]
    fn frequency_positions_round_trip() {
        FREQUENCY_CHOICES
            .into_iter()
            .for_each(|schedule_frequency| {
                assert_eq!(
                    frequency_at(frequency_position(schedule_frequency)),
                    Some(schedule_frequency)
                );
            });
        assert_eq!(frequency_at(9), None);
    }

    #[test]
    fn a_readable_time_turns_into_a_schedule() {
        let scan_schedule = daily_schedule_settings()
            .scan_schedule()
            .expect("02:30 is a valid time");
        assert_eq!(
            scan_schedule.schedule_frequency,
            ScheduleFrequency::Daily {
                scan_time: ScheduleClockTime {
                    scan_hour: 2,
                    scan_minute: 30
                }
            }
        );
        assert!(
            StoredScheduleSettings {
                schedule_time_text: "half past two".to_owned(),
                ..daily_schedule_settings()
            }
            .scan_schedule()
            .is_none()
        );
    }

    #[test]
    fn hourly_schedules_ignore_the_time() {
        assert_eq!(
            StoredScheduleSettings {
                frequency_choice: ScheduleFrequencyChoice::Hourly,
                schedule_time_text: "half past two".to_owned(),
                ..daily_schedule_settings()
            }
            .scan_schedule()
            .map(|scan_schedule| scan_schedule.schedule_frequency),
            Some(ScheduleFrequency::Hourly)
        );
    }

    #[test]
    fn stored_calendar_settings_keep_their_systemd_calendar_text() {
        let calendar_text_for = |frequency_choice, weekday_position, month_day| {
            StoredScheduleSettings {
                frequency_choice,
                weekday_position,
                month_day,
                ..daily_schedule_settings()
            }
            .scan_schedule()
            .map(|scan_schedule| on_calendar_expression(&scan_schedule))
        };
        assert_eq!(
            calendar_text_for(ScheduleFrequencyChoice::Hourly, 0, 1).as_deref(),
            Some("*-*-* *:00:00")
        );
        assert_eq!(
            calendar_text_for(ScheduleFrequencyChoice::Daily, 3, 9).as_deref(),
            Some("*-*-* 02:30:00")
        );
        [
            (0, "Mon"),
            (1, "Tue"),
            (2, "Wed"),
            (3, "Thu"),
            (4, "Fri"),
            (5, "Sat"),
            (6, "Sun"),
            (7, "Mon"),
            (13, "Sun"),
        ]
        .into_iter()
        .for_each(|(weekday_position, weekday_name)| {
            assert_eq!(
                calendar_text_for(ScheduleFrequencyChoice::Weekly, weekday_position, 1),
                Some(format!("{weekday_name} *-*-* 02:30:00"))
            );
        });
        assert_eq!(
            calendar_text_for(ScheduleFrequencyChoice::Monthly, 0, 15).as_deref(),
            Some("*-*-15 02:30:00")
        );
        assert_eq!(
            calendar_text_for(ScheduleFrequencyChoice::Monthly, 0, 31).as_deref(),
            Some("*-*-28 02:30:00")
        );
        assert_eq!(
            calendar_text_for(ScheduleFrequencyChoice::Monthly, 0, 0).as_deref(),
            Some("*-*-01 02:30:00")
        );
    }
}
