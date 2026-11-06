use relm4::gtk::{gio, gio::prelude::*};

use crate::scan_page::scan_schedule_page::scan_schedule_units::{
    ScanSchedule, ScheduleFrequency, parse_schedule_time,
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
pub const FREQUENCY_CHOICES: [ScheduleFrequency; 4] = [
    ScheduleFrequency::Hourly,
    ScheduleFrequency::Daily,
    ScheduleFrequency::Weekly,
    ScheduleFrequency::Monthly,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredScheduleSettings {
    pub schedule_enabled: bool,
    pub schedule_frequency: ScheduleFrequency,
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

pub fn frequency_position(schedule_frequency: ScheduleFrequency) -> u32 {
    FREQUENCY_CHOICES
        .iter()
        .position(|frequency_choice| *frequency_choice == schedule_frequency)
        .and_then(|frequency_position| u32::try_from(frequency_position).ok())
        .unwrap_or(1)
}

pub fn frequency_at(frequency_position: u32) -> Option<ScheduleFrequency> {
    usize::try_from(frequency_position)
        .ok()
        .and_then(|frequency_position| FREQUENCY_CHOICES.get(frequency_position))
        .copied()
}

impl StoredScheduleSettings {
    pub fn read_from(stored_settings: &gio::Settings) -> Self {
        Self {
            schedule_enabled: stored_settings.boolean(ENABLED_KEY),
            schedule_frequency: ScheduleFrequency::from_stored_text(
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
            stored_settings.set_string(FREQUENCY_KEY, self.schedule_frequency.stored_text());
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

    pub fn scan_schedule(&self) -> Option<ScanSchedule> {
        let clock_time = parse_schedule_time(&self.schedule_time_text)?;
        Some(ScanSchedule {
            schedule_frequency: self.schedule_frequency,
            scan_hour: clock_time.scan_hour,
            scan_minute: clock_time.scan_minute,
            weekday_position: u8::try_from(self.weekday_position).unwrap_or(0),
            month_day: u8::try_from(self.month_day).unwrap_or(1),
            scan_targets: self.scan_targets.clone(),
            skip_on_battery: self.skip_on_battery,
            auto_quarantine: self.auto_quarantine,
        })
    }
}

#[cfg(test)]
mod scan_schedule_settings_tests {
    use super::*;

    fn daily_schedule_settings() -> StoredScheduleSettings {
        StoredScheduleSettings {
            schedule_enabled: true,
            schedule_frequency: ScheduleFrequency::Daily,
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
            (scan_schedule.scan_hour, scan_schedule.scan_minute),
            (2, 30)
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
}
