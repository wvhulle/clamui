use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    activity_history::activity_entry_row::formatted_local_time,
    desktop_integration::flatpak_sandbox::{running_in_flatpak, sandboxed_launcher_words},
    systemd_bus::host_systemd_units::{
        TimerUnitSnapshot, UnitState, UnitTimestamp, disable_user_timer, enable_user_timer,
        reload_user_manager, user_timer_snapshot,
    },
};

const SERVICE_FILE_NAME: &str = "lazaret-scheduled-scan.service";
const TIMER_FILE_NAME: &str = "lazaret-scheduled-scan.timer";
const WEEKDAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const SERVICE_TEMPLATE: &str = include_str!("../../data/lazaret-scheduled-scan.service.in");
const TIMER_TEMPLATE: &str = include_str!("../../data/lazaret-scheduled-scan.timer.in");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScheduleFrequency {
    Hourly,
    Daily,
    Weekly,
    Monthly,
}

impl ScheduleFrequency {
    pub fn from_stored_text(stored_text: &str) -> Self {
        match stored_text {
            "hourly" => Self::Hourly,
            "weekly" => Self::Weekly,
            "monthly" => Self::Monthly,
            _daily => Self::Daily,
        }
    }

    pub const fn stored_text(self) -> &'static str {
        match self {
            Self::Hourly => "hourly",
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanSchedule {
    pub schedule_frequency: ScheduleFrequency,
    pub scan_hour: u8,
    pub scan_minute: u8,
    pub weekday_position: u8,
    pub month_day: u8,
    pub scan_targets: Vec<String>,
    pub skip_on_battery: bool,
    pub auto_quarantine: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ScheduleApplyFailure {
    #[error("the systemd user unit files could not be written: {0}")]
    UnitFilesUnwritable(io::Error),
    #[error("the systemd user manager refused the timer: {0}")]
    UserManagerFailed(#[from] zbus::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScheduleTimerState {
    TimerInactive,
    TimerActive { next_run_text: String },
    SystemdUnavailable,
}

pub fn parse_schedule_time(time_text: &str) -> Option<ScheduleClockTime> {
    let (hour_text, minute_text) = time_text.trim().split_once(':')?;
    let scan_hour = hour_text.parse::<u8>().ok().filter(|hour| *hour < 24)?;
    let scan_minute = minute_text
        .parse::<u8>()
        .ok()
        .filter(|minute| *minute < 60)?;
    Some(ScheduleClockTime {
        scan_hour,
        scan_minute,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScheduleClockTime {
    pub scan_hour: u8,
    pub scan_minute: u8,
}

pub fn on_calendar_expression(scan_schedule: &ScanSchedule) -> String {
    let clock_time = format!(
        "{:02}:{:02}:00",
        scan_schedule.scan_hour, scan_schedule.scan_minute
    );
    match scan_schedule.schedule_frequency {
        ScheduleFrequency::Hourly => "*-*-* *:00:00".to_owned(),
        ScheduleFrequency::Daily => format!("*-*-* {clock_time}"),
        ScheduleFrequency::Weekly => format!(
            "{} *-*-* {clock_time}",
            WEEKDAY_NAMES[usize::from(scan_schedule.weekday_position) % WEEKDAY_NAMES.len()]
        ),
        ScheduleFrequency::Monthly => format!(
            "*-*-{:02} {clock_time}",
            scan_schedule.month_day.clamp(1, 28)
        ),
    }
}

fn systemd_quoted_argument(raw_argument: &str) -> String {
    let escaped_argument = raw_argument
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "$$")
        .replace('%', "%%");
    format!("\"{escaped_argument}\"")
}

pub fn service_unit_text(launcher_words: &[String], scan_schedule: &ScanSchedule) -> String {
    let option_arguments = [
        scan_schedule.skip_on_battery.then_some("--skip-on-battery"),
        scan_schedule.auto_quarantine.then_some("--auto-quarantine"),
    ];
    let command_words =
        launcher_words
            .iter()
            .map(|launcher_word| systemd_quoted_argument(launcher_word))
            .chain(std::iter::once("--scheduled-scan".to_owned()))
            .chain(option_arguments.into_iter().flatten().map(str::to_owned))
            .chain(scan_schedule.scan_targets.iter().flat_map(|scan_target| {
                ["--target".to_owned(), systemd_quoted_argument(scan_target)]
            }))
            .collect::<Vec<_>>()
            .join(" ");
    SERVICE_TEMPLATE.replace("@EXEC_START@", &command_words)
}

pub fn timer_unit_text(scan_schedule: &ScanSchedule) -> String {
    TIMER_TEMPLATE.replace("@ON_CALENDAR@", &on_calendar_expression(scan_schedule))
}

pub fn launcher_path_from(
    invoked_program: &OsStr,
    search_path: &OsStr,
    fallback_executable: PathBuf,
) -> PathBuf {
    let invoked_path = Path::new(invoked_program);
    if invoked_path.is_absolute() {
        return invoked_path.to_path_buf();
    }
    if invoked_path.components().count() > 1 {
        return fallback_executable;
    }
    std::env::split_paths(search_path)
        .map(|search_directory| search_directory.join(invoked_path))
        .find(|candidate_path| candidate_path.is_file())
        .unwrap_or(fallback_executable)
}

pub fn current_launcher_path() -> io::Result<PathBuf> {
    let current_executable = std::env::current_exe()?;
    Ok(launcher_path_from(
        &std::env::args_os().next().unwrap_or_default(),
        &std::env::var_os("PATH").unwrap_or_default(),
        current_executable,
    ))
}

fn current_launcher_words() -> io::Result<Vec<String>> {
    if running_in_flatpak() {
        return Ok(sandboxed_launcher_words(crate::APPLICATION_ID));
    }
    Ok(vec![
        current_launcher_path()?.to_string_lossy().into_owned(),
    ])
}

pub async fn enable_scan_schedule(
    unit_directory: PathBuf,
    scan_schedule: ScanSchedule,
) -> Result<(), ScheduleApplyFailure> {
    let launcher_words =
        current_launcher_words().map_err(ScheduleApplyFailure::UnitFilesUnwritable)?;
    fs::create_dir_all(&unit_directory)
        .and_then(|()| {
            fs::write(
                unit_directory.join(SERVICE_FILE_NAME),
                service_unit_text(&launcher_words, &scan_schedule),
            )
        })
        .and_then(|()| {
            fs::write(
                unit_directory.join(TIMER_FILE_NAME),
                timer_unit_text(&scan_schedule),
            )
        })
        .map_err(ScheduleApplyFailure::UnitFilesUnwritable)?;
    enable_user_timer(TIMER_FILE_NAME).await?;
    Ok(())
}

pub async fn disable_scan_schedule(unit_directory: PathBuf) -> Result<(), ScheduleApplyFailure> {
    disable_user_timer(TIMER_FILE_NAME).await?;
    [SERVICE_FILE_NAME, TIMER_FILE_NAME]
        .iter()
        .try_for_each(
            |unit_file_name| match fs::remove_file(unit_directory.join(unit_file_name)) {
                Ok(()) => Ok(()),
                Err(remove_failure) if remove_failure.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(remove_failure) => Err(remove_failure),
            },
        )
        .map_err(ScheduleApplyFailure::UnitFilesUnwritable)?;
    reload_user_manager().await?;
    Ok(())
}

pub fn schedule_state_from_timer(timer_snapshot: TimerUnitSnapshot) -> ScheduleTimerState {
    match timer_snapshot.unit_state {
        UnitState::UnitActive => ScheduleTimerState::TimerActive {
            next_run_text: match timer_snapshot.next_run {
                UnitTimestamp::RecordedAt { unix_seconds } => formatted_local_time(unix_seconds),
                UnitTimestamp::NeverRecorded => String::new(),
            },
        },
        UnitState::UnitInactive | UnitState::UnitNotFound => ScheduleTimerState::TimerInactive,
        UnitState::SystemdUnavailable => ScheduleTimerState::SystemdUnavailable,
    }
}

pub async fn read_schedule_timer_state() -> ScheduleTimerState {
    schedule_state_from_timer(user_timer_snapshot(TIMER_FILE_NAME).await)
}

#[cfg(test)]
mod scan_schedule_units_tests {
    use std::ffi::OsString;

    use super::*;

    fn weekly_schedule() -> ScanSchedule {
        ScanSchedule {
            schedule_frequency: ScheduleFrequency::Weekly,
            scan_hour: 2,
            scan_minute: 5,
            weekday_position: 6,
            month_day: 31,
            scan_targets: vec!["/home/a b/100%$HOME\"x".to_owned()],
            skip_on_battery: true,
            auto_quarantine: false,
        }
    }

    #[test]
    fn calendar_expressions_follow_the_frequency() {
        let on_calendar_with = |schedule_frequency| {
            on_calendar_expression(&ScanSchedule {
                schedule_frequency,
                ..weekly_schedule()
            })
        };
        assert_eq!(on_calendar_with(ScheduleFrequency::Hourly), "*-*-* *:00:00");
        assert_eq!(on_calendar_with(ScheduleFrequency::Daily), "*-*-* 02:05:00");
        assert_eq!(
            on_calendar_with(ScheduleFrequency::Weekly),
            "Sun *-*-* 02:05:00"
        );
        assert_eq!(
            on_calendar_with(ScheduleFrequency::Monthly),
            "*-*-28 02:05:00"
        );
    }

    #[test]
    fn service_arguments_cannot_expand_or_break_quoting() {
        let unit_text = service_unit_text(&["/usr/bin/lazaret".to_owned()], &weekly_schedule());
        assert!(unit_text.contains(
            "ExecStart=\"/usr/bin/lazaret\" --scheduled-scan --skip-on-battery --target \"/home/a \
             b/100%%$$HOME\\\"x\"\n"
        ));
        assert!(unit_text.contains("Nice=19"));
    }

    #[test]
    fn sandboxed_scans_start_through_flatpak_run() {
        let unit_text = service_unit_text(
            &sandboxed_launcher_words("page.codeberg.wvhulle.Lazaret"),
            &weekly_schedule(),
        );
        assert!(unit_text.contains(
            "ExecStart=\"flatpak\" \"run\" \"--command=lazaret\" \
             \"page.codeberg.wvhulle.Lazaret\" --scheduled-scan "
        ));
    }

    #[test]
    fn timer_is_persistent_so_missed_runs_still_happen() {
        let unit_text = timer_unit_text(&weekly_schedule());
        assert!(unit_text.contains("OnCalendar=Sun *-*-* 02:05:00\n"));
        assert!(unit_text.contains("Persistent=true"));
    }

    #[test]
    fn schedule_times_are_validated() {
        assert_eq!(
            parse_schedule_time("23:59"),
            Some(ScheduleClockTime {
                scan_hour: 23,
                scan_minute: 59
            })
        );
        assert_eq!(parse_schedule_time("24:00"), None);
        assert_eq!(parse_schedule_time("12:60"), None);
        assert_eq!(parse_schedule_time("noon"), None);
    }

    #[test]
    fn an_inactive_or_missing_timer_is_not_scheduled_but_an_unreachable_manager_is_distinct() {
        let timer_snapshot_with = |unit_state| TimerUnitSnapshot {
            unit_state,
            next_run: UnitTimestamp::NeverRecorded,
            last_trigger: UnitTimestamp::NeverRecorded,
        };
        assert_eq!(
            schedule_state_from_timer(timer_snapshot_with(UnitState::UnitNotFound)),
            ScheduleTimerState::TimerInactive
        );
        assert_eq!(
            schedule_state_from_timer(timer_snapshot_with(UnitState::SystemdUnavailable)),
            ScheduleTimerState::SystemdUnavailable
        );
        assert!(matches!(
            schedule_state_from_timer(timer_snapshot_with(UnitState::UnitActive)),
            ScheduleTimerState::TimerActive { .. }
        ));
    }

    #[test]
    fn the_launcher_keeps_stable_search_path_entries() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        fs::write(temporary_root.path().join("lazaret"), b"").expect("launcher");
        assert_eq!(
            launcher_path_from(
                &OsString::from("lazaret"),
                temporary_root.path().as_os_str(),
                PathBuf::from("/fallback/.lazaret-wrapped"),
            ),
            temporary_root.path().join("lazaret")
        );
        assert_eq!(
            launcher_path_from(
                &OsString::from("/opt/lazaret"),
                OsStr::new(""),
                PathBuf::from("/fallback")
            ),
            PathBuf::from("/opt/lazaret")
        );
        assert_eq!(
            launcher_path_from(
                &OsString::from("./lazaret"),
                OsStr::new(""),
                PathBuf::from("/fallback")
            ),
            PathBuf::from("/fallback")
        );
    }
}
