use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use futures::{StreamExt, future::ready, stream};
use gettextrs::{gettext, ngettext};
use jiff::Timestamp;
use relm4::gtk::glib;

use crate::{
    application_data_directory,
    host_services::{
        activity_history::activity_history_database::{
            ActivityHistory, ActivityRecord, FoundThreatCount, NewActivityEntry,
            ScanActivityStatus, ScanOrigin,
        },
        clamav_config::detection_options::host_clamscan_detection_arguments,
        clamav_scanner::{
            scan_exclusion_rules::ScanExclusions,
            scan_progress_events::{CompletedScanOutcome, ScanRequest, scan_progress_events},
            scanner_command_builder::{ScannerProgramPaths, choose_scanner_backend},
        },
        desktop::{
            desktop_notifications::send_session_notification,
            file_process_lock::{FileLockAttempt, try_file_lock},
            stored_settings::{
                application_settings, read_exclusion_entries, scanner_backend_preference,
            },
        },
        quarantine_vault::quarantine_entry_database::QuarantineVault,
    },
};

const THREATS_FOUND_EXIT_CODE: u8 = 1;
const SCAN_FAILED_EXIT_CODE: u8 = 2;
pub const POWER_SUPPLY_DIRECTORY: &str = "/sys/class/power_supply";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScheduledScanOptions {
    pub skip_on_battery: bool,
    pub auto_quarantine: bool,
    pub scan_targets: Vec<PathBuf>,
}

pub fn parse_scheduled_scan_options(
    program_arguments: impl IntoIterator<Item = String>,
) -> Option<ScheduledScanOptions> {
    let mut remaining_arguments = program_arguments.into_iter().skip(1).peekable();
    remaining_arguments.next_if(|first_argument| first_argument == "--scheduled-scan")?;
    let mut scan_options = ScheduledScanOptions::default();
    while let Some(scan_argument) = remaining_arguments.next() {
        match scan_argument.as_str() {
            "--skip-on-battery" => scan_options.skip_on_battery = true,
            "--auto-quarantine" => scan_options.auto_quarantine = true,
            "--target" => scan_options
                .scan_targets
                .extend(remaining_arguments.next().map(PathBuf::from)),
            _ignored_argument => {}
        }
    }
    Some(scan_options)
}

pub fn host_runs_on_battery(power_supply_directory: &Path) -> bool {
    let Ok(supply_entries) = fs::read_dir(power_supply_directory) else {
        return false;
    };
    let supply_directories = supply_entries
        .filter_map(Result::ok)
        .map(|supply_entry| supply_entry.path())
        .collect::<Vec<_>>();
    let supply_value_is = |supply_directory: &Path, value_name: &str, expected_value: &str| {
        fs::read_to_string(supply_directory.join(value_name))
            .is_ok_and(|value_text| value_text.trim() == expected_value)
    };
    let mains_online = supply_directories.iter().any(|supply_directory| {
        supply_value_is(supply_directory, "type", "Mains")
            && supply_value_is(supply_directory, "online", "1")
    });
    let battery_discharging = supply_directories.iter().any(|supply_directory| {
        supply_value_is(supply_directory, "type", "Battery")
            && supply_value_is(supply_directory, "status", "Discharging")
    });
    !mains_online && battery_discharging
}

fn scan_status_of(scan_outcome: &CompletedScanOutcome) -> ScanActivityStatus {
    match FoundThreatCount::from_findings(&scan_outcome.threat_findings) {
        Some(found_threats) => ScanActivityStatus::ScanInfected { found_threats },
        None if scan_outcome.scan_problems.is_empty() => ScanActivityStatus::ScanClean,
        None => ScanActivityStatus::ScanFailed,
    }
}

fn skipped_entry(scan_targets: &[PathBuf]) -> NewActivityEntry {
    NewActivityEntry {
        started_at: Timestamp::now(),
        activity_record: ActivityRecord::SkippedScan {
            scan_targets: scan_targets.to_vec(),
        },
        duration_millis: 0,
        activity_output: String::new(),
    }
}

async fn quarantine_detected_threats(
    scan_outcome: &CompletedScanOutcome,
    data_directory: &Path,
) -> usize {
    let lock_path = data_directory.join("quarantine.lock");
    let Ok(FileLockAttempt::LockAcquired(_vault_lock)) = try_file_lock(&lock_path) else {
        return 0;
    };
    let Ok(quarantine_vault) = QuarantineVault::open_vault(
        data_directory.join("quarantine.db"),
        data_directory.join("quarantine"),
    )
    .await
    else {
        return 0;
    };
    stream::iter(scan_outcome.threat_findings.attributed_threats().to_vec())
        .then(|detected_threat| {
            let quarantine_vault = quarantine_vault.clone();
            async move {
                quarantine_vault
                    .move_file_into_quarantine(
                        &detected_threat.file_path,
                        &detected_threat.threat_identity,
                    )
                    .await
                    .is_ok()
            }
        })
        .filter(|file_was_moved| ready(*file_was_moved))
        .count()
        .await
}

fn finished_scan_notification_body(
    scan_outcome: &CompletedScanOutcome,
    quarantined_count: usize,
) -> String {
    let threat_count = scan_outcome.threat_findings.attributed_threats().len();
    let found_text = ngettext(
        "{count} threat found",
        "{count} threats found",
        u32::try_from(threat_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &threat_count.to_string());
    if quarantined_count == 0 {
        format!("{found_text}. {}", gettext("Open Lazaret to review them."))
    } else {
        format!(
            "{found_text}. {}",
            ngettext(
                "{count} moved to quarantine.",
                "{count} moved to quarantine.",
                u32::try_from(quarantined_count).unwrap_or(u32::MAX),
            )
            .replace("{count}", &quarantined_count.to_string())
        )
    }
}

async fn run_scheduled_scan_async(scan_options: ScheduledScanOptions) -> ExitCode {
    let settings = application_settings();
    let data_directory = application_data_directory();
    let activity_history = ActivityHistory::at_database_path(data_directory.join("history.db"));
    let scan_targets = if scan_options.scan_targets.is_empty() {
        vec![glib::home_dir()]
    } else {
        scan_options.scan_targets.clone()
    };
    if scan_options.skip_on_battery && host_runs_on_battery(Path::new(POWER_SUPPLY_DIRECTORY)) {
        let _history_unavailable = activity_history
            .record_activity(skipped_entry(&scan_targets))
            .await;
        return ExitCode::SUCCESS;
    }
    let started_at = Timestamp::now();
    let started_instant = Instant::now();
    let scanner_programs = ScannerProgramPaths::locate_trusted_programs();
    let scanner_backend =
        choose_scanner_backend(scanner_backend_preference(&settings), &scanner_programs).await;
    let scan_outcome = scan_progress_events(ScanRequest {
        scan_targets: scan_targets.clone(),
        scanner_backend,
        scanner_programs,
        file_list_directory: data_directory.clone(),
        scan_exclusions: ScanExclusions::from_entries(
            &read_exclusion_entries(&settings),
            &glib::home_dir(),
        ),
        detection_arguments: host_clamscan_detection_arguments(),
    })
    .fold(
        CompletedScanOutcome::default(),
        |mut scan_outcome, progress_event| {
            scan_outcome.absorb_progress_event(progress_event);
            ready(scan_outcome)
        },
    )
    .await;
    let quarantined_count = if scan_options.auto_quarantine {
        quarantine_detected_threats(&scan_outcome, &data_directory).await
    } else {
        0
    };
    let scan_status = scan_status_of(&scan_outcome);
    let _history_unavailable = activity_history
        .record_activity(NewActivityEntry {
            started_at,
            activity_record: ActivityRecord::ScanActivity {
                scan_targets,
                inspected_file_count: scan_outcome.inspected_file_count,
                scan_status,
                scan_origin: ScanOrigin::ScheduledScan,
            },
            duration_millis: started_instant.elapsed().as_millis() as u64,
            activity_output: scan_outcome.noteworthy_output.clone(),
        })
        .await;
    match scan_status {
        ScanActivityStatus::ScanInfected { .. } => {
            send_session_notification(
                &gettext("Threats Detected"),
                &finished_scan_notification_body(&scan_outcome, quarantined_count),
            );
            ExitCode::from(THREATS_FOUND_EXIT_CODE)
        }
        ScanActivityStatus::ScanFailed => {
            send_session_notification(
                &gettext("Scheduled scan failed"),
                &gettext("Open Lazaret to read the log."),
            );
            ExitCode::from(SCAN_FAILED_EXIT_CODE)
        }
        ScanActivityStatus::ScanClean | ScanActivityStatus::ScanCancelled => ExitCode::SUCCESS,
    }
}

pub fn run_scheduled_scan(scan_options: ScheduledScanOptions) -> ExitCode {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(scan_runtime) => scan_runtime.block_on(run_scheduled_scan_async(scan_options)),
        Err(runtime_failure) => {
            eprintln!("{runtime_failure}");
            ExitCode::from(SCAN_FAILED_EXIT_CODE)
        }
    }
}

#[cfg(test)]
mod headless_scheduled_scan_tests {
    use super::*;

    fn arguments_of(listed_arguments: &[&str]) -> Vec<String> {
        listed_arguments
            .iter()
            .map(|listed_argument| (*listed_argument).to_owned())
            .collect()
    }

    fn write_power_supply(power_root: &Path, supply_name: &str, supply_values: &[&[&str; 2]]) {
        let supply_directory = power_root.join(supply_name);
        fs::create_dir_all(&supply_directory).expect("supply directory");
        supply_values.iter().for_each(|supply_value| {
            fs::write(supply_directory.join(supply_value[0]), supply_value[1])
                .expect("supply value");
        });
    }

    #[test]
    fn only_the_scheduled_flag_selects_headless_mode() {
        assert_eq!(
            parse_scheduled_scan_options(arguments_of(&["lazaret", "/scan"])),
            None
        );
        assert_eq!(
            parse_scheduled_scan_options(arguments_of(&[
                "lazaret",
                "--scheduled-scan",
                "--skip-on-battery",
                "--auto-quarantine",
                "--target",
                "/one",
                "--target",
                "/two",
            ])),
            Some(ScheduledScanOptions {
                skip_on_battery: true,
                auto_quarantine: true,
                scan_targets: vec![PathBuf::from("/one"), PathBuf::from("/two")],
            })
        );
    }

    #[test]
    fn battery_state_needs_a_discharging_battery_without_mains() {
        let power_root = tempfile::tempdir().expect("power root");
        assert!(!host_runs_on_battery(power_root.path()));
        write_power_supply(
            power_root.path(),
            "BAT0",
            &[&["type", "Battery\n"], &["status", "Discharging\n"]],
        );
        assert!(host_runs_on_battery(power_root.path()));
        write_power_supply(
            power_root.path(),
            "AC",
            &[&["type", "Mains\n"], &["online", "1\n"]],
        );
        assert!(!host_runs_on_battery(power_root.path()));
    }

    #[test]
    fn a_missing_power_supply_directory_is_not_battery_power() {
        assert!(!host_runs_on_battery(Path::new("/nonexistent/power")));
    }
}
