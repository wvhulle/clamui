use gettextrs::gettext;

use crate::host_services::activity_history::activity_history_database::{
    ActivityEntryRecord, ActivityRecord, FoundThreatCount, ScanActivityStatus, ScanOrigin,
    StoredActivityColumns, UpdateActivityStatus,
};

const CSV_HEADER: &str =
    "entry_id,started_at,status,origin,targets,files_scanned,threats,duration_millis";

fn exported_origin_text(activity_record: &ActivityRecord) -> &'static str {
    match activity_record {
        ActivityRecord::ScanActivity { scan_origin, .. } => scan_origin.stored_origin_text(),
        ActivityRecord::SkippedScan { .. } => ScanOrigin::ScheduledScan.stored_origin_text(),
        ActivityRecord::UpdateActivity { .. } => "",
    }
}

pub fn activity_status_text(activity_record: &ActivityRecord) -> String {
    match activity_record {
        ActivityRecord::ScanActivity { scan_status, .. } => match scan_status {
            ScanActivityStatus::ScanClean => gettext("Clean"),
            ScanActivityStatus::ScanInfected { .. } => gettext("Infected"),
            ScanActivityStatus::ScanFailed => gettext("Error"),
            ScanActivityStatus::ScanCancelled => gettext("Cancelled"),
        },
        ActivityRecord::SkippedScan { .. } => gettext("Skipped"),
        ActivityRecord::UpdateActivity { update_status } => match update_status {
            UpdateActivityStatus::UpdateFailed => gettext("Error"),
            UpdateActivityStatus::UpdateCancelled => gettext("Cancelled"),
            UpdateActivityStatus::UpdateApplied => gettext("Success"),
            UpdateActivityStatus::UpdateAlreadyCurrent => gettext("Up to date"),
            UpdateActivityStatus::UpdateRequested => gettext("Requested"),
            UpdateActivityStatus::UpdateResultUnknown => gettext("Ran"),
        },
    }
}

fn found_threats_text(found_threats: FoundThreatCount) -> String {
    match found_threats {
        FoundThreatCount::CountedThreats { threat_count } => gettextrs::ngettext(
            "Found {count} threat",
            "Found {count} threats",
            u32::try_from(threat_count.get()).unwrap_or(u32::MAX),
        )
        .replace("{count}", &threat_count.to_string()),
        FoundThreatCount::UncountedThreats => {
            gettext("The scanner reported a threat without naming the file.")
        }
    }
}

pub fn activity_summary_text(activity_entry: &ActivityEntryRecord) -> String {
    match &activity_entry.activity_record {
        ActivityRecord::ScanActivity { scan_status, .. } => match scan_status {
            ScanActivityStatus::ScanInfected { found_threats } => {
                found_threats_text(*found_threats)
            }
            ScanActivityStatus::ScanClean => gettext("No threats found"),
            ScanActivityStatus::ScanFailed => gettext("The scan did not finish cleanly"),
            ScanActivityStatus::ScanCancelled => gettext("Scan cancelled by user"),
        },
        ActivityRecord::SkippedScan { .. } => gettext("Scheduled scan skipped (on battery power)"),
        ActivityRecord::UpdateActivity { update_status } => match update_status {
            UpdateActivityStatus::UpdateApplied => gettext("Virus definitions updated"),
            UpdateActivityStatus::UpdateAlreadyCurrent => {
                gettext("Virus definitions are up to date")
            }
            UpdateActivityStatus::UpdateRequested => gettext("Update requested from the service"),
            UpdateActivityStatus::UpdateResultUnknown => {
                gettext("The update service ran without reporting a result")
            }
            UpdateActivityStatus::UpdateFailed => gettext("Database update failed"),
            UpdateActivityStatus::UpdateCancelled => gettext("Database update cancelled"),
        },
    }
}

#[derive(serde::Serialize)]
struct ExportedActivityEntry<'entry> {
    entry_id: i64,
    started_at: jiff::Timestamp,
    activity_status: &'static str,
    scan_origin: &'static str,
    activity_targets: String,
    inspected_file_count: u64,
    threat_count: u64,
    duration_millis: u64,
    activity_output: &'entry str,
}

impl<'entry> ExportedActivityEntry<'entry> {
    fn from_entry(activity_entry: &'entry ActivityEntryRecord) -> Self {
        let StoredActivityColumns {
            activity_status,
            activity_targets,
            scan_origin: _stored_origin,
            inspected_file_count,
            threat_count,
        } = activity_entry.activity_record.stored_columns();
        Self {
            entry_id: activity_entry.entry_id,
            started_at: activity_entry.started_at,
            activity_status,
            scan_origin: exported_origin_text(&activity_entry.activity_record),
            activity_targets,
            inspected_file_count,
            threat_count,
            duration_millis: activity_entry.duration_millis,
            activity_output: &activity_entry.activity_output,
        }
    }
}

fn csv_field(field_text: &str) -> String {
    let guarded_text = if field_text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{field_text}")
    } else {
        field_text.to_owned()
    };
    if guarded_text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded_text.replace('"', "\"\""))
    } else {
        guarded_text
    }
}

pub fn activity_entries_as_csv(activity_entries: &[ActivityEntryRecord]) -> String {
    std::iter::once(CSV_HEADER.to_owned())
        .chain(activity_entries.iter().map(|activity_entry| {
            let exported_entry = ExportedActivityEntry::from_entry(activity_entry);
            format!(
                "{},{},{},{},{},{},{},{}",
                exported_entry.entry_id,
                exported_entry.started_at,
                csv_field(activity_status_text(&activity_entry.activity_record).as_str()),
                exported_entry.scan_origin,
                csv_field(&exported_entry.activity_targets),
                exported_entry.inspected_file_count,
                exported_entry.threat_count,
                exported_entry.duration_millis,
            )
        }))
        .map(|csv_line| csv_line + "\n")
        .collect()
}

pub fn activity_entries_as_json(
    activity_entries: &[ActivityEntryRecord],
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(
        &activity_entries
            .iter()
            .map(ExportedActivityEntry::from_entry)
            .collect::<Vec<_>>(),
    )
}

pub fn formatted_duration_text(duration_millis: u64) -> String {
    humantime::format_duration(std::time::Duration::from_secs(duration_millis / 1000).max(
        std::time::Duration::from_secs(u64::from(duration_millis > 0)),
    ))
    .to_string()
}

pub fn activity_detail_text(
    activity_entry: &ActivityEntryRecord,
    formatted_start_time: &str,
) -> String {
    let heading = match activity_entry.activity_record {
        ActivityRecord::ScanActivity { .. } | ActivityRecord::SkippedScan { .. } => {
            gettext("SCAN LOG")
        }
        ActivityRecord::UpdateActivity { .. } => gettext("UPDATE LOG"),
    };
    let metadata_lines = [
        format!("{}: {formatted_start_time}", gettext("Timestamp")),
        format!(
            "{}: {}",
            gettext("Status"),
            activity_status_text(&activity_entry.activity_record)
        ),
        format!(
            "{}: {}",
            gettext("Duration"),
            formatted_duration_text(activity_entry.duration_millis)
        ),
        format!(
            "{}: {}",
            gettext("Summary"),
            activity_summary_text(activity_entry)
        ),
    ]
    .join("\n");
    let scan_targets = activity_entry.activity_record.scan_targets();
    let target_section = if scan_targets.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n{}:\n{}",
            gettext("Path"),
            scan_targets
                .iter()
                .map(|scan_target| scan_target.display().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    let output_section = if activity_entry.activity_output.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n{}:\n{}",
            gettext("Full Output"),
            activity_entry.activity_output
        )
    };
    format!("{heading}\n\n{metadata_lines}{target_section}{output_section}\n")
}

#[cfg(test)]
mod activity_export_formats_tests {
    use super::*;

    fn infected_entry() -> ActivityEntryRecord {
        ActivityEntryRecord {
            entry_id: 7,
            started_at: jiff::Timestamp::constant(1000, 0),
            activity_record: ActivityRecord::ScanActivity {
                scan_targets: vec![
                    std::path::PathBuf::from("/scan/a,b"),
                    std::path::PathBuf::from("=/scan/\"c\""),
                ],
                inspected_file_count: 3,
                scan_status: ScanActivityStatus::ScanInfected {
                    found_threats: FoundThreatCount::CountedThreats {
                        threat_count: std::num::NonZeroU64::MIN,
                    },
                },
                scan_origin: ScanOrigin::ManualScan,
            },
            duration_millis: 2500,
            activity_output: "/scan/a,b: Bad FOUND\n".to_owned(),
        }
    }

    #[test]
    fn csv_quotes_separators_and_guards_spreadsheet_formulas() {
        assert_eq!(csv_field("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        let csv_text = activity_entries_as_csv(&[infected_entry()]);
        assert!(csv_text.starts_with("entry_id,"));
        assert!(csv_text.contains("7,1970-01-01T00:16:40Z,Infected,manual_scan,"));
        assert!(csv_text.contains("\"/scan/a,b\n=/scan/\"\"c\"\"\",3,1,2500\n"));
    }

    #[test]
    fn json_keeps_the_output_and_uses_stable_status_names() {
        let json_text = activity_entries_as_json(&[infected_entry()]).expect("json");
        assert!(json_text.contains("\"activity_status\": \"scan_infected\""));
        assert!(json_text.contains("\"scan_origin\": \"manual_scan\""));
        assert!(json_text.contains("Bad FOUND"));
        assert!(json_text.contains("\"started_at\": \"1970-01-01T00:16:40Z\""));
    }

    #[test]
    fn details_contain_status_targets_and_output() {
        let detail_text = activity_detail_text(&infected_entry(), "start time");
        assert!(detail_text.starts_with("SCAN LOG"));
        assert!(detail_text.contains("Timestamp: start time"));
        assert!(detail_text.contains("Duration: 2s"));
        assert!(detail_text.contains("Found 1 threat"));
        assert!(detail_text.contains("/scan/a,b: Bad FOUND"));
    }

    #[test]
    fn update_entries_export_empty_scan_columns() {
        let update_entry = ActivityEntryRecord {
            activity_record: ActivityRecord::UpdateActivity {
                update_status: UpdateActivityStatus::UpdateApplied,
            },
            ..infected_entry()
        };
        assert!(
            activity_entries_as_csv(std::slice::from_ref(&update_entry))
                .contains("7,1970-01-01T00:16:40Z,Success,,,0,0,2500\n")
        );
        let json_text = activity_entries_as_json(&[update_entry]).expect("json");
        assert!(json_text.contains("\"activity_status\": \"update_applied\""));
        assert!(json_text.contains("\"threat_count\": 0"));
        assert!(json_text.contains("\"scan_origin\": \"\""));
    }

    #[test]
    fn scheduled_scans_export_their_origin_beside_the_unchanged_status() {
        let scheduled_entry = ActivityEntryRecord {
            activity_record: ActivityRecord::ScanActivity {
                scan_targets: vec![std::path::PathBuf::from("/home")],
                inspected_file_count: 3,
                scan_status: ScanActivityStatus::ScanClean,
                scan_origin: ScanOrigin::ScheduledScan,
            },
            ..infected_entry()
        };
        assert!(
            activity_entries_as_csv(std::slice::from_ref(&scheduled_entry))
                .contains(",Clean,scheduled_scan,/home,")
        );
        let json_text = activity_entries_as_json(&[scheduled_entry]).expect("json");
        assert!(json_text.contains("\"activity_status\": \"scan_clean\""));
        assert!(json_text.contains("\"scan_origin\": \"scheduled_scan\""));
    }
}
