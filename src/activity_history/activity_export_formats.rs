use gettextrs::gettext;

use crate::activity_history::activity_history_database::{ActivityEntryRecord, ActivityStatus};

const CSV_HEADER: &str =
    "entry_id,started_at_unix,status,targets,files_scanned,threats,duration_millis";

pub fn activity_status_text(activity_status: ActivityStatus) -> String {
    match activity_status {
        ActivityStatus::ScanClean => gettext("Clean"),
        ActivityStatus::ScanSkipped => gettext("Skipped"),
        ActivityStatus::ScanInfected => gettext("Infected"),
        ActivityStatus::ScanFailed | ActivityStatus::UpdateFailed => gettext("Error"),
        ActivityStatus::ScanCancelled | ActivityStatus::UpdateCancelled => gettext("Cancelled"),
        ActivityStatus::UpdateApplied => gettext("Success"),
        ActivityStatus::UpdateAlreadyCurrent => gettext("Up to date"),
        ActivityStatus::UpdateRequested => gettext("Requested"),
    }
}

pub fn activity_summary_text(activity_entry: &ActivityEntryRecord) -> String {
    match activity_entry.activity_status {
        ActivityStatus::ScanInfected => gettextrs::ngettext(
            "Found {count} threat",
            "Found {count} threats",
            u32::try_from(activity_entry.threat_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &activity_entry.threat_count.to_string()),
        ActivityStatus::ScanClean => gettext("No threats found"),
        ActivityStatus::ScanSkipped => gettext("Scheduled scan skipped (on battery power)"),
        ActivityStatus::ScanFailed => gettext("The scan did not finish cleanly"),
        ActivityStatus::ScanCancelled => gettext("Scan cancelled by user"),
        ActivityStatus::UpdateApplied => gettext("Virus definitions updated"),
        ActivityStatus::UpdateAlreadyCurrent => gettext("Virus definitions are up to date"),
        ActivityStatus::UpdateRequested => gettext("Update requested from the service"),
        ActivityStatus::UpdateFailed => gettext("Database update failed"),
        ActivityStatus::UpdateCancelled => gettext("Database update cancelled"),
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
            format!(
                "{},{},{},{},{},{},{}",
                activity_entry.entry_id,
                activity_entry.started_at_unix,
                csv_field(activity_status_text(activity_entry.activity_status).as_str()),
                csv_field(&activity_entry.activity_targets),
                activity_entry.inspected_file_count,
                activity_entry.threat_count,
                activity_entry.duration_millis,
            )
        }))
        .map(|csv_line| csv_line + "\n")
        .collect()
}

pub fn activity_entries_as_json(
    activity_entries: &[ActivityEntryRecord],
) -> serde_json::Result<String> {
    serde_json::to_string_pretty(activity_entries)
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
    let heading = if activity_entry.activity_status.is_virus_scan()
        || activity_entry.activity_status == ActivityStatus::ScanSkipped
    {
        gettext("SCAN LOG")
    } else {
        gettext("UPDATE LOG")
    };
    let metadata_lines = [
        format!("{}: {formatted_start_time}", gettext("Timestamp")),
        format!(
            "{}: {}",
            gettext("Status"),
            activity_status_text(activity_entry.activity_status)
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
    let target_section = if activity_entry.activity_targets.is_empty() {
        String::new()
    } else {
        format!(
            "\n\n{}:\n{}",
            gettext("Path"),
            activity_entry.activity_targets
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
            started_at_unix: 1000,
            activity_status: ActivityStatus::ScanInfected,
            activity_targets: "/scan/a,b\n=/scan/\"c\"".to_owned(),
            inspected_file_count: 3,
            threat_count: 1,
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
        assert!(csv_text.contains("7,1000,Infected,\"/scan/a,b\n=/scan/\"\"c\"\"\",3,1,2500\n"));
    }

    #[test]
    fn json_keeps_the_output_and_uses_stable_status_names() {
        let json_text = activity_entries_as_json(&[infected_entry()]).expect("json");
        assert!(json_text.contains("\"activity_status\": \"scan_infected\""));
        assert!(json_text.contains("Bad FOUND"));
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
}
