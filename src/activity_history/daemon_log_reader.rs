use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use tokio::{process::Command, task::spawn_blocking};

use crate::malware_scan::scanner_output_parser::sanitize_scanner_text;

const SHOWN_LINE_COUNT: usize = 100;
const LOG_TAIL_BYTES: u64 = 256 * 1024;
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_LOG_PATHS: [&str; 2] = ["/var/log/clamav/clamd.log", "/var/log/clamd.log"];
const CLAMD_CONFIG_PATHS: [&str; 3] = [
    "/etc/clamav/clamd.conf",
    "/etc/clamd.conf",
    "/etc/clamd.d/scan.conf",
];
const DAEMON_SERVICE_UNITS: [&str; 3] = ["clamav-daemon", "clamd", "clamd@scan"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DaemonLogContents {
    FromLogFile { log_path: PathBuf, log_text: String },
    FromSystemJournal { log_text: String },
    NoReadableLog,
}

pub fn log_path_in_config(config_text: &str) -> Option<PathBuf> {
    config_text
        .lines()
        .map(str::trim)
        .filter_map(|config_line| config_line.strip_prefix("LogFile"))
        .filter(|config_value| config_value.starts_with(char::is_whitespace))
        .filter_map(|config_value| config_value.split_whitespace().next())
        .next_back()
        .map(PathBuf::from)
}

pub fn last_log_lines(log_text: &str, line_count: usize) -> String {
    let retained_lines = log_text.lines().rev().take(line_count).collect::<Vec<_>>();
    retained_lines
        .into_iter()
        .rev()
        .map(|log_line| format!("{log_line}\n"))
        .collect()
}

fn read_log_tail(log_path: &Path) -> Option<String> {
    let mut log_file = fs::File::open(log_path).ok()?;
    let log_length = log_file.metadata().ok()?.len();
    log_file
        .seek(SeekFrom::Start(log_length.saturating_sub(LOG_TAIL_BYTES)))
        .ok()?;
    let mut tail_bytes = Vec::new();
    log_file.read_to_end(&mut tail_bytes).ok()?;
    Some(sanitize_scanner_text(&last_log_lines(
        &String::from_utf8_lossy(&tail_bytes),
        SHOWN_LINE_COUNT,
    )))
}

fn read_configured_log_file() -> Option<DaemonLogContents> {
    let configured_paths = CLAMD_CONFIG_PATHS
        .iter()
        .filter_map(|config_path| fs::read_to_string(config_path).ok())
        .filter_map(|config_text| log_path_in_config(&config_text));
    let default_paths = DEFAULT_LOG_PATHS.iter().map(PathBuf::from);
    configured_paths.chain(default_paths).find_map(|log_path| {
        read_log_tail(&log_path)
            .map(|log_text| DaemonLogContents::FromLogFile { log_path, log_text })
    })
}

async fn read_system_journal() -> Option<DaemonLogContents> {
    let mut journal_command = Command::new("journalctl");
    DAEMON_SERVICE_UNITS.iter().for_each(|service_unit| {
        journal_command.arg("--unit").arg(service_unit);
    });
    journal_command
        .arg("--lines")
        .arg(SHOWN_LINE_COUNT.to_string())
        .args(["--no-pager", "--quiet"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let journal_output = tokio::time::timeout(JOURNAL_TIMEOUT, journal_command.output())
        .await
        .ok()?
        .ok()?;
    (journal_output.status.success() && !journal_output.stdout.is_empty()).then(|| {
        DaemonLogContents::FromSystemJournal {
            log_text: sanitize_scanner_text(&String::from_utf8_lossy(&journal_output.stdout)),
        }
    })
}

pub async fn read_daemon_log() -> DaemonLogContents {
    let file_contents = spawn_blocking(read_configured_log_file)
        .await
        .ok()
        .flatten();
    match file_contents {
        Some(file_contents) => file_contents,
        None => read_system_journal()
            .await
            .unwrap_or(DaemonLogContents::NoReadableLog),
    }
}

#[cfg(test)]
mod daemon_log_reader_tests {
    use super::*;

    #[test]
    fn log_file_setting_is_found_and_commented_settings_are_ignored() {
        assert_eq!(
            log_path_in_config("#LogFile /old.log\nLogFile /var/log/custom.log\nLogTime yes\n"),
            Some(PathBuf::from("/var/log/custom.log"))
        );
        assert_eq!(log_path_in_config("LogFileMaxSize 2M\n"), None);
    }

    #[test]
    fn only_the_last_lines_are_kept_in_order() {
        assert_eq!(last_log_lines("one\ntwo\nthree\n", 2), "two\nthree\n");
    }

    #[test]
    fn a_log_tail_starts_at_the_end_of_large_files() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let log_path = temporary_root.path().join("clamd.log");
        let many_lines = (0..200)
            .map(|line_number| format!("line {line_number}\n"))
            .collect::<String>();
        fs::write(&log_path, many_lines).expect("log file");
        let log_tail = read_log_tail(&log_path).expect("log tail");
        assert_eq!(log_tail.lines().count(), SHOWN_LINE_COUNT);
        assert_eq!(log_tail.lines().last(), Some("line 199"));
    }
}
