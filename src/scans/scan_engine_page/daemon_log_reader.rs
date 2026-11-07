use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use futures::{Stream, StreamExt, stream};
use inotify::{Inotify, WatchMask};
use tokio::task::spawn_blocking;

use crate::host_services::{
    blocking_iterator_stream::blocking_iterator_stream,
    clamav_scanner::clamd_log_lines::{ClamdLogLine, parse_clamd_log_text},
    desktop::flatpak_sandbox::readable_host_path,
    systemd_journal::{
        service_log_contents::{SHOWN_LOG_LINE_COUNT, ServiceLogContents, read_unit_journal_log},
        unit_journal_reader::appended_unit_entries,
    },
};

const DAEMON_LOG_WATCH_THREAD: &str = "daemon-log-watch";
const CHANGE_BURST_SIZE: usize = 64;
const INOTIFY_BUFFER_SIZE: usize = 4096;
const LOG_TAIL_BYTES: u64 = 256 * 1024;
const DEFAULT_LOG_PATHS: [&str; 2] = ["/var/log/clamav/clamd.log", "/var/log/clamd.log"];
const CLAMD_CONFIG_PATHS: [&str; 3] = [
    "/etc/clamav/clamd.conf",
    "/etc/clamd.conf",
    "/etc/clamd.d/scan.conf",
];
const DAEMON_SERVICE_UNITS: [&str; 3] = [
    "clamav-daemon.service",
    "clamd.service",
    "clamd@scan.service",
];

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

fn read_log_tail(log_path: &Path) -> Option<Vec<ClamdLogLine>> {
    let mut log_file = fs::File::open(log_path).ok()?;
    let log_length = log_file.metadata().ok()?.len();
    log_file
        .seek(SeekFrom::Start(log_length.saturating_sub(LOG_TAIL_BYTES)))
        .ok()?;
    let mut tail_bytes = Vec::new();
    log_file.read_to_end(&mut tail_bytes).ok()?;
    Some(parse_clamd_log_text(&last_log_lines(
        &String::from_utf8_lossy(&tail_bytes),
        SHOWN_LOG_LINE_COUNT,
    )))
}

fn readable_log_file() -> Option<PathBuf> {
    let configured_paths = CLAMD_CONFIG_PATHS
        .iter()
        .filter_map(|config_path| fs::read_to_string(readable_host_path(config_path)).ok())
        .filter_map(|config_text| log_path_in_config(&config_text));
    let default_paths = DEFAULT_LOG_PATHS.iter().map(PathBuf::from);
    configured_paths
        .chain(default_paths)
        .find(|log_path| fs::File::open(log_path).is_ok())
}

fn read_configured_log_file() -> Option<ServiceLogContents> {
    let log_path = readable_log_file()?;
    read_log_tail(&log_path).map(|log_lines| ServiceLogContents::FromLogFile {
        log_path,
        log_lines,
    })
}

fn log_file_changes(log_path: &Path) -> impl Iterator<Item = ()> + use<> {
    let watched_name = log_path.file_name().map(ToOwned::to_owned);
    let watching_inotify = log_path.parent().and_then(|log_directory| {
        let inotify = Inotify::init().ok()?;
        inotify
            .watches()
            .add(
                log_directory,
                WatchMask::MODIFY
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::CREATE
                    | WatchMask::MOVED_TO
                    | WatchMask::DELETE,
            )
            .ok()?;
        Some(inotify)
    });
    watching_inotify.into_iter().flat_map(move |mut inotify| {
        let watched_name = watched_name.clone();
        let mut event_buffer = vec![0; INOTIFY_BUFFER_SIZE];
        std::iter::from_fn(move || {
            loop {
                let log_file_changed = inotify
                    .read_events_blocking(&mut event_buffer)
                    .ok()?
                    .any(|directory_event| directory_event.name == watched_name.as_deref());
                if log_file_changed {
                    return Some(());
                }
            }
        })
    })
}

fn daemon_log_changes() -> Box<dyn Iterator<Item = ()>> {
    match readable_log_file() {
        Some(log_path) => Box::new(log_file_changes(&log_path)),
        None => Box::new(appended_unit_entries(&DAEMON_SERVICE_UNITS)),
    }
}

pub fn daemon_log_updates() -> impl Stream<Item = ServiceLogContents> + Send + 'static {
    stream::once(read_daemon_log()).chain(
        blocking_iterator_stream(
            DAEMON_LOG_WATCH_THREAD,
            daemon_log_changes,
            |_spawn_failure| (),
        )
        .ready_chunks(CHANGE_BURST_SIZE)
        .then(|_change_burst| read_daemon_log()),
    )
}

pub async fn read_daemon_log() -> ServiceLogContents {
    let file_contents = spawn_blocking(read_configured_log_file)
        .await
        .ok()
        .flatten();
    match file_contents {
        Some(file_contents) => file_contents,
        None => read_unit_journal_log(&DAEMON_SERVICE_UNITS).await,
    }
}

#[cfg(test)]
mod daemon_log_reader_tests {
    use super::*;
    use crate::host_services::systemd_journal::journal_log_entries::LogSeverityLevel;

    #[test]
    fn appending_to_the_log_file_is_reported_and_other_files_are_not() {
        let log_directory = tempfile::tempdir().expect("log directory");
        let log_path = log_directory.path().join("clamd.log");
        fs::write(&log_path, b"started\n").expect("log file");
        let mut log_changes = log_file_changes(&log_path);
        fs::write(log_directory.path().join("freshclam.log"), b"other\n").expect("other log");
        let appended_log = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            fs::OpenOptions::new()
                .append(true)
                .open(&log_path)
                .and_then(|mut log_file| std::io::Write::write_all(&mut log_file, b"found\n"))
                .expect("appended line");
        });
        assert_eq!(log_changes.next(), Some(()));
        appended_log.join().expect("appending thread");
    }

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
        let many_lines = (0..1000)
            .map(|line_number| format!("line {line_number}\n"))
            .collect::<String>();
        fs::write(&log_path, many_lines).expect("log file");
        let log_tail = read_log_tail(&log_path).expect("log tail");
        assert_eq!(log_tail.len(), SHOWN_LOG_LINE_COUNT);
        assert_eq!(
            log_tail.last(),
            Some(&ClamdLogLine::Unstamped {
                severity_level: LogSeverityLevel::Informational,
                message_text: "line 999".to_owned(),
            })
        );
    }
}
