use jiff::{Timestamp, civil, tz::TimeZone};

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    systemd_journal::journal_log_entries::LogSeverityLevel,
};

const CLAMD_LOG_TIME_FORMAT: &str = "%a %b %e %H:%M:%S %Y";
const CLAMD_LOG_TIME_SEPARATOR: &str = " -> ";
const ERROR_MESSAGE_PREFIXES: [&str; 2] = ["ERROR:", "LibClamAV Error:"];
const WARNING_MESSAGE_PREFIXES: [&str; 2] = ["WARNING:", "LibClamAV Warning:"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamdLogLine {
    Stamped {
        logged_at: Timestamp,
        severity_level: LogSeverityLevel,
        message_text: String,
    },
    Unstamped {
        severity_level: LogSeverityLevel,
        message_text: String,
    },
}

fn clamd_message_severity(message_text: &str) -> LogSeverityLevel {
    if ERROR_MESSAGE_PREFIXES
        .iter()
        .any(|error_prefix| message_text.starts_with(error_prefix))
    {
        LogSeverityLevel::Error
    } else if WARNING_MESSAGE_PREFIXES
        .iter()
        .any(|warning_prefix| message_text.starts_with(warning_prefix))
    {
        LogSeverityLevel::Warning
    } else {
        LogSeverityLevel::Informational
    }
}

fn parse_clamd_log_time(time_text: &str, log_time_zone: &TimeZone) -> Option<Timestamp> {
    civil::DateTime::strptime(CLAMD_LOG_TIME_FORMAT, time_text.trim())
        .ok()?
        .to_zoned(log_time_zone.clone())
        .ok()
        .map(|logged_time| logged_time.timestamp())
}

pub fn parse_clamd_log_line(raw_log_line: &str, log_time_zone: &TimeZone) -> ClamdLogLine {
    let sanitized_line = sanitize_scanner_line(raw_log_line);
    let stamped_parts = sanitized_line
        .split_once(CLAMD_LOG_TIME_SEPARATOR)
        .and_then(|(time_text, message_text)| {
            parse_clamd_log_time(time_text, log_time_zone)
                .map(|logged_at| (logged_at, message_text))
        });
    match stamped_parts {
        Some((logged_at, message_text)) => ClamdLogLine::Stamped {
            logged_at,
            severity_level: clamd_message_severity(message_text),
            message_text: message_text.to_owned(),
        },
        None => ClamdLogLine::Unstamped {
            severity_level: clamd_message_severity(&sanitized_line),
            message_text: sanitized_line,
        },
    }
}

pub fn parse_clamd_log_text(log_text: &str) -> Vec<ClamdLogLine> {
    let log_time_zone = TimeZone::system();
    log_text
        .lines()
        .filter(|raw_log_line| !raw_log_line.trim().is_empty())
        .map(|raw_log_line| parse_clamd_log_line(raw_log_line, &log_time_zone))
        .collect()
}

#[cfg(test)]
mod clamd_log_lines_tests {
    use super::*;

    #[test]
    fn a_log_time_prefix_becomes_the_line_timestamp() {
        let parsed_line = parse_clamd_log_line(
            "Sat Nov  7 10:15:42 2026 -> /home/user/eicar.txt: Eicar-Test-Signature FOUND",
            &TimeZone::UTC,
        );
        assert_eq!(
            parsed_line,
            ClamdLogLine::Stamped {
                logged_at: "2026-11-07T10:15:42Z".parse().expect("timestamp"),
                severity_level: LogSeverityLevel::Informational,
                message_text: "/home/user/eicar.txt: Eicar-Test-Signature FOUND".to_owned(),
            }
        );
    }

    #[test]
    fn lines_without_log_time_keep_their_whole_text() {
        assert_eq!(
            parse_clamd_log_line("+++ Started at Sat Nov  7 10:15:42 2026", &TimeZone::UTC),
            ClamdLogLine::Unstamped {
                severity_level: LogSeverityLevel::Informational,
                message_text: "+++ Started at Sat Nov  7 10:15:42 2026".to_owned(),
            }
        );
    }

    #[test]
    fn clamd_error_and_warning_prefixes_set_the_severity() {
        assert_eq!(
            parse_clamd_log_line(
                "Sat Nov  7 10:15:42 2026 -> ERROR: Can't open /run/clamd.ctl",
                &TimeZone::UTC
            ),
            ClamdLogLine::Stamped {
                logged_at: "2026-11-07T10:15:42Z".parse().expect("timestamp"),
                severity_level: LogSeverityLevel::Error,
                message_text: "ERROR: Can't open /run/clamd.ctl".to_owned(),
            }
        );
        assert_eq!(
            parse_clamd_log_line("LibClamAV Warning: old database", &TimeZone::UTC),
            ClamdLogLine::Unstamped {
                severity_level: LogSeverityLevel::Warning,
                message_text: "LibClamAV Warning: old database".to_owned(),
            }
        );
    }

    #[test]
    fn blank_lines_are_dropped_from_the_log_text() {
        assert_eq!(parse_clamd_log_text("first\n\n  \nsecond\n").len(), 2);
    }
}
