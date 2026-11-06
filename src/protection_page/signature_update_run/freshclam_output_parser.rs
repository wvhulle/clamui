use crate::{
    host_services::{
        clamav_scanner::{
            scanner_exit_classification::AbnormalScannerExit,
            scanner_process_events::ScanStartFailure,
        },
        systemd_bus::host_systemd_units::{SystemdBusFailure, UnitStartOutcome},
    },
    protection_page::signature_update_run::{
        database_update_events::UpdaterFinish, updater_exit_status::FreshclamExit,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RateLimitCooldown {
    CooldownUnknown,
    CooldownUntil { cooldown_text: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitedDatabase {
    pub database_name: String,
    pub rate_limit_cooldown: RateLimitCooldown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FreshclamReportSummary {
    pub updated_databases: Vec<String>,
    pub current_databases: Vec<String>,
    pub rate_limited_databases: Vec<RateLimitedDatabase>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum UpdateFailureReason {
    AuthorizationRefused,
    SystemdUnreachable(SystemdBusFailure),
    ServiceJobEnded { job_result: String },
    FreshclamEndedAbnormally(AbnormalScannerExit),
    RateLimitedDatabases,
    RateLimitedByMirror,
    BlockedByCdn,
    MirrorUnavailable,
    CertificateRejected,
    ConnectionTimedOut,
    DatabaseLocked,
    PermissionDenied,
    ConnectionFailed,
    NameResolutionFailed,
    ReportedByUpdater { diagnostic_text: String },
    UpdaterResultMissing,
}

#[derive(Debug)]
pub enum DatabaseUpdateOutcome {
    DefinitionsUpdated(FreshclamReportSummary),
    AlreadyCurrent(FreshclamReportSummary),
    ServiceRanWithoutVerdict(FreshclamReportSummary),
    UpdateRequestedFromDaemon,
    UpdateCancelled,
    UpdateFailed {
        failure_reason: UpdateFailureReason,
        report_summary: FreshclamReportSummary,
    },
    UpdaterNeverStarted(ScanStartFailure),
}

const RATE_LIMIT_MARKERS: &[&str] = &[
    "rate limit",
    "rate-limit",
    "429",
    "too many requests",
    "temporarily blocked",
    "blocked temporarily",
];
const CDN_MARKERS: &[&str] = &["cloudfront", "cloudflare"];
const CERTIFICATE_MARKERS: &[&str] = &["certificate", "ssl error", "tls error", "verify failed"];

fn database_name_in_line(report_line: &str) -> Option<String> {
    report_line
        .split(|line_character: char| {
            !(line_character.is_ascii_alphanumeric() || matches!(line_character, '.' | '_' | '-'))
        })
        .find(|line_word| {
            let lowercase_word = line_word.to_ascii_lowercase();
            [".cvd", ".cld", ".cud"]
                .iter()
                .any(|database_suffix| lowercase_word.ends_with(database_suffix))
        })
        .map(str::to_owned)
}

fn cooldown_in_line(report_line: &str) -> Option<String> {
    let lowercase_line = report_line.to_ascii_lowercase();
    let cooldown_position = lowercase_line
        .find("cool-down until after:")
        .or_else(|| lowercase_line.find("cooldown until after:"))?;
    report_line[cooldown_position..]
        .split_once(':')
        .map(|label_and_cooldown| label_and_cooldown.1.trim().to_owned())
        .filter(|cooldown_text| !cooldown_text.is_empty())
}

fn line_mentions_any(lowercase_text: &str, text_markers: &[&str]) -> bool {
    text_markers
        .iter()
        .any(|text_marker| lowercase_text.contains(text_marker))
}

#[derive(Default)]
struct ReportParsingState {
    report_summary: FreshclamReportSummary,
    current_database: Option<String>,
}

impl ReportParsingState {
    fn remember_rate_limit(&mut self, rate_limit_cooldown: RateLimitCooldown) {
        let Some(database_name) = self.current_database.clone() else {
            return;
        };
        let rate_limited_databases = &mut self.report_summary.rate_limited_databases;
        match rate_limited_databases
            .iter_mut()
            .find(|known_database| known_database.database_name == database_name)
        {
            Some(known_database) if rate_limit_cooldown != RateLimitCooldown::CooldownUnknown => {
                known_database.rate_limit_cooldown = rate_limit_cooldown;
            }
            Some(_already_recorded) => {}
            None => rate_limited_databases.push(RateLimitedDatabase {
                database_name,
                rate_limit_cooldown,
            }),
        }
    }

    fn absorb_report_line(mut self, report_line: &str) -> Self {
        let lowercase_line = report_line.to_ascii_lowercase();
        let line_database = database_name_in_line(report_line);
        if line_database.is_some() {
            self.current_database.clone_from(&line_database);
        }
        if let Some(cooldown_text) = cooldown_in_line(report_line) {
            self.remember_rate_limit(RateLimitCooldown::CooldownUntil { cooldown_text });
        } else if line_mentions_any(&lowercase_line, RATE_LIMIT_MARKERS)
            || line_mentions_any(&lowercase_line, CDN_MARKERS)
        {
            self.remember_rate_limit(RateLimitCooldown::CooldownUnknown);
        } else if let Some(database_name) = line_database {
            let target_list = if lowercase_line.contains("updated (version:") {
                Some(&mut self.report_summary.updated_databases)
            } else if lowercase_line.contains("is up-to-date")
                || lowercase_line.contains("is up to date")
            {
                Some(&mut self.report_summary.current_databases)
            } else {
                None
            };
            if let Some(target_list) = target_list {
                if !target_list.contains(&database_name) {
                    target_list.push(database_name.clone());
                }
                self.report_summary
                    .rate_limited_databases
                    .retain(|known_database| known_database.database_name != database_name);
            }
        }
        self
    }
}

pub fn summarize_freshclam_report(report_text: &str) -> FreshclamReportSummary {
    report_text
        .lines()
        .map(str::trim)
        .filter(|report_line| !report_line.is_empty())
        .fold(
            ReportParsingState::default(),
            ReportParsingState::absorb_report_line,
        )
        .report_summary
}

fn classify_update_failure(
    report_text: &str,
    report_summary: &FreshclamReportSummary,
    silent_failure_reason: UpdateFailureReason,
) -> UpdateFailureReason {
    let lowercase_report = report_text.to_ascii_lowercase();
    if !report_summary.rate_limited_databases.is_empty() {
        UpdateFailureReason::RateLimitedDatabases
    } else if line_mentions_any(&lowercase_report, RATE_LIMIT_MARKERS) {
        UpdateFailureReason::RateLimitedByMirror
    } else if line_mentions_any(&lowercase_report, CDN_MARKERS) {
        UpdateFailureReason::BlockedByCdn
    } else if lowercase_report.contains("mirror")
        && (lowercase_report.contains("down") || lowercase_report.contains("unavailable"))
    {
        UpdateFailureReason::MirrorUnavailable
    } else if line_mentions_any(&lowercase_report, CERTIFICATE_MARKERS) {
        UpdateFailureReason::CertificateRejected
    } else if lowercase_report.contains("timeout") || lowercase_report.contains("timed out") {
        UpdateFailureReason::ConnectionTimedOut
    } else if lowercase_report.contains("locked") || lowercase_report.contains("lock") {
        UpdateFailureReason::DatabaseLocked
    } else if lowercase_report.contains("permission denied") {
        UpdateFailureReason::PermissionDenied
    } else if lowercase_report.contains("can't resolve")
        || lowercase_report.contains("host not found")
    {
        UpdateFailureReason::NameResolutionFailed
    } else if lowercase_report.contains("can't connect") || lowercase_report.contains("connection")
    {
        UpdateFailureReason::ConnectionFailed
    } else if report_text.trim().is_empty() {
        silent_failure_reason
    } else {
        UpdateFailureReason::ReportedByUpdater {
            diagnostic_text: report_text.trim().to_owned(),
        }
    }
}

fn failed_update(
    failure_reason: UpdateFailureReason,
    report_summary: FreshclamReportSummary,
) -> DatabaseUpdateOutcome {
    DatabaseUpdateOutcome::UpdateFailed {
        failure_reason,
        report_summary,
    }
}

fn interpret_unit_run(
    report_text: &str,
    unit_outcome: UnitStartOutcome,
    report_summary: FreshclamReportSummary,
) -> DatabaseUpdateOutcome {
    match unit_outcome {
        UnitStartOutcome::UnitFinished if !report_summary.updated_databases.is_empty() => {
            DatabaseUpdateOutcome::DefinitionsUpdated(report_summary)
        }
        UnitStartOutcome::UnitFinished if !report_summary.current_databases.is_empty() => {
            DatabaseUpdateOutcome::AlreadyCurrent(report_summary)
        }
        UnitStartOutcome::UnitFinished => {
            DatabaseUpdateOutcome::ServiceRanWithoutVerdict(report_summary)
        }
        UnitStartOutcome::JobEnded { job_result } => {
            let failure_reason = classify_update_failure(
                report_text,
                &report_summary,
                UpdateFailureReason::ServiceJobEnded { job_result },
            );
            failed_update(failure_reason, report_summary)
        }
        UnitStartOutcome::AuthorizationRefused => {
            failed_update(UpdateFailureReason::AuthorizationRefused, report_summary)
        }
        UnitStartOutcome::BusFailure(bus_failure) => failed_update(
            UpdateFailureReason::SystemdUnreachable(bus_failure),
            report_summary,
        ),
    }
}

fn interpret_daemon_signal(
    signal_outcome: UnitStartOutcome,
    report_summary: FreshclamReportSummary,
) -> DatabaseUpdateOutcome {
    match signal_outcome {
        UnitStartOutcome::UnitFinished => DatabaseUpdateOutcome::UpdateRequestedFromDaemon,
        UnitStartOutcome::JobEnded { job_result } => failed_update(
            UpdateFailureReason::ServiceJobEnded { job_result },
            report_summary,
        ),
        UnitStartOutcome::AuthorizationRefused => {
            failed_update(UpdateFailureReason::AuthorizationRefused, report_summary)
        }
        UnitStartOutcome::BusFailure(bus_failure) => failed_update(
            UpdateFailureReason::SystemdUnreachable(bus_failure),
            report_summary,
        ),
    }
}

fn interpret_freshclam_exit(
    report_text: &str,
    freshclam_exit: FreshclamExit,
    report_summary: FreshclamReportSummary,
) -> DatabaseUpdateOutcome {
    match freshclam_exit {
        FreshclamExit::UpdateSucceeded if !report_summary.updated_databases.is_empty() => {
            DatabaseUpdateOutcome::DefinitionsUpdated(report_summary)
        }
        FreshclamExit::UpdateSucceeded | FreshclamExit::UpdateAlreadyCurrent => {
            DatabaseUpdateOutcome::AlreadyCurrent(report_summary)
        }
        FreshclamExit::ExitedAbnormally(
            abnormal_exit @ AbnormalScannerExit::ScannerError { .. },
        ) => {
            let failure_reason = classify_update_failure(
                report_text,
                &report_summary,
                UpdateFailureReason::FreshclamEndedAbnormally(abnormal_exit),
            );
            failed_update(failure_reason, report_summary)
        }
        FreshclamExit::ExitedAbnormally(
            abnormal_exit @ (AbnormalScannerExit::KilledBySignal { .. }
            | AbnormalScannerExit::UnrecognizedWaitStatus { .. }
            | AbnormalScannerExit::WaitFailed { .. }),
        ) => failed_update(
            UpdateFailureReason::FreshclamEndedAbnormally(abnormal_exit),
            report_summary,
        ),
    }
}

pub fn interpret_updater_finish(
    report_text: &str,
    updater_finish: UpdaterFinish,
) -> DatabaseUpdateOutcome {
    let report_summary = summarize_freshclam_report(report_text);
    match updater_finish {
        UpdaterFinish::FreshclamExited(freshclam_exit) => {
            interpret_freshclam_exit(report_text, freshclam_exit, report_summary)
        }
        UpdaterFinish::ServiceUnitRan(unit_outcome) => {
            interpret_unit_run(report_text, unit_outcome, report_summary)
        }
        UpdaterFinish::RunningDaemonSignalled(signal_outcome) => {
            interpret_daemon_signal(signal_outcome, report_summary)
        }
        UpdaterFinish::UpdaterNeverStarted(start_failure) => {
            DatabaseUpdateOutcome::UpdaterNeverStarted(start_failure)
        }
    }
}

pub fn interpret_unfinished_update(report_text: &str) -> DatabaseUpdateOutcome {
    failed_update(
        UpdateFailureReason::UpdaterResultMissing,
        summarize_freshclam_report(report_text),
    )
}

#[cfg(test)]
mod freshclam_output_parser_tests {
    use super::*;

    #[test]
    fn updated_and_current_databases_are_separated() {
        let report_summary = summarize_freshclam_report(
            "daily.cld updated (version: 28173, sigs: 100)\nmain.cvd database is up-to-date \
             (version: 63)\n",
        );
        assert_eq!(report_summary.updated_databases, vec!["daily.cld"]);
        assert_eq!(report_summary.current_databases, vec!["main.cvd"]);
        assert!(report_summary.rate_limited_databases.is_empty());
    }

    #[test]
    fn cooldown_is_attached_to_the_database_in_progress() {
        let report_summary = summarize_freshclam_report(
            "Downloading daily.cvd\nreceived error code 429 or 403 from the ClamAV Content \
             Delivery Network\nCool-down until after: 2026-11-05 12:00:00\n",
        );
        assert_eq!(
            report_summary.rate_limited_databases,
            vec![RateLimitedDatabase {
                database_name: "daily.cvd".to_owned(),
                rate_limit_cooldown: RateLimitCooldown::CooldownUntil {
                    cooldown_text: "2026-11-05 12:00:00".to_owned(),
                },
            }]
        );
    }

    #[test]
    fn a_later_success_clears_an_earlier_rate_limit() {
        let report_summary = summarize_freshclam_report(
            "daily.cvd rate limited\ndaily.cvd updated (version: 1, sigs: 2)\n",
        );
        assert!(report_summary.rate_limited_databases.is_empty());
        assert_eq!(report_summary.updated_databases, vec!["daily.cvd"]);
    }

    fn freshclam_finish(freshclam_exit: FreshclamExit) -> UpdaterFinish {
        UpdaterFinish::FreshclamExited(freshclam_exit)
    }

    fn freshclam_error(exit_code: i32) -> UpdaterFinish {
        freshclam_finish(FreshclamExit::ExitedAbnormally(
            AbnormalScannerExit::ScannerError { exit_code },
        ))
    }

    #[test]
    fn freshclam_exit_decides_the_outcome() {
        assert!(matches!(
            interpret_updater_finish(
                "daily.cld updated (version: 1, sigs: 2)",
                freshclam_finish(FreshclamExit::UpdateSucceeded)
            ),
            DatabaseUpdateOutcome::DefinitionsUpdated(_)
        ));
        assert!(matches!(
            interpret_updater_finish(
                "main.cvd database is up-to-date",
                freshclam_finish(FreshclamExit::UpdateSucceeded)
            ),
            DatabaseUpdateOutcome::AlreadyCurrent(_)
        ));
        assert!(matches!(
            interpret_updater_finish("", freshclam_finish(FreshclamExit::UpdateAlreadyCurrent)),
            DatabaseUpdateOutcome::AlreadyCurrent(_)
        ));
    }

    #[test]
    fn a_unit_run_without_a_version_line_is_not_already_current() {
        assert!(matches!(
            interpret_updater_finish(
                "Started clamav-freshclam.service",
                UpdaterFinish::ServiceUnitRan(UnitStartOutcome::UnitFinished)
            ),
            DatabaseUpdateOutcome::ServiceRanWithoutVerdict(_)
        ));
        assert!(matches!(
            interpret_updater_finish(
                "daily.cld updated (version: 1, sigs: 2)",
                UpdaterFinish::ServiceUnitRan(UnitStartOutcome::UnitFinished)
            ),
            DatabaseUpdateOutcome::DefinitionsUpdated(_)
        ));
        assert!(matches!(
            interpret_updater_finish(
                "main.cvd database is up-to-date (version: 63)",
                UpdaterFinish::ServiceUnitRan(UnitStartOutcome::UnitFinished)
            ),
            DatabaseUpdateOutcome::AlreadyCurrent(_)
        ));
    }

    #[test]
    fn a_signalled_daemon_only_requested_an_update() {
        assert!(matches!(
            interpret_updater_finish(
                "",
                UpdaterFinish::RunningDaemonSignalled(UnitStartOutcome::UnitFinished)
            ),
            DatabaseUpdateOutcome::UpdateRequestedFromDaemon
        ));
    }

    fn failure_reason_of(report_text: &str, updater_finish: UpdaterFinish) -> UpdateFailureReason {
        match interpret_updater_finish(report_text, updater_finish) {
            DatabaseUpdateOutcome::UpdateFailed { failure_reason, .. } => failure_reason,
            unexpected_outcome => panic!("expected a failure, got {unexpected_outcome:?}"),
        }
    }

    #[test]
    fn a_refused_authorization_is_typed_and_never_read_from_the_transcript() {
        assert_eq!(
            failure_reason_of(
                "",
                UpdaterFinish::ServiceUnitRan(UnitStartOutcome::AuthorizationRefused)
            ),
            UpdateFailureReason::AuthorizationRefused
        );
        assert_eq!(
            failure_reason_of(
                "",
                UpdaterFinish::RunningDaemonSignalled(UnitStartOutcome::AuthorizationRefused)
            ),
            UpdateFailureReason::AuthorizationRefused
        );
        assert_eq!(
            failure_reason_of("access denied", freshclam_error(2)),
            UpdateFailureReason::ReportedByUpdater {
                diagnostic_text: "access denied".to_owned(),
            }
        );
    }

    #[test]
    fn failures_are_classified_from_the_report() {
        assert_eq!(
            failure_reason_of("Failed to lock database directory", freshclam_error(62)),
            UpdateFailureReason::DatabaseLocked
        );
        assert_eq!(
            failure_reason_of("Can't resolve database.clamav.net", freshclam_error(52)),
            UpdateFailureReason::NameResolutionFailed
        );
        assert_eq!(
            failure_reason_of("", freshclam_error(56)),
            UpdateFailureReason::FreshclamEndedAbnormally(AbnormalScannerExit::ScannerError {
                exit_code: 56
            })
        );
        assert_eq!(
            failure_reason_of(
                "",
                UpdaterFinish::ServiceUnitRan(UnitStartOutcome::JobEnded {
                    job_result: "failed".to_owned()
                })
            ),
            UpdateFailureReason::ServiceJobEnded {
                job_result: "failed".to_owned()
            }
        );
        assert_eq!(
            failure_reason_of("something odd", freshclam_error(2)),
            UpdateFailureReason::ReportedByUpdater {
                diagnostic_text: "something odd".to_owned(),
            }
        );
    }

    #[test]
    fn a_killed_freshclam_keeps_its_signal() {
        assert_eq!(
            failure_reason_of(
                "Downloading daily.cvd connection",
                freshclam_finish(FreshclamExit::ExitedAbnormally(
                    AbnormalScannerExit::KilledBySignal { signal_number: 9 }
                ))
            ),
            UpdateFailureReason::FreshclamEndedAbnormally(AbnormalScannerExit::KilledBySignal {
                signal_number: 9
            })
        );
    }
}
