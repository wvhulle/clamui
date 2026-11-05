use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use gettextrs::{gettext, ngettext};
use relm4::gtk::glib;
use tokio::task::spawn_blocking;

use crate::{
    clamav_components::{
        component_availability::{
            ClamavComponent, ProgramProbe, clamd_answers_ping, probe_program_version,
        },
        distribution_install_guides::{DistributionFamily, component_install_guides},
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    system_audit::{
        audit_report_model::{AuditCategory, AuditCheck, AuditSection, AuditStatus},
        host_command_probes::{first_active_unit, systemd_is_available},
        suggested_audit_commands::{FRESHCLAM_UPDATE_COMMAND, SuggestedRemedy, suggested_command},
    },
    virus_database::database_directory_status::{
        FreshclamServiceState, configured_database_directory, detect_freshclam_service,
    },
};

const CLAMAV_DOCUMENTATION_URL: &str = "https://docs.clamav.net/";
const FRESHCLAM_DOCUMENTATION_URL: &str =
    "https://docs.clamav.net/manual/Usage/SignatureManagement.html";
const CLAMD_DOCUMENTATION_URL: &str = "https://docs.clamav.net/manual/Usage/Scanning.html#clamd";

const DATABASE_HEADER_LENGTH: u64 = 512;
const DATABASE_HEADER_MAGIC: &str = "ClamAV-VDB";
const DATABASE_FRESH_DAYS: u64 = 3;
const DATABASE_STALE_DAYS: u64 = 7;
const SECONDS_PER_DAY: u64 = 86_400;
const FALLBACK_DATABASE_DIRECTORIES: [&str; 2] = ["/var/lib/clamav", "/usr/local/share/clamav"];
const DAILY_DATABASE_FILE_NAMES: [&str; 2] = ["daily.cvd", "daily.cld"];
const DAEMON_SERVICE_UNITS: [&str; 3] = [
    "clamav-daemon.service",
    "clamd@scan.service",
    "clamd.service",
];
const MONTH_ABBREVIATIONS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseEvidence {
    BuiltDaysAgo { age_days: u64, build_date: String },
    AgeUndetermined,
    DatabaseMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseFileEvidence {
    StampedDatabase { build_seconds: u64 },
    UnstampedDatabase,
    NoDatabaseFile,
}

pub fn parse_database_header_seconds(header_bytes: &[u8]) -> Option<u64> {
    let header_text = String::from_utf8_lossy(header_bytes);
    let header_fields = header_text.split(':').collect::<Vec<_>>();
    if !header_fields.first()?.starts_with(DATABASE_HEADER_MAGIC) {
        return None;
    }
    header_fields
        .get(8)?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

pub fn parse_version_banner_seconds(version_banner: &str) -> Option<u64> {
    let date_fields = version_banner
        .split('/')
        .nth(2)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let [_weekday_name, month_name, day_text, clock_text, year_text] = date_fields.as_slice()
    else {
        return None;
    };
    let month_position = MONTH_ABBREVIATIONS
        .iter()
        .position(|month_abbreviation| month_abbreviation == month_name)?;
    let clock_fields = clock_text
        .split(':')
        .map(str::parse::<i32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let [clock_hour, clock_minute, clock_second] = clock_fields.as_slice() else {
        return None;
    };
    let banner_time = glib::DateTime::from_local(
        year_text.parse().ok()?,
        i32::try_from(month_position).ok()? + 1,
        day_text.parse().ok()?,
        *clock_hour,
        *clock_minute,
        f64::from(*clock_second),
    )
    .ok()?;
    u64::try_from(banner_time.to_unix()).ok()
}

fn formatted_build_date(build_seconds: u64) -> String {
    i64::try_from(build_seconds)
        .ok()
        .and_then(|unix_seconds| glib::DateTime::from_unix_local(unix_seconds).ok())
        .and_then(|build_time| build_time.format("%x").ok())
        .map(|formatted_date| formatted_date.to_string())
        .unwrap_or_default()
}

pub fn database_evidence_from_stamp(build_seconds: u64, current_seconds: u64) -> DatabaseEvidence {
    current_seconds.checked_sub(build_seconds).map_or(
        DatabaseEvidence::AgeUndetermined,
        |elapsed_seconds| DatabaseEvidence::BuiltDaysAgo {
            age_days: elapsed_seconds / SECONDS_PER_DAY,
            build_date: formatted_build_date(build_seconds),
        },
    )
}

fn database_age_detail(age_days: u64, build_date: &str) -> String {
    ngettext(
        "Database is {days} day old (built {date})",
        "Database is {days} days old (built {date})",
        u32::try_from(age_days).unwrap_or(u32::MAX),
    )
    .replace("{days}", &age_days.to_string())
    .replace("{date}", build_date)
}

pub fn database_freshness_check(database_evidence: &DatabaseEvidence) -> AuditCheck {
    let check_name = gettext("Virus Database");
    let database_check = match database_evidence {
        DatabaseEvidence::BuiltDaysAgo {
            age_days,
            build_date,
        } if *age_days <= DATABASE_FRESH_DAYS => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            ngettext(
                "Up to date ({days} day old, built {date})",
                "Up to date ({days} days old, built {date})",
                u32::try_from(*age_days).unwrap_or(u32::MAX),
            )
            .replace("{days}", &age_days.to_string())
            .replace("{date}", build_date),
        ),
        DatabaseEvidence::BuiltDaysAgo {
            age_days,
            build_date,
        } if *age_days <= DATABASE_STALE_DAYS => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            database_age_detail(*age_days, build_date),
        )
        .with_recommendation(gettext("Update virus database to ensure protection"))
        .with_suggested_commands([FRESHCLAM_UPDATE_COMMAND]),
        DatabaseEvidence::BuiltDaysAgo {
            age_days,
            build_date,
        } => AuditCheck::new(
            check_name,
            AuditStatus::CheckFailed,
            database_age_detail(*age_days, build_date),
        )
        .with_recommendation(gettext(
            "Database is critically outdated. Update immediately.",
        ))
        .with_suggested_commands([FRESHCLAM_UPDATE_COMMAND]),
        DatabaseEvidence::AgeUndetermined => AuditCheck::new(
            check_name,
            AuditStatus::StatusUnknown,
            gettext("Database files exist but age could not be determined"),
        ),
        DatabaseEvidence::DatabaseMissing => AuditCheck::new(
            check_name,
            AuditStatus::CheckFailed,
            gettext("No virus database found"),
        )
        .with_recommendation(gettext("Download virus database"))
        .with_suggested_commands([FRESHCLAM_UPDATE_COMMAND]),
    };
    database_check.with_documentation(FRESHCLAM_DOCUMENTATION_URL)
}

fn read_database_header(database_path: &Path) -> Option<Vec<u8>> {
    let mut header_bytes = Vec::new();
    fs::File::open(database_path)
        .ok()?
        .take(DATABASE_HEADER_LENGTH)
        .read_to_end(&mut header_bytes)
        .ok()?;
    Some(header_bytes)
}

fn daily_database_paths() -> Vec<PathBuf> {
    let mut database_directories = std::iter::once(configured_database_directory())
        .chain(FALLBACK_DATABASE_DIRECTORIES.map(PathBuf::from))
        .collect::<Vec<_>>();
    database_directories.dedup();
    database_directories
        .iter()
        .flat_map(|database_directory| {
            DAILY_DATABASE_FILE_NAMES.map(|file_name| database_directory.join(file_name))
        })
        .filter(|database_path| database_path.exists())
        .collect()
}

fn read_database_file_evidence() -> DatabaseFileEvidence {
    let database_paths = daily_database_paths();
    let newest_build_seconds = database_paths
        .iter()
        .filter_map(|database_path| read_database_header(database_path))
        .filter_map(|header_bytes| parse_database_header_seconds(&header_bytes))
        .max();
    match newest_build_seconds {
        Some(build_seconds) => DatabaseFileEvidence::StampedDatabase { build_seconds },
        None if database_paths.is_empty() => DatabaseFileEvidence::NoDatabaseFile,
        None => DatabaseFileEvidence::UnstampedDatabase,
    }
}

async fn inspect_database_evidence(version_banner: &str) -> DatabaseEvidence {
    let file_evidence = spawn_blocking(read_database_file_evidence)
        .await
        .unwrap_or(DatabaseFileEvidence::NoDatabaseFile);
    let current_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let banner_seconds = parse_version_banner_seconds(version_banner);
    match file_evidence {
        DatabaseFileEvidence::StampedDatabase { build_seconds } => {
            database_evidence_from_stamp(build_seconds, current_seconds)
        }
        DatabaseFileEvidence::UnstampedDatabase | DatabaseFileEvidence::NoDatabaseFile
            if banner_seconds.is_some() =>
        {
            banner_seconds.map_or(DatabaseEvidence::AgeUndetermined, |build_seconds| {
                database_evidence_from_stamp(build_seconds, current_seconds)
            })
        }
        DatabaseFileEvidence::UnstampedDatabase => DatabaseEvidence::AgeUndetermined,
        DatabaseFileEvidence::NoDatabaseFile => DatabaseEvidence::DatabaseMissing,
    }
}

pub fn clamav_missing_check(distribution_family: DistributionFamily) -> AuditCheck {
    AuditCheck::new(
        gettext("ClamAV Installation"),
        AuditStatus::CheckFailed,
        gettext("ClamAV is not installed"),
    )
    .with_recommendation(gettext("Install ClamAV to enable virus scanning"))
    .with_suggested_commands(
        component_install_guides(ClamavComponent::ClamscanScanner)
            .iter()
            .filter(|install_guide| install_guide.distribution_family == distribution_family)
            .map(|install_guide| install_guide.install_command),
    )
    .with_documentation(CLAMAV_DOCUMENTATION_URL)
}

fn clamav_installed_check(version_banner: &str) -> AuditCheck {
    let shown_version = if version_banner.is_empty() {
        "ClamAV".to_owned()
    } else {
        sanitize_scanner_line(version_banner)
    };
    AuditCheck::new(
        gettext("ClamAV Installation"),
        AuditStatus::CheckPassed,
        gettext("Installed: {version}").replace("{version}", &shown_version),
    )
    .with_documentation(CLAMAV_DOCUMENTATION_URL)
}

fn clamav_probe_failed_check(failure_text: &str) -> AuditCheck {
    AuditCheck::new(
        gettext("ClamAV Installation"),
        AuditStatus::StatusUnknown,
        sanitize_scanner_line(failure_text),
    )
    .with_documentation(CLAMAV_DOCUMENTATION_URL)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClamavDaemonEvidence {
    ServiceRunning { service_unit: &'static str },
    DaemonResponding,
    DaemonSilent,
}

pub fn clamav_daemon_check(
    daemon_evidence: ClamavDaemonEvidence,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("ClamAV Daemon");
    let daemon_check = match daemon_evidence {
        ClamavDaemonEvidence::ServiceRunning { service_unit } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Service {name} is running").replace("{name}", service_unit),
        ),
        ClamavDaemonEvidence::DaemonResponding => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Daemon is responding"),
        ),
        ClamavDaemonEvidence::DaemonSilent => AuditCheck::new(
            check_name,
            AuditStatus::NeedsReview,
            gettext("ClamAV daemon is not running"),
        )
        .with_recommendation(gettext("Start the daemon for faster scanning"))
        .with_suggested_commands(suggested_command(
            SuggestedRemedy::ClamavDaemonStart,
            distribution_family,
        )),
    };
    daemon_check.with_documentation(CLAMD_DOCUMENTATION_URL)
}

pub fn freshclam_service_check(
    freshclam_service: FreshclamServiceState,
    systemd_available: bool,
    distribution_family: DistributionFamily,
) -> AuditCheck {
    let check_name = gettext("Automatic Updates");
    let service_check = match freshclam_service {
        FreshclamServiceState::DaemonRunning { .. }
        | FreshclamServiceState::TimerScheduled { .. } => AuditCheck::new(
            check_name,
            AuditStatus::CheckPassed,
            gettext("Freshclam service is active"),
        ),
        FreshclamServiceState::ServiceStopped { .. } | FreshclamServiceState::ServiceNotFound
            if !systemd_available =>
        {
            AuditCheck::new(
                check_name,
                AuditStatus::StatusUnknown,
                gettext("Could not determine automatic update status"),
            )
        }
        FreshclamServiceState::ServiceStopped { .. } | FreshclamServiceState::ServiceNotFound => {
            AuditCheck::new(
                check_name,
                AuditStatus::NeedsReview,
                gettext("Freshclam automatic update service is not running"),
            )
            .with_recommendation(gettext("Enable automatic database updates"))
            .with_suggested_commands(suggested_command(
                SuggestedRemedy::FreshclamUpdatesEnable,
                distribution_family,
            ))
        }
    };
    service_check.with_documentation(FRESHCLAM_DOCUMENTATION_URL)
}

async fn inspect_daemon_evidence() -> ClamavDaemonEvidence {
    if let Some(service_unit) = first_active_unit(&DAEMON_SERVICE_UNITS).await {
        ClamavDaemonEvidence::ServiceRunning { service_unit }
    } else if clamd_answers_ping(Path::new("clamdscan")).await {
        ClamavDaemonEvidence::DaemonResponding
    } else {
        ClamavDaemonEvidence::DaemonSilent
    }
}

pub async fn audit_clamav_health(distribution_family: DistributionFamily) -> AuditSection {
    let section_checks = match probe_program_version(Path::new("clamscan")).await {
        ProgramProbe::NotFoundOnPath => vec![clamav_missing_check(distribution_family)],
        ProgramProbe::ProbeFailed { failure_text } => {
            vec![clamav_probe_failed_check(&failure_text)]
        }
        ProgramProbe::VersionReported { version_text } => vec![
            clamav_installed_check(&version_text),
            database_freshness_check(&inspect_database_evidence(&version_text).await),
            clamav_daemon_check(inspect_daemon_evidence().await, distribution_family),
            freshclam_service_check(
                detect_freshclam_service().await,
                systemd_is_available(),
                distribution_family,
            ),
        ],
    };
    AuditSection {
        audit_category: AuditCategory::ClamavHealth,
        section_checks,
    }
}

#[cfg(test)]
mod clamav_health_checks_tests {
    use super::*;
    use crate::system_audit::audit_report_model::CheckGuidance;

    const HEADER_TEXT: &str =
        "ClamAV-VDB:03 Nov 2026 07-27 +0000:28173:355000:90:md5sum:signature:builder:1793688000  ";

    fn database_status(age_days: u64) -> AuditStatus {
        database_freshness_check(&DatabaseEvidence::BuiltDaysAgo {
            age_days,
            build_date: "2026-11-03".to_owned(),
        })
        .check_status
    }

    fn suggested_commands(audit_check: &AuditCheck) -> Vec<&'static str> {
        audit_check
            .check_guidance
            .iter()
            .filter_map(|check_guidance| match check_guidance {
                CheckGuidance::SuggestedCommand(suggested_command) => Some(*suggested_command),
                CheckGuidance::RecommendationText(_) | CheckGuidance::DocumentationLink(_) => None,
            })
            .collect()
    }

    #[test]
    fn database_headers_yield_their_build_time() {
        assert_eq!(
            parse_database_header_seconds(HEADER_TEXT.as_bytes()),
            Some(1_793_688_000)
        );
        assert_eq!(parse_database_header_seconds(b"not a database"), None);
        assert_eq!(parse_database_header_seconds(b"ClamAV-VDB:short:row"), None);
        assert_eq!(
            parse_database_header_seconds(b"ClamAV-VDB:a:b:c:d:e:f:g:notanumber"),
            None
        );
    }

    #[test]
    fn version_banners_yield_the_database_date_when_present() {
        let expected_seconds = glib::DateTime::from_local(2026, 11, 3, 7, 27, 52.0)
            .expect("fixture date")
            .to_unix();
        assert_eq!(
            parse_version_banner_seconds("ClamAV 1.5.4/28173/Tue Nov  3 07:27:52 2026"),
            u64::try_from(expected_seconds).ok()
        );
        assert_eq!(parse_version_banner_seconds("ClamAV 1.5.4"), None);
        assert_eq!(
            parse_version_banner_seconds("ClamAV 1.5.4/28173/Tue Foo  3 07:27:52 2026"),
            None
        );
    }

    #[test]
    fn database_age_is_whole_days_and_a_future_stamp_is_undetermined() {
        assert!(matches!(
            database_evidence_from_stamp(1000, 1000 + 2 * SECONDS_PER_DAY + 5),
            DatabaseEvidence::BuiltDaysAgo { age_days: 2, .. }
        ));
        assert_eq!(
            database_evidence_from_stamp(5000, 1000),
            DatabaseEvidence::AgeUndetermined
        );
    }

    #[test]
    fn database_freshness_thresholds_match_the_audit_policy() {
        assert_eq!(database_status(3), AuditStatus::CheckPassed);
        assert_eq!(database_status(4), AuditStatus::NeedsReview);
        assert_eq!(database_status(7), AuditStatus::NeedsReview);
        assert_eq!(database_status(8), AuditStatus::CheckFailed);
        assert_eq!(
            database_freshness_check(&DatabaseEvidence::DatabaseMissing).check_status,
            AuditStatus::CheckFailed
        );
        assert_eq!(
            database_freshness_check(&DatabaseEvidence::AgeUndetermined).check_status,
            AuditStatus::StatusUnknown
        );
    }

    #[test]
    fn database_details_contain_the_age_and_date() {
        let audit_check = database_freshness_check(&DatabaseEvidence::BuiltDaysAgo {
            age_days: 1,
            build_date: "2026-11-03".to_owned(),
        });
        assert_eq!(
            audit_check.status_detail,
            "Up to date (1 day old, built 2026-11-03)"
        );
    }

    #[test]
    fn a_missing_installation_suggests_the_distribution_command() {
        assert_eq!(
            suggested_commands(&clamav_missing_check(DistributionFamily::DebianFamily)),
            vec!["sudo apt install clamav"]
        );
        assert_eq!(
            suggested_commands(&clamav_missing_check(DistributionFamily::NixosFamily)),
            vec!["environment.systemPackages = [ pkgs.clamav ];"]
        );
        assert!(
            suggested_commands(&clamav_missing_check(
                DistributionFamily::UnrecognizedFamily
            ))
            .is_empty()
        );
    }

    #[test]
    fn daemon_and_freshclam_rows_follow_their_evidence() {
        assert_eq!(
            clamav_daemon_check(
                ClamavDaemonEvidence::DaemonSilent,
                DistributionFamily::FedoraWorkstation
            )
            .check_status,
            AuditStatus::NeedsReview
        );
        assert_eq!(
            suggested_commands(&clamav_daemon_check(
                ClamavDaemonEvidence::DaemonSilent,
                DistributionFamily::FedoraWorkstation
            )),
            vec!["sudo systemctl start clamd@scan"]
        );
        assert_eq!(
            freshclam_service_check(
                FreshclamServiceState::TimerScheduled {
                    service_unit: "clamav-freshclam"
                },
                true,
                DistributionFamily::NixosFamily
            )
            .check_status,
            AuditStatus::CheckPassed
        );
        assert_eq!(
            freshclam_service_check(
                FreshclamServiceState::ServiceNotFound,
                true,
                DistributionFamily::NixosFamily
            )
            .check_status,
            AuditStatus::NeedsReview
        );
        assert_eq!(
            freshclam_service_check(
                FreshclamServiceState::ServiceNotFound,
                false,
                DistributionFamily::NixosFamily
            )
            .check_status,
            AuditStatus::StatusUnknown
        );
    }
}
