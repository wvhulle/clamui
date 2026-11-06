use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use relm4::gtk::glib;
use tokio::task::spawn_blocking;

use crate::{
    desktop_integration::flatpak_sandbox::readable_host_path,
    virus_database::database_directory_status::configured_database_directory,
};

const DATABASE_HEADER_LENGTH: u64 = 512;
const DATABASE_HEADER_MAGIC: &str = "ClamAV-VDB";
const SECONDS_PER_DAY: u64 = 86_400;
const FALLBACK_DATABASE_DIRECTORIES: [&str; 2] = ["/var/lib/clamav", "/usr/local/share/clamav"];
const DAILY_DATABASE_FILE_NAMES: [&str; 2] = ["daily.cvd", "daily.cld"];
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
        .map(readable_host_path)
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

pub fn parse_database_header_version(header_bytes: &[u8]) -> Option<u64> {
    let header_text = String::from_utf8_lossy(header_bytes);
    let header_fields = header_text.split(':').collect::<Vec<_>>();
    if !header_fields.first()?.starts_with(DATABASE_HEADER_MAGIC) {
        return None;
    }
    header_fields.get(2)?.trim().parse().ok()
}

pub fn newest_disk_signature_version() -> Option<u64> {
    daily_database_paths()
        .iter()
        .filter_map(|database_path| read_database_header(database_path))
        .filter_map(|header_bytes| parse_database_header_version(&header_bytes))
        .max()
}

pub async fn inspect_database_evidence(version_banner: &str) -> DatabaseEvidence {
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

#[cfg(test)]
mod clamav_engine_evidence_tests {
    use super::*;

    const HEADER_TEXT: &str =
        "ClamAV-VDB:03 Nov 2026 07-27 +0000:28173:355000:90:md5sum:signature:builder:1793688000  ";

    #[test]
    fn database_headers_yield_their_signature_version() {
        assert_eq!(
            parse_database_header_version(HEADER_TEXT.as_bytes()),
            Some(28_173)
        );
        assert_eq!(parse_database_header_version(b"not a database"), None);
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
}
