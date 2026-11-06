use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use jiff::{Timestamp, civil, tz::TimeZone};
use tokio::task::spawn_blocking;

use crate::host_services::{
    clamav_programs::database_directory_status::configured_database_directory,
    desktop::flatpak_sandbox::readable_host_path,
};

const DATABASE_HEADER_LENGTH: u64 = 512;
const DATABASE_HEADER_MAGIC: &str = "ClamAV-VDB";
const FALLBACK_DATABASE_DIRECTORIES: [&str; 2] = ["/var/lib/clamav", "/usr/local/share/clamav"];
const DAILY_DATABASE_FILE_NAMES: [&str; 2] = ["daily.cvd", "daily.cld"];
const BANNER_DATE_FORMAT: &str = "%a %b %e %H:%M:%S %Y";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DatabaseEvidence {
    BuiltAt { built_at: Timestamp },
    AgeUndetermined,
    DatabaseMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DatabaseFileEvidence {
    StampedDatabase { built_at: Timestamp },
    UnstampedDatabase,
    NoDatabaseFile,
}

pub fn parse_database_header_build_time(header_bytes: &[u8]) -> Option<Timestamp> {
    let header_text = String::from_utf8_lossy(header_bytes);
    let header_fields = header_text.split(':').collect::<Vec<_>>();
    if !header_fields.first()?.starts_with(DATABASE_HEADER_MAGIC) {
        return None;
    }
    let build_seconds = header_fields
        .get(8)?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()?;
    Timestamp::from_second(build_seconds).ok()
}

pub fn parse_version_banner_build_time(version_banner: &str) -> Option<Timestamp> {
    let banner_date = version_banner.split('/').nth(2)?.trim();
    civil::DateTime::strptime(BANNER_DATE_FORMAT, banner_date)
        .ok()?
        .to_zoned(TimeZone::system())
        .ok()
        .map(|banner_time| banner_time.timestamp())
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
    let newest_build_time = database_paths
        .iter()
        .filter_map(|database_path| read_database_header(database_path))
        .filter_map(|header_bytes| parse_database_header_build_time(&header_bytes))
        .max();
    match newest_build_time {
        Some(built_at) => DatabaseFileEvidence::StampedDatabase { built_at },
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

async fn read_database_file_evidence_off_thread() -> DatabaseFileEvidence {
    spawn_blocking(read_database_file_evidence)
        .await
        .unwrap_or(DatabaseFileEvidence::NoDatabaseFile)
}

const fn database_evidence_from_files(file_evidence: DatabaseFileEvidence) -> DatabaseEvidence {
    match file_evidence {
        DatabaseFileEvidence::StampedDatabase { built_at } => {
            DatabaseEvidence::BuiltAt { built_at }
        }
        DatabaseFileEvidence::UnstampedDatabase => DatabaseEvidence::AgeUndetermined,
        DatabaseFileEvidence::NoDatabaseFile => DatabaseEvidence::DatabaseMissing,
    }
}

pub async fn inspect_database_evidence_without_banner() -> DatabaseEvidence {
    database_evidence_from_files(read_database_file_evidence_off_thread().await)
}

pub async fn inspect_database_evidence_with_banner(version_banner: &str) -> DatabaseEvidence {
    let file_evidence = read_database_file_evidence_off_thread().await;
    match parse_version_banner_build_time(version_banner) {
        Some(banner_built_at) => match file_evidence {
            DatabaseFileEvidence::StampedDatabase { built_at } => {
                DatabaseEvidence::BuiltAt { built_at }
            }
            DatabaseFileEvidence::UnstampedDatabase | DatabaseFileEvidence::NoDatabaseFile => {
                DatabaseEvidence::BuiltAt {
                    built_at: banner_built_at,
                }
            }
        },
        None => database_evidence_from_files(file_evidence),
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
            parse_database_header_build_time(HEADER_TEXT.as_bytes()),
            Timestamp::from_second(1_793_688_000).ok()
        );
        assert_eq!(parse_database_header_build_time(b"not a database"), None);
        assert_eq!(
            parse_database_header_build_time(b"ClamAV-VDB:short:row"),
            None
        );
        assert_eq!(
            parse_database_header_build_time(b"ClamAV-VDB:a:b:c:d:e:f:g:notanumber"),
            None
        );
    }

    #[test]
    fn version_banners_yield_the_database_date_when_present() {
        assert_eq!(
            parse_version_banner_build_time("ClamAV 1.5.4/28173/Tue Nov  3 07:27:52 2026"),
            civil::date(2026, 11, 3)
                .at(7, 27, 52, 0)
                .to_zoned(TimeZone::system())
                .ok()
                .map(|banner_time| banner_time.timestamp())
        );
        assert_eq!(parse_version_banner_build_time("ClamAV 1.5.4"), None);
        assert_eq!(
            parse_version_banner_build_time("ClamAV 1.5.4/28173/Tue Foo  3 07:27:52 2026"),
            None
        );
    }
}
