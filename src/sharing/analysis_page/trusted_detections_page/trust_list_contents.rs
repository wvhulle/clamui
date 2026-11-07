use std::{fs, io, path::Path};

use bytesize::ByteSize;

use crate::host_services::{
    clamav_programs::database_directory_status::configured_database_directory,
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
};

pub const TRUSTED_FILES_NAME: &str = "lazaret-local.sfp";
pub const IGNORED_SIGNATURES_NAME: &str = "lazaret-local.ign2";
const ALLOWLIST_EXTENSIONS: [&str; 4] = ["fp", "sfp", "ign", "ign2"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TrustListReadFailure {
    #[error("permission denied")]
    AccessDenied,
    #[error("reading failed: {failure_kind}")]
    OtherReadFailure { failure_kind: io::ErrorKind },
    #[error("the task reading the trust lists stopped before it finished")]
    ReadingTaskAborted,
}

impl From<io::Error> for TrustListReadFailure {
    fn from(read_failure: io::Error) -> Self {
        match read_failure.kind() {
            io::ErrorKind::PermissionDenied => Self::AccessDenied,
            failure_kind => Self::OtherReadFailure { failure_kind },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedFileEntry {
    pub sha256_hex: String,
    pub file_size: ByteSize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AllowlistEntries {
    EntriesCounted { entry_count: u64 },
    FileUnreadable(TrustListReadFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignAllowlistFile {
    pub file_name: String,
    pub allowlist_entries: AllowlistEntries,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LazaretListReading<ListEntry> {
    ListRead(Vec<ListEntry>),
    ListUnreadable(TrustListReadFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustListContents {
    pub trusted_files: LazaretListReading<TrustedFileEntry>,
    pub ignored_signatures: LazaretListReading<String>,
    pub foreign_allowlists: Vec<ForeignAllowlistFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustListReading {
    ListsRead(TrustListContents),
    FolderMissing,
    FolderUnreadable(TrustListReadFailure),
}

fn list_lines(list_text: &str) -> impl Iterator<Item = &str> {
    list_text
        .lines()
        .map(str::trim)
        .filter(|list_line| !list_line.is_empty() && !list_line.starts_with('#'))
}

pub fn parse_trusted_files(list_text: &str) -> Vec<TrustedFileEntry> {
    list_lines(list_text)
        .filter_map(|list_line| {
            let mut line_fields = list_line.split(':');
            let sha256_hex = line_fields.next()?;
            let file_size = ByteSize::b(line_fields.next()?.parse().ok()?);
            Some(TrustedFileEntry {
                sha256_hex: sanitize_scanner_line(sha256_hex),
                file_size,
            })
        })
        .collect()
}

pub fn parse_ignored_signatures(list_text: &str) -> Vec<String> {
    list_lines(list_text)
        .map(|list_line| sanitize_scanner_line(list_line.split(':').next().unwrap_or(list_line)))
        .collect()
}

fn is_foreign_allowlist(file_name: &str) -> bool {
    file_name != TRUSTED_FILES_NAME
        && file_name != IGNORED_SIGNATURES_NAME
        && Path::new(file_name)
            .extension()
            .and_then(|file_extension| file_extension.to_str())
            .is_some_and(|file_extension| ALLOWLIST_EXTENSIONS.contains(&file_extension))
}

fn read_list_text(list_path: &Path) -> Result<String, io::Error> {
    fs::read(list_path).map(|list_bytes| String::from_utf8_lossy(&list_bytes).into_owned())
}

fn foreign_allowlist_file(directory_entry: &fs::DirEntry) -> Option<ForeignAllowlistFile> {
    let file_name = directory_entry.file_name().to_string_lossy().into_owned();
    is_foreign_allowlist(&file_name).then(|| ForeignAllowlistFile {
        allowlist_entries: match read_list_text(&directory_entry.path()) {
            Ok(list_text) => AllowlistEntries::EntriesCounted {
                entry_count: list_lines(&list_text).count() as u64,
            },
            Err(read_failure) => AllowlistEntries::FileUnreadable(read_failure.into()),
        },
        file_name: sanitize_scanner_line(&file_name),
    })
}

fn foreign_allowlists(database_directory: &Path) -> Result<Vec<ForeignAllowlistFile>, io::Error> {
    let directory_entries = fs::read_dir(database_directory)?.collect::<Result<Vec<_>, _>>()?;
    let mut foreign_files = directory_entries
        .iter()
        .filter_map(foreign_allowlist_file)
        .collect::<Vec<_>>();
    foreign_files
        .sort_by(|first_file, second_file| first_file.file_name.cmp(&second_file.file_name));
    Ok(foreign_files)
}

fn read_lazaret_list<ListEntry>(
    list_path: &Path,
    parse_list: fn(&str) -> Vec<ListEntry>,
) -> LazaretListReading<ListEntry> {
    match read_list_text(list_path) {
        Ok(list_text) => LazaretListReading::ListRead(parse_list(&list_text)),
        Err(read_failure) if read_failure.kind() == io::ErrorKind::NotFound => {
            LazaretListReading::ListRead(Vec::new())
        }
        Err(read_failure) => LazaretListReading::ListUnreadable(read_failure.into()),
    }
}

pub fn read_trust_list(database_directory: &Path) -> TrustListReading {
    match foreign_allowlists(database_directory) {
        Ok(foreign_allowlists) => TrustListReading::ListsRead(TrustListContents {
            trusted_files: read_lazaret_list(
                &database_directory.join(TRUSTED_FILES_NAME),
                parse_trusted_files,
            ),
            ignored_signatures: read_lazaret_list(
                &database_directory.join(IGNORED_SIGNATURES_NAME),
                parse_ignored_signatures,
            ),
            foreign_allowlists,
        }),
        Err(folder_failure) if folder_failure.kind() == io::ErrorKind::NotFound => {
            TrustListReading::FolderMissing
        }
        Err(folder_failure) => TrustListReading::FolderUnreadable(folder_failure.into()),
    }
}

pub async fn read_configured_trust_list() -> TrustListReading {
    tokio::task::spawn_blocking(|| read_trust_list(&configured_database_directory()))
        .await
        .unwrap_or(TrustListReading::FolderUnreadable(
            TrustListReadFailure::ReadingTaskAborted,
        ))
}

#[cfg(test)]
mod trust_list_contents_tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn lazaret_lists_are_parsed_and_other_allowlists_reported_as_foreign() {
        let database_directory = tempfile::tempdir().unwrap();
        fs::write(
            database_directory.path().join(TRUSTED_FILES_NAME),
            "ab12:68:Lazaret.TrustedFile\nbroken line\n",
        )
        .unwrap();
        fs::write(
            database_directory.path().join(IGNORED_SIGNATURES_NAME),
            "# comment\nWin.Test.EICAR_HDB-1\n",
        )
        .unwrap();
        fs::write(database_directory.path().join("local.ign2"), "A\nB\n").unwrap();
        fs::write(database_directory.path().join("main.cvd"), "signatures").unwrap();
        assert_eq!(
            read_trust_list(database_directory.path()),
            TrustListReading::ListsRead(TrustListContents {
                trusted_files: LazaretListReading::ListRead(vec![TrustedFileEntry {
                    sha256_hex: "ab12".to_owned(),
                    file_size: ByteSize::b(68),
                }]),
                ignored_signatures: LazaretListReading::ListRead(vec![
                    "Win.Test.EICAR_HDB-1".to_owned()
                ]),
                foreign_allowlists: vec![ForeignAllowlistFile {
                    file_name: "local.ign2".to_owned(),
                    allowlist_entries: AllowlistEntries::EntriesCounted { entry_count: 2 },
                }],
            })
        );
    }

    #[test]
    fn missing_lazaret_lists_are_read_as_empty() {
        let database_directory = tempfile::tempdir().unwrap();
        assert_eq!(
            read_trust_list(database_directory.path()),
            TrustListReading::ListsRead(TrustListContents {
                trusted_files: LazaretListReading::ListRead(Vec::new()),
                ignored_signatures: LazaretListReading::ListRead(Vec::new()),
                foreign_allowlists: Vec::new(),
            })
        );
    }

    #[test]
    fn unreadable_lists_are_reported_instead_of_counted_as_empty() {
        let database_directory = tempfile::tempdir().unwrap();
        fs::create_dir(database_directory.path().join(TRUSTED_FILES_NAME)).unwrap();
        fs::create_dir(database_directory.path().join("local.ign2")).unwrap();
        let TrustListReading::ListsRead(trust_list_contents) =
            read_trust_list(database_directory.path())
        else {
            panic!("the signature folder itself is readable");
        };
        assert!(matches!(
            trust_list_contents.trusted_files,
            LazaretListReading::ListUnreadable(TrustListReadFailure::OtherReadFailure { .. })
        ));
        assert!(matches!(
            trust_list_contents.foreign_allowlists.as_slice(),
            [ForeignAllowlistFile {
                allowlist_entries: AllowlistEntries::FileUnreadable(_),
                ..
            }]
        ));
    }

    #[test]
    fn an_unlistable_signature_folder_is_reported_as_unreadable() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let database_directory = tempfile::tempdir().unwrap();
        fs::set_permissions(database_directory.path(), fs::Permissions::from_mode(0o300)).unwrap();
        let trust_list_reading = read_trust_list(database_directory.path());
        fs::set_permissions(database_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            trust_list_reading,
            TrustListReading::FolderUnreadable(TrustListReadFailure::AccessDenied)
        );
    }

    #[test]
    fn a_missing_signature_folder_is_reported_as_missing() {
        let database_directory = tempfile::tempdir().unwrap();
        assert_eq!(
            read_trust_list(&database_directory.path().join("absent")),
            TrustListReading::FolderMissing
        );
    }

    #[test]
    fn pinned_and_unpinned_ignore_entries_are_both_listed_by_name() {
        assert_eq!(
            parse_ignored_signatures(
                "Win.Test.Pinned:44d88612fea8a8f36de82e1278abb02f\nWin.Test.Unpinned\n"
            ),
            vec!["Win.Test.Pinned", "Win.Test.Unpinned"]
        );
    }
}
