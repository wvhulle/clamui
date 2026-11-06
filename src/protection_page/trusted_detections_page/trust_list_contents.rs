use std::{fs, path::Path};

use crate::host_services::clamav_scanner::scanner_output_parser::sanitize_scanner_line;

pub const TRUSTED_FILES_NAME: &str = "lazaret-local.sfp";
pub const IGNORED_SIGNATURES_NAME: &str = "lazaret-local.ign2";
const ALLOWLIST_EXTENSIONS: [&str; 4] = ["fp", "sfp", "ign", "ign2"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedFileEntry {
    pub sha256_hex: String,
    pub file_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForeignAllowlistFile {
    pub file_name: String,
    pub entry_count: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TrustListContents {
    pub trusted_files: Vec<TrustedFileEntry>,
    pub ignored_signatures: Vec<String>,
    pub foreign_allowlists: Vec<ForeignAllowlistFile>,
}

impl TrustListContents {
    pub fn lazaret_entry_count(&self) -> usize {
        self.trusted_files.len() + self.ignored_signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lazaret_entry_count() == 0 && self.foreign_allowlists.is_empty()
    }
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
            let file_size = line_fields.next()?.parse().ok()?;
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

fn foreign_allowlists(database_directory: &Path) -> Vec<ForeignAllowlistFile> {
    let mut foreign_files = fs::read_dir(database_directory)
        .map(|directory_entries| {
            directory_entries
                .filter_map(Result::ok)
                .filter_map(|directory_entry| {
                    let file_name = directory_entry.file_name().to_string_lossy().into_owned();
                    is_foreign_allowlist(&file_name).then(|| ForeignAllowlistFile {
                        entry_count: fs::read_to_string(directory_entry.path())
                            .map_or(0, |list_text| list_lines(&list_text).count() as u64),
                        file_name: sanitize_scanner_line(&file_name),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    foreign_files
        .sort_by(|first_file, second_file| first_file.file_name.cmp(&second_file.file_name));
    foreign_files
}

pub fn read_trust_list_contents(database_directory: &Path) -> TrustListContents {
    let read_list = |list_name: &str| {
        fs::read_to_string(database_directory.join(list_name)).unwrap_or_default()
    };
    TrustListContents {
        trusted_files: parse_trusted_files(&read_list(TRUSTED_FILES_NAME)),
        ignored_signatures: parse_ignored_signatures(&read_list(IGNORED_SIGNATURES_NAME)),
        foreign_allowlists: foreign_allowlists(database_directory),
    }
}

#[cfg(test)]
mod trust_list_contents_tests {
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
            read_trust_list_contents(database_directory.path()),
            TrustListContents {
                trusted_files: vec![TrustedFileEntry {
                    sha256_hex: "ab12".to_owned(),
                    file_size: 68,
                }],
                ignored_signatures: vec!["Win.Test.EICAR_HDB-1".to_owned()],
                foreign_allowlists: vec![ForeignAllowlistFile {
                    file_name: "local.ign2".to_owned(),
                    entry_count: 2,
                }],
            }
        );
    }
}
