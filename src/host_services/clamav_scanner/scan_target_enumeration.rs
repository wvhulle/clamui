use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::host_services::clamav_scanner::scan_exclusion_rules::ScanExclusions;

#[derive(Debug, thiserror::Error)]
pub enum ScanTargetFailure {
    #[error("the scan target does not exist")]
    TargetMissing,
    #[error("the scan target is not a regular file or directory")]
    TargetNotScannable,
    #[error("the scan target could not be listed: {directory_failure}")]
    TargetDirectoryUnreadable {
        target_path: PathBuf,
        directory_failure: io::Error,
    },
    #[error("the private clamd file list could not be written: {0}")]
    FileListUnwritable(#[from] io::Error),
    #[error("enumerating the scan target stopped unexpectedly")]
    EnumerationInterrupted,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct EnumeratedScanFiles {
    pub file_paths: Vec<PathBuf>,
    pub directory_count: u64,
    pub excluded_entry_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnumerationProgress {
    pub found_file_count: u64,
    pub found_directory_count: u64,
    pub current_directory: PathBuf,
}

#[derive(Debug)]
pub enum WalkStep {
    DirectoryEntered(EnumerationProgress),
    WalkCompleted(Result<EnumeratedScanFiles, ScanTargetFailure>),
}

enum WalkState {
    NotStarted { target_path: PathBuf },
    Walking { open_directories: Vec<fs::ReadDir> },
    Completed,
}

pub struct ScanWalk {
    scan_exclusions: ScanExclusions,
    enumerated_files: EnumeratedScanFiles,
    walk_state: WalkState,
}

impl ScanWalk {
    pub fn of_target(target_path: &Path, scan_exclusions: ScanExclusions) -> Self {
        Self {
            scan_exclusions,
            enumerated_files: EnumeratedScanFiles::default(),
            walk_state: WalkState::NotStarted {
                target_path: target_path.to_path_buf(),
            },
        }
    }

    fn entered_directory(&mut self, directory_path: &Path) -> WalkStep {
        self.enumerated_files.directory_count += 1;
        WalkStep::DirectoryEntered(EnumerationProgress {
            found_file_count: self.enumerated_files.file_paths.len() as u64,
            found_directory_count: self.enumerated_files.directory_count,
            current_directory: directory_path.to_path_buf(),
        })
    }

    fn completed(
        &mut self,
        walk_outcome: Result<EnumeratedScanFiles, ScanTargetFailure>,
    ) -> WalkStep {
        self.walk_state = WalkState::Completed;
        WalkStep::WalkCompleted(walk_outcome)
    }

    fn started_walk(&mut self, target_path: &Path) -> WalkStep {
        if !target_path.exists() {
            return self.completed(Err(ScanTargetFailure::TargetMissing));
        }
        if target_path.is_file() {
            return self.completed(Ok(EnumeratedScanFiles {
                file_paths: vec![target_path.to_path_buf()],
                directory_count: 0,
                excluded_entry_count: 0,
            }));
        }
        if !target_path.is_dir() {
            return self.completed(Err(ScanTargetFailure::TargetNotScannable));
        }
        match fs::read_dir(target_path) {
            Ok(target_entries) => {
                self.walk_state = WalkState::Walking {
                    open_directories: vec![target_entries],
                };
                self.entered_directory(target_path)
            }
            Err(directory_failure) => {
                self.completed(Err(ScanTargetFailure::TargetDirectoryUnreadable {
                    target_path: target_path.to_path_buf(),
                    directory_failure,
                }))
            }
        }
    }

    fn visited_entry(&mut self, directory_entry: &fs::DirEntry) -> Option<WalkStep> {
        let entry_path = directory_entry.path();
        let entry_kind = directory_entry.file_type().ok()?;
        if entry_kind.is_dir() {
            if self.scan_exclusions.excludes_directory(&entry_path) {
                self.enumerated_files.excluded_entry_count += 1;
                return None;
            }
            let nested_entries = fs::read_dir(&entry_path).ok()?;
            if let WalkState::Walking { open_directories } = &mut self.walk_state {
                open_directories.push(nested_entries);
            }
            return Some(self.entered_directory(&entry_path));
        }
        if entry_kind.is_file() {
            if self.scan_exclusions.excludes_file(&entry_path) {
                self.enumerated_files.excluded_entry_count += 1;
            } else {
                self.enumerated_files.file_paths.push(entry_path);
            }
        }
        None
    }
}

impl Iterator for ScanWalk {
    type Item = WalkStep;

    fn next(&mut self) -> Option<WalkStep> {
        loop {
            match &mut self.walk_state {
                WalkState::Completed => return None,
                WalkState::NotStarted { target_path } => {
                    let target_path = std::mem::take(target_path);
                    return Some(self.started_walk(&target_path));
                }
                WalkState::Walking { open_directories } => {
                    let Some(innermost_directory) = open_directories.last_mut() else {
                        let enumerated_files = std::mem::take(&mut self.enumerated_files);
                        return Some(self.completed(Ok(enumerated_files)));
                    };
                    match innermost_directory.next() {
                        None => {
                            open_directories.pop();
                        }
                        Some(Err(_unreadable_entry)) => {}
                        Some(Ok(directory_entry)) => {
                            if let Some(walk_step) = self.visited_entry(&directory_entry) {
                                return Some(walk_step);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub fn enumerate_scan_files(
    target_path: &Path,
    scan_exclusions: &ScanExclusions,
) -> Result<EnumeratedScanFiles, ScanTargetFailure> {
    ScanWalk::of_target(target_path, scan_exclusions.clone())
        .find_map(|walk_step| match walk_step {
            WalkStep::WalkCompleted(walk_outcome) => Some(walk_outcome),
            WalkStep::DirectoryEntered(_entered_directory) => None,
        })
        .unwrap_or(Err(ScanTargetFailure::EnumerationInterrupted))
}

#[cfg(test)]
mod scan_target_enumeration_tests {
    use super::*;
    use crate::host_services::clamav_scanner::scan_exclusion_rules::{
        ExclusionEntry, ExclusionKind,
    };

    #[test]
    fn traversal_skips_symlinks_and_enters_directories() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let scan_root = temporary_root.path().join("scan");
        fs::create_dir_all(scan_root.join("nested")).expect("nested directory");
        fs::write(scan_root.join("nested/file.txt"), b"fixture").expect("nested file");
        std::os::unix::fs::symlink(scan_root.join("nested/file.txt"), scan_root.join("link"))
            .expect("symlink");
        assert_eq!(
            enumerate_scan_files(&scan_root, &ScanExclusions::default()).expect("enumerated files"),
            EnumeratedScanFiles {
                file_paths: vec![scan_root.join("nested/file.txt")],
                directory_count: 2,
                excluded_entry_count: 0,
            }
        );
    }

    #[test]
    fn excluded_directories_and_files_are_not_enumerated() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let scan_root = temporary_root.path().join("scan");
        fs::create_dir_all(scan_root.join("node_modules")).expect("excluded directory");
        fs::write(scan_root.join("node_modules/lib.js"), b"fixture").expect("hidden file");
        fs::write(scan_root.join("cache.tmp"), b"fixture").expect("excluded file");
        fs::write(scan_root.join("kept.txt"), b"fixture").expect("kept file");
        let scan_exclusions = ScanExclusions::from_entries(
            &[
                ExclusionEntry {
                    exclusion_pattern: "node_modules".to_owned(),
                    exclusion_kind: ExclusionKind::DirectoryOnly,
                    is_enabled: true,
                },
                ExclusionEntry::enabled_pattern("*.tmp".to_owned()),
            ],
            Path::new("/home/user"),
        );
        assert_eq!(
            enumerate_scan_files(&scan_root, &scan_exclusions).expect("enumerated files"),
            EnumeratedScanFiles {
                file_paths: vec![scan_root.join("kept.txt")],
                directory_count: 1,
                excluded_entry_count: 2,
            }
        );
    }

    #[test]
    fn a_dropped_walk_stops_at_the_next_folder() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let scan_root = temporary_root.path().join("scan");
        fs::create_dir_all(scan_root.join("first/second")).expect("nested directories");
        let entered_folders = ScanWalk::of_target(&scan_root, ScanExclusions::default())
            .take(2)
            .filter(|walk_step| matches!(walk_step, WalkStep::DirectoryEntered(_)))
            .count();
        assert_eq!(entered_folders, 2);
    }

    #[test]
    fn every_entered_directory_is_reported_with_running_counts() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let scan_root = temporary_root.path().join("scan");
        fs::create_dir_all(scan_root.join("nested")).expect("nested directory");
        fs::write(scan_root.join("top.txt"), b"fixture").expect("top file");
        fs::write(scan_root.join("nested/inner.txt"), b"fixture").expect("nested file");
        let reported_directories = ScanWalk::of_target(&scan_root, ScanExclusions::default())
            .filter_map(|walk_step| match walk_step {
                WalkStep::DirectoryEntered(enumeration_progress) => {
                    Some(enumeration_progress.current_directory)
                }
                WalkStep::WalkCompleted(_walk_outcome) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(reported_directories.first(), Some(&scan_root));
        assert!(reported_directories.contains(&scan_root.join("nested")));
    }

    #[test]
    fn missing_target_is_rejected() {
        assert!(matches!(
            enumerate_scan_files(
                Path::new("/scan/invalid\0target"),
                &ScanExclusions::default()
            ),
            Err(ScanTargetFailure::TargetMissing)
        ));
    }
}
