use std::{
    fs, io,
    ops::ControlFlow,
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

#[cfg(test)]
pub fn enumerate_scan_files(
    target_path: &Path,
    scan_exclusions: &ScanExclusions,
) -> Result<EnumeratedScanFiles, ScanTargetFailure> {
    enumerate_scan_files_reporting(target_path, scan_exclusions, &mut |_enumeration_progress| {
        ControlFlow::Continue(())
    })
}

pub fn enumerate_scan_files_reporting(
    target_path: &Path,
    scan_exclusions: &ScanExclusions,
    report_progress: &mut dyn FnMut(&EnumerationProgress) -> ControlFlow<()>,
) -> Result<EnumeratedScanFiles, ScanTargetFailure> {
    if !target_path.exists() {
        return Err(ScanTargetFailure::TargetMissing);
    }
    if target_path.is_file() {
        return Ok(EnumeratedScanFiles {
            file_paths: vec![target_path.to_path_buf()],
            directory_count: 0,
            excluded_entry_count: 0,
        });
    }
    if !target_path.is_dir() {
        return Err(ScanTargetFailure::TargetNotScannable);
    }
    let target_entries = fs::read_dir(target_path).map_err(|directory_failure| {
        ScanTargetFailure::TargetDirectoryUnreadable {
            target_path: target_path.to_path_buf(),
            directory_failure,
        }
    })?;
    if report_directory_entered(
        target_path,
        &EnumeratedScanFiles::default(),
        report_progress,
    )
    .is_break()
    {
        return Err(ScanTargetFailure::EnumerationInterrupted);
    }
    match collect_directory_files(
        target_entries,
        scan_exclusions,
        EnumeratedScanFiles {
            file_paths: Vec::new(),
            directory_count: 1,
            excluded_entry_count: 0,
        },
        report_progress,
    ) {
        ControlFlow::Continue(enumerated_files) => Ok(enumerated_files),
        ControlFlow::Break(()) => Err(ScanTargetFailure::EnumerationInterrupted),
    }
}

fn report_directory_entered(
    directory_path: &Path,
    enumerated_files: &EnumeratedScanFiles,
    report_progress: &mut dyn FnMut(&EnumerationProgress) -> ControlFlow<()>,
) -> ControlFlow<()> {
    report_progress(&EnumerationProgress {
        found_file_count: enumerated_files.file_paths.len() as u64,
        found_directory_count: enumerated_files.directory_count,
        current_directory: directory_path.to_path_buf(),
    })
}

fn collect_directory_files(
    directory_entries: fs::ReadDir,
    scan_exclusions: &ScanExclusions,
    enumerated_files: EnumeratedScanFiles,
    report_progress: &mut dyn FnMut(&EnumerationProgress) -> ControlFlow<()>,
) -> ControlFlow<(), EnumeratedScanFiles> {
    directory_entries.filter_map(Result::ok).try_fold(
        enumerated_files,
        |mut enumerated_files, directory_entry| {
            let entry_path = directory_entry.path();
            let Ok(entry_kind) = directory_entry.file_type() else {
                return ControlFlow::Continue(enumerated_files);
            };
            if entry_kind.is_dir() {
                if scan_exclusions.excludes_directory(&entry_path) {
                    enumerated_files.excluded_entry_count += 1;
                    return ControlFlow::Continue(enumerated_files);
                }
                return match fs::read_dir(&entry_path) {
                    Ok(nested_entries) => {
                        enumerated_files.directory_count += 1;
                        report_directory_entered(&entry_path, &enumerated_files, report_progress)?;
                        collect_directory_files(
                            nested_entries,
                            scan_exclusions,
                            enumerated_files,
                            report_progress,
                        )
                    }
                    Err(_unreadable_directory) => ControlFlow::Continue(enumerated_files),
                };
            }
            if entry_kind.is_file() {
                if scan_exclusions.excludes_file(&entry_path) {
                    enumerated_files.excluded_entry_count += 1;
                } else {
                    enumerated_files.file_paths.push(entry_path);
                }
            }
            ControlFlow::Continue(enumerated_files)
        },
    )
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
    fn a_cancelled_walk_stops_at_the_next_folder() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let scan_root = temporary_root.path().join("scan");
        fs::create_dir_all(scan_root.join("first/second")).expect("nested directories");
        let mut entered_folders = 0;
        let walk_outcome = enumerate_scan_files_reporting(
            &scan_root,
            &ScanExclusions::default(),
            &mut |_enumeration_progress| {
                entered_folders += 1;
                if entered_folders > 1 {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            },
        );
        assert!(matches!(
            walk_outcome,
            Err(ScanTargetFailure::EnumerationInterrupted)
        ));
        assert_eq!(entered_folders, 2);
    }

    #[test]
    fn every_entered_directory_is_reported_with_running_counts() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let scan_root = temporary_root.path().join("scan");
        fs::create_dir_all(scan_root.join("nested")).expect("nested directory");
        fs::write(scan_root.join("top.txt"), b"fixture").expect("top file");
        fs::write(scan_root.join("nested/inner.txt"), b"fixture").expect("nested file");
        let mut reported_directories = Vec::new();
        enumerate_scan_files_reporting(
            &scan_root,
            &ScanExclusions::default(),
            &mut |enumeration_progress| {
                reported_directories.push(enumeration_progress.current_directory.clone());
                ControlFlow::Continue(())
            },
        )
        .expect("enumerated files");
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
