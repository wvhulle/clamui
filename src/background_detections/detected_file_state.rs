use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

use rustix::process::geteuid;

use crate::malware_scan::scanner_output_parser::is_blocked_by_on_access;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedFileState {
    BlockedInPlace,
    ReadableInPlace,
    OwnedByOtherUser,
    NoLongerThere,
    StateUnknown,
}

impl DetectedFileState {
    pub const fn file_is_present(self) -> bool {
        matches!(
            self,
            Self::BlockedInPlace | Self::ReadableInPlace | Self::OwnedByOtherUser
        )
    }
}

pub fn classify_file_state(
    metadata_outcome: Result<u32, io::ErrorKind>,
    current_user_id: u32,
    blocked_by_on_access: bool,
) -> DetectedFileState {
    match metadata_outcome {
        Err(io::ErrorKind::NotFound) => DetectedFileState::NoLongerThere,
        Err(_other_failure) => DetectedFileState::StateUnknown,
        Ok(_any_owner) if blocked_by_on_access => DetectedFileState::BlockedInPlace,
        Ok(owner_user_id) if owner_user_id != current_user_id => {
            DetectedFileState::OwnedByOtherUser
        }
        Ok(_own_file) => DetectedFileState::ReadableInPlace,
    }
}

pub fn inspect_detected_file(file_path: &Path) -> DetectedFileState {
    let metadata_outcome = fs::symlink_metadata(file_path)
        .map(|file_metadata| file_metadata.uid())
        .map_err(|metadata_failure| metadata_failure.kind());
    classify_file_state(
        metadata_outcome,
        geteuid().as_raw(),
        is_blocked_by_on_access(file_path),
    )
}

#[cfg(test)]
mod detected_file_state_tests {
    use super::*;

    const OWN_USER: u32 = 1000;

    #[test]
    fn a_refused_open_is_a_blocked_file_even_when_someone_else_owns_it() {
        assert_eq!(
            classify_file_state(Ok(OWN_USER), OWN_USER, true),
            DetectedFileState::BlockedInPlace
        );
        assert_eq!(
            classify_file_state(Ok(0), OWN_USER, true),
            DetectedFileState::BlockedInPlace
        );
    }

    #[test]
    fn missing_and_foreign_files_are_told_apart() {
        assert_eq!(
            classify_file_state(Err(io::ErrorKind::NotFound), OWN_USER, false),
            DetectedFileState::NoLongerThere
        );
        assert_eq!(
            classify_file_state(Ok(0), OWN_USER, false),
            DetectedFileState::OwnedByOtherUser
        );
        assert_eq!(
            classify_file_state(Ok(OWN_USER), OWN_USER, false),
            DetectedFileState::ReadableInPlace
        );
        assert_eq!(
            classify_file_state(Err(io::ErrorKind::PermissionDenied), OWN_USER, false),
            DetectedFileState::StateUnknown
        );
    }
}
