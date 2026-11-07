use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

use rustix::process::geteuid;

use crate::host_services::clamav_scanner::scanner_output_parser::is_blocked_by_on_access;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileAccess {
    BlockedOnAccess,
    Readable,
    NotOpened,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileOwner {
    CurrentUser,
    OtherUser,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedFileState {
    Present {
        access: FileAccess,
        owner: FileOwner,
    },
    NoLongerThere,
    StateUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpeningCheck {
    OpenToCheckBlocking,
    InspectWithoutOpening,
}

impl DetectedFileState {
    pub const fn file_is_present(self) -> bool {
        matches!(self, Self::Present { .. })
    }

    pub const fn user_can_move_or_delete(self) -> bool {
        matches!(
            self,
            Self::Present {
                owner: FileOwner::CurrentUser,
                ..
            }
        )
    }
}

pub fn classify_file_state(
    metadata_outcome: Result<u32, io::ErrorKind>,
    current_user_id: u32,
    file_access: FileAccess,
) -> DetectedFileState {
    match metadata_outcome {
        Err(io::ErrorKind::NotFound) => DetectedFileState::NoLongerThere,
        Err(_other_failure) => DetectedFileState::StateUnknown,
        Ok(owner_user_id) => DetectedFileState::Present {
            access: file_access,
            owner: if owner_user_id == current_user_id {
                FileOwner::CurrentUser
            } else {
                FileOwner::OtherUser
            },
        },
    }
}

fn file_owner_outcome(file_path: &Path) -> Result<u32, io::ErrorKind> {
    fs::symlink_metadata(file_path)
        .map(|file_metadata| file_metadata.uid())
        .map_err(|metadata_failure| metadata_failure.kind())
}

pub fn inspect_detected_file(file_path: &Path, opening_check: OpeningCheck) -> DetectedFileState {
    let file_access = match opening_check {
        OpeningCheck::InspectWithoutOpening => FileAccess::NotOpened,
        OpeningCheck::OpenToCheckBlocking if is_blocked_by_on_access(file_path) => {
            FileAccess::BlockedOnAccess
        }
        OpeningCheck::OpenToCheckBlocking => FileAccess::Readable,
    };
    classify_file_state(
        file_owner_outcome(file_path),
        geteuid().as_raw(),
        file_access,
    )
}

#[cfg(test)]
mod detected_file_state_tests {
    use super::*;

    const OWN_USER: u32 = 1000;

    #[test]
    fn a_blocked_file_keeps_its_owner() {
        assert_eq!(
            classify_file_state(Ok(0), OWN_USER, FileAccess::BlockedOnAccess),
            DetectedFileState::Present {
                access: FileAccess::BlockedOnAccess,
                owner: FileOwner::OtherUser,
            }
        );
        assert!(
            !classify_file_state(Ok(0), OWN_USER, FileAccess::BlockedOnAccess)
                .user_can_move_or_delete()
        );
        assert!(
            classify_file_state(Ok(OWN_USER), OWN_USER, FileAccess::BlockedOnAccess)
                .user_can_move_or_delete()
        );
    }

    #[test]
    fn missing_unknown_and_present_files_are_told_apart() {
        assert_eq!(
            classify_file_state(Err(io::ErrorKind::NotFound), OWN_USER, FileAccess::Readable),
            DetectedFileState::NoLongerThere
        );
        assert_eq!(
            classify_file_state(
                Err(io::ErrorKind::PermissionDenied),
                OWN_USER,
                FileAccess::Readable
            ),
            DetectedFileState::StateUnknown
        );
        assert!(
            !classify_file_state(
                Err(io::ErrorKind::PermissionDenied),
                OWN_USER,
                FileAccess::Readable
            )
            .user_can_move_or_delete()
        );
    }
}
