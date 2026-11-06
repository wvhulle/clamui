use gettextrs::gettext;

use crate::host_services::{
    clamav_programs::database_directory_status::DatabaseFolderReadFailure,
    systemd_journal::unit_journal_reader::UnitJournalReadFailure,
};

pub fn unit_journal_failure_text(read_failure: UnitJournalReadFailure) -> String {
    match read_failure {
        UnitJournalReadFailure::JournalReadFailed { failure_kind } => {
            gettext("The system journal could not be read: {error}")
                .replace("{error}", &failure_kind.to_string())
        }
        UnitJournalReadFailure::ReadingTaskInterrupted => {
            gettext("Reading the system journal stopped before it finished")
        }
    }
}

pub fn database_folder_failure_text(read_failure: DatabaseFolderReadFailure) -> String {
    match read_failure {
        DatabaseFolderReadFailure::FolderUnreadable { failure_kind } => {
            gettext("The signature folder could not be read: {error}")
                .replace("{error}", &failure_kind.to_string())
        }
        DatabaseFolderReadFailure::ReadingTaskInterrupted => {
            gettext("Reading the signature folder stopped before it finished")
        }
    }
}

#[cfg(test)]
mod host_read_failure_text_tests {
    use std::io;

    use super::*;

    #[test]
    fn read_failures_name_what_could_not_be_read() {
        assert_eq!(
            unit_journal_failure_text(UnitJournalReadFailure::JournalReadFailed {
                failure_kind: io::ErrorKind::PermissionDenied,
            }),
            "The system journal could not be read: permission denied"
        );
        assert_eq!(
            database_folder_failure_text(DatabaseFolderReadFailure::FolderUnreadable {
                failure_kind: io::ErrorKind::PermissionDenied,
            }),
            "The signature folder could not be read: permission denied"
        );
    }
}
