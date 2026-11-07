use gettextrs::gettext;

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    quarantine_vault::quarantine_file_moves::QuarantineMoveFailure,
};

pub fn describe_quarantine_failure(move_failure: &QuarantineMoveFailure) -> String {
    match move_failure {
        QuarantineMoveFailure::FileHashMismatch => {
            gettext("File hash mismatch — file may be corrupted")
        }
        QuarantineMoveFailure::RestoreRefusedIntegrityUnknown => gettext(
            "This quarantine record has no usable hash, so the file cannot be verified and is not \
             restored. You can still delete it.",
        ),
        QuarantineMoveFailure::BlockedFileOnOtherFilesystem => gettext(
            "On-access scanning blocks this file and it is on another filesystem, so it cannot be \
             moved to quarantine. You can delete it instead.",
        ),
        QuarantineMoveFailure::EntryNotFound { entry_id } => {
            gettext("Quarantine entry not found: {id}").replace("{id}", &entry_id.to_string())
        }
        QuarantineMoveFailure::RecordingFailedFileRestored { .. } => gettext(
            "Failed to record quarantine entry in database. File has been restored to original \
             location.",
        ),
        QuarantineMoveFailure::RecordingFailedRollbackFailed {
            rollback_failure,
            payload_path,
            ..
        } => gettext(
            "Failed to record quarantine entry in database. Rollback also failed: {error}. File \
             may be orphaned at: {path}",
        )
        .replace("{error}", &rollback_failure.to_string())
        .replace(
            "{path}",
            &sanitize_scanner_line(&payload_path.to_string_lossy()),
        ),
        QuarantineMoveFailure::EntryRecordNotRemoved => gettext(
            "The file was moved, but its quarantine record could not be removed. It may still \
             appear in the list.",
        ),
        QuarantineMoveFailure::SystemCallFailed(system_call_failure) => {
            gettext("A system call failed: {error}")
                .replace("{error}", &system_call_failure.to_string())
        }
        QuarantineMoveFailure::FileOperationFailed(file_failure) => {
            gettext("A file operation failed: {error}")
                .replace("{error}", &file_failure.to_string())
        }
        QuarantineMoveFailure::DatabaseOperationFailed(database_failure) => {
            gettext("The quarantine database operation failed: {error}")
                .replace("{error}", &database_failure.to_string())
        }
        QuarantineMoveFailure::BlockingStepInterrupted(interrupted_step) => {
            gettext("A background quarantine step stopped unexpectedly: {error}")
                .replace("{error}", &interrupted_step.to_string())
        }
        QuarantineMoveFailure::PathContainsNul => gettext("The path contains a NUL byte"),
        QuarantineMoveFailure::PathHasNoParent => gettext("The path has no parent folder"),
        QuarantineMoveFailure::PathHasNoFileName => gettext("The path has no file name"),
        QuarantineMoveFailure::DatabasePathNotUtf8 => {
            gettext("The quarantine database path is not valid UTF-8")
        }
        QuarantineMoveFailure::DatabaseNotRegularFile => {
            gettext("The quarantine database is not a regular file")
        }
        QuarantineMoveFailure::SourceBlockedByOnAccess => {
            gettext("On-access scanning blocks reading the file")
        }
        QuarantineMoveFailure::MovedPayloadStillBlocked => {
            gettext("The blocked file is still unreadable after moving it to quarantine")
        }
        QuarantineMoveFailure::SourceNotRegularFile => gettext("The file is not a regular file"),
        QuarantineMoveFailure::PayloadNotRegularFile => {
            gettext("The quarantined file is not a regular file")
        }
        QuarantineMoveFailure::NotEnoughFreeSpace => {
            gettext("There is not enough free space to quarantine the file")
        }
        QuarantineMoveFailure::FileReplacedDuringOperation => {
            gettext("The file was replaced while it was being moved, so it was not removed")
        }
        QuarantineMoveFailure::PathOutsideQuarantine => {
            gettext("The path is not inside the quarantine folder")
        }
        QuarantineMoveFailure::InvalidRestorePath => gettext("The restore path is not valid"),
        QuarantineMoveFailure::ProtectedRestoreDestination => {
            gettext("Restoring into a protected system folder is not allowed")
        }
        QuarantineMoveFailure::StoredPathUnreadable { .. } => {
            gettext("A path stored in the quarantine database could not be read")
        }
    }
}
