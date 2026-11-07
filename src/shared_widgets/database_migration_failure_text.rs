use gettextrs::gettext;

use crate::host_services::{
    activity_history::activity_history_database::ActivityHistoryFailure,
    lazaret_database::database_migration_runner::DatabaseMigrationFailure,
};

pub fn describe_migration_failure(migration_failure: &DatabaseMigrationFailure) -> String {
    match migration_failure {
        DatabaseMigrationFailure::DatabaseFromNewerRelease {
            found_version,
            known_version,
        } => gettext(
            "This database was made by a newer Lazaret: it has layout version {found}, and this \
             version knows up to {known}. Update Lazaret to open it.",
        )
        .replace("{found}", &found_version.to_string())
        .replace("{known}", &known_version.to_string()),
        DatabaseMigrationFailure::MigrationStepFailed {
            migration_name,
            database_failure,
        } => gettext("Updating the database layout failed at step {step}: {error}")
            .replace("{step}", migration_name)
            .replace("{error}", &database_failure.to_string()),
        DatabaseMigrationFailure::VersionCheckFailed(database_failure) => {
            gettext("The database layout version could not be checked: {error}")
                .replace("{error}", &database_failure.to_string())
        }
    }
}

pub fn describe_history_failure(history_failure: &ActivityHistoryFailure) -> String {
    match history_failure {
        ActivityHistoryFailure::HistorySchemaUnusable(migration_failure) => {
            describe_migration_failure(migration_failure)
        }
        ActivityHistoryFailure::DatabaseFailed(_)
        | ActivityHistoryFailure::HistoryFileUnavailable(_)
        | ActivityHistoryFailure::HistoryFileCheckInterrupted(_)
        | ActivityHistoryFailure::DetectedFileCheckInterrupted(_)
        | ActivityHistoryFailure::DatabasePathNotUtf8
        | ActivityHistoryFailure::StoredStatusUnknown
        | ActivityHistoryFailure::StoredOriginUnknown
        | ActivityHistoryFailure::StoredScanDetailsInconsistent
        | ActivityHistoryFailure::StoredDetectionUnreadable
        | ActivityHistoryFailure::StoredSubmissionUnreadable
        | ActivityHistoryFailure::StoredTimeInvalid(_)
        | ActivityHistoryFailure::HistoryLockUnavailable(_) => history_failure.to_string(),
    }
}

#[cfg(test)]
mod database_migration_failure_text_tests {
    use super::*;

    #[test]
    fn a_newer_database_names_both_layout_versions() {
        let newer_database = DatabaseMigrationFailure::DatabaseFromNewerRelease {
            found_version: 4,
            known_version: 1,
        };
        let history_text = describe_history_failure(
            &ActivityHistoryFailure::HistorySchemaUnusable(newer_database),
        );
        assert!(history_text.contains("layout version 4"));
        assert!(history_text.contains("up to 1"));
    }
}
