use turso::{
    Connection,
    transaction::{Transaction, TransactionBehavior},
};

use crate::host_services::lazaret_database::embedded_migration_lists::EmbeddedMigration;

#[derive(Debug, thiserror::Error)]
pub enum DatabaseMigrationFailure {
    #[error(
        "the database has schema version {found_version}, newer than version {known_version} that \
         this Lazaret knows"
    )]
    DatabaseFromNewerRelease {
        found_version: i64,
        known_version: i64,
    },
    #[error("the database migration {migration_name} failed: {database_failure}")]
    MigrationStepFailed {
        migration_name: &'static str,
        database_failure: turso::Error,
    },
    #[error("the database schema version could not be checked: {0}")]
    VersionCheckFailed(#[from] turso::Error),
}

enum MigrationProgress {
    SchemaCurrent,
    MigrationApplied { migration_name: &'static str },
}

async fn stored_schema_version(
    migration_transaction: &Transaction<'_>,
) -> Result<i64, turso::Error> {
    migration_transaction
        .prepare("PRAGMA user_version")
        .await?
        .query_row(())
        .await?
        .get(0)
}

async fn apply_migration_step(
    migration_transaction: &Transaction<'_>,
    pending_migration: &EmbeddedMigration,
    reached_version: i64,
) -> Result<(), DatabaseMigrationFailure> {
    let step_failure = |database_failure| DatabaseMigrationFailure::MigrationStepFailed {
        migration_name: pending_migration.migration_name,
        database_failure,
    };
    migration_transaction
        .execute_batch(pending_migration.migration_sql)
        .await
        .map_err(step_failure)?;
    migration_transaction
        .execute_batch(&format!("PRAGMA user_version = {reached_version}"))
        .await
        .map_err(step_failure)
}

async fn advance_schema_once(
    migration_transaction: &Transaction<'_>,
    ordered_migrations: &[EmbeddedMigration],
) -> Result<MigrationProgress, DatabaseMigrationFailure> {
    let known_version = i64::try_from(ordered_migrations.len()).unwrap_or(i64::MAX);
    let applied_version = stored_schema_version(migration_transaction).await?;
    if applied_version > known_version || applied_version < 0 {
        return Err(DatabaseMigrationFailure::DatabaseFromNewerRelease {
            found_version: applied_version,
            known_version,
        });
    }
    let pending_migration = usize::try_from(applied_version)
        .ok()
        .and_then(|applied_count| ordered_migrations.get(applied_count));
    match pending_migration {
        Some(pending_migration) => {
            apply_migration_step(
                migration_transaction,
                pending_migration,
                applied_version + 1,
            )
            .await?;
            Ok(MigrationProgress::MigrationApplied {
                migration_name: pending_migration.migration_name,
            })
        }
        None => Ok(MigrationProgress::SchemaCurrent),
    }
}

pub async fn apply_pending_migrations(
    database_connection: &mut Connection,
    ordered_migrations: &[EmbeddedMigration],
) -> Result<(), DatabaseMigrationFailure> {
    loop {
        let migration_transaction = database_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        match advance_schema_once(&migration_transaction, ordered_migrations).await {
            Ok(MigrationProgress::MigrationApplied { migration_name }) => migration_transaction
                .commit()
                .await
                .map_err(
                    |database_failure| DatabaseMigrationFailure::MigrationStepFailed {
                        migration_name,
                        database_failure,
                    },
                )?,
            Ok(MigrationProgress::SchemaCurrent) => {
                migration_transaction.rollback().await?;
                return Ok(());
            }
            Err(migration_failure) => {
                migration_transaction.rollback().await?;
                return Err(migration_failure);
            }
        }
    }
}

#[cfg(test)]
pub async fn create_migrated_test_database(
    database_path: &std::path::Path,
    ordered_migrations: &[EmbeddedMigration],
) {
    std::fs::create_dir_all(database_path.parent().expect("database folder"))
        .expect("database folder");
    let test_database = turso::Builder::new_local(database_path.to_str().expect("utf-8 path"))
        .build()
        .await
        .expect("test database");
    let mut test_connection = test_database.connect().expect("test connection");
    apply_pending_migrations(&mut test_connection, ordered_migrations)
        .await
        .expect("migrated test database");
}

#[cfg(test)]
mod database_migration_runner_tests {
    use std::time::Duration;

    use turso::Builder;

    use super::*;
    use crate::host_services::lazaret_database::embedded_migration_lists::LAZARET_MIGRATIONS;

    const TWO_STEP_MIGRATIONS: &[EmbeddedMigration] = &[
        EmbeddedMigration {
            migration_name: "first_step",
            migration_sql: "CREATE TABLE first_step_rows (row_text TEXT NOT NULL);",
        },
        EmbeddedMigration {
            migration_name: "second_step",
            migration_sql: "CREATE TABLE second_step_rows (row_text TEXT NOT NULL);",
        },
    ];

    const FAILING_SECOND_STEP: &[EmbeddedMigration] = &[
        EmbeddedMigration {
            migration_name: "first_step",
            migration_sql: "CREATE TABLE first_step_rows (row_text TEXT NOT NULL);",
        },
        EmbeddedMigration {
            migration_name: "broken_step",
            migration_sql: "CREATE TABLE half_done_rows (row_text TEXT NOT NULL);
                            INSERT INTO missing_rows VALUES ('never');",
        },
    ];

    async fn open_test_connection(database_path: &std::path::Path) -> Connection {
        let test_database = Builder::new_local(database_path.to_str().expect("utf-8 path"))
            .build()
            .await
            .expect("database");
        let test_connection = test_database.connect().expect("connection");
        test_connection
            .busy_timeout(Duration::from_secs(30))
            .expect("busy timeout");
        test_connection
    }

    async fn stored_user_version(test_connection: &Connection) -> i64 {
        test_connection
            .prepare("PRAGMA user_version")
            .await
            .expect("version query")
            .query_row(())
            .await
            .expect("version row")
            .get(0)
            .expect("version value")
    }

    async fn table_exists(test_connection: &Connection, table_name: &str) -> bool {
        let matching_count: i64 = test_connection
            .prepare("SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?1")
            .await
            .expect("table query")
            .query_row((table_name,))
            .await
            .expect("table row")
            .get(0)
            .expect("table count");
        matching_count == 1
    }

    #[tokio::test]
    async fn a_fresh_database_reaches_the_latest_version() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("fresh.db");
        let mut test_connection = open_test_connection(&database_path).await;
        apply_pending_migrations(&mut test_connection, LAZARET_MIGRATIONS)
            .await
            .expect("migrated");
        assert_eq!(stored_user_version(&test_connection).await, 1);
        assert!(table_exists(&test_connection, "activity_entries").await);
        assert!(table_exists(&test_connection, "submissions").await);
    }

    #[tokio::test]
    async fn reopening_a_current_database_changes_nothing() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("reopened.db");
        let mut first_connection = open_test_connection(&database_path).await;
        apply_pending_migrations(&mut first_connection, TWO_STEP_MIGRATIONS)
            .await
            .expect("first open");
        first_connection
            .execute("INSERT INTO second_step_rows VALUES ('kept')", ())
            .await
            .expect("row");
        drop(first_connection);
        let mut second_connection = open_test_connection(&database_path).await;
        apply_pending_migrations(&mut second_connection, TWO_STEP_MIGRATIONS)
            .await
            .expect("second open");
        assert_eq!(stored_user_version(&second_connection).await, 2);
        let kept_rows: i64 = second_connection
            .prepare("SELECT COUNT(*) FROM second_step_rows")
            .await
            .expect("count query")
            .query_row(())
            .await
            .expect("count row")
            .get(0)
            .expect("count");
        assert_eq!(kept_rows, 1);
    }

    #[tokio::test]
    async fn a_database_at_an_earlier_version_gets_only_the_later_steps() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("earlier.db");
        let mut test_connection = open_test_connection(&database_path).await;
        apply_pending_migrations(&mut test_connection, &TWO_STEP_MIGRATIONS[..1])
            .await
            .expect("first step");
        assert_eq!(stored_user_version(&test_connection).await, 1);
        apply_pending_migrations(&mut test_connection, TWO_STEP_MIGRATIONS)
            .await
            .expect("second step");
        assert_eq!(stored_user_version(&test_connection).await, 2);
        assert!(table_exists(&test_connection, "second_step_rows").await);
    }

    #[tokio::test]
    async fn a_database_from_a_newer_release_is_refused() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("newer.db");
        let mut test_connection = open_test_connection(&database_path).await;
        test_connection
            .execute_batch(
                "CREATE TABLE future_rows (row_text TEXT NOT NULL); PRAGMA user_version = 7;",
            )
            .await
            .expect("newer schema");
        let migration_failure = apply_pending_migrations(&mut test_connection, TWO_STEP_MIGRATIONS)
            .await
            .expect_err("refused");
        assert!(matches!(
            migration_failure,
            DatabaseMigrationFailure::DatabaseFromNewerRelease {
                found_version: 7,
                known_version: 2
            }
        ));
        assert_eq!(stored_user_version(&test_connection).await, 7);
    }

    #[tokio::test]
    async fn a_failing_step_rolls_back_and_keeps_the_earlier_version() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("failing.db");
        let mut test_connection = open_test_connection(&database_path).await;
        let migration_failure = apply_pending_migrations(&mut test_connection, FAILING_SECOND_STEP)
            .await
            .expect_err("second step fails");
        assert!(matches!(
            migration_failure,
            DatabaseMigrationFailure::MigrationStepFailed {
                migration_name: "broken_step",
                ..
            }
        ));
        drop(test_connection);
        let reopened_connection = open_test_connection(&database_path).await;
        assert_eq!(stored_user_version(&reopened_connection).await, 1);
        assert!(table_exists(&reopened_connection, "first_step_rows").await);
        assert!(!table_exists(&reopened_connection, "half_done_rows").await);
    }

    #[tokio::test]
    async fn concurrent_opens_apply_each_step_once() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let database_path = temporary_root.path().join("concurrent.db");
        let migration_outcomes = futures::future::join_all((0..4).map(|_opener_index| {
            let opened_path = database_path.clone();
            tokio::spawn(async move {
                let mut opener_connection = open_test_connection(&opened_path).await;
                apply_pending_migrations(&mut opener_connection, TWO_STEP_MIGRATIONS).await
            })
        }))
        .await;
        migration_outcomes.into_iter().for_each(|opener_outcome| {
            opener_outcome
                .expect("opener task")
                .expect("concurrent migration");
        });
        let checked_connection = open_test_connection(&database_path).await;
        assert_eq!(stored_user_version(&checked_connection).await, 2);
    }
}
