use std::{
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    time::Duration,
};

use tokio::task::{JoinError, spawn_blocking};
use turso::{Builder, Connection};

use crate::host_services::{
    desktop::file_process_lock::{ProcessFileLock, wait_for_file_lock},
    lazaret_database::{
        database_migration_runner::{DatabaseMigrationFailure, apply_pending_migrations},
        embedded_migration_lists::LAZARET_MIGRATIONS,
    },
    quarantine_vault::quarantine_file_moves::{
        QuarantineMoveFailure, pin_database_file, secure_database_files,
    },
};

pub const LAZARET_DATABASE_FILE_NAME: &str = "lazaret.db";
const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_PRAGMAS: &str = "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;";

pub fn lazaret_database_path(data_directory: &Path) -> PathBuf {
    data_directory.join(LAZARET_DATABASE_FILE_NAME)
}

pub fn quarantine_owner_lock_path(data_directory: &Path) -> PathBuf {
    data_directory.join("quarantine.lock")
}

pub fn database_access_lock_path(database_path: &Path) -> PathBuf {
    database_path.with_extension("lock")
}

#[derive(Debug)]
pub struct DatabasePathNotUtf8;

pub struct LockedDatabaseConnection {
    database_connection: Connection,
    _access_lock: ProcessFileLock,
}

impl Deref for LockedDatabaseConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.database_connection
    }
}

impl DerefMut for LockedDatabaseConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.database_connection
    }
}

pub async fn open_locked_connection<StoreFailure>(
    database_path: &Path,
) -> Result<LockedDatabaseConnection, StoreFailure>
where
    StoreFailure: From<std::io::Error>
        + From<JoinError>
        + From<QuarantineMoveFailure>
        + From<turso::Error>
        + From<DatabaseMigrationFailure>
        + From<DatabasePathNotUtf8>,
{
    let lock_path = database_access_lock_path(database_path);
    let access_lock = spawn_blocking(move || wait_for_file_lock(&lock_path)).await??;
    let pinned_path = database_path.to_path_buf();
    spawn_blocking(move || pin_database_file(&pinned_path)).await??;
    let database_text_path = database_path.to_str().ok_or(DatabasePathNotUtf8)?;
    let lazaret_database = Builder::new_local(database_text_path).build().await?;
    let mut database_connection = lazaret_database.connect()?;
    database_connection.busy_timeout(DATABASE_BUSY_TIMEOUT)?;
    database_connection
        .execute_batch(CONNECTION_PRAGMAS)
        .await?;
    apply_pending_migrations(&mut database_connection, LAZARET_MIGRATIONS).await?;
    database_connection
        .query("PRAGMA journal_mode=WAL", ())
        .await?
        .next()
        .await?;
    secure_database_files(database_path);
    Ok(LockedDatabaseConnection {
        database_connection,
        _access_lock: access_lock,
    })
}
