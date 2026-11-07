use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    time::Duration,
};

use bytesize::ByteSize;
use futures::{TryStreamExt, stream};
use jiff::Timestamp;
use tokio::task::spawn_blocking;
use turso::{Builder, Connection, Database, Row, Value, transaction::TransactionBehavior};

use crate::host_services::{
    clamav_scanner::scanner_output_parser::ThreatIdentity,
    quarantine_vault::{
        quarantine_file_moves::{
            QuarantineMoveFailure, RecordedPayloadHash, copy_file_into_quarantine,
            delete_payload_file, discard_copied_payload, ensure_quarantine_directory,
            lexically_normalized_path, neutralize_payload_in_place, open_payload_plaintext,
            parsed_sha256_hex, payload_content_hash, pin_database_file, plan_blocked_file_rename,
            read_verified_payload_bytes, remove_quarantined_source,
            remove_stale_neutralizing_copies, rename_blocked_file_into_quarantine,
            restore_payload_file, secure_database_files,
        },
        quarantine_payload_format::PlaintextReader,
    },
};

const DATABASE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECTION_PRAGMAS: &str = "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;";
const QUARANTINE_SCHEMA: &str = include_str!("../../../data/database-schemas/quarantine.sql");
const ENTRY_QUERY: &str = "
    SELECT quarantine.entry_id, quarantine.original_path, quarantine.quarantine_path,
        quarantine_signatures.signature_name, quarantine.detection_date,
        file_contents.byte_size, quarantine.content_sha256, quarantine.original_permissions
    FROM quarantine
    JOIN file_contents ON file_contents.content_sha256 = quarantine.content_sha256
    LEFT JOIN quarantine_signatures ON quarantine_signatures.entry_id = quarantine.entry_id";
const PENDING_QUERY: &str = "
    SELECT quarantine_pending.quarantine_path, quarantine_pending.original_path,
        pending_signatures.signature_name, quarantine_pending.byte_size,
        pending_payload_hashes.content_sha256, quarantine_pending.original_permissions
    FROM quarantine_pending
    LEFT JOIN pending_signatures
        ON pending_signatures.quarantine_path = quarantine_pending.quarantine_path
    LEFT JOIN pending_payload_hashes
        ON pending_payload_hashes.quarantine_path = quarantine_pending.quarantine_path";
const ORPHANED_CONTENT_REMOVAL: &str = "DELETE FROM file_contents WHERE NOT EXISTS (SELECT 1 FROM \
                                        quarantine WHERE quarantine.content_sha256 = \
                                        file_contents.content_sha256)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredDetectionDate {
    DetectedAt(Timestamp),
    UnreadableText(String),
}

impl From<String> for StoredDetectionDate {
    fn from(stored_text: String) -> Self {
        stored_text.parse().map_or_else(
            |_unparseable| Self::UnreadableText(stored_text),
            Self::DetectedAt,
        )
    }
}

fn threat_identity_from_stored(stored_signature: Option<String>) -> ThreatIdentity {
    match stored_signature {
        Some(signature_name) => ThreatIdentity::Signature { signature_name },
        None => ThreatIdentity::BlockedByOnAccess,
    }
}

async fn record_threat_signature(
    database_connection: &Connection,
    signature_insert: &str,
    stored_key: Value,
    threat_identity: &ThreatIdentity,
) -> Result<(), QuarantineMoveFailure> {
    match threat_identity {
        ThreatIdentity::Signature { signature_name } => {
            database_connection
                .execute(signature_insert, (stored_key, signature_name.as_str()))
                .await?;
            Ok(())
        }
        ThreatIdentity::BlockedByOnAccess => Ok(()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineEntryRecord {
    pub entry_id: i64,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub threat_identity: ThreatIdentity,
    pub detection_date: StoredDetectionDate,
    pub file_size: ByteSize,
    pub payload_hash: RecordedPayloadHash,
    pub original_permissions: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingPayloadHash {
    NotYetHashed,
    Hashed { sha256_hex: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoredPendingHash {
    NotYetHashed,
    Hashed { sha256_hex: String },
    UnrecognisedText,
}

impl StoredPendingHash {
    fn from_stored_hash(stored_hash: Option<String>) -> Self {
        match stored_hash {
            None => Self::NotYetHashed,
            Some(stored_text) => parsed_sha256_hex(&stored_text)
                .map_or(Self::UnrecognisedText, |sha256_hex| Self::Hashed {
                    sha256_hex,
                }),
        }
    }
}

struct PendingQuarantineRow {
    quarantine_path: PathBuf,
    original_path: PathBuf,
    threat_identity: ThreatIdentity,
    file_size: ByteSize,
    stored_hash: StoredPendingHash,
    original_permissions: u32,
}

struct PendingMove {
    source_path: PathBuf,
    destination_path: PathBuf,
    file_size: ByteSize,
    pending_hash: PendingPayloadHash,
    original_permissions: u32,
}

pub struct VerifiedPayload {
    pub entry_record: QuarantineEntryRecord,
    pub content_sha256: String,
    pub payload_bytes: Vec<u8>,
}

impl std::fmt::Debug for VerifiedPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedPayload")
            .field("entry_record", &self.entry_record)
            .field("content_sha256", &self.content_sha256)
            .field("payload_size", &self.payload_bytes.len())
            .finish()
    }
}

#[derive(Clone)]
pub struct QuarantineVault {
    entry_database: Database,
    database_path: PathBuf,
    quarantine_directory: PathBuf,
}

impl std::fmt::Debug for QuarantineVault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuarantineVault")
            .field("database_path", &self.database_path)
            .field("quarantine_directory", &self.quarantine_directory)
            .finish_non_exhaustive()
    }
}

fn path_blob(stored_path: &Path) -> Value {
    Value::Blob(stored_path.as_os_str().as_bytes().to_vec())
}

fn stored_path_column(
    database_row: &Row,
    column_index: usize,
) -> Result<PathBuf, QuarantineMoveFailure> {
    match database_row.get_value(column_index)? {
        Value::Blob(raw_path) => Ok(PathBuf::from(OsString::from_vec(raw_path))),
        Value::Text(text_path) => Ok(PathBuf::from(text_path)),
        _other_value => Err(QuarantineMoveFailure::StoredPathUnreadable { column_index }),
    }
}

fn entry_record_from_row(
    database_row: &Row,
) -> Result<QuarantineEntryRecord, QuarantineMoveFailure> {
    Ok(QuarantineEntryRecord {
        entry_id: database_row.get(0)?,
        original_path: stored_path_column(database_row, 1)?,
        quarantine_path: stored_path_column(database_row, 2)?,
        threat_identity: threat_identity_from_stored(database_row.get(3)?),
        detection_date: StoredDetectionDate::from(database_row.get::<String>(4)?),
        file_size: ByteSize::b(database_row.get(5)?),
        payload_hash: RecordedPayloadHash::from(database_row.get::<String>(6)?),
        original_permissions: database_row.get::<u32>(7)? & 0o777,
    })
}

impl QuarantineVault {
    pub async fn open_vault(
        database_path: PathBuf,
        quarantine_directory: PathBuf,
    ) -> Result<Self, QuarantineMoveFailure> {
        let prepared_database_path = database_path.clone();
        let prepared_quarantine_directory = quarantine_directory.clone();
        spawn_blocking(move || {
            ensure_quarantine_directory(&prepared_quarantine_directory)?;
            pin_database_file(&prepared_database_path)
        })
        .await??;
        let database_text_path = database_path
            .to_str()
            .ok_or(QuarantineMoveFailure::DatabasePathNotUtf8)?;
        let entry_database = Builder::new_local(database_text_path).build().await?;
        let quarantine_vault = Self {
            entry_database,
            database_path,
            quarantine_directory,
        };
        let schema_connection = quarantine_vault.open_connection().await?;
        schema_connection
            .query("PRAGMA journal_mode=WAL", ())
            .await?
            .next()
            .await?;
        schema_connection.execute_batch(QUARANTINE_SCHEMA).await?;
        quarantine_vault
            .reconcile_pending_entries(&schema_connection)
            .await?;
        secure_database_files(&quarantine_vault.database_path);
        quarantine_vault.neutralize_listed_payloads().await;
        Ok(quarantine_vault)
    }

    async fn neutralize_listed_payloads(&self) {
        let quarantine_directory = self.quarantine_directory.clone();
        let listed_entries = self.list_quarantine_entries().await.unwrap_or_default();
        let _interrupted_neutralizing = spawn_blocking(move || {
            remove_stale_neutralizing_copies(&quarantine_directory);
            listed_entries.iter().for_each(|listed_entry| {
                let _payload_stays_raw = neutralize_payload_in_place(
                    &quarantine_directory,
                    &listed_entry.quarantine_path,
                    &listed_entry.payload_hash,
                );
            });
        })
        .await;
    }

    async fn neutralize_committed_payload(&self, recorded_payload: &RecordedPayload) {
        let quarantine_directory = self.quarantine_directory.clone();
        let payload_path = recorded_payload.destination_path.clone();
        let recorded_hash = RecordedPayloadHash::KnownSha256 {
            sha256_hex: recorded_payload.sha256_hex.clone(),
        };
        let _payload_stays_raw = spawn_blocking(move || {
            neutralize_payload_in_place(&quarantine_directory, &payload_path, &recorded_hash)
        })
        .await;
    }

    pub async fn read_payload_plaintext(
        &self,
        entry_id: i64,
    ) -> Result<PlaintextReader<std::fs::File>, QuarantineMoveFailure> {
        let database_connection = self.open_connection().await?;
        let entry_record = self
            .find_quarantine_entry(&database_connection, entry_id)
            .await?;
        drop(database_connection);
        let quarantine_directory = self.quarantine_directory.clone();
        spawn_blocking(move || {
            open_payload_plaintext(&quarantine_directory, &entry_record.quarantine_path)
        })
        .await?
    }

    pub async fn read_verified_payload(
        &self,
        entry_id: i64,
        maximum_size: ByteSize,
    ) -> Result<VerifiedPayload, QuarantineMoveFailure> {
        let database_connection = self.open_connection().await?;
        let entry_record = self
            .find_quarantine_entry(&database_connection, entry_id)
            .await?;
        drop(database_connection);
        let RecordedPayloadHash::KnownSha256 { sha256_hex } = entry_record.payload_hash.clone()
        else {
            return Err(QuarantineMoveFailure::UploadRefusedIntegrityUnknown);
        };
        let quarantine_directory = self.quarantine_directory.clone();
        let payload_path = entry_record.quarantine_path.clone();
        let verified_sha256 = sha256_hex.clone();
        let payload_bytes = spawn_blocking(move || {
            read_verified_payload_bytes(
                &quarantine_directory,
                &payload_path,
                &verified_sha256,
                maximum_size,
            )
        })
        .await??;
        Ok(VerifiedPayload {
            entry_record,
            content_sha256: sha256_hex,
            payload_bytes,
        })
    }

    async fn open_connection(&self) -> Result<Connection, QuarantineMoveFailure> {
        let database_connection = self.entry_database.connect()?;
        database_connection.busy_timeout(DATABASE_BUSY_TIMEOUT)?;
        database_connection
            .execute_batch(CONNECTION_PRAGMAS)
            .await?;
        secure_database_files(&self.database_path);
        Ok(database_connection)
    }

    async fn reconcile_pending_entries(
        &self,
        database_connection: &Connection,
    ) -> Result<(), QuarantineMoveFailure> {
        let mut pending_rows = database_connection.query(PENDING_QUERY, ()).await?;
        let mut pending_entries = Vec::new();
        while let Some(pending_row) = pending_rows.next().await? {
            pending_entries.push(PendingQuarantineRow {
                quarantine_path: stored_path_column(&pending_row, 0)?,
                original_path: stored_path_column(&pending_row, 1)?,
                threat_identity: threat_identity_from_stored(pending_row.get(2)?),
                file_size: ByteSize::b(pending_row.get(3)?),
                stored_hash: StoredPendingHash::from_stored_hash(pending_row.get(4)?),
                original_permissions: pending_row.get(5)?,
            });
        }
        drop(pending_rows);
        stream::iter(pending_entries.into_iter().map(Ok))
            .try_for_each(|pending_entry| {
                recover_verified_pending_entry(database_connection, pending_entry)
            })
            .await
    }

    pub async fn list_quarantine_entries(
        &self,
    ) -> Result<Vec<QuarantineEntryRecord>, QuarantineMoveFailure> {
        let database_connection = self.open_connection().await?;
        let mut entry_rows = database_connection
            .query(
                format!(
                    "{ENTRY_QUERY} ORDER BY quarantine.detection_date DESC, quarantine.entry_id \
                     DESC"
                ),
                (),
            )
            .await?;
        let mut listed_entries = Vec::new();
        while let Some(entry_row) = entry_rows.next().await? {
            listed_entries.push(entry_record_from_row(&entry_row)?);
        }
        Ok(listed_entries)
    }

    async fn find_quarantine_entry(
        &self,
        database_connection: &Connection,
        entry_id: i64,
    ) -> Result<QuarantineEntryRecord, QuarantineMoveFailure> {
        let mut entry_rows = database_connection
            .query(
                format!("{ENTRY_QUERY} WHERE quarantine.entry_id = ?1"),
                [entry_id],
            )
            .await?;
        let Some(entry_row) = entry_rows.next().await? else {
            return Err(QuarantineMoveFailure::EntryNotFound { entry_id });
        };
        entry_record_from_row(&entry_row)
    }

    async fn record_pending_move(
        &self,
        pending_move: &PendingMove,
        threat_identity: &ThreatIdentity,
    ) -> Result<(), QuarantineMoveFailure> {
        let mut database_connection = self.open_connection().await?;
        let pending_transaction = database_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        pending_transaction
            .execute(
                "INSERT INTO quarantine_pending (quarantine_path, original_path, byte_size, \
                 original_permissions) VALUES (?1, ?2, ?3, ?4)",
                (
                    path_blob(&pending_move.destination_path),
                    path_blob(&pending_move.source_path),
                    pending_move.file_size.as_u64(),
                    pending_move.original_permissions & 0o777,
                ),
            )
            .await?;
        if let PendingPayloadHash::Hashed { sha256_hex } = &pending_move.pending_hash {
            pending_transaction
                .execute(
                    "INSERT INTO pending_payload_hashes (quarantine_path, content_sha256) VALUES \
                     (?1, ?2)",
                    (
                        path_blob(&pending_move.destination_path),
                        sha256_hex.as_str(),
                    ),
                )
                .await?;
        }
        record_threat_signature(
            &pending_transaction,
            "INSERT INTO pending_signatures (quarantine_path, signature_name) VALUES (?1, ?2)",
            path_blob(&pending_move.destination_path),
            threat_identity,
        )
        .await?;
        pending_transaction.commit().await?;
        Ok(())
    }

    async fn forget_pending_move(&self, destination_path: &Path) {
        if let Ok(database_connection) = self.open_connection().await {
            let _pending_row_kept = database_connection
                .execute(
                    "DELETE FROM quarantine_pending WHERE quarantine_path = ?1",
                    vec![path_blob(destination_path)],
                )
                .await;
        }
    }

    pub(super) async fn rename_and_record_blocked_source(
        &self,
        source_path: &Path,
        threat_identity: &ThreatIdentity,
    ) -> Result<RecordedPayload, QuarantineMoveFailure> {
        let normalized_source = lexically_normalized_path(source_path);
        let quarantine_directory = self.quarantine_directory.clone();
        let planned_rename = spawn_blocking(move || {
            plan_blocked_file_rename(&quarantine_directory, &normalized_source)
        })
        .await??;
        let pending_move = PendingMove {
            source_path: planned_rename.source_path.clone(),
            destination_path: planned_rename.destination_path.clone(),
            file_size: planned_rename.file_size,
            pending_hash: PendingPayloadHash::NotYetHashed,
            original_permissions: planned_rename.original_permissions,
        };
        self.record_pending_move(&pending_move, threat_identity)
            .await?;
        let rename_outcome =
            spawn_blocking(move || rename_blocked_file_into_quarantine(&planned_rename))
                .await
                .map_err(QuarantineMoveFailure::from)
                .and_then(|rename_outcome| rename_outcome);
        match rename_outcome {
            Ok(sha256_hex) => Ok(RecordedPayload {
                source_path: pending_move.source_path,
                destination_path: pending_move.destination_path,
                file_size: pending_move.file_size,
                sha256_hex,
                original_permissions: pending_move.original_permissions,
            }),
            Err(rename_failure) => {
                self.forget_pending_move(&pending_move.destination_path)
                    .await;
                Err(rename_failure)
            }
        }
    }

    async fn commit_quarantine_entry(
        &self,
        recorded_payload: &RecordedPayload,
        threat_identity: &ThreatIdentity,
    ) -> Result<i64, QuarantineMoveFailure> {
        let mut database_connection = self.open_connection().await?;
        let entry_transaction = database_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        insert_committed_entry(
            &entry_transaction,
            &CommittedEntry {
                original_path: &recorded_payload.source_path,
                quarantine_path: &recorded_payload.destination_path,
                threat_identity,
                file_size: recorded_payload.file_size,
                sha256_hex: &recorded_payload.sha256_hex,
                original_permissions: recorded_payload.original_permissions,
                path_conflict: QuarantinePathConflict::FailOnExistingEntry,
            },
        )
        .await?;
        let entry_id = entry_transaction
            .prepare("SELECT entry_id FROM quarantine WHERE quarantine_path = ?1")
            .await?
            .query_row([path_blob(&recorded_payload.destination_path)])
            .await?
            .get(0)?;
        entry_transaction.commit().await?;
        Ok(entry_id)
    }

    async fn roll_back_recording_failure(
        &self,
        recorded_payload: &RecordedPayload,
        recording_failure: QuarantineMoveFailure,
    ) -> QuarantineMoveFailure {
        let quarantine_directory = self.quarantine_directory.clone();
        let payload_path = recorded_payload.destination_path.clone();
        let source_path = recorded_payload.source_path.clone();
        let original_permissions = recorded_payload.original_permissions;
        let sha256_hex = recorded_payload.sha256_hex.clone();
        let rollback_outcome = spawn_blocking(move || {
            restore_payload_file(
                &quarantine_directory,
                &payload_path,
                &source_path,
                original_permissions,
                &sha256_hex,
            )
        })
        .await
        .map_err(QuarantineMoveFailure::from)
        .and_then(|restore_outcome| restore_outcome);
        match rollback_outcome {
            Ok(()) => {
                self.forget_pending_move(&recorded_payload.destination_path)
                    .await;
                QuarantineMoveFailure::RecordingFailedFileRestored {
                    recording_failure: Box::new(recording_failure),
                }
            }
            Err(rollback_failure) => QuarantineMoveFailure::RecordingFailedRollbackFailed {
                recording_failure: Box::new(recording_failure),
                rollback_failure: Box::new(rollback_failure),
                payload_path: recorded_payload.destination_path.clone(),
            },
        }
    }

    pub(super) async fn copy_record_and_remove_source(
        &self,
        source_path: &Path,
        threat_identity: &ThreatIdentity,
    ) -> Result<RecordedPayload, QuarantineMoveFailure> {
        let normalized_source = lexically_normalized_path(source_path);
        let quarantine_directory = self.quarantine_directory.clone();
        let copied_payload = spawn_blocking(move || {
            copy_file_into_quarantine(&quarantine_directory, &normalized_source)
        })
        .await??;
        let pending_outcome = self
            .record_pending_move(
                &PendingMove {
                    source_path: copied_payload.source_path.clone(),
                    destination_path: copied_payload.destination_path.clone(),
                    file_size: copied_payload.file_size,
                    pending_hash: PendingPayloadHash::Hashed {
                        sha256_hex: copied_payload.sha256_hex.clone(),
                    },
                    original_permissions: copied_payload.original_permissions,
                },
                threat_identity,
            )
            .await;
        spawn_blocking(move || {
            if let Err(pending_failure) = pending_outcome {
                discard_copied_payload(&copied_payload);
                return Err(pending_failure);
            }
            remove_quarantined_source(&copied_payload)?;
            Ok(RecordedPayload {
                source_path: copied_payload.source_path,
                destination_path: copied_payload.destination_path,
                file_size: copied_payload.file_size,
                sha256_hex: copied_payload.sha256_hex,
                original_permissions: copied_payload.original_permissions,
            })
        })
        .await?
    }

    pub async fn move_file_into_quarantine(
        &self,
        source_path: &Path,
        threat_identity: &ThreatIdentity,
    ) -> Result<QuarantineEntryRecord, QuarantineMoveFailure> {
        let recorded_payload = match self
            .copy_record_and_remove_source(source_path, threat_identity)
            .await
        {
            Err(QuarantineMoveFailure::SourceBlockedByOnAccess) => {
                self.rename_and_record_blocked_source(source_path, threat_identity)
                    .await?
            }
            copy_outcome => copy_outcome?,
        };
        match self
            .commit_quarantine_entry(&recorded_payload, threat_identity)
            .await
        {
            Ok(entry_id) => {
                self.neutralize_committed_payload(&recorded_payload).await;
                let database_connection = self.open_connection().await?;
                self.find_quarantine_entry(&database_connection, entry_id)
                    .await
            }
            Err(recording_failure) => Err(self
                .roll_back_recording_failure(&recorded_payload, recording_failure)
                .await),
        }
    }

    async fn remove_entry_record(&self, entry_id: i64) -> Result<(), QuarantineMoveFailure> {
        let mut database_connection = self.open_connection().await?;
        let removal_transaction = database_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .await?;
        let removed_rows = removal_transaction
            .execute("DELETE FROM quarantine WHERE entry_id = ?1", [entry_id])
            .await?;
        if removed_rows == 0 {
            return Err(QuarantineMoveFailure::EntryRecordNotRemoved);
        }
        removal_transaction
            .execute(ORPHANED_CONTENT_REMOVAL, ())
            .await?;
        removal_transaction.commit().await?;
        Ok(())
    }

    pub async fn restore_quarantined_file(
        &self,
        entry_id: i64,
    ) -> Result<QuarantineEntryRecord, QuarantineMoveFailure> {
        let database_connection = self.open_connection().await?;
        let entry_record = self
            .find_quarantine_entry(&database_connection, entry_id)
            .await?;
        drop(database_connection);
        let RecordedPayloadHash::KnownSha256 { sha256_hex } = entry_record.payload_hash.clone()
        else {
            return Err(QuarantineMoveFailure::RestoreRefusedIntegrityUnknown);
        };
        let quarantine_directory = self.quarantine_directory.clone();
        let restored_record = entry_record.clone();
        spawn_blocking(move || {
            restore_payload_file(
                &quarantine_directory,
                &restored_record.quarantine_path,
                &restored_record.original_path,
                restored_record.original_permissions,
                &sha256_hex,
            )
        })
        .await??;
        self.remove_entry_record(entry_id)
            .await
            .map_err(|_removal_failure| QuarantineMoveFailure::EntryRecordNotRemoved)?;
        Ok(entry_record)
    }

    pub async fn delete_quarantined_file(
        &self,
        entry_id: i64,
    ) -> Result<QuarantineEntryRecord, QuarantineMoveFailure> {
        let database_connection = self.open_connection().await?;
        let entry_record = self
            .find_quarantine_entry(&database_connection, entry_id)
            .await?;
        drop(database_connection);
        let quarantine_directory = self.quarantine_directory.clone();
        let payload_path = entry_record.quarantine_path.clone();
        spawn_blocking(move || delete_payload_file(&quarantine_directory, &payload_path)).await??;
        self.remove_entry_record(entry_id)
            .await
            .map_err(|_removal_failure| QuarantineMoveFailure::EntryRecordNotRemoved)?;
        Ok(entry_record)
    }
}

pub(super) struct RecordedPayload {
    source_path: PathBuf,
    destination_path: PathBuf,
    file_size: ByteSize,
    sha256_hex: String,
    original_permissions: u32,
}

enum PendingEntryAssessment {
    RecoverEntry { committed_sha256_hex: String },
    DiscardPendingRow,
    KeepForManualRecovery,
}

fn assess_pending_entry(
    original_path: &Path,
    payload_path: &Path,
    stored_hash: &StoredPendingHash,
) -> PendingEntryAssessment {
    let original_confirmed_missing = matches!(
        std::fs::symlink_metadata(original_path),
        Err(metadata_failure) if metadata_failure.kind() == std::io::ErrorKind::NotFound
    );
    let payload_confirmed_missing = matches!(
        std::fs::symlink_metadata(payload_path),
        Err(metadata_failure) if metadata_failure.kind() == std::io::ErrorKind::NotFound
    );
    match stored_hash {
        StoredPendingHash::NotYetHashed if payload_confirmed_missing => {
            PendingEntryAssessment::DiscardPendingRow
        }
        _payload_may_exist if !original_confirmed_missing => {
            PendingEntryAssessment::KeepForManualRecovery
        }
        StoredPendingHash::NotYetHashed => payload_content_hash(payload_path).map_or(
            PendingEntryAssessment::KeepForManualRecovery,
            |first_sha256_hex| PendingEntryAssessment::RecoverEntry {
                committed_sha256_hex: first_sha256_hex,
            },
        ),
        StoredPendingHash::Hashed { sha256_hex } => match payload_content_hash(payload_path) {
            Ok(actual_sha256_hex) if actual_sha256_hex == *sha256_hex => {
                PendingEntryAssessment::RecoverEntry {
                    committed_sha256_hex: actual_sha256_hex,
                }
            }
            _unverified_payload => PendingEntryAssessment::KeepForManualRecovery,
        },
        StoredPendingHash::UnrecognisedText => PendingEntryAssessment::KeepForManualRecovery,
    }
}

async fn recover_verified_pending_entry(
    database_connection: &Connection,
    pending_entry: PendingQuarantineRow,
) -> Result<(), QuarantineMoveFailure> {
    let original_path = pending_entry.original_path.clone();
    let payload_path = pending_entry.quarantine_path.clone();
    let stored_hash = pending_entry.stored_hash.clone();
    let pending_assessment =
        spawn_blocking(move || assess_pending_entry(&original_path, &payload_path, &stored_hash))
            .await?;
    let committed_sha256_hex = match pending_assessment {
        PendingEntryAssessment::KeepForManualRecovery => return Ok(()),
        PendingEntryAssessment::DiscardPendingRow => {
            database_connection
                .execute(
                    "DELETE FROM quarantine_pending WHERE quarantine_path = ?1",
                    vec![path_blob(&pending_entry.quarantine_path)],
                )
                .await?;
            return Ok(());
        }
        PendingEntryAssessment::RecoverEntry {
            committed_sha256_hex,
        } => committed_sha256_hex,
    };
    let recovery_transaction = database_connection.unchecked_transaction().await?;
    insert_committed_entry(
        &recovery_transaction,
        &CommittedEntry {
            original_path: &pending_entry.original_path,
            quarantine_path: &pending_entry.quarantine_path,
            threat_identity: &pending_entry.threat_identity,
            file_size: pending_entry.file_size,
            sha256_hex: &committed_sha256_hex,
            original_permissions: pending_entry.original_permissions,
            path_conflict: QuarantinePathConflict::KeepExistingEntry,
        },
    )
    .await?;
    recovery_transaction.commit().await?;
    Ok(())
}

enum QuarantinePathConflict {
    FailOnExistingEntry,
    KeepExistingEntry,
}

impl QuarantinePathConflict {
    const fn entry_insert(&self) -> &'static str {
        match self {
            Self::FailOnExistingEntry => {
                "INSERT INTO quarantine (original_path, quarantine_path, content_sha256, \
                 detection_date, original_permissions) VALUES (?1, ?2, ?3, ?4, ?5)"
            }
            Self::KeepExistingEntry => {
                "INSERT OR IGNORE INTO quarantine (original_path, quarantine_path, content_sha256, \
                 detection_date, original_permissions) VALUES (?1, ?2, ?3, ?4, ?5)"
            }
        }
    }
}

struct CommittedEntry<'entry> {
    original_path: &'entry Path,
    quarantine_path: &'entry Path,
    threat_identity: &'entry ThreatIdentity,
    file_size: ByteSize,
    sha256_hex: &'entry str,
    original_permissions: u32,
    path_conflict: QuarantinePathConflict,
}

async fn insert_committed_entry(
    database_connection: &Connection,
    committed_entry: &CommittedEntry<'_>,
) -> Result<(), QuarantineMoveFailure> {
    database_connection
        .execute(
            "INSERT OR IGNORE INTO file_contents (content_sha256, byte_size) VALUES (?1, ?2)",
            (
                committed_entry.sha256_hex,
                committed_entry.file_size.as_u64(),
            ),
        )
        .await?;
    database_connection
        .execute(
            committed_entry.path_conflict.entry_insert(),
            (
                path_blob(committed_entry.original_path),
                path_blob(committed_entry.quarantine_path),
                committed_entry.sha256_hex,
                format!("{:.3}", Timestamp::now()),
                committed_entry.original_permissions & 0o777,
            ),
        )
        .await?;
    record_threat_signature(
        database_connection,
        "INSERT OR IGNORE INTO quarantine_signatures (entry_id, signature_name) SELECT entry_id, \
         ?2 FROM quarantine WHERE quarantine_path = ?1",
        path_blob(committed_entry.quarantine_path),
        committed_entry.threat_identity,
    )
    .await?;
    database_connection
        .execute(
            "DELETE FROM quarantine_pending WHERE quarantine_path = ?1",
            [path_blob(committed_entry.quarantine_path)],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod quarantine_entry_database_tests {
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use rusqlite::params;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;

    fn signature_identity(signature_name: &str) -> ThreatIdentity {
        ThreatIdentity::Signature {
            signature_name: signature_name.to_owned(),
        }
    }

    fn stored_plaintext(payload_path: &Path) -> Vec<u8> {
        use std::io::Read;
        let mut plaintext = Vec::new();
        crate::host_services::quarantine_vault::quarantine_payload_format::open_plaintext_reader(
            std::fs::File::open(payload_path).expect("payload"),
        )
        .expect("payload reader")
        .read_to_end(&mut plaintext)
        .expect("plaintext");
        plaintext
    }

    struct VaultFixture {
        temporary_root: TempDir,
        quarantine_vault: QuarantineVault,
    }

    impl VaultFixture {
        fn database_path(temporary_root: &TempDir) -> PathBuf {
            temporary_root.path().join("data/quarantine.db")
        }

        fn quarantine_directory(temporary_root: &TempDir) -> PathBuf {
            temporary_root.path().join("data/quarantine")
        }

        async fn open_fixture() -> Self {
            let temporary_root = tempfile::tempdir().expect("temporary root");
            let quarantine_vault = open_fixture_vault(&temporary_root).await;
            Self {
                temporary_root,
                quarantine_vault,
            }
        }

        fn source_file(&self, file_name: &str, file_bytes: &[u8]) -> PathBuf {
            let source_path = self.temporary_root.path().join(file_name);
            fs::write(&source_path, file_bytes).expect("source file");
            source_path
        }
    }

    async fn open_fixture_vault(temporary_root: &TempDir) -> QuarantineVault {
        QuarantineVault::open_vault(
            VaultFixture::database_path(temporary_root),
            VaultFixture::quarantine_directory(temporary_root),
        )
        .await
        .expect("opened vault")
    }

    fn sha256_text(file_bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(file_bytes))
    }

    enum SeededPendingHash<'seeded> {
        NotYetHashed,
        Hashed { sha256_hex: &'seeded str },
        TamperedHash { stored_text: &'seeded str },
    }

    fn seed_pending_row(
        temporary_root: &TempDir,
        payload_path: &Path,
        original_path: &Path,
        seeded_hash: SeededPendingHash<'_>,
    ) {
        let sqlite_connection =
            rusqlite::Connection::open(VaultFixture::database_path(temporary_root))
                .expect("sqlite connection");
        sqlite_connection
            .execute_batch(QUARANTINE_SCHEMA)
            .expect("quarantine schema");
        sqlite_connection
            .execute(
                "INSERT INTO quarantine_pending VALUES (?1, ?2, 15, 420)",
                params![
                    payload_path.as_os_str().as_bytes(),
                    original_path.as_os_str().as_bytes(),
                ],
            )
            .expect("pending row");
        sqlite_connection
            .execute(
                "INSERT INTO pending_signatures VALUES (?1, 'Crash.Test')",
                params![payload_path.as_os_str().as_bytes()],
            )
            .expect("pending signature");
        let stored_hash = match seeded_hash {
            SeededPendingHash::NotYetHashed => return,
            SeededPendingHash::Hashed { sha256_hex } => sha256_hex,
            SeededPendingHash::TamperedHash { stored_text } => {
                sqlite_connection
                    .execute_batch("PRAGMA ignore_check_constraints=ON")
                    .expect("ignore checks");
                stored_text
            }
        };
        sqlite_connection
            .execute(
                "INSERT INTO pending_payload_hashes VALUES (?1, ?2)",
                params![payload_path.as_os_str().as_bytes(), stored_hash],
            )
            .expect("pending hash");
    }

    fn insert_tampered_entry(
        temporary_root: &TempDir,
        original_path: &Path,
        payload_path: &Path,
        byte_size: i64,
    ) {
        let sqlite_connection =
            rusqlite::Connection::open(VaultFixture::database_path(temporary_root))
                .expect("sqlite connection");
        sqlite_connection
            .execute_batch(
                "PRAGMA ignore_check_constraints=ON; PRAGMA foreign_keys=ON; INSERT OR IGNORE \
                 INTO file_contents VALUES ('', 0);",
            )
            .expect("tampered content row");
        sqlite_connection
            .execute(
                "UPDATE file_contents SET byte_size = ?1 WHERE content_sha256 = ''",
                params![byte_size],
            )
            .expect("tampered size");
        sqlite_connection
            .execute(
                "INSERT INTO quarantine (original_path, quarantine_path, content_sha256, \
                 detection_date, original_permissions) VALUES (?1, ?2, '', \
                 '2020-01-01T00:00:00Z', 420)",
                params![
                    original_path.as_os_str().as_bytes(),
                    payload_path.as_os_str().as_bytes(),
                ],
            )
            .expect("tampered row");
        sqlite_connection
            .execute(
                "INSERT INTO quarantine_signatures SELECT entry_id, 'Tampered.Test' FROM \
                 quarantine WHERE quarantine_path = ?1",
                params![payload_path.as_os_str().as_bytes()],
            )
            .expect("tampered signature");
    }

    fn pending_row_count(temporary_root: &TempDir) -> i64 {
        rusqlite::Connection::open(VaultFixture::database_path(temporary_root))
            .expect("sqlite connection")
            .query_row("SELECT COUNT(*) FROM quarantine_pending", [], |count_row| {
                count_row.get(0)
            })
            .expect("pending count")
    }

    #[tokio::test]
    async fn the_screenshot_fixture_loads_as_a_verified_entry() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let quarantine_directory = VaultFixture::quarantine_directory(&temporary_root);
        fs::create_dir_all(&quarantine_directory).expect("quarantine directory");
        let payload_path = quarantine_directory.join("0123456789abcdef_invoice.pdf.exe");
        fs::write(&payload_path, b"fixture payload").expect("payload");
        rusqlite::Connection::open(VaultFixture::database_path(&temporary_root))
            .expect("sqlite connection")
            .execute_batch(
                &(QUARANTINE_SCHEMA.to_owned()
                    + &include_str!("../../../xtask/assets/quarantine-seed.sql").replace(
                        "@PAYLOAD_PATH@",
                        &format!("'{}'", payload_path.to_string_lossy()),
                    )),
            )
            .expect("fixture rows");
        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        let listed_entries = quarantine_vault
            .list_quarantine_entries()
            .await
            .expect("listed");
        assert_eq!(listed_entries.len(), 1);
        assert_eq!(
            listed_entries[0].threat_identity,
            signature_identity("Win.Trojan.Agent")
        );
        assert_eq!(listed_entries[0].file_size, ByteSize::b(15));
        assert_eq!(
            quarantine_vault
                .read_verified_payload(listed_entries[0].entry_id, ByteSize::mib(1))
                .await
                .expect("verified")
                .payload_bytes,
            b"fixture payload"
        );
    }

    #[tokio::test]
    async fn equal_contents_share_one_content_row_until_the_last_entry_leaves() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let first_source = vault_fixture.source_file("first-copy.bin", b"same bytes");
        let second_source = vault_fixture.source_file("second-copy.bin", b"same bytes");
        let first_entry = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&first_source, &signature_identity("Test.Signature"))
            .await
            .expect("first quarantined");
        let second_entry = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&second_source, &ThreatIdentity::BlockedByOnAccess)
            .await
            .expect("second quarantined");
        let content_rows = async || -> u64 {
            vault_fixture
                .quarantine_vault
                .open_connection()
                .await
                .expect("connection")
                .prepare("SELECT COUNT(*) FROM file_contents")
                .await
                .expect("statement")
                .query_row(())
                .await
                .expect("count row")
                .get(0)
                .expect("content rows")
        };
        assert_eq!(content_rows().await, 1);
        assert_eq!(first_entry.payload_hash, second_entry.payload_hash);
        vault_fixture
            .quarantine_vault
            .delete_quarantined_file(first_entry.entry_id)
            .await
            .expect("first deleted");
        assert_eq!(content_rows().await, 1);
        vault_fixture
            .quarantine_vault
            .restore_quarantined_file(second_entry.entry_id)
            .await
            .expect("second restored");
        assert_eq!(content_rows().await, 0);
    }

    #[tokio::test]
    async fn the_quarantine_schema_refuses_rows_that_cannot_exist() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        drop(open_fixture_vault(&temporary_root).await);
        let checked_connection =
            rusqlite::Connection::open(VaultFixture::database_path(&temporary_root))
                .expect("sqlite connection");
        let valid_sha256 = sha256_text(b"valid");
        checked_connection
            .execute_batch(&format!(
                "PRAGMA foreign_keys = ON;
                 INSERT INTO file_contents VALUES ('{valid_sha256}', 5);
                 INSERT INTO quarantine VALUES (1, CAST('/a' AS BLOB), CAST('/q/a' AS BLOB), \
                 '{valid_sha256}', '2026-11-04T12:00:00.000Z', 420);
                 INSERT INTO quarantine_pending VALUES (CAST('/q/b' AS BLOB), CAST('/b' AS BLOB), \
                 5, 420);"
            ))
            .expect("valid rows");
        [
            "INSERT INTO file_contents VALUES ('', 5)".to_owned(),
            format!(
                "INSERT INTO file_contents VALUES ('{}', 5)",
                valid_sha256.to_uppercase()
            ),
            format!(
                "INSERT INTO file_contents VALUES ('{}', -1)",
                sha256_text(b"other")
            ),
            format!(
                "INSERT INTO quarantine VALUES (2, CAST('/c' AS BLOB), CAST('/q/c' AS BLOB), \
                 '{}', '2026-11-04T12:00:00.000Z', 420)",
                sha256_text(b"missing")
            ),
            format!(
                "INSERT INTO quarantine VALUES (2, CAST('/c' AS BLOB), CAST('/q/a' AS BLOB), \
                 '{valid_sha256}', '2026-11-04T12:00:00.000Z', 420)"
            ),
            format!(
                "INSERT INTO quarantine VALUES (2, CAST('/c' AS BLOB), CAST('/q/c' AS BLOB), \
                 '{valid_sha256}', 'yesterday', 420)"
            ),
            format!(
                "INSERT INTO quarantine VALUES (2, CAST('/c' AS BLOB), CAST('/q/c' AS BLOB), \
                 '{valid_sha256}', '2026-11-04T12:00:00.000Z', 3565)"
            ),
            "INSERT INTO quarantine_signatures VALUES (9, 'Orphan.Signature')".to_owned(),
            "INSERT INTO pending_payload_hashes VALUES (CAST('/q/b' AS BLOB), '')".to_owned(),
            format!(
                "INSERT INTO pending_payload_hashes VALUES (CAST('/q/z' AS BLOB), \
                 '{valid_sha256}')"
            ),
            "INSERT INTO pending_signatures VALUES (CAST('/q/z' AS BLOB), 'Orphan')".to_owned(),
            "INSERT INTO quarantine_pending VALUES (CAST('/q/d' AS BLOB), CAST('/d' AS BLOB), -1, \
             420)"
                .to_owned(),
        ]
        .into_iter()
        .for_each(|invalid_insert| {
            assert!(
                checked_connection.execute(&invalid_insert, []).is_err(),
                "accepted: {invalid_insert}"
            );
        });
        checked_connection
            .execute("DELETE FROM quarantine_pending", [])
            .expect("pending removed");
        assert!(
            checked_connection
                .execute(
                    &format!("DELETE FROM file_contents WHERE content_sha256 = '{valid_sha256}'"),
                    []
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn quarantines_and_restores_with_hash_permissions_and_secure_payload_modes() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("infected.bin", b"malicious bytes");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o755)).expect("mode");

        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("quarantined");
        assert!(!source_path.exists());
        assert_eq!(
            stored_plaintext(&entry_record.quarantine_path),
            b"malicious bytes"
        );
        assert_eq!(
            fs::metadata(&entry_record.quarantine_path)
                .expect("payload metadata")
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(VaultFixture::quarantine_directory(
                &vault_fixture.temporary_root
            ))
            .expect("directory metadata")
            .permissions()
            .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            entry_record.payload_hash,
            RecordedPayloadHash::KnownSha256 {
                sha256_hex: sha256_text(b"malicious bytes")
            }
        );

        vault_fixture
            .quarantine_vault
            .restore_quarantined_file(entry_record.entry_id)
            .await
            .expect("restored");
        assert_eq!(
            fs::read(&source_path).expect("restored"),
            b"malicious bytes"
        );
        assert_eq!(
            fs::metadata(&source_path)
                .expect("restored metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(!entry_record.quarantine_path.exists());
        assert!(
            vault_fixture
                .quarantine_vault
                .list_quarantine_entries()
                .await
                .expect("listed")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn on_access_blocks_are_stored_without_a_signature_row_and_read_back() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("blocked.bin", b"blocked bytes");
        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &ThreatIdentity::BlockedByOnAccess)
            .await
            .expect("quarantined");
        assert_eq!(
            entry_record.threat_identity,
            ThreatIdentity::BlockedByOnAccess
        );
        let signature_rows: i64 =
            rusqlite::Connection::open(VaultFixture::database_path(&vault_fixture.temporary_root))
                .expect("sqlite connection")
                .query_row(
                    "SELECT COUNT(*) FROM quarantine_signatures WHERE entry_id = ?1",
                    params![entry_record.entry_id],
                    |stored_row| stored_row.get(0),
                )
                .expect("signature rows");
        assert_eq!(signature_rows, 0);
    }

    #[tokio::test]
    async fn non_utf8_original_paths_round_trip_through_the_database() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture
            .temporary_root
            .path()
            .join(OsString::from_vec(b"restored-\xff.bin".to_vec()));
        fs::write(&source_path, b"legacy bytes").expect("source");
        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Legacy.Signature"))
            .await
            .expect("quarantined");
        assert_eq!(entry_record.original_path, source_path);
        vault_fixture
            .quarantine_vault
            .restore_quarantined_file(entry_record.entry_id)
            .await
            .expect("restored");
        assert_eq!(
            source_path.file_name().expect("file name").as_bytes(),
            b"restored-\xff.bin"
        );
        assert_eq!(fs::read(&source_path).expect("restored"), b"legacy bytes");
    }

    #[tokio::test]
    async fn hash_tampering_blocks_restore_and_preserves_the_payload() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("infected.bin", b"original payload");
        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("quarantined");
        fs::set_permissions(
            &entry_record.quarantine_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("payload mode");
        fs::write(&entry_record.quarantine_path, b"tampered payload").expect("tamper");

        let restore_outcome = vault_fixture
            .quarantine_vault
            .restore_quarantined_file(entry_record.entry_id)
            .await;
        assert!(matches!(
            restore_outcome,
            Err(QuarantineMoveFailure::FileHashMismatch)
        ));
        assert!(!source_path.exists());
        assert_eq!(
            stored_plaintext(&entry_record.quarantine_path),
            b"tampered payload"
        );
        assert_eq!(
            vault_fixture
                .quarantine_vault
                .list_quarantine_entries()
                .await
                .expect("listed"),
            vec![entry_record]
        );
    }

    #[tokio::test]
    async fn verified_reads_return_the_original_bytes_and_leave_the_entry_in_place() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("sample.bin", b"sample payload");
        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("quarantined");
        let verified_payload = vault_fixture
            .quarantine_vault
            .read_verified_payload(entry_record.entry_id, ByteSize::mib(1))
            .await
            .expect("verified read");
        assert_eq!(verified_payload.payload_bytes, b"sample payload");
        assert_eq!(
            verified_payload.content_sha256,
            sha256_text(b"sample payload")
        );
        assert!(entry_record.quarantine_path.exists());
        assert!(!source_path.exists());
        assert!(matches!(
            vault_fixture
                .quarantine_vault
                .read_verified_payload(entry_record.entry_id, ByteSize::b(4))
                .await,
            Err(QuarantineMoveFailure::PayloadTooLargeToSend { .. })
        ));
    }

    #[tokio::test]
    async fn verified_reads_refuse_tampered_and_unhashed_payloads() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("tampered.bin", b"original payload");
        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("quarantined");
        fs::set_permissions(
            &entry_record.quarantine_path,
            fs::Permissions::from_mode(0o600),
        )
        .expect("payload mode");
        fs::write(&entry_record.quarantine_path, b"tampered payload").expect("tamper");
        assert!(matches!(
            vault_fixture
                .quarantine_vault
                .read_verified_payload(entry_record.entry_id, ByteSize::mib(1))
                .await,
            Err(QuarantineMoveFailure::FileHashMismatch)
        ));

        let temporary_root = tempfile::tempdir().expect("temporary root");
        drop(open_fixture_vault(&temporary_root).await);
        let payload_path =
            VaultFixture::quarantine_directory(&temporary_root).join("unhashed-payload");
        fs::write(&payload_path, b"unhashed payload").expect("payload");
        insert_tampered_entry(
            &temporary_root,
            Path::new("/home/user/unhashed.bin"),
            &payload_path,
            16,
        );
        let unhashed_vault = open_fixture_vault(&temporary_root).await;
        let unhashed_entry = unhashed_vault
            .list_quarantine_entries()
            .await
            .expect("listed")
            .remove(0);
        assert!(matches!(
            unhashed_vault
                .read_verified_payload(unhashed_entry.entry_id, ByteSize::mib(1))
                .await,
            Err(QuarantineMoveFailure::UploadRefusedIntegrityUnknown)
        ));
    }

    #[tokio::test]
    async fn restore_never_overwrites_an_existing_file_or_destination_symlink() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("infected.bin", b"quarantined payload");
        let victim_path = vault_fixture.source_file("victim.txt", b"do not touch");
        let entry_record = vault_fixture
            .quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("quarantined");
        symlink(&victim_path, &source_path).expect("destination symlink");

        let restore_outcome = vault_fixture
            .quarantine_vault
            .restore_quarantined_file(entry_record.entry_id)
            .await;
        assert!(matches!(
            restore_outcome,
            Err(QuarantineMoveFailure::SystemCallFailed(
                rustix::io::Errno::EXIST
            ))
        ));
        assert_eq!(fs::read(&victim_path).expect("victim"), b"do not touch");
        assert!(entry_record.quarantine_path.exists());
    }

    #[tokio::test]
    async fn rejects_source_symlinks_without_touching_their_targets() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let target_path = vault_fixture.source_file("target.bin", b"target bytes");
        let link_path = vault_fixture
            .temporary_root
            .path()
            .join("infected-link.bin");
        symlink(&target_path, &link_path).expect("source symlink");

        assert!(
            vault_fixture
                .quarantine_vault
                .move_file_into_quarantine(&link_path, &signature_identity("Test.Signature"))
                .await
                .is_err()
        );
        assert_eq!(fs::read(&target_path).expect("target"), b"target bytes");
        assert!(
            link_path
                .symlink_metadata()
                .expect("link metadata")
                .file_type()
                .is_symlink()
        );
    }

    #[tokio::test]
    async fn restore_masks_tampered_permission_bits_before_creating_the_destination() {
        let VaultFixture {
            temporary_root,
            quarantine_vault,
        } = VaultFixture::open_fixture().await;
        let source_path = temporary_root.path().join("permission-mask.bin");
        fs::write(&source_path, b"payload").expect("source");
        let entry_record = quarantine_vault
            .move_file_into_quarantine(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("quarantined");
        drop(quarantine_vault);
        let sqlite_connection =
            rusqlite::Connection::open(VaultFixture::database_path(&temporary_root))
                .expect("sqlite connection");
        sqlite_connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .expect("ignore checks");
        sqlite_connection
            .execute(
                "UPDATE quarantine SET original_permissions = 3565 WHERE entry_id = ?1",
                [entry_record.entry_id],
            )
            .expect("tamper permissions");
        drop(sqlite_connection);

        let reopened_vault = open_fixture_vault(&temporary_root).await;
        reopened_vault
            .restore_quarantined_file(entry_record.entry_id)
            .await
            .expect("restored");
        assert_eq!(
            fs::metadata(source_path)
                .expect("restored metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }

    #[tokio::test]
    async fn startup_reconciles_durable_pending_intent_only_when_original_is_confirmed_missing() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let original_path = temporary_root.path().join("lost-before-finalize.bin");
        let quarantine_directory = VaultFixture::quarantine_directory(&temporary_root);
        let payload_path = quarantine_directory.join("pending-payload");
        fs::create_dir_all(&quarantine_directory).expect("quarantine directory");
        fs::write(&payload_path, b"pending payload").expect("payload");
        seed_pending_row(
            &temporary_root,
            &payload_path,
            &original_path,
            SeededPendingHash::Hashed {
                sha256_hex: &sha256_text(b"pending payload"),
            },
        );

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        let listed_entries = quarantine_vault
            .list_quarantine_entries()
            .await
            .expect("listed");
        assert_eq!(listed_entries.len(), 1);
        assert_eq!(listed_entries[0].quarantine_path, payload_path);
        assert_eq!(pending_row_count(&temporary_root), 0);
    }

    #[tokio::test]
    async fn startup_preserves_pending_payload_when_an_original_replacement_exists() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let original_path = temporary_root.path().join("replacement.bin");
        let quarantine_directory = VaultFixture::quarantine_directory(&temporary_root);
        let payload_path = quarantine_directory.join("pending-replacement");
        fs::create_dir_all(&quarantine_directory).expect("quarantine directory");
        fs::write(&original_path, b"replacement").expect("replacement");
        fs::write(&payload_path, b"pending payload").expect("payload");
        seed_pending_row(
            &temporary_root,
            &payload_path,
            &original_path,
            SeededPendingHash::Hashed {
                sha256_hex: &sha256_text(b"pending payload"),
            },
        );

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        assert!(
            quarantine_vault
                .list_quarantine_entries()
                .await
                .expect("listed")
                .is_empty()
        );
        assert_eq!(fs::read(&original_path).expect("original"), b"replacement");
        assert_eq!(
            fs::read(&payload_path).expect("payload"),
            b"pending payload"
        );
        assert_eq!(pending_row_count(&temporary_root), 1);
    }

    #[tokio::test]
    async fn startup_preserves_an_unverified_pending_payload_for_manual_recovery() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let original_path = temporary_root.path().join("missing-original.bin");
        let quarantine_directory = VaultFixture::quarantine_directory(&temporary_root);
        let payload_path = quarantine_directory.join("unverified-pending");
        fs::create_dir_all(&quarantine_directory).expect("quarantine directory");
        fs::write(&payload_path, b"payload changed after crash").expect("payload");
        seed_pending_row(
            &temporary_root,
            &payload_path,
            &original_path,
            SeededPendingHash::TamperedHash {
                stored_text: "not-a-valid-hash",
            },
        );

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        assert!(
            quarantine_vault
                .list_quarantine_entries()
                .await
                .expect("listed")
                .is_empty()
        );
        assert!(payload_path.exists());
        assert_eq!(pending_row_count(&temporary_root), 1);
    }

    #[tokio::test]
    async fn failed_recording_restores_the_file_to_its_original_location() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("rollback.bin", b"rollback payload");
        let recorded_payload = vault_fixture
            .quarantine_vault
            .copy_record_and_remove_source(&source_path, &signature_identity("Test.Signature"))
            .await
            .expect("copied and recorded");
        assert!(!source_path.exists());
        let recording_failure = vault_fixture
            .quarantine_vault
            .roll_back_recording_failure(
                &recorded_payload,
                QuarantineMoveFailure::EntryRecordNotRemoved,
            )
            .await;
        assert!(matches!(
            recording_failure,
            QuarantineMoveFailure::RecordingFailedFileRestored { .. }
        ));
        assert_eq!(
            fs::read(&source_path).expect("restored"),
            b"rollback payload"
        );
        assert_eq!(pending_row_count(&vault_fixture.temporary_root), 0);
    }

    #[tokio::test]
    async fn blocked_source_is_renamed_recorded_and_restorable() {
        let vault_fixture = VaultFixture::open_fixture().await;
        let source_path = vault_fixture.source_file("blocked.bin", b"blocked payload");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o640)).expect("mode");
        let recorded_payload = vault_fixture
            .quarantine_vault
            .rename_and_record_blocked_source(&source_path, &signature_identity("Blocked.Test"))
            .await
            .expect("renamed");
        assert!(!source_path.exists());
        assert_eq!(recorded_payload.sha256_hex, sha256_text(b"blocked payload"));
        assert_eq!(
            fs::metadata(&recorded_payload.destination_path)
                .expect("payload metadata")
                .permissions()
                .mode()
                & 0o777,
            0o400
        );
        let entry_id = vault_fixture
            .quarantine_vault
            .commit_quarantine_entry(&recorded_payload, &signature_identity("Blocked.Test"))
            .await
            .expect("committed");
        assert_eq!(pending_row_count(&vault_fixture.temporary_root), 0);
        vault_fixture
            .quarantine_vault
            .restore_quarantined_file(entry_id)
            .await
            .expect("restored");
        assert_eq!(
            fs::read(&source_path).expect("restored"),
            b"blocked payload"
        );
        assert_eq!(
            fs::metadata(&source_path)
                .expect("restored metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    #[tokio::test]
    async fn startup_recovers_a_blocked_rename_interrupted_before_commit() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let original_path = temporary_root.path().join("renamed-before-commit.bin");
        let quarantine_directory = VaultFixture::quarantine_directory(&temporary_root);
        let payload_path = quarantine_directory.join("renamed-payload");
        fs::create_dir_all(&quarantine_directory).expect("quarantine directory");
        fs::write(&payload_path, b"pending payload").expect("payload");
        seed_pending_row(
            &temporary_root,
            &payload_path,
            &original_path,
            SeededPendingHash::NotYetHashed,
        );

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        let listed_entries = quarantine_vault
            .list_quarantine_entries()
            .await
            .expect("listed");
        assert_eq!(listed_entries.len(), 1);
        assert_eq!(
            listed_entries[0].payload_hash,
            RecordedPayloadHash::KnownSha256 {
                sha256_hex: sha256_text(b"pending payload")
            }
        );
        assert_eq!(pending_row_count(&temporary_root), 0);

        quarantine_vault
            .restore_quarantined_file(listed_entries[0].entry_id)
            .await
            .expect("restored");
        assert_eq!(
            fs::read(&original_path).expect("restored"),
            b"pending payload"
        );
    }

    #[tokio::test]
    async fn tampered_entry_without_a_usable_hash_stays_listed_and_is_never_restored() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        drop(open_fixture_vault(&temporary_root).await);
        let original_path = temporary_root.path().join("legacy-unhashed.bin");
        let payload_path =
            VaultFixture::quarantine_directory(&temporary_root).join("legacy-unhashed-payload");
        fs::write(&payload_path, b"legacy unhashed payload").expect("payload");
        insert_tampered_entry(&temporary_root, &original_path, &payload_path, 23);

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        let listed_entries = quarantine_vault
            .list_quarantine_entries()
            .await
            .expect("listed");
        assert_eq!(listed_entries.len(), 1);
        assert_eq!(
            listed_entries[0].payload_hash,
            RecordedPayloadHash::IntegrityUnknown
        );
        assert_ne!(
            fs::read(&payload_path).expect("payload"),
            b"legacy unhashed payload"
        );
        assert_eq!(stored_plaintext(&payload_path), b"legacy unhashed payload");

        let restore_outcome = quarantine_vault
            .restore_quarantined_file(listed_entries[0].entry_id)
            .await;
        assert!(matches!(
            restore_outcome,
            Err(QuarantineMoveFailure::RestoreRefusedIntegrityUnknown)
        ));
        assert!(!original_path.exists());
        assert!(payload_path.exists());
        assert_eq!(
            quarantine_vault
                .list_quarantine_entries()
                .await
                .expect("listed"),
            listed_entries
        );

        quarantine_vault
            .delete_quarantined_file(listed_entries[0].entry_id)
            .await
            .expect("deleted");
        assert!(!payload_path.exists());
    }

    #[tokio::test]
    async fn startup_discards_a_blocked_rename_interrupted_before_moving() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let original_path = temporary_root.path().join("not-yet-renamed.bin");
        let quarantine_directory = VaultFixture::quarantine_directory(&temporary_root);
        fs::create_dir_all(&quarantine_directory).expect("quarantine directory");
        let payload_path = quarantine_directory.join("never-written");
        fs::write(&original_path, b"still in place").expect("original");
        seed_pending_row(
            &temporary_root,
            &payload_path,
            &original_path,
            SeededPendingHash::NotYetHashed,
        );

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        assert!(
            quarantine_vault
                .list_quarantine_entries()
                .await
                .expect("listed")
                .is_empty()
        );
        assert_eq!(
            fs::read(&original_path).expect("original"),
            b"still in place"
        );
        assert_eq!(pending_row_count(&temporary_root), 0);
    }

    #[tokio::test]
    async fn sigkill_between_source_removal_and_commit_recovers_the_entry() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let source_path = temporary_root.path().join("crash.bin");
        fs::write(&source_path, b"crash payload").expect("source");
        let crash_status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "--ignored",
                "host_services::quarantine_vault::quarantine_entry_database::quarantine_entry_database_tests::crash_helper_stops_before_commit",
            ])
            .env("CRASH_HELPER_ROOT", temporary_root.path())
            .status()
            .expect("crash helper");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&crash_status),
            Some(9),
            "helper must die by SIGKILL"
        );
        assert!(!source_path.exists());
        assert_eq!(pending_row_count(&temporary_root), 1);

        let quarantine_vault = open_fixture_vault(&temporary_root).await;
        let listed_entries = quarantine_vault
            .list_quarantine_entries()
            .await
            .expect("listed");
        assert_eq!(listed_entries.len(), 1);
        assert_eq!(listed_entries[0].original_path, source_path);
        assert_eq!(
            stored_plaintext(&listed_entries[0].quarantine_path),
            b"crash payload"
        );
        assert_eq!(pending_row_count(&temporary_root), 0);
        drop(quarantine_vault);

        let integrity_report: String =
            rusqlite::Connection::open(VaultFixture::database_path(&temporary_root))
                .expect("sqlite connection")
                .query_row("PRAGMA integrity_check", [], |report_row| report_row.get(0))
                .expect("integrity check");
        assert_eq!(integrity_report, "ok");
    }

    #[tokio::test]
    #[ignore = "run only as a child of the SIGKILL recovery test"]
    async fn crash_helper_stops_before_commit() {
        let crash_root = PathBuf::from(std::env::var_os("CRASH_HELPER_ROOT").expect("crash root"));
        let quarantine_vault = QuarantineVault::open_vault(
            crash_root.join("data/quarantine.db"),
            crash_root.join("data/quarantine"),
        )
        .await
        .expect("opened vault");
        let _recorded_payload = quarantine_vault
            .copy_record_and_remove_source(
                &crash_root.join("crash.bin"),
                &signature_identity("Crash.Test"),
            )
            .await
            .expect("copied and recorded");
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL)
            .expect("self kill");
    }
}
