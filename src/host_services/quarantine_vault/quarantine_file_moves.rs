use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use bytesize::ByteSize;
use rustix::{
    fs::{AtFlags, Mode, OFlags, RenameFlags},
    io::Errno,
};
use sha2::{Digest, Sha256};

use crate::host_services::quarantine_vault::quarantine_payload_format::{
    PayloadEncoding, PayloadWriter, PlaintextReader, fresh_scrambling_key, open_plaintext_reader,
};

const DATABASE_FILE_MODE: u32 = 0o600;
const QUARANTINE_DIRECTORY_MODE: u32 = 0o700;
const QUARANTINE_FILE_MODE: u32 = 0o400;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const FREE_SPACE_RESERVE: ByteSize = ByteSize::mib(10);
const MAXIMUM_FILE_NAME_LENGTH: usize = 255;
const QUARANTINE_NAME_PREFIX_LENGTH: usize = 17;
pub const UNKNOWN_PAYLOAD_HASH: &str = "";
const PROTECTED_RESTORE_ROOTS: &[&str] = &[
    "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/root", "/sys", "/proc",
];

#[derive(Debug, thiserror::Error)]
pub enum QuarantineMoveFailure {
    #[error("system call failed: {0}")]
    SystemCallFailed(#[from] Errno),
    #[error("file operation failed: {0}")]
    FileOperationFailed(#[from] io::Error),
    #[error("quarantine database operation failed: {0}")]
    DatabaseOperationFailed(#[from] turso::Error),
    #[error("a background quarantine step stopped unexpectedly: {0}")]
    BlockingStepInterrupted(#[from] tokio::task::JoinError),
    #[error("the path contains a NUL byte")]
    PathContainsNul,
    #[error("the path has no parent directory")]
    PathHasNoParent,
    #[error("the path has no file name")]
    PathHasNoFileName,
    #[error("the database path is not valid UTF-8")]
    DatabasePathNotUtf8,
    #[error("the quarantine database is not a regular file")]
    DatabaseNotRegularFile,
    #[error("on-access scanning blocks reading the source file")]
    SourceBlockedByOnAccess,
    #[error("the blocked file is on another filesystem, so it cannot be moved without reading it")]
    BlockedFileOnOtherFilesystem,
    #[error("the blocked file is still unreadable after moving it to quarantine")]
    MovedPayloadStillBlocked,
    #[error("the source is not a regular file")]
    SourceNotRegularFile,
    #[error("the quarantined path is not a regular file")]
    PayloadNotRegularFile,
    #[error("not enough free space to quarantine the file")]
    NotEnoughFreeSpace,
    #[error("the file was replaced during the operation; refusing to unlink it")]
    FileReplacedDuringOperation,
    #[error("the file hash does not match its quarantine record")]
    FileHashMismatch,
    #[error("the path is not inside the quarantine directory")]
    PathOutsideQuarantine,
    #[error("the restore path is invalid")]
    InvalidRestorePath,
    #[error("restoring to a protected system directory is not allowed")]
    ProtectedRestoreDestination,
    #[error("quarantine entry {entry_id} was not found")]
    EntryNotFound { entry_id: i64 },
    #[error("stored path column {column_index} is neither BLOB nor TEXT")]
    StoredPathUnreadable { column_index: usize },
    #[error("recording the entry failed and the file was restored: {recording_failure}")]
    RecordingFailedFileRestored {
        recording_failure: Box<QuarantineMoveFailure>,
    },
    #[error(
        "recording the entry failed ({recording_failure}) and rollback failed \
         ({rollback_failure}); the file may be orphaned at {payload_path:?}"
    )]
    RecordingFailedRollbackFailed {
        recording_failure: Box<QuarantineMoveFailure>,
        rollback_failure: Box<QuarantineMoveFailure>,
        payload_path: PathBuf,
    },
    #[error("the file was removed from quarantine but its record could not be removed")]
    EntryRecordNotRemoved,
}

pub struct PinnedParentDirectory {
    parent_directory: File,
    entry_name: CString,
}

pub struct CopiedQuarantinePayload {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub file_size: ByteSize,
    pub file_hash: String,
    pub original_permissions: u32,
    source_parent: PinnedParentDirectory,
    source_metadata: fs::Metadata,
    destination_parent: PinnedParentDirectory,
}

fn path_as_c_string(raw_path: &OsStr) -> Result<CString, QuarantineMoveFailure> {
    CString::new(raw_path.as_bytes()).map_err(|_nul_error| QuarantineMoveFailure::PathContainsNul)
}

pub fn open_absolute_path(
    file_path: &Path,
    open_flags: OFlags,
    file_mode: u32,
) -> Result<File, QuarantineMoveFailure> {
    Ok(File::from(rustix::fs::open(
        file_path,
        open_flags | OFlags::CLOEXEC,
        Mode::from_bits_truncate(file_mode),
    )?))
}

fn open_relative_entry(
    parent_directory: &File,
    entry_name: &CStr,
    open_flags: OFlags,
    file_mode: u32,
) -> Result<File, QuarantineMoveFailure> {
    Ok(File::from(rustix::fs::openat(
        parent_directory,
        entry_name,
        open_flags | OFlags::CLOEXEC,
        Mode::from_bits_truncate(file_mode),
    )?))
}

fn change_file_mode(open_file: &File, file_mode: u32) -> Result<(), QuarantineMoveFailure> {
    Ok(rustix::fs::fchmod(
        open_file,
        Mode::from_bits_truncate(file_mode),
    )?)
}

fn unlink_relative_entry(
    parent_directory: &File,
    entry_name: &CStr,
) -> Result<(), QuarantineMoveFailure> {
    Ok(rustix::fs::unlinkat(
        parent_directory,
        entry_name,
        AtFlags::empty(),
    )?)
}

pub fn pin_parent_directory(
    file_path: &Path,
) -> Result<PinnedParentDirectory, QuarantineMoveFailure> {
    let parent_path = file_path
        .parent()
        .ok_or(QuarantineMoveFailure::PathHasNoParent)?;
    let parent_directory = open_absolute_path(
        parent_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        0,
    )?;
    let entry_name = path_as_c_string(
        file_path
            .file_name()
            .ok_or(QuarantineMoveFailure::PathHasNoFileName)?,
    )?;
    Ok(PinnedParentDirectory {
        parent_directory,
        entry_name,
    })
}

fn ensure_entry_identity(
    pinned_parent: &PinnedParentDirectory,
    pinned_metadata: &fs::Metadata,
) -> Result<(), QuarantineMoveFailure> {
    let current_entry = rustix::fs::statat(
        &pinned_parent.parent_directory,
        pinned_parent.entry_name.as_c_str(),
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    if current_entry.st_dev == pinned_metadata.dev()
        && current_entry.st_ino == pinned_metadata.ino()
    {
        Ok(())
    } else {
        Err(QuarantineMoveFailure::FileReplacedDuringOperation)
    }
}

pub fn ensure_quarantine_directory(
    quarantine_directory: &Path,
) -> Result<(), QuarantineMoveFailure> {
    fs::create_dir_all(quarantine_directory)?;
    let opened_directory = open_absolute_path(
        quarantine_directory,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        0,
    )?;
    change_file_mode(&opened_directory, QUARANTINE_DIRECTORY_MODE)
}

pub fn pin_database_file(database_path: &Path) -> Result<(), QuarantineMoveFailure> {
    if let Some(database_directory) = database_path.parent() {
        fs::create_dir_all(database_directory)?;
    }
    let database_file = open_absolute_path(
        database_path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW,
        DATABASE_FILE_MODE,
    )?;
    if !database_file.metadata()?.is_file() {
        return Err(QuarantineMoveFailure::DatabaseNotRegularFile);
    }
    change_file_mode(&database_file, DATABASE_FILE_MODE)
}

fn database_sidecar_path(database_path: &Path, sidecar_suffix: &[u8]) -> PathBuf {
    let raw_sidecar_path = [database_path.as_os_str().as_bytes(), sidecar_suffix].concat();
    PathBuf::from(OsString::from_vec(raw_sidecar_path))
}

pub fn secure_database_files(database_path: &Path) {
    [
        database_path.to_path_buf(),
        database_sidecar_path(database_path, b"-wal"),
        database_sidecar_path(database_path, b"-shm"),
    ]
    .iter()
    .for_each(|database_file_path| {
        if let Ok(database_file) =
            open_absolute_path(database_file_path, OFlags::RDONLY | OFlags::NOFOLLOW, 0)
        {
            let _unsupported_on_this_file = change_file_mode(&database_file, DATABASE_FILE_MODE);
        }
    });
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unique_quarantine_name(source_path: &Path) -> Vec<u8> {
    let mut random_prefix = [0_u8; 8];
    if File::open("/dev/urandom")
        .and_then(|mut random_source| random_source.read_exact(&mut random_prefix))
        .is_err()
    {
        random_prefix = current_unix_timestamp().to_le_bytes();
    }
    let source_name = source_path
        .file_name()
        .unwrap_or_else(|| OsStr::new("payload"))
        .as_bytes();
    let retained_length = source_name
        .len()
        .min(MAXIMUM_FILE_NAME_LENGTH - QUARANTINE_NAME_PREFIX_LENGTH);
    [
        hex::encode(random_prefix).as_bytes(),
        b"_",
        &source_name[..retained_length],
    ]
    .concat()
}

fn available_disk_space(directory_path: &Path) -> Result<ByteSize, QuarantineMoveFailure> {
    let filesystem_stats = rustix::fs::statvfs(directory_path)?;
    Ok(ByteSize::b(
        filesystem_stats
            .f_bavail
            .saturating_mul(filesystem_stats.f_frsize),
    ))
}

pub fn lexically_normalized_path(unnormalized_path: &Path) -> PathBuf {
    let absolute_path = if unnormalized_path.is_absolute() {
        unnormalized_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_missing_directory| PathBuf::from("/"))
            .join(unnormalized_path)
    };
    absolute_path
        .components()
        .fold(PathBuf::new(), |mut normalized_path, path_component| {
            match path_component {
                Component::RootDir => normalized_path.push("/"),
                Component::ParentDir => {
                    normalized_path.pop();
                }
                Component::Normal(path_part) => normalized_path.push(path_part),
                Component::CurDir | Component::Prefix(_) => {}
            }
            normalized_path
        })
}

fn copy_hash_and_sync(
    source_content: &mut impl Read,
    destination_file: &mut File,
    destination_mode: u32,
    payload_encoding: PayloadEncoding,
) -> Result<String, QuarantineMoveFailure> {
    let mut content_hash = Sha256::new();
    let mut copy_buffer = vec![0_u8; COPY_BUFFER_SIZE];
    let mut payload_writer = PayloadWriter::starting(&mut *destination_file, payload_encoding)?;
    loop {
        let read_length = source_content.read(&mut copy_buffer)?;
        if read_length == 0 {
            break;
        }
        content_hash.update(&copy_buffer[..read_length]);
        payload_writer.write_all(&copy_buffer[..read_length])?;
    }
    payload_writer.flush()?;
    destination_file.sync_all()?;
    change_file_mode(destination_file, destination_mode)?;
    Ok(format!("{:x}", content_hash.finalize()))
}

pub fn copy_file_into_quarantine(
    quarantine_directory: &Path,
    source_path: &Path,
) -> Result<CopiedQuarantinePayload, QuarantineMoveFailure> {
    ensure_quarantine_directory(quarantine_directory)?;
    let source_parent = pin_parent_directory(source_path)?;
    let mut source_file = open_relative_entry(
        &source_parent.parent_directory,
        &source_parent.entry_name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        0,
    )
    .map_err(|open_failure| match open_failure {
        QuarantineMoveFailure::SystemCallFailed(Errno::PERM) => {
            QuarantineMoveFailure::SourceBlockedByOnAccess
        }
        other_failure => other_failure,
    })?;
    let source_metadata = source_file.metadata()?;
    if !source_metadata.is_file() {
        return Err(QuarantineMoveFailure::SourceNotRegularFile);
    }
    let file_size = ByteSize::b(source_metadata.len());
    if available_disk_space(quarantine_directory)? < file_size + FREE_SPACE_RESERVE {
        return Err(QuarantineMoveFailure::NotEnoughFreeSpace);
    }
    let destination_path =
        quarantine_directory.join(OsString::from_vec(unique_quarantine_name(source_path)));
    let destination_parent = pin_parent_directory(&destination_path)?;
    let mut destination_file = open_relative_entry(
        &destination_parent.parent_directory,
        &destination_parent.entry_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        QUARANTINE_FILE_MODE,
    )?;
    let neutralized_encoding = PayloadEncoding::NeutralizedPayload {
        scrambling_key: fresh_scrambling_key()?,
    };
    let file_hash = match copy_hash_and_sync(
        &mut source_file,
        &mut destination_file,
        QUARANTINE_FILE_MODE,
        neutralized_encoding,
    ) {
        Ok(file_hash) => file_hash,
        Err(copy_failure) => {
            let _nothing_to_clean = unlink_relative_entry(
                &destination_parent.parent_directory,
                &destination_parent.entry_name,
            );
            return Err(copy_failure);
        }
    };
    drop(destination_file);
    destination_parent.parent_directory.sync_all()?;
    Ok(CopiedQuarantinePayload {
        source_path: source_path.to_path_buf(),
        destination_path,
        file_size,
        file_hash,
        original_permissions: source_metadata.mode() & 0o777,
        source_parent,
        source_metadata,
        destination_parent,
    })
}

pub struct PlannedBlockedRename {
    pub source_path: PathBuf,
    pub destination_path: PathBuf,
    pub file_size: ByteSize,
    pub original_permissions: u32,
    source_parent: PinnedParentDirectory,
    source_metadata: fs::Metadata,
    destination_parent: PinnedParentDirectory,
}

pub fn plan_blocked_file_rename(
    quarantine_directory: &Path,
    source_path: &Path,
) -> Result<PlannedBlockedRename, QuarantineMoveFailure> {
    ensure_quarantine_directory(quarantine_directory)?;
    let source_parent = pin_parent_directory(source_path)?;
    let source_handle = open_relative_entry(
        &source_parent.parent_directory,
        &source_parent.entry_name,
        OFlags::PATH | OFlags::NOFOLLOW,
        0,
    )?;
    let source_metadata = source_handle.metadata()?;
    if !source_metadata.is_file() {
        return Err(QuarantineMoveFailure::SourceNotRegularFile);
    }
    if fs::metadata(quarantine_directory)?.dev() != source_metadata.dev() {
        return Err(QuarantineMoveFailure::BlockedFileOnOtherFilesystem);
    }
    let destination_path =
        quarantine_directory.join(OsString::from_vec(unique_quarantine_name(source_path)));
    let destination_parent = pin_parent_directory(&destination_path)?;
    Ok(PlannedBlockedRename {
        source_path: source_path.to_path_buf(),
        destination_path,
        file_size: ByteSize::b(source_metadata.len()),
        original_permissions: source_metadata.mode() & 0o777,
        source_parent,
        source_metadata,
        destination_parent,
    })
}

fn rename_without_replacing(
    from_parent: &PinnedParentDirectory,
    to_parent: &PinnedParentDirectory,
) -> Result<(), QuarantineMoveFailure> {
    rustix::fs::renameat_with(
        &from_parent.parent_directory,
        from_parent.entry_name.as_c_str(),
        &to_parent.parent_directory,
        to_parent.entry_name.as_c_str(),
        RenameFlags::NOREPLACE,
    )
    .map_err(|rename_failure| match rename_failure {
        Errno::XDEV => QuarantineMoveFailure::BlockedFileOnOtherFilesystem,
        other_errno => QuarantineMoveFailure::SystemCallFailed(other_errno),
    })
}

fn hash_and_secure_renamed_payload(
    planned_rename: &PlannedBlockedRename,
) -> Result<String, QuarantineMoveFailure> {
    let destination_parent = &planned_rename.destination_parent;
    ensure_entry_identity(destination_parent, &planned_rename.source_metadata)?;
    let mut payload_file = open_relative_entry(
        &destination_parent.parent_directory,
        &destination_parent.entry_name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        0,
    )
    .map_err(|open_failure| match open_failure {
        QuarantineMoveFailure::SystemCallFailed(Errno::PERM) => {
            QuarantineMoveFailure::MovedPayloadStillBlocked
        }
        other_failure => other_failure,
    })?;
    let mut content_hash = Sha256::new();
    io::copy(&mut payload_file, &mut content_hash)?;
    change_file_mode(&payload_file, QUARANTINE_FILE_MODE)?;
    Ok(format!("{:x}", content_hash.finalize()))
}

pub fn rename_blocked_file_into_quarantine(
    planned_rename: &PlannedBlockedRename,
) -> Result<String, QuarantineMoveFailure> {
    ensure_entry_identity(
        &planned_rename.source_parent,
        &planned_rename.source_metadata,
    )?;
    rename_without_replacing(
        &planned_rename.source_parent,
        &planned_rename.destination_parent,
    )?;
    match hash_and_secure_renamed_payload(planned_rename) {
        Ok(file_hash) => {
            planned_rename
                .destination_parent
                .parent_directory
                .sync_all()?;
            planned_rename.source_parent.parent_directory.sync_all()?;
            Ok(file_hash)
        }
        Err(payload_failure) => {
            let _rollback_outcome = rename_without_replacing(
                &planned_rename.destination_parent,
                &planned_rename.source_parent,
            );
            Err(payload_failure)
        }
    }
}

pub fn discard_copied_payload(copied_payload: &CopiedQuarantinePayload) {
    let _nothing_to_clean = unlink_relative_entry(
        &copied_payload.destination_parent.parent_directory,
        &copied_payload.destination_parent.entry_name,
    );
}

pub fn remove_quarantined_source(
    copied_payload: &CopiedQuarantinePayload,
) -> Result<(), QuarantineMoveFailure> {
    ensure_entry_identity(
        &copied_payload.source_parent,
        &copied_payload.source_metadata,
    )?;
    unlink_relative_entry(
        &copied_payload.source_parent.parent_directory,
        &copied_payload.source_parent.entry_name,
    )?;
    copied_payload.source_parent.parent_directory.sync_all()?;
    Ok(())
}

fn validate_quarantine_path(
    quarantine_directory: &Path,
    payload_path: &Path,
) -> Result<(), QuarantineMoveFailure> {
    let quarantine_root = quarantine_directory.canonicalize()?;
    if payload_path.canonicalize()?.starts_with(quarantine_root) {
        Ok(())
    } else {
        Err(QuarantineMoveFailure::PathOutsideQuarantine)
    }
}

fn validate_restore_path(restore_path: &Path) -> Result<(), QuarantineMoveFailure> {
    let raw_path = restore_path.as_os_str().as_bytes();
    if raw_path.is_empty()
        || raw_path
            .iter()
            .any(|path_byte| matches!(path_byte, b'\n' | b'\r' | 0))
    {
        return Err(QuarantineMoveFailure::InvalidRestorePath);
    }
    let absolute_path = lexically_normalized_path(restore_path);
    let is_protected_path = |candidate_path: &Path| {
        PROTECTED_RESTORE_ROOTS
            .iter()
            .any(|protected_root| candidate_path.starts_with(protected_root))
    };
    if is_protected_path(&absolute_path) {
        return Err(QuarantineMoveFailure::ProtectedRestoreDestination);
    }
    absolute_path
        .ancestors()
        .filter(|ancestor_path| {
            fs::symlink_metadata(ancestor_path)
                .is_ok_and(|ancestor_metadata| ancestor_metadata.file_type().is_symlink())
        })
        .try_for_each(|symlink_ancestor| {
            if is_protected_path(&symlink_ancestor.canonicalize()?) {
                Err(QuarantineMoveFailure::ProtectedRestoreDestination)
            } else {
                Ok(())
            }
        })
}

fn open_restore_parent(
    destination_path: &Path,
) -> Result<PinnedParentDirectory, QuarantineMoveFailure> {
    if !destination_path.is_absolute() {
        return Err(QuarantineMoveFailure::InvalidRestorePath);
    }
    let path_parts = destination_path
        .components()
        .filter_map(|path_component| match path_component {
            Component::Normal(path_part) => Some(path_part),
            _other_component => None,
        })
        .collect::<Vec<_>>();
    let (entry_part, parent_parts) = path_parts
        .split_last()
        .ok_or(QuarantineMoveFailure::PathHasNoFileName)?;
    let root_directory = open_absolute_path(
        Path::new("/"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        0,
    )?;
    let parent_directory =
        parent_parts
            .iter()
            .try_fold(root_directory, |current_directory, parent_part| {
                open_or_create_child_directory(&current_directory, parent_part)
            })?;
    Ok(PinnedParentDirectory {
        parent_directory,
        entry_name: path_as_c_string(entry_part)?,
    })
}

fn open_or_create_child_directory(
    current_directory: &File,
    child_part: &OsStr,
) -> Result<File, QuarantineMoveFailure> {
    let child_name = path_as_c_string(child_part)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    match open_relative_entry(current_directory, &child_name, directory_flags, 0) {
        Err(QuarantineMoveFailure::SystemCallFailed(Errno::NOENT)) => {
            rustix::fs::mkdirat(
                current_directory,
                child_name.as_c_str(),
                Mode::from_bits_truncate(0o777),
            )?;
            open_relative_entry(current_directory, &child_name, directory_flags, 0)
        }
        open_result => open_result,
    }
}

pub fn restore_payload_file(
    quarantine_directory: &Path,
    payload_path: &Path,
    destination_path: &Path,
    original_permissions: u32,
    expected_hash: &str,
) -> Result<(), QuarantineMoveFailure> {
    validate_quarantine_path(quarantine_directory, payload_path)?;
    let destination_path = lexically_normalized_path(destination_path);
    validate_restore_path(&destination_path)?;
    let payload_parent = pin_parent_directory(payload_path)?;
    let payload_file = open_relative_entry(
        &payload_parent.parent_directory,
        &payload_parent.entry_name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        0,
    )?;
    let payload_metadata = payload_file.metadata()?;
    if !payload_metadata.is_file() {
        return Err(QuarantineMoveFailure::PayloadNotRegularFile);
    }
    let mut plaintext_reader = open_plaintext_reader(payload_file)?;
    let restore_parent = open_restore_parent(&destination_path)?;
    let restore_mode = original_permissions & 0o777;
    let mut restored_file = open_relative_entry(
        &restore_parent.parent_directory,
        &restore_parent.entry_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        restore_mode,
    )?;
    let restored_hash = match copy_hash_and_sync(
        &mut plaintext_reader,
        &mut restored_file,
        restore_mode,
        PayloadEncoding::RawPayload,
    ) {
        Ok(restored_hash) => restored_hash,
        Err(copy_failure) => {
            drop(restored_file);
            let _nothing_to_clean =
                unlink_relative_entry(&restore_parent.parent_directory, &restore_parent.entry_name);
            return Err(copy_failure);
        }
    };
    drop(restored_file);
    if restored_hash != expected_hash {
        let _nothing_to_clean =
            unlink_relative_entry(&restore_parent.parent_directory, &restore_parent.entry_name);
        return Err(QuarantineMoveFailure::FileHashMismatch);
    }
    restore_parent.parent_directory.sync_all()?;
    ensure_entry_identity(&payload_parent, &payload_metadata)?;
    unlink_relative_entry(&payload_parent.parent_directory, &payload_parent.entry_name)?;
    payload_parent.parent_directory.sync_all()?;
    Ok(())
}

pub fn delete_payload_file(
    quarantine_directory: &Path,
    payload_path: &Path,
) -> Result<(), QuarantineMoveFailure> {
    validate_quarantine_path(quarantine_directory, payload_path)?;
    let payload_parent = pin_parent_directory(payload_path)?;
    let payload_file = open_relative_entry(
        &payload_parent.parent_directory,
        &payload_parent.entry_name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        0,
    )?;
    let payload_metadata = payload_file.metadata()?;
    if !payload_metadata.is_file() {
        return Err(QuarantineMoveFailure::PayloadNotRegularFile);
    }
    change_file_mode(&payload_file, 0)?;
    ensure_entry_identity(&payload_parent, &payload_metadata)?;
    unlink_relative_entry(&payload_parent.parent_directory, &payload_parent.entry_name)?;
    payload_parent.parent_directory.sync_all()?;
    Ok(())
}

pub fn payload_content_hash(payload_path: &Path) -> Result<String, QuarantineMoveFailure> {
    let payload_file = open_absolute_path(payload_path, OFlags::RDONLY | OFlags::NOFOLLOW, 0)?;
    if !payload_file.metadata()?.is_file() {
        return Err(QuarantineMoveFailure::PayloadNotRegularFile);
    }
    change_file_mode(&payload_file, QUARANTINE_FILE_MODE)?;
    let mut content_hash = Sha256::new();
    io::copy(&mut open_plaintext_reader(payload_file)?, &mut content_hash)?;
    Ok(format!("{:x}", content_hash.finalize()))
}

pub fn open_payload_plaintext(
    quarantine_directory: &Path,
    payload_path: &Path,
) -> Result<PlaintextReader<File>, QuarantineMoveFailure> {
    validate_quarantine_path(quarantine_directory, payload_path)?;
    let payload_file = open_absolute_path(payload_path, OFlags::RDONLY | OFlags::NOFOLLOW, 0)?;
    if !payload_file.metadata()?.is_file() {
        return Err(QuarantineMoveFailure::PayloadNotRegularFile);
    }
    Ok(open_plaintext_reader(payload_file)?)
}

pub const NEUTRALIZING_NAME_PREFIX: &str = ".neutralizing-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NeutralizingOutcome {
    AlreadyNeutralized,
    NeutralizedNow,
}

pub fn neutralize_payload_in_place(
    quarantine_directory: &Path,
    payload_path: &Path,
    expected_hash: &str,
) -> Result<NeutralizingOutcome, QuarantineMoveFailure> {
    validate_quarantine_path(quarantine_directory, payload_path)?;
    let payload_parent = pin_parent_directory(payload_path)?;
    let payload_file = open_relative_entry(
        &payload_parent.parent_directory,
        &payload_parent.entry_name,
        OFlags::RDONLY | OFlags::NOFOLLOW,
        0,
    )?;
    let payload_metadata = payload_file.metadata()?;
    if !payload_metadata.is_file() {
        return Err(QuarantineMoveFailure::PayloadNotRegularFile);
    }
    let mut plaintext_reader = open_plaintext_reader(payload_file)?;
    if plaintext_reader.payload_encoding() != PayloadEncoding::RawPayload {
        return Ok(NeutralizingOutcome::AlreadyNeutralized);
    }
    let staged_name = path_as_c_string(OsStr::new(&format!(
        "{NEUTRALIZING_NAME_PREFIX}{}",
        hex::encode(fresh_scrambling_key()?)
    )))?;
    let mut staged_file = open_relative_entry(
        &payload_parent.parent_directory,
        &staged_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
        QUARANTINE_FILE_MODE,
    )?;
    let discard_staged = || {
        let _nothing_to_clean =
            unlink_relative_entry(&payload_parent.parent_directory, &staged_name);
    };
    let staged_hash = match copy_hash_and_sync(
        &mut plaintext_reader,
        &mut staged_file,
        QUARANTINE_FILE_MODE,
        PayloadEncoding::NeutralizedPayload {
            scrambling_key: fresh_scrambling_key()?,
        },
    ) {
        Ok(staged_hash) => staged_hash,
        Err(copy_failure) => {
            discard_staged();
            return Err(copy_failure);
        }
    };
    drop(staged_file);
    if expected_hash != UNKNOWN_PAYLOAD_HASH && staged_hash != expected_hash {
        discard_staged();
        return Err(QuarantineMoveFailure::FileHashMismatch);
    }
    if let Err(replaced_failure) = ensure_entry_identity(&payload_parent, &payload_metadata) {
        discard_staged();
        return Err(replaced_failure);
    }
    rustix::fs::renameat(
        &payload_parent.parent_directory,
        staged_name.as_c_str(),
        &payload_parent.parent_directory,
        payload_parent.entry_name.as_c_str(),
    )?;
    payload_parent.parent_directory.sync_all()?;
    Ok(NeutralizingOutcome::NeutralizedNow)
}

pub fn remove_stale_neutralizing_copies(quarantine_directory: &Path) {
    let Ok(directory_entries) = fs::read_dir(quarantine_directory) else {
        return;
    };
    directory_entries
        .filter_map(Result::ok)
        .filter(|directory_entry| {
            directory_entry
                .file_name()
                .as_bytes()
                .starts_with(NEUTRALIZING_NAME_PREFIX.as_bytes())
        })
        .for_each(|stale_entry| {
            let _already_gone = fs::remove_file(stale_entry.path());
        });
}

#[cfg(test)]
mod quarantine_file_moves_tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn stored_plaintext(payload_path: &Path) -> Vec<u8> {
        let mut plaintext = Vec::new();
        crate::host_services::quarantine_vault::quarantine_payload_format::open_plaintext_reader(
            std::fs::File::open(payload_path).expect("payload"),
        )
        .expect("payload reader")
        .read_to_end(&mut plaintext)
        .expect("plaintext");
        plaintext
    }

    #[test]
    fn pinned_payload_parent_cannot_be_redirected_before_unlink() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let mutable_ancestor = temporary_root.path().join("a/swap");
        let payload_path = mutable_ancestor.join("quarantine/payload");
        let victim_root = temporary_root.path().join("victim/quarantine");
        fs::create_dir_all(payload_path.parent().expect("payload parent")).expect("payload root");
        fs::create_dir_all(&victim_root).expect("victim root");
        fs::write(&payload_path, b"quarantine payload").expect("payload");
        let victim_file = victim_root.join("payload");
        fs::write(&victim_file, b"must not be deleted").expect("victim");

        let payload_parent = pin_parent_directory(&payload_path).expect("pinned parent");
        let payload_file = open_relative_entry(
            &payload_parent.parent_directory,
            &payload_parent.entry_name,
            OFlags::RDONLY | OFlags::NOFOLLOW,
            0,
        )
        .expect("payload file");
        let payload_metadata = payload_file.metadata().expect("metadata");
        let moved_ancestor = temporary_root.path().join("a/swap-original");
        fs::rename(&mutable_ancestor, &moved_ancestor).expect("rename ancestor");
        symlink(temporary_root.path().join("victim"), &mutable_ancestor).expect("symlink");

        ensure_entry_identity(&payload_parent, &payload_metadata).expect("identity");
        unlink_relative_entry(&payload_parent.parent_directory, &payload_parent.entry_name)
            .expect("unlink");
        assert!(!moved_ancestor.join("quarantine/payload").exists());
        assert_eq!(
            fs::read(victim_file).expect("victim bytes"),
            b"must not be deleted"
        );
    }

    #[test]
    fn replaced_source_is_not_unlinked() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let quarantine_directory = temporary_root.path().join("quarantine");
        let source_path = temporary_root.path().join("infected.bin");
        fs::write(&source_path, b"original").expect("source");
        let copied_payload =
            copy_file_into_quarantine(&quarantine_directory, &source_path).expect("copied");
        fs::remove_file(&source_path).expect("remove source");
        fs::write(&source_path, b"replacement").expect("replacement");
        assert!(matches!(
            remove_quarantined_source(&copied_payload),
            Err(QuarantineMoveFailure::FileReplacedDuringOperation)
        ));
        assert_eq!(
            fs::read(&source_path).expect("source bytes"),
            b"replacement"
        );
    }

    #[test]
    fn maximum_length_filenames_can_be_quarantined() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let quarantine_directory = temporary_root.path().join("quarantine");
        let source_path = temporary_root
            .path()
            .join("a".repeat(MAXIMUM_FILE_NAME_LENGTH));
        fs::write(&source_path, b"long name").expect("source");
        let copied_payload =
            copy_file_into_quarantine(&quarantine_directory, &source_path).expect("copied");
        assert_eq!(
            stored_plaintext(&copied_payload.destination_path),
            b"long name"
        );
    }

    #[test]
    fn blocked_rename_refuses_symlinks_and_replaced_files() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let quarantine_directory = temporary_root.path().join("quarantine");
        let target_path = temporary_root.path().join("target.bin");
        let link_path = temporary_root.path().join("link.bin");
        fs::write(&target_path, b"target").expect("target");
        symlink(&target_path, &link_path).expect("symlink");
        assert!(plan_blocked_file_rename(&quarantine_directory, &link_path).is_err());

        let planned_rename =
            plan_blocked_file_rename(&quarantine_directory, &target_path).expect("planned");
        fs::remove_file(&target_path).expect("remove target");
        fs::write(&target_path, b"replacement").expect("replacement");
        assert!(matches!(
            rename_blocked_file_into_quarantine(&planned_rename),
            Err(QuarantineMoveFailure::FileReplacedDuringOperation)
        ));
        assert_eq!(fs::read(&target_path).expect("target"), b"replacement");
        assert!(!planned_rename.destination_path.exists());
    }

    #[test]
    fn blocked_rename_never_replaces_an_existing_payload() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let quarantine_directory = temporary_root.path().join("quarantine");
        let source_path = temporary_root.path().join("blocked.bin");
        fs::write(&source_path, b"blocked").expect("source");
        let planned_rename =
            plan_blocked_file_rename(&quarantine_directory, &source_path).expect("planned");
        fs::write(&planned_rename.destination_path, b"existing").expect("existing payload");
        assert!(matches!(
            rename_blocked_file_into_quarantine(&planned_rename),
            Err(QuarantineMoveFailure::SystemCallFailed(Errno::EXIST))
        ));
        assert_eq!(fs::read(&source_path).expect("source"), b"blocked");
        assert_eq!(
            fs::read(&planned_rename.destination_path).expect("payload"),
            b"existing"
        );
    }

    #[test]
    fn quarantined_copies_are_neutralized_and_restore_to_the_original_bytes() {
        let temporary_root = tempfile::tempdir().unwrap();
        let quarantine_directory = temporary_root.path().join("quarantine");
        let source_path = temporary_root.path().join("eicar.com");
        let eicar_pattern =
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        fs::write(&source_path, eicar_pattern).unwrap();
        let copied_payload =
            copy_file_into_quarantine(&quarantine_directory, &source_path).unwrap();
        let stored_bytes = fs::read(&copied_payload.destination_path).unwrap();
        assert!(
            !stored_bytes
                .windows(eicar_pattern.len())
                .any(|stored_window| stored_window == eicar_pattern)
        );
        assert_eq!(
            payload_content_hash(&copied_payload.destination_path).unwrap(),
            copied_payload.file_hash
        );
        remove_quarantined_source(&copied_payload).unwrap();
        restore_payload_file(
            &quarantine_directory,
            &copied_payload.destination_path,
            &source_path,
            0o644,
            &copied_payload.file_hash,
        )
        .unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), eicar_pattern);
    }

    #[test]
    fn raw_payloads_are_neutralized_in_place_once() {
        let temporary_root = tempfile::tempdir().unwrap();
        let quarantine_directory = temporary_root.path().join("quarantine");
        ensure_quarantine_directory(&quarantine_directory).unwrap();
        let payload_path = quarantine_directory.join("legacy-payload");
        fs::write(&payload_path, b"legacy raw payload").unwrap();
        let expected_hash = payload_content_hash(&payload_path).unwrap();
        assert_eq!(
            neutralize_payload_in_place(&quarantine_directory, &payload_path, &expected_hash)
                .unwrap(),
            NeutralizingOutcome::NeutralizedNow
        );
        assert_ne!(fs::read(&payload_path).unwrap(), b"legacy raw payload");
        assert_eq!(payload_content_hash(&payload_path).unwrap(), expected_hash);
        assert_eq!(
            neutralize_payload_in_place(&quarantine_directory, &payload_path, &expected_hash)
                .unwrap(),
            NeutralizingOutcome::AlreadyNeutralized
        );
        assert_eq!(fs::read_dir(&quarantine_directory).unwrap().count(), 1);
    }

    #[test]
    fn neutralizing_refuses_a_payload_whose_content_changed() {
        let temporary_root = tempfile::tempdir().unwrap();
        let quarantine_directory = temporary_root.path().join("quarantine");
        ensure_quarantine_directory(&quarantine_directory).unwrap();
        let payload_path = quarantine_directory.join("tampered-payload");
        fs::write(&payload_path, b"tampered").unwrap();
        assert!(matches!(
            neutralize_payload_in_place(&quarantine_directory, &payload_path, "00"),
            Err(QuarantineMoveFailure::FileHashMismatch)
        ));
        assert_eq!(fs::read(&payload_path).unwrap(), b"tampered");
        assert_eq!(fs::read_dir(&quarantine_directory).unwrap().count(), 1);
    }

    #[test]
    fn restore_rejects_protected_system_directories() {
        assert!(matches!(
            validate_restore_path(Path::new("/etc/passwd")),
            Err(QuarantineMoveFailure::ProtectedRestoreDestination)
        ));
        assert!(matches!(
            validate_restore_path(Path::new("/home/user/bad\nname")),
            Err(QuarantineMoveFailure::InvalidRestorePath)
        ));
    }
}
