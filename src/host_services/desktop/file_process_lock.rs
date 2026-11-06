use std::{fs, io, os::unix::fs::OpenOptionsExt, path::Path};

use rustix::fs::{FlockOperation, flock};

const LOCK_FILE_MODE: u32 = 0o600;

#[derive(Debug)]
pub struct ProcessFileLock {
    _locked_file: fs::File,
}

#[derive(Debug)]
pub enum FileLockAttempt {
    LockAcquired(ProcessFileLock),
    HeldByAnotherProcess,
}

fn open_lock_file(lock_path: &Path) -> io::Result<fs::File> {
    if let Some(lock_directory) = lock_path.parent() {
        fs::create_dir_all(lock_directory)?;
    }
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(LOCK_FILE_MODE)
        .open(lock_path)
}

pub fn wait_for_file_lock(lock_path: &Path) -> io::Result<ProcessFileLock> {
    let locked_file = open_lock_file(lock_path)?;
    flock(&locked_file, FlockOperation::LockExclusive)?;
    Ok(ProcessFileLock {
        _locked_file: locked_file,
    })
}

pub fn try_file_lock(lock_path: &Path) -> io::Result<FileLockAttempt> {
    let locked_file = open_lock_file(lock_path)?;
    match flock(&locked_file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(FileLockAttempt::LockAcquired(ProcessFileLock {
            _locked_file: locked_file,
        })),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(FileLockAttempt::HeldByAnotherProcess),
        Err(lock_failure) => Err(lock_failure.into()),
    }
}

#[cfg(test)]
mod file_process_lock_tests {
    use super::*;

    #[test]
    fn a_second_holder_is_refused_until_the_first_is_dropped() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let lock_path = temporary_root.path().join("nested/vault.lock");
        let first_lock = wait_for_file_lock(&lock_path).expect("first lock");
        assert!(matches!(
            try_file_lock(&lock_path).expect("second attempt"),
            FileLockAttempt::HeldByAnotherProcess
        ));
        drop(first_lock);
        assert!(matches!(
            try_file_lock(&lock_path).expect("third attempt"),
            FileLockAttempt::LockAcquired(_)
        ));
    }
}
