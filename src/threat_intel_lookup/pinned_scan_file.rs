use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use rustix::fs::{Mode, OFlags};
use sha2::{Digest, Sha256};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PinnedFileFailure {
    #[error("the file could not be read: {0}")]
    FileUnreadable(#[from] io::Error),
    #[error("only regular files can be sent to VirusTotal")]
    NotRegularFile,
}

#[derive(Debug)]
pub struct PinnedScanFile {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub content_hash: String,
    pinned_file: File,
}

fn hash_open_file(pinned_file: &File) -> io::Result<String> {
    let mut hash_reader = pinned_file.try_clone()?;
    std::io::Seek::rewind(&mut hash_reader)?;
    let mut content_digest = Sha256::new();
    let mut hash_buffer = vec![0_u8; HASH_BUFFER_SIZE];
    loop {
        let read_length = hash_reader.read(&mut hash_buffer)?;
        if read_length == 0 {
            return Ok(hex::encode(content_digest.finalize()));
        }
        content_digest.update(&hash_buffer[..read_length]);
    }
}

impl PinnedScanFile {
    pub fn open_and_hash(file_path: &Path) -> Result<Self, PinnedFileFailure> {
        let pinned_file = File::from(
            rustix::fs::open(
                file_path,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        let file_metadata = pinned_file.metadata()?;
        if !file_metadata.is_file() {
            return Err(PinnedFileFailure::NotRegularFile);
        }
        Ok(Self {
            file_path: file_path.to_path_buf(),
            file_size: file_metadata.len(),
            content_hash: hash_open_file(&pinned_file)?,
            pinned_file,
        })
    }

    pub fn content_is_unchanged(&self) -> io::Result<bool> {
        Ok(hash_open_file(&self.pinned_file)? == self.content_hash)
    }

    pub fn upload_handle(&self) -> io::Result<File> {
        let mut upload_handle = self.pinned_file.try_clone()?;
        std::io::Seek::rewind(&mut upload_handle)?;
        Ok(upload_handle)
    }
}

#[cfg(test)]
mod pinned_scan_file_tests {
    use std::fs;

    use super::*;

    #[test]
    fn the_hash_matches_the_contents() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let file_path = temporary_root.path().join("sample");
        fs::write(&file_path, b"abc").expect("sample");
        let pinned_file = PinnedScanFile::open_and_hash(&file_path).expect("pinned");
        assert_eq!(pinned_file.file_size, 3);
        assert_eq!(
            pinned_file.content_hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(pinned_file.content_is_unchanged().expect("rehash"));
    }

    #[test]
    fn changing_the_file_after_confirmation_is_detected() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let file_path = temporary_root.path().join("sample");
        fs::write(&file_path, b"abc").expect("sample");
        let pinned_file = PinnedScanFile::open_and_hash(&file_path).expect("pinned");
        fs::write(&file_path, b"abd").expect("changed");
        assert!(!pinned_file.content_is_unchanged().expect("rehash"));
    }

    #[test]
    fn symlinks_and_directories_are_refused() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let target_path = temporary_root.path().join("target");
        fs::write(&target_path, b"abc").expect("target");
        let link_path = temporary_root.path().join("link");
        std::os::unix::fs::symlink(&target_path, &link_path).expect("symlink");
        assert!(matches!(
            PinnedScanFile::open_and_hash(&link_path),
            Err(PinnedFileFailure::FileUnreadable(_))
        ));
        assert!(matches!(
            PinnedScanFile::open_and_hash(temporary_root.path()),
            Err(PinnedFileFailure::NotRegularFile)
        ));
    }
}
