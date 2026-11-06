use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

const EICAR_SIGNATURE_PARTS: [&str; 3] = [
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-ANTIVIRUS-",
    "TEST-FILE!$H+H*",
];

#[derive(Debug, thiserror::Error)]
pub enum EicarTestFileFailure {
    #[error("writing the EICAR test file stopped unexpectedly")]
    WritingInterrupted(#[source] tokio::task::JoinError),
    #[error("the EICAR test file could not be written")]
    FileUnwritable(#[source] io::Error),
}

pub async fn written_eicar_test_file(
    test_file_directory: PathBuf,
) -> Result<NamedTempFile, EicarTestFileFailure> {
    tokio::task::spawn_blocking(move || write_eicar_test_file(&test_file_directory))
        .await
        .map_err(EicarTestFileFailure::WritingInterrupted)?
        .map_err(EicarTestFileFailure::FileUnwritable)
}

pub fn eicar_test_bytes() -> Vec<u8> {
    EICAR_SIGNATURE_PARTS.concat().into_bytes()
}

pub fn write_eicar_test_file(test_file_directory: &Path) -> io::Result<NamedTempFile> {
    fs::create_dir_all(test_file_directory)?;
    let mut eicar_file = tempfile::Builder::new()
        .prefix("eicar-test-")
        .suffix(".txt")
        .tempfile_in(test_file_directory)?;
    eicar_file.write_all(&eicar_test_bytes())?;
    eicar_file.as_file().sync_all()?;
    Ok(eicar_file)
}

#[cfg(test)]
mod eicar_test_file_tests {
    use super::*;

    #[test]
    fn test_file_holds_the_standard_signature_and_is_removed_on_drop() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let eicar_file = write_eicar_test_file(temporary_root.path()).expect("test file");
        let eicar_path = eicar_file.path().to_path_buf();
        assert_eq!(fs::read(&eicar_path).expect("contents").len(), 68);
        drop(eicar_file);
        assert!(!eicar_path.exists());
    }
}
