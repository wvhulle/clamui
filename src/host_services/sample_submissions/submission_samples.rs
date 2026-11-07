use std::{
    io::{self, Read},
    path::{Path, PathBuf},
};

use bytesize::ByteSize;
use sha2::{Digest, Sha256};
use tokio::task::spawn_blocking;

use crate::host_services::{
    activity_history::submission_history_store::SubmittedFile,
    clamav_programs::clamav_report_submission::{SubmittedContent, open_detected_file},
    clamav_scanner::scanner_output_parser::{ThreatIdentity, sanitize_scanner_line},
    quarantine_vault::{
        quarantine_entry_database::{QuarantineVault, VerifiedPayload},
        quarantine_file_moves::QuarantineMoveFailure,
    },
};

pub const MAXIMUM_SAMPLE_SIZE: ByteSize = ByteSize::mib(64);

#[derive(Debug, thiserror::Error)]
pub enum SampleReadFailure {
    #[error("the quarantined copy could not be read: {0}")]
    QuarantinedCopyUnreadable(#[from] QuarantineMoveFailure),
    #[error("the file could not be read: {0}")]
    FileUnreadable(#[from] io::Error),
    #[error("the path is not a regular file")]
    FileNotRegular,
    #[error("the file is larger than {maximum_size}")]
    FileTooLarge { maximum_size: ByteSize },
    #[error("reading the file stopped unexpectedly: {0}")]
    ReadingInterrupted(#[from] tokio::task::JoinError),
}

pub struct SubmissionSample {
    pub submitted_file: SubmittedFile,
    pub sample_bytes: Vec<u8>,
}

impl std::fmt::Debug for SubmissionSample {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubmissionSample")
            .field("submitted_file", &self.submitted_file)
            .field("sample_size", &self.sample_bytes.len())
            .finish()
    }
}

#[derive(Debug)]
pub struct QuarantinedSample {
    pub submission_sample: SubmissionSample,
    pub threat_identity: ThreatIdentity,
}

pub fn shown_file_name(file_path: &Path) -> String {
    sanitize_scanner_line(
        &file_path
            .file_name()
            .unwrap_or(file_path.as_os_str())
            .to_string_lossy(),
    )
}

pub fn content_sha256_text(sample_bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(sample_bytes))
}

fn quarantined_sample_from_payload(verified_payload: VerifiedPayload) -> QuarantinedSample {
    QuarantinedSample {
        submission_sample: SubmissionSample {
            submitted_file: SubmittedFile {
                content_sha256: verified_payload.content_sha256,
                file_name: shown_file_name(&verified_payload.entry_record.original_path),
            },
            sample_bytes: verified_payload.payload_bytes,
        },
        threat_identity: verified_payload.entry_record.threat_identity,
    }
}

pub async fn read_quarantined_sample(
    quarantine_vault: &QuarantineVault,
    entry_id: i64,
    maximum_size: ByteSize,
) -> Result<QuarantinedSample, SampleReadFailure> {
    Ok(quarantined_sample_from_payload(
        quarantine_vault
            .read_verified_payload(entry_id, maximum_size)
            .await?,
    ))
}

fn read_file_bytes(file_path: &Path, maximum_size: ByteSize) -> Result<Vec<u8>, SampleReadFailure> {
    let opened_file = open_detected_file(file_path)?;
    if !opened_file.metadata()?.is_file() {
        return Err(SampleReadFailure::FileNotRegular);
    }
    let mut sample_bytes = Vec::new();
    opened_file
        .take(maximum_size.as_u64().saturating_add(1))
        .read_to_end(&mut sample_bytes)?;
    if sample_bytes.len() as u64 > maximum_size.as_u64() {
        return Err(SampleReadFailure::FileTooLarge { maximum_size });
    }
    Ok(sample_bytes)
}

pub async fn read_file_sample(
    file_path: PathBuf,
    maximum_size: ByteSize,
) -> Result<SubmissionSample, SampleReadFailure> {
    let file_name = shown_file_name(&file_path);
    let sample_bytes = spawn_blocking(move || read_file_bytes(&file_path, maximum_size)).await??;
    Ok(SubmissionSample {
        submitted_file: SubmittedFile {
            content_sha256: content_sha256_text(&sample_bytes),
            file_name,
        },
        sample_bytes,
    })
}

pub async fn read_submitted_content(
    quarantine_vault: &QuarantineVault,
    submitted_content: &SubmittedContent,
) -> Result<SubmissionSample, SampleReadFailure> {
    match submitted_content {
        SubmittedContent::FileOnDisk { file_path } => {
            read_file_sample(file_path.clone(), MAXIMUM_SAMPLE_SIZE).await
        }
        SubmittedContent::QuarantinedEntry { entry_id } => {
            read_quarantined_sample(quarantine_vault, *entry_id, MAXIMUM_SAMPLE_SIZE)
                .await
                .map(|quarantined_sample| quarantined_sample.submission_sample)
        }
    }
}

#[cfg(test)]
mod submission_samples_tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[tokio::test]
    async fn a_picked_file_is_read_with_its_hash_and_name() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let picked_path = temporary_root.path().join("dropper.js");
        std::fs::write(&picked_path, b"missed sample").expect("picked file");
        let submission_sample = read_file_sample(picked_path, ByteSize::mib(1))
            .await
            .expect("read");
        assert_eq!(submission_sample.sample_bytes, b"missed sample");
        assert_eq!(submission_sample.submitted_file.file_name, "dropper.js");
        assert_eq!(
            submission_sample.submitted_file.content_sha256,
            content_sha256_text(b"missed sample")
        );
    }

    #[tokio::test]
    async fn a_symbolic_link_is_never_followed() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let target_path = temporary_root.path().join("private.txt");
        std::fs::write(&target_path, b"private").expect("target");
        let link_path = temporary_root.path().join("sample.exe");
        symlink(&target_path, &link_path).expect("link");
        assert!(matches!(
            read_file_sample(link_path, ByteSize::mib(1)).await,
            Err(SampleReadFailure::FileUnreadable(_))
        ));
    }

    #[tokio::test]
    async fn files_beyond_the_limit_and_folders_are_refused() {
        let temporary_root = tempfile::tempdir().expect("temporary root");
        let large_path = temporary_root.path().join("large.bin");
        std::fs::write(&large_path, [0_u8; 32]).expect("large file");
        assert!(matches!(
            read_file_sample(large_path, ByteSize::b(16)).await,
            Err(SampleReadFailure::FileTooLarge { .. })
        ));
        assert!(matches!(
            read_file_sample(temporary_root.path().to_path_buf(), ByteSize::mib(1)).await,
            Err(SampleReadFailure::FileNotRegular | SampleReadFailure::FileUnreadable(_))
        ));
    }
}
