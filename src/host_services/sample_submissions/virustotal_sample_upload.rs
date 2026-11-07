use jiff::Timestamp;

use crate::host_services::{
    activity_history::{
        activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        submission_history_store::{
            EarlierSubmission, NewSubmission, SubmissionRecord, SubmissionRecording,
            SubmissionState, SubmissionTarget, VirusTotalSampleStatus,
        },
    },
    quarantine_vault::quarantine_entry_database::QuarantineVault,
    sample_submissions::submission_samples::{SampleReadFailure, read_quarantined_sample},
    threat_intel::{
        service_key_storage::{
            KeyStorageFailure, ResolvedApiKey, ThreatIntelService, read_api_key,
        },
        virustotal_api_client::{
            AnalysisProgress, FileReportLookup, MAXIMUM_DIRECT_UPLOAD_SIZE, VirusTotalClient,
            VirusTotalFailure, VirusTotalReport, VirusTotalUploadAnswer,
        },
    },
};

#[derive(Debug)]
pub enum VirusTotalUploadAttempt {
    SubmissionRecorded(SubmissionRecord),
    AlreadySubmitted(SubmissionRecord),
    ReportAlreadyAvailable(VirusTotalReport),
    KeyMissing,
    KeyUnreadable(KeyStorageFailure),
    SampleUnreadable(SampleReadFailure),
    VirusTotalUnavailable(VirusTotalFailure),
    HistoryUnavailable(ActivityHistoryFailure),
    SentWithoutRecord(ActivityHistoryFailure),
}

#[derive(Debug)]
pub enum VirusTotalUploadStep {
    ShowExistingReport(VirusTotalReport),
    UploadSample,
}

pub fn virustotal_step_after_lookup(report_lookup: FileReportLookup) -> VirusTotalUploadStep {
    match report_lookup {
        FileReportLookup::ReportAvailable(file_report) => {
            VirusTotalUploadStep::ShowExistingReport(file_report)
        }
        FileReportLookup::FileUnknownToVirusTotal => VirusTotalUploadStep::UploadSample,
    }
}

pub fn virustotal_state_after_upload(upload_answer: VirusTotalUploadAnswer) -> SubmissionState {
    SubmissionState::VirusTotalSample {
        virustotal_status: match upload_answer {
            VirusTotalUploadAnswer::AnalysisQueued { analysis_id } => {
                VirusTotalSampleStatus::VirusTotalAnalysisQueued { analysis_id }
            }
            VirusTotalUploadAnswer::UploadRefused { error_code } => {
                VirusTotalSampleStatus::SubmissionRefused {
                    refusal_reason: error_code,
                }
            }
        },
    }
}

pub fn virustotal_state_after_analysis(
    analysis_id: &str,
    analysis_progress: AnalysisProgress,
) -> SubmissionState {
    SubmissionState::VirusTotalSample {
        virustotal_status: match analysis_progress {
            AnalysisProgress::AnalysisPending => VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                analysis_id: analysis_id.to_owned(),
            },
            AnalysisProgress::AnalysisCompleted {
                malicious_count,
                engine_count,
            } => VirusTotalSampleStatus::VirusTotalAnalysed {
                analysis_id: analysis_id.to_owned(),
                malicious_count,
                engine_count,
            },
        },
    }
}

pub async fn virustotal_client() -> Result<VirusTotalClient, VirusTotalUploadAttempt> {
    match read_api_key(ThreatIntelService::VirusTotalService).await {
        Ok(ResolvedApiKey::FromKeyFile(api_key) | ResolvedApiKey::FromKeyring(api_key)) => {
            VirusTotalClient::with_api_key(api_key)
                .map_err(VirusTotalUploadAttempt::VirusTotalUnavailable)
        }
        Ok(ResolvedApiKey::NotConfigured) => Err(VirusTotalUploadAttempt::KeyMissing),
        Err(key_failure) => Err(VirusTotalUploadAttempt::KeyUnreadable(key_failure)),
    }
}

enum VirusTotalOutcome {
    StateToRecord(SubmissionState),
    ExistingReport(VirusTotalReport),
}

async fn virustotal_outcome(
    virustotal_client: &VirusTotalClient,
    content_sha256: &str,
    sample_bytes: Vec<u8>,
) -> Result<VirusTotalOutcome, VirusTotalFailure> {
    match virustotal_step_after_lookup(
        virustotal_client
            .look_up_file_report(content_sha256)
            .await?,
    ) {
        VirusTotalUploadStep::ShowExistingReport(file_report) => {
            Ok(VirusTotalOutcome::ExistingReport(file_report))
        }
        VirusTotalUploadStep::UploadSample => Ok(VirusTotalOutcome::StateToRecord(
            virustotal_state_after_upload(
                virustotal_client
                    .upload_file(content_sha256.to_owned(), sample_bytes)
                    .await?,
            ),
        )),
    }
}

pub async fn upload_to_virustotal(
    activity_history: &ActivityHistory,
    quarantine_vault: &QuarantineVault,
    entry_id: i64,
) -> VirusTotalUploadAttempt {
    let virustotal_client = match virustotal_client().await {
        Ok(virustotal_client) => virustotal_client,
        Err(client_attempt) => return client_attempt,
    };
    let quarantined_sample =
        match read_quarantined_sample(quarantine_vault, entry_id, MAXIMUM_DIRECT_UPLOAD_SIZE).await
        {
            Ok(quarantined_sample) => quarantined_sample,
            Err(read_failure) => return VirusTotalUploadAttempt::SampleUnreadable(read_failure),
        };
    let submitted_file = quarantined_sample.submission_sample.submitted_file;
    match activity_history
        .find_earlier_submission(
            &submitted_file.content_sha256,
            SubmissionTarget::VirusTotalSample,
        )
        .await
    {
        Ok(EarlierSubmission::SubmittedBefore(earlier_submission)) => {
            return VirusTotalUploadAttempt::AlreadySubmitted(earlier_submission);
        }
        Ok(EarlierSubmission::NotSubmittedBefore) => {}
        Err(history_failure) => {
            return VirusTotalUploadAttempt::HistoryUnavailable(history_failure);
        }
    }
    let submission_state = match virustotal_outcome(
        &virustotal_client,
        &submitted_file.content_sha256,
        quarantined_sample.submission_sample.sample_bytes,
    )
    .await
    {
        Ok(VirusTotalOutcome::StateToRecord(submission_state)) => submission_state,
        Ok(VirusTotalOutcome::ExistingReport(file_report)) => {
            return VirusTotalUploadAttempt::ReportAlreadyAvailable(file_report);
        }
        Err(virustotal_failure) => {
            return VirusTotalUploadAttempt::VirusTotalUnavailable(virustotal_failure);
        }
    };
    match activity_history
        .record_submission(NewSubmission {
            submitted_file,
            submitted_at: Timestamp::now(),
            submission_state,
        })
        .await
    {
        Ok(SubmissionRecording::SubmissionRecorded(recorded_submission)) => {
            VirusTotalUploadAttempt::SubmissionRecorded(recorded_submission)
        }
        Ok(SubmissionRecording::AlreadySubmitted(earlier_submission)) => {
            VirusTotalUploadAttempt::AlreadySubmitted(earlier_submission)
        }
        Err(history_failure) => VirusTotalUploadAttempt::SentWithoutRecord(history_failure),
    }
}

pub async fn refreshed_virustotal_state(
    virustotal_client: &VirusTotalClient,
    submission_record: &SubmissionRecord,
) -> Result<SubmissionState, VirusTotalFailure> {
    match &submission_record.submission_state {
        SubmissionState::VirusTotalSample {
            virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued { analysis_id },
        } => Ok(virustotal_state_after_analysis(
            analysis_id,
            virustotal_client.fetch_analysis(analysis_id).await?,
        )),
        unchanged_state => Ok(unchanged_state.clone()),
    }
}

#[cfg(test)]
mod virustotal_sample_upload_tests {
    use super::*;

    #[test]
    fn a_hash_virustotal_already_reports_on_is_never_uploaded() {
        assert!(matches!(
            virustotal_step_after_lookup(FileReportLookup::ReportAvailable(VirusTotalReport {
                content_hash: "ab12".to_owned(),
                detecting_engine_count: 3,
                total_engine_count: 70,
                engine_detections: Vec::new(),
                report_url: "https://www.virustotal.com/gui/file/ab12".to_owned(),
            })),
            VirusTotalUploadStep::ShowExistingReport(_)
        ));
        assert!(matches!(
            virustotal_step_after_lookup(FileReportLookup::FileUnknownToVirusTotal),
            VirusTotalUploadStep::UploadSample
        ));
    }

    #[test]
    fn uploads_and_analyses_become_submission_states() {
        assert_eq!(
            virustotal_state_after_upload(VirusTotalUploadAnswer::AnalysisQueued {
                analysis_id: "analysis-1".to_owned(),
            }),
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                    analysis_id: "analysis-1".to_owned(),
                },
            }
        );
        assert_eq!(
            virustotal_state_after_upload(VirusTotalUploadAnswer::UploadRefused {
                error_code: "BadRequestError".to_owned(),
            }),
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::SubmissionRefused {
                    refusal_reason: "BadRequestError".to_owned(),
                },
            }
        );
        assert_eq!(
            virustotal_state_after_analysis(
                "analysis-1",
                AnalysisProgress::AnalysisCompleted {
                    malicious_count: 41,
                    engine_count: 68,
                }
            ),
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysed {
                    analysis_id: "analysis-1".to_owned(),
                    malicious_count: 41,
                    engine_count: 68,
                },
            }
        );
        assert_eq!(
            virustotal_state_after_analysis("analysis-1", AnalysisProgress::AnalysisPending),
            SubmissionState::VirusTotalSample {
                virustotal_status: VirusTotalSampleStatus::VirusTotalAnalysisQueued {
                    analysis_id: "analysis-1".to_owned(),
                },
            }
        );
    }
}
