use jiff::Timestamp;

use crate::host_services::{
    activity_history::{
        activity_history_database::{ActivityHistory, ActivityHistoryFailure},
        submission_history_store::{
            BazaarSampleStatus, EarlierSubmission, NewSubmission, SubmissionRecord,
            SubmissionRecording, SubmissionState, SubmissionTarget,
        },
    },
    clamav_scanner::scanner_output_parser::ThreatIdentity,
    quarantine_vault::quarantine_entry_database::QuarantineVault,
    sample_submissions::submission_samples::{
        MAXIMUM_SAMPLE_SIZE, SampleReadFailure, read_quarantined_sample,
    },
    threat_intel::{
        malware_bazaar_client::{
            BazaarSampleUpload, BazaarUploadAnswer, KnownSampleLookup, MalwareBazaarFailure,
            bazaar_signature_tag, look_up_file_hash, upload_sample,
        },
        service_key_storage::{
            KeyStorageFailure, ResolvedApiKey, ThreatIntelService, read_api_key,
        },
    },
};

const UNWANTED_PROGRAM_PREFIX: &str = "PUA.";

#[derive(Debug)]
pub enum BazaarUploadAttempt {
    SubmissionRecorded(SubmissionRecord),
    AlreadySubmitted(SubmissionRecord),
    KeyMissing,
    KeyUnreadable(KeyStorageFailure),
    SampleUnreadable(SampleReadFailure),
    NotDetectedByClamav,
    UnwantedProgramOnly,
    BazaarUnavailable(MalwareBazaarFailure),
    HistoryUnavailable(ActivityHistoryFailure),
    SentWithoutRecord(ActivityHistoryFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BazaarUploadStep {
    RecordExistingListing,
    UploadSample,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BazaarEligibility {
    EligibleSignature { signature_name: String },
    NotDetectedByClamav,
    UnwantedProgramOnly,
}

pub fn bazaar_eligibility(threat_identity: &ThreatIdentity) -> BazaarEligibility {
    match threat_identity {
        ThreatIdentity::Signature { signature_name }
            if signature_name.starts_with(UNWANTED_PROGRAM_PREFIX) =>
        {
            BazaarEligibility::UnwantedProgramOnly
        }
        ThreatIdentity::Signature { signature_name } => BazaarEligibility::EligibleSignature {
            signature_name: signature_name.clone(),
        },
        ThreatIdentity::BlockedByOnAccess => BazaarEligibility::NotDetectedByClamav,
    }
}

pub const fn bazaar_step_after_lookup(sample_lookup: &KnownSampleLookup) -> BazaarUploadStep {
    match sample_lookup {
        KnownSampleLookup::SamplesFound { .. } => BazaarUploadStep::RecordExistingListing,
        KnownSampleLookup::NoKnownSamples => BazaarUploadStep::UploadSample,
    }
}

pub fn bazaar_state_after_upload(upload_answer: BazaarUploadAnswer) -> SubmissionState {
    SubmissionState::MalwareBazaarSample {
        bazaar_status: match upload_answer {
            BazaarUploadAnswer::SampleInserted => BazaarSampleStatus::UploadAccepted,
            BazaarUploadAnswer::SampleAlreadyKnown => BazaarSampleStatus::ListedOnMalwareBazaar,
            BazaarUploadAnswer::UploadRefused { query_status } => {
                BazaarSampleStatus::SubmissionRefused {
                    refusal_reason: query_status,
                }
            }
        },
    }
}

pub async fn abuse_ch_key() -> Result<String, BazaarUploadAttempt> {
    match read_api_key(ThreatIntelService::AbuseChService).await {
        Ok(ResolvedApiKey::FromKeyFile(api_key) | ResolvedApiKey::FromKeyring(api_key)) => {
            Ok(api_key)
        }
        Ok(ResolvedApiKey::NotConfigured) => Err(BazaarUploadAttempt::KeyMissing),
        Err(key_failure) => Err(BazaarUploadAttempt::KeyUnreadable(key_failure)),
    }
}

async fn bazaar_outcome_state(
    auth_key: &str,
    content_sha256: &str,
    sample_upload: BazaarSampleUpload,
) -> Result<SubmissionState, MalwareBazaarFailure> {
    match bazaar_step_after_lookup(&look_up_file_hash(auth_key, content_sha256).await?) {
        BazaarUploadStep::RecordExistingListing => Ok(SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
        }),
        BazaarUploadStep::UploadSample => Ok(bazaar_state_after_upload(
            upload_sample(auth_key, sample_upload).await?,
        )),
    }
}

pub async fn upload_to_malware_bazaar(
    activity_history: &ActivityHistory,
    quarantine_vault: &QuarantineVault,
    entry_id: i64,
) -> BazaarUploadAttempt {
    let auth_key = match abuse_ch_key().await {
        Ok(auth_key) => auth_key,
        Err(key_attempt) => return key_attempt,
    };
    let quarantined_sample =
        match read_quarantined_sample(quarantine_vault, entry_id, MAXIMUM_SAMPLE_SIZE).await {
            Ok(quarantined_sample) => quarantined_sample,
            Err(read_failure) => return BazaarUploadAttempt::SampleUnreadable(read_failure),
        };
    let signature_name = match bazaar_eligibility(&quarantined_sample.threat_identity) {
        BazaarEligibility::EligibleSignature { signature_name } => signature_name,
        BazaarEligibility::NotDetectedByClamav => return BazaarUploadAttempt::NotDetectedByClamav,
        BazaarEligibility::UnwantedProgramOnly => return BazaarUploadAttempt::UnwantedProgramOnly,
    };
    let submitted_file = quarantined_sample.submission_sample.submitted_file;
    match activity_history
        .find_earlier_submission(
            &submitted_file.content_sha256,
            SubmissionTarget::MalwareBazaarSample,
        )
        .await
    {
        Ok(EarlierSubmission::SubmittedBefore(earlier_submission)) => {
            return BazaarUploadAttempt::AlreadySubmitted(earlier_submission);
        }
        Ok(EarlierSubmission::NotSubmittedBefore) => {}
        Err(history_failure) => return BazaarUploadAttempt::HistoryUnavailable(history_failure),
    }
    let submission_state = match bazaar_outcome_state(
        &auth_key,
        &submitted_file.content_sha256,
        BazaarSampleUpload {
            sample_bytes: quarantined_sample.submission_sample.sample_bytes,
            upload_name: submitted_file.content_sha256.clone(),
            signature_tag: bazaar_signature_tag(&signature_name),
        },
    )
    .await
    {
        Ok(submission_state) => submission_state,
        Err(bazaar_failure) => return BazaarUploadAttempt::BazaarUnavailable(bazaar_failure),
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
            BazaarUploadAttempt::SubmissionRecorded(recorded_submission)
        }
        Ok(SubmissionRecording::AlreadySubmitted(earlier_submission)) => {
            BazaarUploadAttempt::AlreadySubmitted(earlier_submission)
        }
        Err(history_failure) => BazaarUploadAttempt::SentWithoutRecord(history_failure),
    }
}

pub async fn refreshed_bazaar_state(
    auth_key: &str,
    submission_record: &SubmissionRecord,
) -> Result<SubmissionState, MalwareBazaarFailure> {
    match &submission_record.submission_state {
        SubmissionState::MalwareBazaarSample {
            bazaar_status: BazaarSampleStatus::UploadAccepted,
        } => Ok(
            match bazaar_step_after_lookup(
                &look_up_file_hash(auth_key, &submission_record.submitted_file.content_sha256)
                    .await?,
            ) {
                BazaarUploadStep::RecordExistingListing => SubmissionState::MalwareBazaarSample {
                    bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
                },
                BazaarUploadStep::UploadSample => submission_record.submission_state.clone(),
            },
        ),
        unchanged_state => Ok(unchanged_state.clone()),
    }
}

#[cfg(test)]
mod bazaar_sample_upload_tests {
    use super::*;
    use crate::host_services::threat_intel::malware_bazaar_client::{
        MalwareFamily, SampleFirstSeen, SampleSummary,
    };

    #[test]
    fn a_hash_malware_bazaar_already_lists_is_recorded_without_uploading() {
        assert_eq!(
            bazaar_step_after_lookup(&KnownSampleLookup::SamplesFound {
                known_samples: vec![SampleSummary {
                    malware_family: MalwareFamily::NamedFamily("AgentTesla".to_owned()),
                    first_seen: SampleFirstSeen::FirstSeenUnknown,
                    sample_tags: Vec::new(),
                }],
            }),
            BazaarUploadStep::RecordExistingListing
        );
        assert_eq!(
            bazaar_step_after_lookup(&KnownSampleLookup::NoKnownSamples),
            BazaarUploadStep::UploadSample
        );
    }

    #[test]
    fn only_clamav_signatures_for_malware_are_eligible() {
        assert_eq!(
            bazaar_eligibility(&ThreatIdentity::Signature {
                signature_name: "Win.Trojan.Agent-1".to_owned(),
            }),
            BazaarEligibility::EligibleSignature {
                signature_name: "Win.Trojan.Agent-1".to_owned(),
            }
        );
        assert_eq!(
            bazaar_eligibility(&ThreatIdentity::Signature {
                signature_name: "PUA.Win.Packer.Upx".to_owned(),
            }),
            BazaarEligibility::UnwantedProgramOnly
        );
        assert_eq!(
            bazaar_eligibility(&ThreatIdentity::BlockedByOnAccess),
            BazaarEligibility::NotDetectedByClamav
        );
    }

    #[test]
    fn upload_answers_become_submission_states() {
        assert_eq!(
            bazaar_state_after_upload(BazaarUploadAnswer::SampleInserted),
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::UploadAccepted,
            }
        );
        assert_eq!(
            bazaar_state_after_upload(BazaarUploadAnswer::SampleAlreadyKnown),
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::ListedOnMalwareBazaar,
            }
        );
        assert_eq!(
            bazaar_state_after_upload(BazaarUploadAnswer::UploadRefused {
                query_status: "file_expected".to_owned(),
            }),
            SubmissionState::MalwareBazaarSample {
                bazaar_status: BazaarSampleStatus::SubmissionRefused {
                    refusal_reason: "file_expected".to_owned(),
                },
            }
        );
    }
}
