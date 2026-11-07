use gettextrs::gettext;

use crate::host_services::activity_history::submission_history_store::{
    SubmissionKind, SubmissionService, SubmissionTarget,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadKey {
    pub content_sha256: String,
    pub submission_service: SubmissionService,
    pub submission_kind: SubmissionKind,
}

impl UploadKey {
    pub fn for_target(content_sha256: &str, submission_target: SubmissionTarget) -> Self {
        Self {
            content_sha256: content_sha256.to_owned(),
            submission_service: submission_target.submission_service(),
            submission_kind: submission_target.submission_kind(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UploadRefusal {
    SameUploadRunning(UploadKey),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadActivity {
    UploadIdle,
    UploadRunning,
}

#[derive(Debug, Default)]
pub struct UploadsInFlight {
    running_uploads: Vec<UploadKey>,
}

impl UploadsInFlight {
    pub fn start_upload(&mut self, upload_key: UploadKey) -> Result<UploadKey, UploadRefusal> {
        match self.upload_activity(&upload_key) {
            UploadActivity::UploadRunning => Err(UploadRefusal::SameUploadRunning(upload_key)),
            UploadActivity::UploadIdle => {
                self.running_uploads.push(upload_key.clone());
                Ok(upload_key)
            }
        }
    }

    pub fn finish_upload(&mut self, upload_key: &UploadKey) {
        self.running_uploads
            .retain(|running_upload| running_upload != upload_key);
    }

    pub fn upload_activity(&self, upload_key: &UploadKey) -> UploadActivity {
        if self.running_uploads.contains(upload_key) {
            UploadActivity::UploadRunning
        } else {
            UploadActivity::UploadIdle
        }
    }
}

pub fn upload_refusal_text(upload_refusal: &UploadRefusal) -> String {
    match upload_refusal {
        UploadRefusal::SameUploadRunning(_) => gettext(
            "This file is already being sent to this service. Wait for that to finish before \
             sending it again.",
        ),
    }
}

#[cfg(test)]
mod uploads_in_flight_tests {
    use super::*;

    fn sample_key(submission_target: SubmissionTarget) -> UploadKey {
        UploadKey::for_target(&"c".repeat(64), submission_target)
    }

    #[test]
    fn a_second_identical_upload_is_refused_while_the_first_runs() {
        let mut uploads_in_flight = UploadsInFlight::default();
        let started_key = uploads_in_flight
            .start_upload(sample_key(SubmissionTarget::MalwareBazaarSample))
            .expect("first upload");
        assert_eq!(
            uploads_in_flight.start_upload(sample_key(SubmissionTarget::MalwareBazaarSample)),
            Err(UploadRefusal::SameUploadRunning(sample_key(
                SubmissionTarget::MalwareBazaarSample
            )))
        );
        assert_eq!(
            uploads_in_flight.upload_activity(&started_key),
            UploadActivity::UploadRunning
        );
        uploads_in_flight.finish_upload(&started_key);
        assert_eq!(
            uploads_in_flight.upload_activity(&started_key),
            UploadActivity::UploadIdle
        );
        assert!(
            uploads_in_flight
                .start_upload(sample_key(SubmissionTarget::MalwareBazaarSample))
                .is_ok()
        );
    }

    #[test]
    fn other_services_kinds_and_files_upload_alongside() {
        let mut uploads_in_flight = UploadsInFlight::default();
        uploads_in_flight
            .start_upload(sample_key(SubmissionTarget::ClamavFalsePositive))
            .expect("false positive report");
        assert!(
            uploads_in_flight
                .start_upload(sample_key(SubmissionTarget::ClamavMissedMalware))
                .is_ok()
        );
        assert!(
            uploads_in_flight
                .start_upload(sample_key(SubmissionTarget::VirusTotalSample))
                .is_ok()
        );
        assert!(
            uploads_in_flight
                .start_upload(UploadKey::for_target(
                    &"d".repeat(64),
                    SubmissionTarget::ClamavFalsePositive
                ))
                .is_ok()
        );
        assert_eq!(
            uploads_in_flight.upload_activity(&sample_key(SubmissionTarget::MalwareBazaarSample)),
            UploadActivity::UploadIdle
        );
    }
}
