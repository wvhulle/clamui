use std::{
    fs::File,
    io::{self, Read},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use gettextrs::gettext;
use tokio::time::timeout;

use crate::host_services::{
    clamav_programs::trusted_program_lookup::{
        ClamavProgram, ProgramRefusal, locate_trusted_program,
    },
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    desktop::{content_pipe::pipe_content_for_child, flatpak_sandbox::host_program_async_command},
};

const SUBMISSION_TIMEOUT: Duration = Duration::from_secs(300);
const MAXIMUM_REPORTER_FIELD_LENGTH: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReporterContact {
    pub reporter_name: String,
    pub reporter_email: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmittedContent {
    DetectedFile { file_path: PathBuf },
    QuarantinedEntry { entry_id: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalsePositiveReport {
    pub reporter_contact: ReporterContact,
    pub detection_name: String,
    pub submitted_content: SubmittedContent,
}

pub fn open_detected_file(file_path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(file_path)
}

#[derive(Debug)]
pub enum SubmissionOutcome {
    ReportSent,
    ContactIncomplete,
    SubmitterMissing,
    SubmitterReplaceable,
    SubmissionFailed(SubmissionFailure),
}

#[derive(Debug, thiserror::Error)]
pub enum SubmissionFailure {
    #[error("the content could not be handed to clamsubmit: {0}")]
    ContentPipeFailed(#[source] io::Error),
    #[error("clamsubmit could not be run: {0}")]
    SubmitterRunFailed(#[source] io::Error),
    #[error("the upload took too long")]
    UploadTimedOut(#[from] tokio::time::error::Elapsed),
    #[error("clamsubmit printed: {submitter_output}")]
    ReportedBySubmitter { submitter_output: String },
}

fn field_is_plain(field_text: &str) -> bool {
    !field_text.is_empty()
        && field_text.len() <= MAXIMUM_REPORTER_FIELD_LENGTH
        && !field_text.chars().any(char::is_control)
}

pub fn contact_is_complete(reporter_contact: &ReporterContact) -> bool {
    let reporter_email = reporter_contact.reporter_email.trim();
    field_is_plain(reporter_contact.reporter_name.trim())
        && field_is_plain(reporter_email)
        && !reporter_email.starts_with('-')
        && !reporter_email.chars().any(char::is_whitespace)
        && reporter_email
            .split_once('@')
            .is_some_and(|(local_part, domain_part)| {
                !local_part.is_empty() && domain_part.contains('.')
            })
}

pub fn submission_arguments(false_positive_report: &FalsePositiveReport) -> Vec<String> {
    vec![
        "-e".to_owned(),
        false_positive_report
            .reporter_contact
            .reporter_email
            .trim()
            .to_owned(),
        "-N".to_owned(),
        false_positive_report
            .reporter_contact
            .reporter_name
            .trim()
            .to_owned(),
        "-V".to_owned(),
        false_positive_report.detection_name.clone(),
        "-p".to_owned(),
        "-".to_owned(),
    ]
}

pub async fn submit_false_positive(
    false_positive_report: FalsePositiveReport,
    plaintext_source: impl Read + Send + 'static,
) -> SubmissionOutcome {
    if !contact_is_complete(&false_positive_report.reporter_contact) {
        return SubmissionOutcome::ContactIncomplete;
    }
    let submitter_location =
        tokio::task::spawn_blocking(|| locate_trusted_program(ClamavProgram::SampleSubmitter))
            .await;
    let Ok(submitter_location) = submitter_location else {
        return SubmissionOutcome::SubmitterMissing;
    };
    let submitter_path = match submitter_location.runnable_path() {
        Ok(submitter_path) => submitter_path.to_path_buf(),
        Err(ProgramRefusal::ProgramMissing) => return SubmissionOutcome::SubmitterMissing,
        Err(ProgramRefusal::ProgramReplaceable { .. }) => {
            return SubmissionOutcome::SubmitterReplaceable;
        }
    };
    match run_submitter(&submitter_path, &false_positive_report, plaintext_source).await {
        Ok(()) => SubmissionOutcome::ReportSent,
        Err(submission_failure) => SubmissionOutcome::SubmissionFailed(submission_failure),
    }
}

fn first_printed_line(submission_output: &std::process::Output) -> String {
    String::from_utf8_lossy(&submission_output.stderr)
        .lines()
        .chain(String::from_utf8_lossy(&submission_output.stdout).lines())
        .find(|output_line| !output_line.trim().is_empty())
        .unwrap_or_default()
        .to_owned()
}

async fn run_submitter(
    submitter_path: &Path,
    false_positive_report: &FalsePositiveReport,
    plaintext_source: impl Read + Send + 'static,
) -> Result<(), SubmissionFailure> {
    let content_pipe =
        pipe_content_for_child(plaintext_source).map_err(SubmissionFailure::ContentPipeFailed)?;
    let mut submission_command = host_program_async_command(submitter_path, &[]);
    submission_command
        .args(submission_arguments(false_positive_report))
        .stdin(Stdio::from(content_pipe))
        .kill_on_drop(true);
    let submission_output = timeout(SUBMISSION_TIMEOUT, submission_command.output())
        .await?
        .map_err(SubmissionFailure::SubmitterRunFailed)?;
    if submission_output.status.success() {
        return Ok(());
    }
    Err(SubmissionFailure::ReportedBySubmitter {
        submitter_output: first_printed_line(&submission_output),
    })
}

pub fn submission_outcome_text(submission_outcome: &SubmissionOutcome) -> String {
    match submission_outcome {
        SubmissionOutcome::ReportSent => gettext(
            "Report sent. If the ClamAV team agrees, a later signature update stops the detection.",
        ),
        SubmissionOutcome::ContactIncomplete => {
            gettext("Enter your name and a valid email address to send a report")
        }
        SubmissionOutcome::SubmitterMissing => {
            gettext("Reporting needs clamsubmit, which comes with ClamAV but isn't installed here")
        }
        SubmissionOutcome::SubmitterReplaceable => {
            gettext("Lazaret refused to run clamsubmit, because your account can replace it")
        }
        SubmissionOutcome::SubmissionFailed(submission_failure) => {
            gettext("The report was not sent: {error}")
                .replace("{error}", &submission_failure_text(submission_failure))
        }
    }
}

fn submission_failure_text(submission_failure: &SubmissionFailure) -> String {
    match submission_failure {
        SubmissionFailure::ContentPipeFailed(pipe_failure) => pipe_failure.to_string(),
        SubmissionFailure::SubmitterRunFailed(run_failure) => run_failure.to_string(),
        SubmissionFailure::UploadTimedOut(_elapsed) => gettext("the upload took too long"),
        SubmissionFailure::ReportedBySubmitter { submitter_output } => {
            sanitize_scanner_line(submitter_output)
        }
    }
}

#[cfg(test)]
mod false_positive_submission_tests {
    use super::*;

    fn contact(reporter_name: &str, reporter_email: &str) -> ReporterContact {
        ReporterContact {
            reporter_name: reporter_name.to_owned(),
            reporter_email: reporter_email.to_owned(),
        }
    }

    #[test]
    fn contacts_need_a_name_and_a_plausible_email() {
        assert!(contact_is_complete(&contact(
            "Alex Doe",
            "alex@example.org"
        )));
        [
            contact("", "alex@example.org"),
            contact("Alex", "alex"),
            contact("Alex", "-e@example.org"),
            contact("Alex", "alex @example.org"),
            contact("Alex\nDoe", "alex@example.org"),
        ]
        .iter()
        .for_each(|incomplete_contact| assert!(!contact_is_complete(incomplete_contact)));
    }

    #[test]
    fn the_file_is_sent_on_standard_input_never_as_an_argument() {
        let submitted_arguments = submission_arguments(&FalsePositiveReport {
            reporter_contact: contact("Alex Doe", " alex@example.org "),
            detection_name: "Win.Test.EICAR_HDB-1".to_owned(),
            submitted_content: SubmittedContent::DetectedFile {
                file_path: PathBuf::from("/home/alex/-rf"),
            },
        });
        assert_eq!(
            submitted_arguments,
            [
                "-e",
                "alex@example.org",
                "-N",
                "Alex Doe",
                "-V",
                "Win.Test.EICAR_HDB-1",
                "-p",
                "-"
            ]
        );
    }
}
