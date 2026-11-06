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
    desktop::flatpak_sandbox::host_program_async_command,
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

fn piped_content(
    mut plaintext_source: impl Read + Send + 'static,
) -> io::Result<std::os::fd::OwnedFd> {
    let (pipe_reader, pipe_writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    std::thread::spawn(move || {
        let _reader_closed = io::copy(&mut plaintext_source, &mut File::from(pipe_writer));
    });
    Ok(pipe_reader)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubmissionOutcome {
    ReportSent,
    ContactIncomplete,
    SubmitterMissing,
    SubmitterReplaceable,
    SubmissionFailed { failure_text: String },
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
    let content_pipe = match piped_content(plaintext_source) {
        Ok(content_pipe) => content_pipe,
        Err(pipe_failure) => {
            return SubmissionOutcome::SubmissionFailed {
                failure_text: pipe_failure.to_string(),
            };
        }
    };
    let mut submission_command = host_program_async_command(&submitter_path, &[]);
    submission_command
        .args(submission_arguments(&false_positive_report))
        .stdin(Stdio::from(content_pipe))
        .kill_on_drop(true);
    match timeout(SUBMISSION_TIMEOUT, submission_command.output()).await {
        Ok(Ok(submission_output)) if submission_output.status.success() => {
            SubmissionOutcome::ReportSent
        }
        Ok(Ok(submission_output)) => SubmissionOutcome::SubmissionFailed {
            failure_text: sanitize_scanner_line(
                String::from_utf8_lossy(&submission_output.stderr)
                    .lines()
                    .chain(String::from_utf8_lossy(&submission_output.stdout).lines())
                    .find(|output_line| !output_line.trim().is_empty())
                    .unwrap_or_default(),
            ),
        },
        Ok(Err(spawn_failure)) => SubmissionOutcome::SubmissionFailed {
            failure_text: spawn_failure.to_string(),
        },
        Err(_submission_timed_out) => SubmissionOutcome::SubmissionFailed {
            failure_text: gettext("the upload took too long"),
        },
    }
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
        SubmissionOutcome::SubmissionFailed { failure_text } => {
            gettext("The report was not sent: {error}")
                .replace("{error}", &sanitize_scanner_line(failure_text))
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
