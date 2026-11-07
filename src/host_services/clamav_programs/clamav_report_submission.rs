use std::{
    fs::File,
    io::{self, Cursor},
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
    FileOnDisk { file_path: PathBuf },
    QuarantinedEntry { entry_id: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClamavReportKind {
    FalsePositive { detection_name: String },
    MissedMalware,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClamavReport {
    pub reporter_contact: ReporterContact,
    pub report_kind: ClamavReportKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClamavReportRequest {
    pub clamav_report: ClamavReport,
    pub submitted_content: SubmittedContent,
}

pub fn open_detected_file(file_path: &Path) -> io::Result<File> {
    File::options()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(file_path)
}

#[derive(Debug, thiserror::Error)]
pub enum ClamsubmitFailure {
    #[error("the reporter's name or email address is incomplete")]
    ContactIncomplete,
    #[error("clamsubmit is not installed")]
    SubmitterMissing,
    #[error("clamsubmit can be replaced by your account")]
    SubmitterReplaceable,
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

pub fn submission_arguments(clamav_report: &ClamavReport) -> Vec<String> {
    let contact_arguments = [
        "-e".to_owned(),
        clamav_report
            .reporter_contact
            .reporter_email
            .trim()
            .to_owned(),
        "-N".to_owned(),
        clamav_report
            .reporter_contact
            .reporter_name
            .trim()
            .to_owned(),
    ];
    let kind_arguments = match &clamav_report.report_kind {
        ClamavReportKind::FalsePositive { detection_name } => vec![
            "-V".to_owned(),
            detection_name.clone(),
            "-p".to_owned(),
            "-".to_owned(),
        ],
        ClamavReportKind::MissedMalware => vec!["-n".to_owned(), "-".to_owned()],
    };
    contact_arguments
        .into_iter()
        .chain(kind_arguments)
        .collect()
}

pub async fn submit_clamav_report(
    clamav_report: &ClamavReport,
    sample_bytes: Vec<u8>,
) -> Result<(), ClamsubmitFailure> {
    if !contact_is_complete(&clamav_report.reporter_contact) {
        return Err(ClamsubmitFailure::ContactIncomplete);
    }
    let submitter_location =
        tokio::task::spawn_blocking(|| locate_trusted_program(ClamavProgram::SampleSubmitter))
            .await
            .map_err(|_lookup_interrupted| ClamsubmitFailure::SubmitterMissing)?;
    let submitter_path = match submitter_location.runnable_path() {
        Ok(submitter_path) => submitter_path.to_path_buf(),
        Err(ProgramRefusal::ProgramMissing) => return Err(ClamsubmitFailure::SubmitterMissing),
        Err(ProgramRefusal::ProgramReplaceable { .. }) => {
            return Err(ClamsubmitFailure::SubmitterReplaceable);
        }
    };
    run_submitter(&submitter_path, clamav_report, sample_bytes).await
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
    clamav_report: &ClamavReport,
    sample_bytes: Vec<u8>,
) -> Result<(), ClamsubmitFailure> {
    let content_pipe = pipe_content_for_child(Cursor::new(sample_bytes))
        .map_err(ClamsubmitFailure::ContentPipeFailed)?;
    let mut submission_command = host_program_async_command(submitter_path, &[]);
    submission_command
        .args(submission_arguments(clamav_report))
        .stdin(Stdio::from(content_pipe))
        .kill_on_drop(true);
    let submission_output = timeout(SUBMISSION_TIMEOUT, submission_command.output())
        .await?
        .map_err(ClamsubmitFailure::SubmitterRunFailed)?;
    if submission_output.status.success() {
        return Ok(());
    }
    Err(ClamsubmitFailure::ReportedBySubmitter {
        submitter_output: first_printed_line(&submission_output),
    })
}

pub fn clamsubmit_failure_text(clamsubmit_failure: &ClamsubmitFailure) -> String {
    match clamsubmit_failure {
        ClamsubmitFailure::ContactIncomplete => {
            gettext("Enter your name and a valid email address to send a report")
        }
        ClamsubmitFailure::SubmitterMissing => {
            gettext("Reporting needs clamsubmit, which comes with ClamAV but isn't installed here")
        }
        ClamsubmitFailure::SubmitterReplaceable => {
            gettext("Lazaret refused to run clamsubmit, because your account can replace it")
        }
        ClamsubmitFailure::ContentPipeFailed(pipe_failure) => {
            gettext("The report was not sent: {error}")
                .replace("{error}", &pipe_failure.to_string())
        }
        ClamsubmitFailure::SubmitterRunFailed(run_failure) => {
            gettext("The report was not sent: {error}").replace("{error}", &run_failure.to_string())
        }
        ClamsubmitFailure::UploadTimedOut(_elapsed) => {
            gettext("The report was not sent: the upload took too long")
        }
        ClamsubmitFailure::ReportedBySubmitter { submitter_output } => {
            gettext("The report was not sent: {error}")
                .replace("{error}", &sanitize_scanner_line(submitter_output))
        }
    }
}

#[cfg(test)]
mod clamav_report_submission_tests {
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
    fn a_false_positive_names_its_detection_and_sends_the_file_on_standard_input() {
        assert_eq!(
            submission_arguments(&ClamavReport {
                reporter_contact: contact("Alex Doe", " alex@example.org "),
                report_kind: ClamavReportKind::FalsePositive {
                    detection_name: "Win.Test.EICAR_HDB-1".to_owned(),
                },
            }),
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

    #[test]
    fn missed_malware_is_reported_with_n_and_without_a_detection_name() {
        let submitted_arguments = submission_arguments(&ClamavReport {
            reporter_contact: contact("Alex Doe", "alex@example.org"),
            report_kind: ClamavReportKind::MissedMalware,
        });
        assert_eq!(
            submitted_arguments,
            ["-e", "alex@example.org", "-N", "Alex Doe", "-n", "-"]
        );
        assert!(!submitted_arguments.iter().any(|argument| argument == "-V"));
        assert!(!submitted_arguments.iter().any(|argument| argument == "-p"));
    }

    #[tokio::test]
    async fn an_incomplete_contact_is_refused_before_anything_runs() {
        assert!(matches!(
            submit_clamav_report(
                &ClamavReport {
                    reporter_contact: contact("", "alex@example.org"),
                    report_kind: ClamavReportKind::MissedMalware,
                },
                b"sample".to_vec(),
            )
            .await,
            Err(ClamsubmitFailure::ContactIncomplete)
        ));
    }
}
