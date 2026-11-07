use gettextrs::{gettext, ngettext};

use crate::{
    host_services::{
        activity_history::{
            activity_history_database::ActivityHistoryFailure,
            submission_history_store::{
                BazaarSampleStatus, SubmissionRecord, SubmissionState, VirusTotalSampleStatus,
            },
        },
        clamav_programs::clamav_report_submission::clamsubmit_failure_text,
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::locale_formatting::{byte_size_text, exact_local_time_text},
        sample_submissions::{
            bazaar_sample_upload::BazaarUploadAttempt, clamav_report_flow::ClamavReportAttempt,
            submission_samples::SampleReadFailure,
            virustotal_sample_upload::VirusTotalUploadAttempt,
        },
        threat_intel::{
            file_reputation_check::{describe_bazaar_failure, describe_virustotal_failure},
            service_key_storage::describe_key_failure,
        },
    },
    shared_widgets::{
        database_migration_failure_text::describe_history_failure,
        quarantine_failure_text::describe_quarantine_failure,
    },
};

pub fn sample_read_failure_text(read_failure: &SampleReadFailure) -> String {
    match read_failure {
        SampleReadFailure::QuarantinedCopyUnreadable(quarantine_failure) => {
            describe_quarantine_failure(quarantine_failure)
        }
        SampleReadFailure::FileUnreadable(read_failure) => {
            gettext("The file could not be read: {error}")
                .replace("{error}", &read_failure.to_string())
        }
        SampleReadFailure::FileNotRegular => gettext("Only regular files can be sent"),
        SampleReadFailure::FileTooLarge { maximum_size } => {
            gettext("The file is larger than {size}, the most Lazaret sends.")
                .replace("{size}", &byte_size_text(*maximum_size))
        }
        SampleReadFailure::ReadingInterrupted(_interrupted_task) => {
            gettext("Reading the file stopped unexpectedly")
        }
    }
}

pub fn history_failure_text(history_failure: &ActivityHistoryFailure) -> String {
    gettext("The submission history could not be read: {error}")
        .replace("{error}", &describe_history_failure(history_failure))
}

pub fn earlier_submission_text(earlier_submission: &SubmissionRecord) -> String {
    gettext("This file was already sent on {time}. Nothing was sent again.").replace(
        "{time}",
        &exact_local_time_text(earlier_submission.submitted_at),
    )
}

pub fn clamav_report_attempt_text(report_attempt: &ClamavReportAttempt) -> String {
    match report_attempt {
        ClamavReportAttempt::ReportRecorded(_recorded_submission) => gettext(
            "Report sent. ClamAV's review takes at least 48 hours; Submissions shows when a \
             signature update changes the verdict.",
        ),
        ClamavReportAttempt::AlreadyReported(earlier_submission) => {
            earlier_submission_text(earlier_submission)
        }
        ClamavReportAttempt::SampleUnreadable(read_failure) => {
            gettext("The report was not sent: {error}")
                .replace("{error}", &sample_read_failure_text(read_failure))
        }
        ClamavReportAttempt::ReportNotSent(clamsubmit_failure) => {
            clamsubmit_failure_text(clamsubmit_failure)
        }
        ClamavReportAttempt::HistoryUnavailable(history_failure) => {
            gettext("The report was not sent: {error}")
                .replace("{error}", &history_failure_text(history_failure))
        }
        ClamavReportAttempt::ReportSentWithoutRecord(history_failure) => {
            gettext("Report sent, but it could not be added to Submissions: {error}")
                .replace("{error}", &describe_history_failure(history_failure))
        }
    }
}

fn upload_not_sent(failure_reason: &str) -> String {
    gettext("Nothing was uploaded: {error}").replace("{error}", failure_reason)
}

pub fn bazaar_upload_attempt_text(upload_attempt: &BazaarUploadAttempt) -> String {
    match upload_attempt {
        BazaarUploadAttempt::SubmissionRecorded(SubmissionRecord {
            submission_state:
                SubmissionState::MalwareBazaarSample {
                    bazaar_status: BazaarSampleStatus::SubmissionRefused { refusal_reason },
                },
            ..
        }) => gettext("MalwareBazaar refused the sample: {reason}")
            .replace("{reason}", &sanitize_scanner_line(refusal_reason)),
        BazaarUploadAttempt::SubmissionRecorded(_recorded_submission) => {
            gettext("MalwareBazaar has the sample. Submissions links to its public entry.")
        }
        BazaarUploadAttempt::AlreadySubmitted(earlier_submission) => {
            earlier_submission_text(earlier_submission)
        }
        BazaarUploadAttempt::KeyMissing => upload_not_sent(&gettext(
            "add an abuse.ch key on the Submissions page first",
        )),
        BazaarUploadAttempt::KeyUnreadable(key_failure) => {
            upload_not_sent(&describe_key_failure(key_failure))
        }
        BazaarUploadAttempt::SampleUnreadable(read_failure) => {
            upload_not_sent(&sample_read_failure_text(read_failure))
        }
        BazaarUploadAttempt::NotDetectedByClamav => upload_not_sent(&gettext(
            "MalwareBazaar only takes files a ClamAV signature detected",
        )),
        BazaarUploadAttempt::UnwantedProgramOnly => upload_not_sent(&gettext(
            "MalwareBazaar doesn't take potentially unwanted programs, only malware",
        )),
        BazaarUploadAttempt::BazaarUnavailable(bazaar_failure) => {
            upload_not_sent(&describe_bazaar_failure(bazaar_failure))
        }
        BazaarUploadAttempt::HistoryUnavailable(history_failure) => {
            upload_not_sent(&history_failure_text(history_failure))
        }
        BazaarUploadAttempt::SentWithoutRecord(history_failure) => {
            gettext("Uploaded, but it could not be added to Submissions: {error}")
                .replace("{error}", &describe_history_failure(history_failure))
        }
    }
}

pub fn virustotal_upload_attempt_text(upload_attempt: &VirusTotalUploadAttempt) -> String {
    match upload_attempt {
        VirusTotalUploadAttempt::SubmissionRecorded(SubmissionRecord {
            submission_state:
                SubmissionState::VirusTotalSample {
                    virustotal_status: VirusTotalSampleStatus::SubmissionRefused { refusal_reason },
                },
            ..
        }) => gettext("VirusTotal refused the file: {reason}")
            .replace("{reason}", &sanitize_scanner_line(refusal_reason)),
        VirusTotalUploadAttempt::SubmissionRecorded(_recorded_submission) => gettext(
            "VirusTotal is analysing the file. Refresh on the Submissions page shows its verdict.",
        ),
        VirusTotalUploadAttempt::AlreadySubmitted(earlier_submission) => {
            earlier_submission_text(earlier_submission)
        }
        VirusTotalUploadAttempt::ReportAlreadyAvailable(file_report) => ngettext(
            "VirusTotal already knows this file: {count} of {total} engine detects it. Nothing \
             was uploaded.",
            "VirusTotal already knows this file: {count} of {total} engines detect it. Nothing \
             was uploaded.",
            u32::try_from(file_report.total_engine_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &file_report.detecting_engine_count.to_string())
        .replace("{total}", &file_report.total_engine_count.to_string()),
        VirusTotalUploadAttempt::KeyMissing => upload_not_sent(&gettext(
            "add a VirusTotal key on the Submissions page first",
        )),
        VirusTotalUploadAttempt::KeyUnreadable(key_failure) => {
            upload_not_sent(&describe_key_failure(key_failure))
        }
        VirusTotalUploadAttempt::SampleUnreadable(read_failure) => {
            upload_not_sent(&sample_read_failure_text(read_failure))
        }
        VirusTotalUploadAttempt::VirusTotalUnavailable(virustotal_failure) => {
            upload_not_sent(&describe_virustotal_failure(virustotal_failure))
        }
        VirusTotalUploadAttempt::HistoryUnavailable(history_failure) => {
            upload_not_sent(&history_failure_text(history_failure))
        }
        VirusTotalUploadAttempt::SentWithoutRecord(history_failure) => {
            gettext("Uploaded, but it could not be added to Submissions: {error}")
                .replace("{error}", &describe_history_failure(history_failure))
        }
    }
}
