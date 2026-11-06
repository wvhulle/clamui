use std::{os::unix::ffi::OsStrExt, path::Path};

use gettextrs::{gettext, ngettext};
use jiff::Timestamp;
use relm4::gtk::{gio, gio::prelude::*, glib::variant::ToVariant};

use crate::{
    APPLICATION_ID,
    detections_page::incident_timeline_presentation::signature_is_test_pattern,
    host_services::{
        activity_history::activity_history_database::ActivityHistoryFailure,
        clamav_scanner::scanner_output_parser::sanitize_scanner_line,
        desktop::stored_settings::application_settings,
        detection_journal::{
            detection_journal_follower::JournalStartPosition,
            detection_journal_records::{DetectionSource, JournalDetectionRecord},
        },
    },
};

pub const OPEN_DETECTION_ACTION: &str = "open-detection";
pub const OPEN_DETECTIONS_ACTION: &str = "open-detections";
const NOTIFICATIONS_ENABLED_KEY: &str = "notifications-enabled";
const MISSED_DETECTIONS_ID: &str = "missed-detections";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalReplay {
    FirstImport,
    AfterSavedCursor,
    MissedEntriesSkipped,
}

#[derive(Debug)]
pub enum JournalResume {
    FirstImport,
    AfterSavedCursor { journal_cursor: String },
    CursorUnreadable(ActivityHistoryFailure),
}

impl JournalResume {
    pub fn from_saved_cursor(saved_cursor: Result<Option<String>, ActivityHistoryFailure>) -> Self {
        match saved_cursor {
            Ok(Some(journal_cursor)) => Self::AfterSavedCursor { journal_cursor },
            Ok(None) => Self::FirstImport,
            Err(cursor_failure) => Self::CursorUnreadable(cursor_failure),
        }
    }

    pub fn start_position(&self) -> JournalStartPosition {
        match self {
            Self::FirstImport => JournalStartPosition::FromOldestEntry,
            Self::AfterSavedCursor { journal_cursor } => JournalStartPosition::AfterCursor {
                journal_cursor: journal_cursor.clone(),
            },
            Self::CursorUnreadable(_) => JournalStartPosition::FromNewestEntry,
        }
    }

    pub const fn journal_replay(&self) -> JournalReplay {
        match self {
            Self::FirstImport => JournalReplay::FirstImport,
            Self::AfterSavedCursor { .. } => JournalReplay::AfterSavedCursor,
            Self::CursorUnreadable(_) => JournalReplay::MissedEntriesSkipped,
        }
    }

    pub fn into_cursor_failure(self) -> Option<ActivityHistoryFailure> {
        match self {
            Self::FirstImport | Self::AfterSavedCursor { .. } => None,
            Self::CursorUnreadable(cursor_failure) => Some(cursor_failure),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectionAlert {
    LiveDetection {
        detection_record: JournalDetectionRecord,
    },
    MissedDetections {
        missed_count: usize,
    },
    MissedDetectionsUncountable,
}

pub fn plan_detection_alerts(
    newly_opened: &[JournalDetectionRecord],
    journal_replay: JournalReplay,
    application_started: Timestamp,
) -> Vec<DetectionAlert> {
    let (live_records, missed_records): (Vec<_>, Vec<_>) = newly_opened
        .iter()
        .partition(|detection_record| detection_record.observed_at >= application_started);
    let missed_count = missed_records
        .iter()
        .filter(|detection_record| !signature_is_test_pattern(&detection_record.signature_name))
        .count();
    let summarises_missed = match journal_replay {
        JournalReplay::AfterSavedCursor => true,
        JournalReplay::FirstImport | JournalReplay::MissedEntriesSkipped => false,
    };
    let missed_alert = (summarises_missed && missed_count > 0)
        .then_some(DetectionAlert::MissedDetections { missed_count });
    live_records
        .into_iter()
        .map(|detection_record| DetectionAlert::LiveDetection {
            detection_record: detection_record.clone(),
        })
        .chain(missed_alert)
        .collect()
}

fn live_detection_title(detection_record: &JournalDetectionRecord) -> String {
    let signature_text = sanitize_scanner_line(&detection_record.signature_name);
    match detection_record.detection_source {
        DetectionSource::OnAccessScanner => {
            gettext("Malware blocked: {signature}").replace("{signature}", &signature_text)
        }
        DetectionSource::ScheduledScan => {
            gettext("Malware found: {signature}").replace("{signature}", &signature_text)
        }
    }
}

pub fn live_detection_priority(
    detection_record: &JournalDetectionRecord,
) -> gio::NotificationPriority {
    if signature_is_test_pattern(&detection_record.signature_name) {
        gio::NotificationPriority::Normal
    } else {
        gio::NotificationPriority::Urgent
    }
}

fn live_detection_notification(detection_record: &JournalDetectionRecord) -> gio::Notification {
    let notification = gio::Notification::new(&live_detection_title(detection_record));
    notification.set_body(Some(&sanitize_scanner_line(
        &detection_record.file_path.to_string_lossy(),
    )));
    notification.set_priority(live_detection_priority(detection_record));
    notification.set_default_action_and_target_value(
        &format!("app.{OPEN_DETECTION_ACTION}"),
        Some(
            &detection_record
                .file_path
                .as_os_str()
                .as_bytes()
                .to_vec()
                .to_variant(),
        ),
    );
    notification
}

fn missed_detections_notification(missed_count: usize) -> gio::Notification {
    let notification = gio::Notification::new(
        &ngettext(
            "{count} detection while Lazaret wasn't running",
            "{count} detections while Lazaret wasn't running",
            u32::try_from(missed_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &missed_count.to_string()),
    );
    notification.set_priority(gio::NotificationPriority::Urgent);
    notification.set_default_action(&format!("app.{OPEN_DETECTIONS_ACTION}"));
    notification
}

fn uncountable_missed_detections_notification() -> gio::Notification {
    let notification = gio::Notification::new(&gettext(
        "Detections while Lazaret wasn't running can't be counted",
    ));
    notification.set_body(Some(&gettext(
        "Lazaret couldn't read where it stopped following the system journal, so it only watches \
         for new detections. Check the Detections page and the system journal for anything found \
         while it was closed.",
    )));
    notification.set_priority(gio::NotificationPriority::Urgent);
    notification.set_default_action(&format!("app.{OPEN_DETECTIONS_ACTION}"));
    notification
}

fn live_notification_id(file_path: &Path) -> String {
    format!(
        "{APPLICATION_ID}.detection.{}",
        hex::encode(file_path.as_os_str().as_bytes())
    )
}

pub fn withdraw_detection_alert(file_path: &Path) {
    relm4::main_application().withdraw_notification(&live_notification_id(file_path));
}

pub fn send_detection_alerts(detection_alerts: &[DetectionAlert]) {
    if !application_settings().boolean(NOTIFICATIONS_ENABLED_KEY) {
        return;
    }
    let main_application = relm4::main_application();
    detection_alerts
        .iter()
        .for_each(|detection_alert| match detection_alert {
            DetectionAlert::LiveDetection { detection_record } => {
                main_application.send_notification(
                    Some(&live_notification_id(&detection_record.file_path)),
                    &live_detection_notification(detection_record),
                );
            }
            DetectionAlert::MissedDetections { missed_count } => {
                main_application.send_notification(
                    Some(MISSED_DETECTIONS_ID),
                    &missed_detections_notification(*missed_count),
                );
            }
            DetectionAlert::MissedDetectionsUncountable => {
                main_application.send_notification(
                    Some(MISSED_DETECTIONS_ID),
                    &uncountable_missed_detections_notification(),
                );
            }
        });
}

#[cfg(test)]
mod detection_alerts_tests {
    use std::path::PathBuf;

    use super::*;

    const STARTED_AT: Timestamp = Timestamp::constant(1_793_869_222, 0);

    fn detection_record(observed_at: Timestamp, signature_name: &str) -> JournalDetectionRecord {
        JournalDetectionRecord {
            observed_at,
            detection_source: DetectionSource::OnAccessScanner,
            file_path: PathBuf::from("/home/user/Downloads/invoice.exe"),
            signature_name: signature_name.to_owned(),
        }
    }

    #[test]
    fn the_first_import_of_old_history_raises_no_alert() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(
                    STARTED_AT - jiff::SignedDuration::from_secs(900),
                    "Win.Test-1"
                )],
                JournalReplay::FirstImport,
                STARTED_AT,
            ),
            vec![]
        );
    }

    #[test]
    fn detections_missed_while_closed_are_summarised_once() {
        assert_eq!(
            plan_detection_alerts(
                &[
                    detection_record(
                        STARTED_AT - jiff::SignedDuration::from_secs(900),
                        "Win.Test-1"
                    ),
                    detection_record(
                        STARTED_AT - jiff::SignedDuration::from_secs(800),
                        "Win.Test-2"
                    ),
                ],
                JournalReplay::AfterSavedCursor,
                STARTED_AT,
            ),
            vec![DetectionAlert::MissedDetections { missed_count: 2 }]
        );
    }

    fn cursor_failure() -> ActivityHistoryFailure {
        ActivityHistoryFailure::HistoryLockUnavailable(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))
    }

    #[test]
    fn a_saved_cursor_resumes_after_it_and_summarises_missed_detections() {
        let journal_resume = JournalResume::from_saved_cursor(Ok(Some("s=1".to_owned())));
        assert_eq!(
            journal_resume.start_position(),
            JournalStartPosition::AfterCursor {
                journal_cursor: "s=1".to_owned()
            }
        );
        assert_eq!(
            journal_resume.journal_replay(),
            JournalReplay::AfterSavedCursor
        );
        assert!(journal_resume.into_cursor_failure().is_none());
    }

    #[test]
    fn no_saved_cursor_imports_the_whole_journal_quietly() {
        let journal_resume = JournalResume::from_saved_cursor(Ok(None));
        assert_eq!(
            journal_resume.start_position(),
            JournalStartPosition::FromOldestEntry
        );
        assert_eq!(journal_resume.journal_replay(), JournalReplay::FirstImport);
    }

    #[test]
    fn an_unreadable_cursor_follows_new_entries_and_warns_instead_of_replaying() {
        let journal_resume = JournalResume::from_saved_cursor(Err(cursor_failure()));
        assert_eq!(
            journal_resume.start_position(),
            JournalStartPosition::FromNewestEntry
        );
        assert_eq!(
            journal_resume.journal_replay(),
            JournalReplay::MissedEntriesSkipped
        );
        assert!(matches!(
            journal_resume.into_cursor_failure(),
            Some(ActivityHistoryFailure::HistoryLockUnavailable(_))
        ));
    }

    #[test]
    fn live_detections_still_alert_after_an_unreadable_cursor() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(
                    STARTED_AT + jiff::SignedDuration::from_secs(5),
                    "Win.Test-1"
                )],
                JournalReplay::MissedEntriesSkipped,
                STARTED_AT,
            )
            .len(),
            1
        );
    }

    #[test]
    fn missed_test_patterns_are_not_worth_a_summary() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(
                    STARTED_AT - jiff::SignedDuration::from_secs(900),
                    "Eicar-Test-Signature"
                )],
                JournalReplay::AfterSavedCursor,
                STARTED_AT,
            ),
            vec![]
        );
    }

    #[test]
    fn live_detections_alert_individually_even_during_the_first_import() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(
                    STARTED_AT + jiff::SignedDuration::from_secs(5),
                    "Win.Test-1"
                )],
                JournalReplay::FirstImport,
                STARTED_AT,
            )
            .len(),
            1
        );
    }

    #[test]
    fn only_real_signatures_are_urgent() {
        assert_eq!(
            live_detection_priority(&detection_record(STARTED_AT, "Win.Test-1")),
            gio::NotificationPriority::Urgent
        );
        assert_eq!(
            live_detection_priority(&detection_record(STARTED_AT, "Eicar-Test-Signature")),
            gio::NotificationPriority::Normal
        );
    }

    #[test]
    fn scheduled_finds_do_not_claim_the_file_was_blocked() {
        let scheduled_record = JournalDetectionRecord {
            detection_source: DetectionSource::ScheduledScan,
            ..detection_record(STARTED_AT, "Win.Test-1")
        };
        assert_eq!(
            live_detection_title(&scheduled_record),
            "Malware found: Win.Test-1"
        );
    }
}
