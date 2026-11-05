use std::{os::unix::ffi::OsStrExt, path::Path};

use gettextrs::{gettext, ngettext};
use relm4::gtk::{gio, gio::prelude::*, glib::variant::ToVariant};

use crate::{
    APPLICATION_ID,
    application_settings::preferences_dialog::application_settings,
    background_detections::{
        detection_journal_records::{DetectionSource, JournalDetectionRecord},
        incident_timeline_presentation::signature_is_test_pattern,
    },
    malware_scan::scanner_output_parser::sanitize_scanner_line,
};

pub const OPEN_DETECTION_ACTION: &str = "open-detection";
pub const OPEN_DETECTIONS_ACTION: &str = "open-detections";
const NOTIFICATIONS_ENABLED_KEY: &str = "notifications-enabled";
const MISSED_DETECTIONS_ID: &str = "missed-detections";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalReplay {
    FirstImport,
    AfterSavedCursor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectionAlert {
    LiveDetection {
        detection_record: JournalDetectionRecord,
    },
    MissedDetections {
        missed_count: usize,
    },
}

pub fn plan_detection_alerts(
    newly_opened: &[JournalDetectionRecord],
    journal_replay: JournalReplay,
    application_started_unix: i64,
) -> Vec<DetectionAlert> {
    let (live_records, missed_records): (Vec<_>, Vec<_>) =
        newly_opened.iter().partition(|detection_record| {
            detection_record.observed_at_unix >= application_started_unix
        });
    let missed_count = missed_records
        .iter()
        .filter(|detection_record| !signature_is_test_pattern(&detection_record.signature_name))
        .count();
    let missed_alert = (journal_replay == JournalReplay::AfterSavedCursor && missed_count > 0)
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
            "{count} detection while ClamUI wasn't running",
            "{count} detections while ClamUI wasn't running",
            u32::try_from(missed_count).unwrap_or(u32::MAX),
        )
        .replace("{count}", &missed_count.to_string()),
    );
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
        });
}

#[cfg(test)]
mod detection_alerts_tests {
    use std::path::PathBuf;

    use super::*;

    const STARTED_UNIX: i64 = 1_793_869_222;

    fn detection_record(observed_at_unix: i64, signature_name: &str) -> JournalDetectionRecord {
        JournalDetectionRecord {
            observed_at_unix,
            detection_source: DetectionSource::OnAccessScanner,
            file_path: PathBuf::from("/home/user/Downloads/invoice.exe"),
            signature_name: signature_name.to_owned(),
        }
    }

    #[test]
    fn the_first_import_of_old_history_raises_no_alert() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(STARTED_UNIX - 900, "Win.Test-1")],
                JournalReplay::FirstImport,
                STARTED_UNIX,
            ),
            vec![]
        );
    }

    #[test]
    fn detections_missed_while_closed_are_summarised_once() {
        assert_eq!(
            plan_detection_alerts(
                &[
                    detection_record(STARTED_UNIX - 900, "Win.Test-1"),
                    detection_record(STARTED_UNIX - 800, "Win.Test-2"),
                ],
                JournalReplay::AfterSavedCursor,
                STARTED_UNIX,
            ),
            vec![DetectionAlert::MissedDetections { missed_count: 2 }]
        );
    }

    #[test]
    fn missed_test_patterns_are_not_worth_a_summary() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(STARTED_UNIX - 900, "Eicar-Test-Signature")],
                JournalReplay::AfterSavedCursor,
                STARTED_UNIX,
            ),
            vec![]
        );
    }

    #[test]
    fn live_detections_alert_individually_even_during_the_first_import() {
        assert_eq!(
            plan_detection_alerts(
                &[detection_record(STARTED_UNIX + 5, "Win.Test-1")],
                JournalReplay::FirstImport,
                STARTED_UNIX,
            )
            .len(),
            1
        );
    }

    #[test]
    fn only_real_signatures_are_urgent() {
        assert_eq!(
            live_detection_priority(&detection_record(STARTED_UNIX, "Win.Test-1")),
            gio::NotificationPriority::Urgent
        );
        assert_eq!(
            live_detection_priority(&detection_record(STARTED_UNIX, "Eicar-Test-Signature")),
            gio::NotificationPriority::Normal
        );
    }

    #[test]
    fn scheduled_finds_do_not_claim_the_file_was_blocked() {
        let scheduled_record = JournalDetectionRecord {
            detection_source: DetectionSource::ScheduledScan,
            ..detection_record(STARTED_UNIX, "Win.Test-1")
        };
        assert_eq!(
            live_detection_title(&scheduled_record),
            "Malware found: Win.Test-1"
        );
    }
}
