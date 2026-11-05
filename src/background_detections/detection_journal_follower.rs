use std::thread;

use futures::{Stream, stream};
use systemd::journal::Journal;
use tokio::sync::mpsc::{self, UnboundedSender};

use crate::{
    background_detections::detection_journal_records::{
        JournalDetectionRecord, ON_ACCESS_SERVICE_UNITS, SCHEDULED_SCAN_SERVICE_UNITS,
        detection_record_from_fields,
    },
    systemd_journal::unit_journal_reader::{journal_field_text, open_system_journal},
};

const FOLLOWER_THREAD_NAME: &str = "detection-journal";
const SYSTEMD_UNIT_FIELD: &str = "_SYSTEMD_UNIT";
const MESSAGE_FIELD: &str = "MESSAGE";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalStartPosition {
    FromOldestEntry,
    AfterCursor { journal_cursor: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalAccess {
    FollowingJournal,
    JournalUnreadable,
    FollowingFailed { failure_text: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectionJournalEvent {
    DetectionObserved {
        detection_record: JournalDetectionRecord,
        journal_cursor: String,
    },
    JournalUnreadable,
    FollowingStopped {
        failure_text: String,
    },
}

fn journal_has_readable_files(journal: &Journal) -> systemd::Result<bool> {
    Ok(journal.has_persistent_files()? || journal.has_runtime_files()?)
}

fn detection_at_position(journal: &mut Journal) -> systemd::Result<Option<JournalDetectionRecord>> {
    let systemd_unit = journal_field_text(journal, SYSTEMD_UNIT_FIELD)?;
    let realtime_microseconds = journal.timestamp_usec()?;
    let message_field = journal.get_data(MESSAGE_FIELD)?;
    let message_bytes = message_field
        .as_ref()
        .and_then(|entry_field| entry_field.value())
        .unwrap_or_default();
    Ok(detection_record_from_fields(
        &systemd_unit,
        message_bytes,
        realtime_microseconds,
    ))
}

fn follow_journal_entries(
    start_position: &JournalStartPosition,
    event_sender: &UnboundedSender<DetectionJournalEvent>,
) -> systemd::Result<()> {
    let mut journal = open_system_journal()?;
    if !journal_has_readable_files(&journal)? {
        let _receiver_gone = event_sender.send(DetectionJournalEvent::JournalUnreadable);
        return Ok(());
    }
    ON_ACCESS_SERVICE_UNITS
        .iter()
        .chain(&SCHEDULED_SCAN_SERVICE_UNITS)
        .try_for_each(|service_unit| {
            journal
                .match_add(SYSTEMD_UNIT_FIELD, *service_unit)
                .map(drop)
        })?;
    match start_position {
        JournalStartPosition::FromOldestEntry => journal.seek_head()?,
        JournalStartPosition::AfterCursor { journal_cursor } => {
            journal.seek_cursor(journal_cursor.as_str())?;
        }
    }
    let mut resumed_cursor = match start_position {
        JournalStartPosition::FromOldestEntry => None,
        JournalStartPosition::AfterCursor { journal_cursor } => Some(journal_cursor.as_str()),
    };
    loop {
        while journal.next()? > 0 {
            if let Some(journal_cursor) = resumed_cursor.take()
                && journal.test_cursor(journal_cursor)?
            {
                continue;
            }
            if let Some(detection_record) = detection_at_position(&mut journal)?
                && event_sender
                    .send(DetectionJournalEvent::DetectionObserved {
                        detection_record,
                        journal_cursor: journal.cursor()?,
                    })
                    .is_err()
            {
                return Ok(());
            }
        }
        journal.wait(None)?;
        if event_sender.is_closed() {
            return Ok(());
        }
    }
}

pub fn detection_journal_events(
    start_position: JournalStartPosition,
) -> impl Stream<Item = DetectionJournalEvent> + Send + 'static {
    let (event_sender, event_receiver) = mpsc::unbounded_channel();
    let thread_sender = event_sender.clone();
    let spawn_outcome = thread::Builder::new()
        .name(FOLLOWER_THREAD_NAME.to_owned())
        .spawn(move || {
            if let Err(follow_failure) = follow_journal_entries(&start_position, &thread_sender) {
                let _receiver_gone = thread_sender.send(DetectionJournalEvent::FollowingStopped {
                    failure_text: follow_failure.to_string(),
                });
            }
        });
    if let Err(spawn_failure) = spawn_outcome {
        let _receiver_gone = event_sender.send(DetectionJournalEvent::FollowingStopped {
            failure_text: spawn_failure.to_string(),
        });
    }
    drop(event_sender);
    stream::unfold(event_receiver, |mut event_receiver| async move {
        event_receiver
            .recv()
            .await
            .map(|journal_event| (journal_event, event_receiver))
    })
}

#[cfg(test)]
mod detection_journal_follower_tests {
    use futures::StreamExt;

    use super::*;

    #[tokio::test]
    #[ignore = "reads the real host journal"]
    async fn host_journal_replays_on_access_detections() {
        let mut journal_events = Box::pin(detection_journal_events(
            JournalStartPosition::FromOldestEntry,
        ));
        let first_event =
            tokio::time::timeout(std::time::Duration::from_secs(10), journal_events.next()).await;
        println!("{first_event:?}");
        assert!(matches!(
            first_event,
            Ok(Some(DetectionJournalEvent::DetectionObserved { .. }))
        ));
    }
}
