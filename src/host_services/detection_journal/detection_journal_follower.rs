use std::io;

use futures::Stream;
use jiff::Timestamp;
use systemd::journal::Journal;

use crate::host_services::{
    blocking_iterator_stream::blocking_iterator_stream,
    detection_journal::detection_journal_records::{
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
    FromNewestEntry,
    AfterCursor { journal_cursor: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalAccess {
    FollowingJournal,
    JournalUnreadable,
    FollowingFailed(JournalFollowFailure),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum JournalFollowFailure {
    #[error("the journal could not be read: {read_failure_kind}")]
    JournalReadFailed { read_failure_kind: io::ErrorKind },
    #[error("a journal entry has a timestamp outside the supported range")]
    EntryTimestampInvalid,
    #[error("the journal reader thread could not start: {spawn_failure_kind}")]
    ReaderThreadFailed { spawn_failure_kind: io::ErrorKind },
}

impl From<systemd::Error> for JournalFollowFailure {
    fn from(journal_failure: systemd::Error) -> Self {
        Self::JournalReadFailed {
            read_failure_kind: journal_failure.kind(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectionJournalEvent {
    DetectionObserved {
        detection_record: JournalDetectionRecord,
        journal_cursor: String,
    },
    JournalUnreadable,
    FollowingStopped(JournalFollowFailure),
}

fn journal_has_readable_files(journal: &Journal) -> systemd::Result<bool> {
    Ok(journal.has_persistent_files()? || journal.has_runtime_files()?)
}

fn detection_at_position(
    journal: &mut Journal,
) -> Result<Option<JournalDetectionRecord>, JournalFollowFailure> {
    let systemd_unit = journal_field_text(journal, SYSTEMD_UNIT_FIELD)?;
    let Ok(observed_at) = Timestamp::try_from(journal.timestamp()?) else {
        return Err(JournalFollowFailure::EntryTimestampInvalid);
    };
    let message_field = journal.get_data(MESSAGE_FIELD)?;
    let message_bytes = message_field
        .as_ref()
        .and_then(|entry_field| entry_field.value())
        .unwrap_or_default();
    Ok(detection_record_from_fields(
        &systemd_unit,
        message_bytes,
        observed_at,
    ))
}

enum SkippedResumeCursor {
    NothingToSkip,
    SkipFirstEntryAt(String),
}

enum FollowerState {
    NotOpened {
        start_position: JournalStartPosition,
    },
    Following {
        journal: Journal,
        skipped_resume_cursor: SkippedResumeCursor,
    },
    Stopped,
}

struct FollowedDetections {
    follower_state: FollowerState,
}

fn opened_detection_journal(
    start_position: &JournalStartPosition,
) -> Result<Option<Journal>, JournalFollowFailure> {
    let mut journal = open_system_journal()?;
    if !journal_has_readable_files(&journal)? {
        return Ok(None);
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
        JournalStartPosition::FromNewestEntry => {
            journal.seek_tail()?;
            journal.previous()?;
        }
        JournalStartPosition::AfterCursor { journal_cursor } => {
            journal.seek_cursor(journal_cursor.as_str())?;
        }
    }
    Ok(Some(journal))
}

fn next_followed_detection(
    journal: &mut Journal,
    skipped_resume_cursor: &mut SkippedResumeCursor,
) -> Result<DetectionJournalEvent, JournalFollowFailure> {
    loop {
        if journal.next()? == 0 {
            journal.wait(None)?;
            continue;
        }
        if let SkippedResumeCursor::SkipFirstEntryAt(journal_cursor) =
            std::mem::replace(skipped_resume_cursor, SkippedResumeCursor::NothingToSkip)
            && journal.test_cursor(&journal_cursor)?
        {
            continue;
        }
        if let Some(detection_record) = detection_at_position(journal)? {
            return Ok(DetectionJournalEvent::DetectionObserved {
                detection_record,
                journal_cursor: journal.cursor()?,
            });
        }
    }
}

impl Iterator for FollowedDetections {
    type Item = DetectionJournalEvent;

    fn next(&mut self) -> Option<DetectionJournalEvent> {
        match std::mem::replace(&mut self.follower_state, FollowerState::Stopped) {
            FollowerState::Stopped => None,
            FollowerState::NotOpened { start_position } => {
                match opened_detection_journal(&start_position) {
                    Ok(Some(journal)) => {
                        self.follower_state = FollowerState::Following {
                            journal,
                            skipped_resume_cursor: match start_position {
                                JournalStartPosition::FromOldestEntry
                                | JournalStartPosition::FromNewestEntry => {
                                    SkippedResumeCursor::NothingToSkip
                                }
                                JournalStartPosition::AfterCursor { journal_cursor } => {
                                    SkippedResumeCursor::SkipFirstEntryAt(journal_cursor)
                                }
                            },
                        };
                        self.next()
                    }
                    Ok(None) => Some(DetectionJournalEvent::JournalUnreadable),
                    Err(open_failure) => {
                        Some(DetectionJournalEvent::FollowingStopped(open_failure))
                    }
                }
            }
            FollowerState::Following {
                mut journal,
                mut skipped_resume_cursor,
            } => match next_followed_detection(&mut journal, &mut skipped_resume_cursor) {
                Ok(journal_event) => {
                    self.follower_state = FollowerState::Following {
                        journal,
                        skipped_resume_cursor,
                    };
                    Some(journal_event)
                }
                Err(follow_failure) => {
                    Some(DetectionJournalEvent::FollowingStopped(follow_failure))
                }
            },
        }
    }
}

pub fn detection_journal_events(
    start_position: JournalStartPosition,
) -> impl Stream<Item = DetectionJournalEvent> + Send + 'static {
    blocking_iterator_stream(
        FOLLOWER_THREAD_NAME,
        move || FollowedDetections {
            follower_state: FollowerState::NotOpened { start_position },
        },
        |spawn_failure| {
            DetectionJournalEvent::FollowingStopped(JournalFollowFailure::ReaderThreadFailed {
                spawn_failure_kind: spawn_failure.kind(),
            })
        },
    )
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
