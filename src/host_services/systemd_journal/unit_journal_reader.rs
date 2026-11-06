use std::io;

use jiff::Timestamp;
use systemd::journal::{Journal, OpenOptions};
use tokio::task::{JoinError, spawn_blocking};

const MESSAGE_FIELD: &str = "MESSAGE";
const SYSTEMD_UNIT_FIELD: &str = "_SYSTEMD_UNIT";
const MANAGER_UNIT_FIELD: &str = "UNIT";
const SENDER_PROCESS_FIELD: &str = "_PID";
const SERVICE_MANAGER_PROCESS: &str = "1";
const UNIT_DEACTIVATED_MESSAGE: &str = "7ad2d189f7e94e70a38c781354912448";
const PROCESS_EXITED_MESSAGE: &str = "98e322203f7a4ed290d09fe03c09fe15";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UnitJournalReadFailure {
    #[error("the system journal could not be read: {failure_kind}")]
    JournalReadFailed { failure_kind: io::ErrorKind },
    #[error("the task reading the system journal stopped before it finished")]
    ReadingTaskInterrupted,
}

impl From<systemd::Error> for UnitJournalReadFailure {
    fn from(journal_failure: systemd::Error) -> Self {
        Self::JournalReadFailed {
            failure_kind: journal_failure.kind(),
        }
    }
}

impl From<JoinError> for UnitJournalReadFailure {
    fn from(_interrupted_task: JoinError) -> Self {
        Self::ReadingTaskInterrupted
    }
}

pub async fn read_journal_off_thread<JournalAnswer: Send + 'static>(
    read_journal: impl FnOnce() -> systemd::Result<JournalAnswer> + Send + 'static,
) -> Result<JournalAnswer, UnitJournalReadFailure> {
    Ok(spawn_blocking(read_journal).await??)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JournalProcessExit {
    ExitedWithStatus {
        exit_status: i32,
    },
    KilledBySignal {
        signal_name: String,
    },
    DumpedCore {
        signal_name: String,
    },
    UnrecognizedExit {
        exit_code_field: String,
        exit_status_field: String,
    },
    ExitFieldsMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnitJournalEvent {
    UnitDeactivated,
    MainProcessExited(JournalProcessExit),
    UnrecognizedMessage { message_id: String },
    MessageIdMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagerUnitRecord {
    pub recorded_at: Timestamp,
    pub unit_journal_event: UnitJournalEvent,
}

pub fn classify_process_exit(exit_code_field: &str, exit_status_field: &str) -> JournalProcessExit {
    match exit_code_field {
        "exited" => exit_status_field.parse().map_or_else(
            |_unparsable_status| JournalProcessExit::UnrecognizedExit {
                exit_code_field: exit_code_field.to_owned(),
                exit_status_field: exit_status_field.to_owned(),
            },
            |exit_status| JournalProcessExit::ExitedWithStatus { exit_status },
        ),
        "killed" => JournalProcessExit::KilledBySignal {
            signal_name: exit_status_field.to_owned(),
        },
        "dumped" => JournalProcessExit::DumpedCore {
            signal_name: exit_status_field.to_owned(),
        },
        unrecognized_code => JournalProcessExit::UnrecognizedExit {
            exit_code_field: unrecognized_code.to_owned(),
            exit_status_field: exit_status_field.to_owned(),
        },
    }
}

pub fn classify_unit_journal_event(
    message_id: &str,
    process_exit: JournalProcessExit,
) -> UnitJournalEvent {
    match message_id {
        UNIT_DEACTIVATED_MESSAGE => UnitJournalEvent::UnitDeactivated,
        PROCESS_EXITED_MESSAGE => UnitJournalEvent::MainProcessExited(process_exit),
        unrecognized_id => UnitJournalEvent::UnrecognizedMessage {
            message_id: unrecognized_id.to_owned(),
        },
    }
}

pub fn open_system_journal() -> systemd::Result<Journal> {
    OpenOptions::default()
        .system(true)
        .current_user(false)
        .local_only(true)
        .open()
}

pub fn journal_field_value(
    journal: &mut Journal,
    field_name: &str,
) -> systemd::Result<Option<String>> {
    Ok(journal.get_data(field_name)?.and_then(|entry_field| {
        entry_field
            .value()
            .map(|field_value| String::from_utf8_lossy(field_value).into_owned())
    }))
}

fn process_exit_at_position(journal: &mut Journal) -> systemd::Result<JournalProcessExit> {
    Ok(
        match (
            journal_field_value(journal, "EXIT_CODE")?,
            journal_field_value(journal, "EXIT_STATUS")?,
        ) {
            (Some(exit_code_field), Some(exit_status_field)) => {
                classify_process_exit(&exit_code_field, &exit_status_field)
            }
            (None, _) | (_, None) => JournalProcessExit::ExitFieldsMissing,
        },
    )
}

fn manager_record_at_position(journal: &mut Journal) -> systemd::Result<ManagerUnitRecord> {
    let process_exit = process_exit_at_position(journal)?;
    Ok(ManagerUnitRecord {
        recorded_at: Timestamp::try_from(journal.timestamp()?).map_err(io::Error::other)?,
        unit_journal_event: match journal_field_value(journal, "MESSAGE_ID")? {
            Some(message_id) => classify_unit_journal_event(&message_id, process_exit),
            None => UnitJournalEvent::MessageIdMissing,
        },
    })
}

pub fn newest_manager_records_for_unit(
    service_unit: &str,
    record_limit: usize,
) -> systemd::Result<Vec<ManagerUnitRecord>> {
    let mut journal = open_system_journal()?;
    journal.match_add(MANAGER_UNIT_FIELD, service_unit)?;
    journal.match_add(SENDER_PROCESS_FIELD, SERVICE_MANAGER_PROCESS)?;
    journal.seek_tail()?;
    let mut manager_records = Vec::new();
    while manager_records.len() < record_limit && journal.previous()? > 0 {
        manager_records.push(manager_record_at_position(&mut journal)?);
    }
    Ok(manager_records)
}

fn add_unit_matches(journal: &mut Journal, service_units: &[&str]) -> systemd::Result<()> {
    service_units.iter().try_for_each(|service_unit| {
        journal
            .match_add(SYSTEMD_UNIT_FIELD, *service_unit)
            .map(drop)
    })
}

pub fn newest_unit_messages(
    service_units: &[&str],
    line_limit: usize,
) -> systemd::Result<Vec<String>> {
    let mut journal = open_system_journal()?;
    add_unit_matches(&mut journal, service_units)?;
    journal.seek_tail()?;
    let mut newest_first = Vec::new();
    while newest_first.len() < line_limit && journal.previous()? > 0 {
        newest_first.extend(journal_field_value(&mut journal, MESSAGE_FIELD)?);
    }
    newest_first.reverse();
    Ok(newest_first)
}

pub fn unit_messages_since(
    service_unit: &str,
    since_moment: Timestamp,
) -> systemd::Result<Vec<String>> {
    let mut journal = open_system_journal()?;
    add_unit_matches(&mut journal, &[service_unit])?;
    journal.seek_realtime_usec(
        u64::try_from(since_moment.as_microsecond()).map_err(io::Error::other)?,
    )?;
    let mut unit_messages = Vec::new();
    while journal.next()? > 0 {
        unit_messages.extend(journal_field_value(&mut journal, MESSAGE_FIELD)?);
    }
    Ok(unit_messages)
}

fn followed_unit_journal(service_units: &[&str]) -> systemd::Result<Journal> {
    let mut journal = open_system_journal()?;
    add_unit_matches(&mut journal, service_units)?;
    journal.seek_tail()?;
    journal.previous()?;
    Ok(journal)
}

fn next_unit_append(journal: &mut Journal) -> systemd::Result<()> {
    loop {
        if journal.next()? > 0 {
            while journal.next()? > 0 {}
            return Ok(());
        }
        journal.wait(None)?;
    }
}

pub fn appended_unit_entries(service_units: &[&str]) -> impl Iterator<Item = ()> + use<> {
    followed_unit_journal(service_units)
        .into_iter()
        .flat_map(|mut journal| std::iter::from_fn(move || next_unit_append(&mut journal).ok()))
}

#[cfg(test)]
mod unit_journal_reader_tests {
    use super::*;

    #[test]
    fn manager_messages_become_typed_unit_events() {
        assert_eq!(
            classify_unit_journal_event(
                UNIT_DEACTIVATED_MESSAGE,
                JournalProcessExit::ExitFieldsMissing
            ),
            UnitJournalEvent::UnitDeactivated
        );
        assert_eq!(
            classify_unit_journal_event(
                PROCESS_EXITED_MESSAGE,
                classify_process_exit("exited", "1")
            ),
            UnitJournalEvent::MainProcessExited(JournalProcessExit::ExitedWithStatus {
                exit_status: 1
            })
        );
        assert_eq!(
            classify_unit_journal_event(
                PROCESS_EXITED_MESSAGE,
                classify_process_exit("killed", "TERM")
            ),
            UnitJournalEvent::MainProcessExited(JournalProcessExit::KilledBySignal {
                signal_name: "TERM".to_owned()
            })
        );
        assert_eq!(
            classify_unit_journal_event(
                PROCESS_EXITED_MESSAGE,
                classify_process_exit("dumped", "SEGV")
            ),
            UnitJournalEvent::MainProcessExited(JournalProcessExit::DumpedCore {
                signal_name: "SEGV".to_owned()
            })
        );
    }

    #[test]
    fn unrecognized_journal_values_keep_their_raw_text() {
        assert_eq!(
            classify_unit_journal_event("0123456789abcdef", JournalProcessExit::ExitFieldsMissing),
            UnitJournalEvent::UnrecognizedMessage {
                message_id: "0123456789abcdef".to_owned()
            }
        );
        assert_eq!(
            classify_unit_journal_event(
                PROCESS_EXITED_MESSAGE,
                classify_process_exit("trapped", "TRAP")
            ),
            UnitJournalEvent::MainProcessExited(JournalProcessExit::UnrecognizedExit {
                exit_code_field: "trapped".to_owned(),
                exit_status_field: "TRAP".to_owned()
            })
        );
        assert_eq!(
            classify_unit_journal_event(
                PROCESS_EXITED_MESSAGE,
                classify_process_exit("exited", "not-a-number")
            ),
            UnitJournalEvent::MainProcessExited(JournalProcessExit::UnrecognizedExit {
                exit_code_field: "exited".to_owned(),
                exit_status_field: "not-a-number".to_owned()
            })
        );
    }

    #[test]
    #[ignore = "reads the real host journal"]
    fn host_journal_returns_messages_in_chronological_order() {
        let daemon_messages =
            newest_unit_messages(&["clamav-daemon.service"], 5).expect("readable journal");
        assert!(daemon_messages.len() <= 5);
        println!("{daemon_messages:#?}");
    }
}
