use std::io;

use jiff::Timestamp;
use systemd::journal::{Journal, OpenOptions};

const MESSAGE_FIELD: &str = "MESSAGE";
const SYSTEMD_UNIT_FIELD: &str = "_SYSTEMD_UNIT";
const MANAGER_UNIT_FIELD: &str = "UNIT";
const SENDER_PROCESS_FIELD: &str = "_PID";
const SERVICE_MANAGER_PROCESS: &str = "1";
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ManagerUnitRecord {
    pub recorded_at: Timestamp,
    pub message_id: String,
    pub exit_code: String,
    pub exit_status: String,
}

pub fn open_system_journal() -> systemd::Result<Journal> {
    OpenOptions::default()
        .system(true)
        .current_user(false)
        .local_only(true)
        .open()
}

pub fn journal_field_text(journal: &mut Journal, field_name: &str) -> systemd::Result<String> {
    Ok(journal
        .get_data(field_name)?
        .and_then(|entry_field| {
            entry_field
                .value()
                .map(|field_value| String::from_utf8_lossy(field_value).into_owned())
        })
        .unwrap_or_default())
}

fn manager_record_at_position(journal: &mut Journal) -> systemd::Result<ManagerUnitRecord> {
    Ok(ManagerUnitRecord {
        recorded_at: Timestamp::try_from(journal.timestamp()?).map_err(io::Error::other)?,
        message_id: journal_field_text(journal, "MESSAGE_ID")?,
        exit_code: journal_field_text(journal, "EXIT_CODE")?,
        exit_status: journal_field_text(journal, "EXIT_STATUS")?,
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
        newest_first.push(journal_field_text(&mut journal, MESSAGE_FIELD)?);
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
        unit_messages.push(journal_field_text(&mut journal, MESSAGE_FIELD)?);
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
    #[ignore = "reads the real host journal"]
    fn host_journal_returns_messages_in_chronological_order() {
        let daemon_messages =
            newest_unit_messages(&["clamav-daemon.service"], 5).expect("readable journal");
        assert!(daemon_messages.len() <= 5);
        println!("{daemon_messages:#?}");
    }
}
