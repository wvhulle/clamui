use gettextrs::gettext;

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    systemd_journal::unit_journal_reader::{journal_field_text, open_system_journal},
};

const HELPER_SERVICE_UNIT: &str = "lazaret-settings-helper.service";
const SYSTEMD_UNIT_FIELD: &str = "_SYSTEMD_UNIT";
const SENDER_USER_FIELD: &str = "_UID";
const ROOT_USER_ID: &str = "0";
const MICROSECONDS_PER_SECOND: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditedOutcome {
    ActionApplied,
    ActionRolledBack,
    AuthorizationRefused,
    ActionFailed,
}

impl AuditedOutcome {
    fn from_field(outcome_field: &str) -> Self {
        match outcome_field {
            "applied" => Self::ActionApplied,
            "rolled-back" => Self::ActionRolledBack,
            "refused" => Self::AuthorizationRefused,
            _failed_or_unknown => Self::ActionFailed,
        }
    }

    pub fn described(self) -> String {
        match self {
            Self::ActionApplied => gettext("Applied"),
            Self::ActionRolledBack => gettext("Rolled back"),
            Self::AuthorizationRefused => gettext("Refused without a password"),
            Self::ActionFailed => gettext("Failed"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperAuditEntry {
    pub recorded_unix_seconds: u64,
    pub action_name: String,
    pub action_subject: String,
    pub audited_outcome: AuditedOutcome,
    pub requester_uid: String,
    pub weakens_protection: bool,
}

impl HelperAuditEntry {
    pub fn lowered_protection(&self) -> bool {
        self.weakens_protection && self.audited_outcome == AuditedOutcome::ActionApplied
    }
}

pub fn newest_helper_audit_entries(entry_limit: usize) -> systemd::Result<Vec<HelperAuditEntry>> {
    let mut journal = open_system_journal()?;
    journal.match_add(SYSTEMD_UNIT_FIELD, HELPER_SERVICE_UNIT)?;
    journal.match_and()?;
    journal.match_add(SENDER_USER_FIELD, ROOT_USER_ID)?;
    journal.seek_tail()?;
    let mut newest_entries = Vec::new();
    while newest_entries.len() < entry_limit && journal.previous()? > 0 {
        let action_name = journal_field_text(&mut journal, "LAZARET_ACTION")?;
        if action_name.is_empty() {
            continue;
        }
        newest_entries.push(HelperAuditEntry {
            recorded_unix_seconds: journal.timestamp_usec()? / MICROSECONDS_PER_SECOND,
            action_name: sanitize_scanner_line(&action_name),
            action_subject: sanitize_scanner_line(&journal_field_text(
                &mut journal,
                "LAZARET_SUBJECT",
            )?),
            audited_outcome: AuditedOutcome::from_field(&journal_field_text(
                &mut journal,
                "LAZARET_OUTCOME",
            )?),
            requester_uid: sanitize_scanner_line(&journal_field_text(
                &mut journal,
                "LAZARET_REQUESTER_UID",
            )?),
            weakens_protection: journal_field_text(&mut journal, "LAZARET_WEAKENS_PROTECTION")?
                == "yes",
        });
    }
    Ok(newest_entries)
}

#[cfg(test)]
mod helper_audit_records_tests {
    use super::*;

    #[test]
    fn only_applied_weakening_changes_lowered_protection() {
        let audit_entry = HelperAuditEntry {
            recorded_unix_seconds: 0,
            action_name: "trust-file".to_owned(),
            action_subject: String::new(),
            audited_outcome: AuditedOutcome::AuthorizationRefused,
            requester_uid: "1000".to_owned(),
            weakens_protection: true,
        };
        assert!(!audit_entry.lowered_protection());
        assert!(
            HelperAuditEntry {
                audited_outcome: AuditedOutcome::ActionApplied,
                ..audit_entry.clone()
            }
            .lowered_protection()
        );
    }

    #[test]
    #[ignore = "reads the real host journal"]
    fn host_audit_entries_are_readable() {
        println!(
            "{:#?}",
            newest_helper_audit_entries(10).expect("readable journal")
        );
    }
}
