use std::{io, os::unix::net::UnixDatagram};

const JOURNAL_SOCKET_PATH: &str = "/run/systemd/journal/socket";
const SYSLOG_IDENTIFIER: &str = "lazaret-settings-helper";
const NOTICE_PRIORITY: &str = "5";
const WARNING_PRIORITY: &str = "4";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    ActionApplied,
    ActionRolledBack,
    AuthorizationRefused,
    ActionFailed,
}

impl AuditOutcome {
    const fn field_value(self) -> &'static str {
        match self {
            Self::ActionApplied => "applied",
            Self::ActionRolledBack => "rolled-back",
            Self::AuthorizationRefused => "refused",
            Self::ActionFailed => "failed",
        }
    }

    const fn priority(self) -> &'static str {
        match self {
            Self::ActionApplied | Self::ActionRolledBack => NOTICE_PRIORITY,
            Self::AuthorizationRefused | Self::ActionFailed => WARNING_PRIORITY,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestingUser {
    KnownUser { user_id: u32 },
    UnknownUser,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperAuditRecord<'record> {
    pub action_name: &'record str,
    pub action_subject: &'record str,
    pub requesting_user: RequestingUser,
    pub audit_outcome: AuditOutcome,
    pub weakens_protection: bool,
}

fn journal_fields(audit_record: &HelperAuditRecord<'_>) -> Vec<(&'static str, String)> {
    let requester_text = match audit_record.requesting_user {
        RequestingUser::KnownUser { user_id } => user_id.to_string(),
        RequestingUser::UnknownUser => "unknown".to_owned(),
    };
    vec![
        (
            "MESSAGE",
            format!(
                "{}: {} (requested by uid {requester_text})",
                audit_record.audit_outcome.field_value(),
                audit_record.action_subject
            ),
        ),
        ("PRIORITY", audit_record.audit_outcome.priority().to_owned()),
        ("SYSLOG_IDENTIFIER", SYSLOG_IDENTIFIER.to_owned()),
        ("LAZARET_ACTION", audit_record.action_name.to_owned()),
        ("LAZARET_SUBJECT", audit_record.action_subject.to_owned()),
        (
            "LAZARET_OUTCOME",
            audit_record.audit_outcome.field_value().to_owned(),
        ),
        ("LAZARET_REQUESTER_UID", requester_text),
        (
            "LAZARET_WEAKENS_PROTECTION",
            if audit_record.weakens_protection {
                "yes"
            } else {
                "no"
            }
            .to_owned(),
        ),
    ]
}

pub fn encode_journal_fields(field_pairs: &[(&str, String)]) -> Vec<u8> {
    field_pairs
        .iter()
        .flat_map(|(field_name, field_value)| {
            field_name
                .bytes()
                .chain(*b"\n")
                .chain((field_value.len() as u64).to_le_bytes())
                .chain(field_value.bytes())
                .chain(*b"\n")
                .collect::<Vec<_>>()
        })
        .collect()
}

fn send_to_journal(encoded_fields: &[u8]) -> io::Result<()> {
    let journal_socket = UnixDatagram::unbound()?;
    journal_socket.send_to(encoded_fields, JOURNAL_SOCKET_PATH)?;
    Ok(())
}

pub fn record_helper_action(audit_record: &HelperAuditRecord<'_>) {
    let field_pairs = journal_fields(audit_record);
    if send_to_journal(&encode_journal_fields(&field_pairs)).is_err()
        && let Some((_message_name, message_text)) = field_pairs.first()
    {
        println!("{message_text}");
    }
}

#[cfg(test)]
mod helper_audit_journal_tests {
    use super::*;

    #[test]
    fn field_values_with_newlines_stay_inside_their_field() {
        let encoded_fields = encode_journal_fields(&[("MESSAGE", "first\nsecond".to_owned())]);
        let mut expected_fields = b"MESSAGE\n".to_vec();
        expected_fields.extend_from_slice(&12_u64.to_le_bytes());
        expected_fields.extend_from_slice(b"first\nsecond\n");
        assert_eq!(encoded_fields, expected_fields);
    }

    #[test]
    fn every_record_names_its_action_requester_and_outcome() {
        let recorded_fields = journal_fields(&HelperAuditRecord {
            action_name: "trust-file",
            action_subject: "trust the file with SHA-256 abc (68 bytes)",
            requesting_user: RequestingUser::KnownUser { user_id: 1000 },
            audit_outcome: AuditOutcome::ActionApplied,
            weakens_protection: true,
        });
        let field_value = |wanted_name: &str| {
            recorded_fields
                .iter()
                .find(|(field_name, _field_value)| *field_name == wanted_name)
                .map(|(_field_name, field_value)| field_value.clone())
        };
        assert_eq!(field_value("LAZARET_ACTION").as_deref(), Some("trust-file"));
        assert_eq!(
            field_value("LAZARET_REQUESTER_UID").as_deref(),
            Some("1000")
        );
        assert_eq!(field_value("LAZARET_OUTCOME").as_deref(), Some("applied"));
        assert_eq!(
            field_value("LAZARET_WEAKENS_PROTECTION").as_deref(),
            Some("yes")
        );
    }
}
