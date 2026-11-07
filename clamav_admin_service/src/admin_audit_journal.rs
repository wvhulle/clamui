use std::{io, os::unix::net::UnixDatagram};

use crate::{
    detection_trust_files::{TrustRequest, request_action_name},
    protection_change_rules::ProtectionReduction,
};

const JOURNAL_SOCKET_PATH: &str = "/run/systemd/journal/socket";
const SYSLOG_IDENTIFIER: &str = "lazaret-clamav-admin";
const NOTICE_PRIORITY: &str = "5";
const WARNING_PRIORITY: &str = "4";
const PROTECTION_REDUCTION_FIELD: &str = "LAZARET_PROTECTION_REDUCTION";
const SHA256_FIELD: &str = "LAZARET_SHA256";
const SIGNATURE_NAME_FIELD: &str = "LAZARET_SIGNATURE_NAME";

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

pub const SETTINGS_ACTION_NAME: &str = "change-settings";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditedAction<'record> {
    ChangeSettings,
    TrustChange(&'record TrustRequest),
}

impl AuditedAction<'_> {
    const fn action_name(self) -> &'static str {
        match self {
            Self::ChangeSettings => SETTINGS_ACTION_NAME,
            Self::TrustChange(trust_request) => request_action_name(trust_request),
        }
    }

    fn target_fields(self) -> Vec<JournalField> {
        match self {
            Self::ChangeSettings => Vec::new(),
            Self::TrustChange(
                TrustRequest::TrustFile { sha256_hex, .. }
                | TrustRequest::ForgetTrustedFile { sha256_hex },
            ) => vec![JournalField::new(SHA256_FIELD, sha256_hex.clone())],
            Self::TrustChange(
                TrustRequest::IgnoreSignature { signature_name }
                | TrustRequest::StopIgnoringSignature { signature_name },
            ) => vec![JournalField::new(
                SIGNATURE_NAME_FIELD,
                signature_name.clone(),
            )],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAuditRecord<'record> {
    pub audited_action: AuditedAction<'record>,
    pub action_subject: &'record str,
    pub requesting_user: RequestingUser,
    pub audit_outcome: AuditOutcome,
    pub protection_reduction: ProtectionReduction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalField {
    pub field_name: &'static str,
    pub field_value: String,
}

impl JournalField {
    pub const fn new(field_name: &'static str, field_value: String) -> Self {
        Self {
            field_name,
            field_value,
        }
    }
}

fn journal_fields(audit_record: &AdminAuditRecord<'_>) -> Vec<JournalField> {
    let requester_text = match audit_record.requesting_user {
        RequestingUser::KnownUser { user_id } => user_id.to_string(),
        RequestingUser::UnknownUser => "unknown".to_owned(),
    };
    [
        JournalField::new(
            "MESSAGE",
            format!(
                "{}: {} (requested by uid {requester_text})",
                audit_record.audit_outcome.field_value(),
                audit_record.action_subject
            ),
        ),
        JournalField::new("PRIORITY", audit_record.audit_outcome.priority().to_owned()),
        JournalField::new("SYSLOG_IDENTIFIER", SYSLOG_IDENTIFIER.to_owned()),
        JournalField::new(
            "LAZARET_ACTION",
            audit_record.audited_action.action_name().to_owned(),
        ),
        JournalField::new("LAZARET_SUBJECT", audit_record.action_subject.to_owned()),
        JournalField::new(
            "LAZARET_OUTCOME",
            audit_record.audit_outcome.field_value().to_owned(),
        ),
        JournalField::new("LAZARET_REQUESTER_UID", requester_text),
        JournalField::new(
            "LAZARET_WEAKENS_PROTECTION",
            if audit_record.protection_reduction.weakens_protection() {
                "yes"
            } else {
                "no"
            }
            .to_owned(),
        ),
        JournalField::new(
            PROTECTION_REDUCTION_FIELD,
            audit_record
                .protection_reduction
                .journal_field_value()
                .to_owned(),
        ),
    ]
    .into_iter()
    .chain(audit_record.audited_action.target_fields())
    .collect()
}

pub fn encode_journal_fields(journal_fields: &[JournalField]) -> Vec<u8> {
    journal_fields
        .iter()
        .flat_map(|journal_field| {
            journal_field
                .field_name
                .bytes()
                .chain(*b"\n")
                .chain((journal_field.field_value.len() as u64).to_le_bytes())
                .chain(journal_field.field_value.bytes())
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

pub fn record_admin_action(audit_record: &AdminAuditRecord<'_>) {
    let recorded_fields = journal_fields(audit_record);
    if send_to_journal(&encode_journal_fields(&recorded_fields)).is_err()
        && let Some(message_field) = recorded_fields.first()
    {
        println!("{}", message_field.field_value);
    }
}

#[cfg(test)]
mod admin_audit_journal_tests {
    use super::*;

    fn field_value(recorded_fields: &[JournalField], wanted_name: &str) -> Option<String> {
        recorded_fields
            .iter()
            .find(|journal_field| journal_field.field_name == wanted_name)
            .map(|journal_field| journal_field.field_value.clone())
    }

    #[test]
    fn field_values_with_newlines_stay_inside_their_field() {
        let encoded_fields =
            encode_journal_fields(&[JournalField::new("MESSAGE", "first\nsecond".to_owned())]);
        let mut expected_fields = b"MESSAGE\n".to_vec();
        expected_fields.extend_from_slice(&12_u64.to_le_bytes());
        expected_fields.extend_from_slice(b"first\nsecond\n");
        assert_eq!(encoded_fields, expected_fields);
    }

    #[test]
    fn every_record_names_its_action_requester_and_outcome() {
        let trust_request = TrustRequest::TrustFile {
            sha256_hex: "abc".to_owned(),
            file_size: 68,
        };
        let recorded_fields = journal_fields(&AdminAuditRecord {
            audited_action: AuditedAction::TrustChange(&trust_request),
            action_subject: "trust the file with SHA-256 abc (68 bytes)",
            requesting_user: RequestingUser::KnownUser { user_id: 1000 },
            audit_outcome: AuditOutcome::ActionApplied,
            protection_reduction: ProtectionReduction::DetectionTrusted,
        });
        assert_eq!(
            field_value(&recorded_fields, "LAZARET_ACTION").as_deref(),
            Some("trust-file")
        );
        assert_eq!(
            field_value(&recorded_fields, "LAZARET_REQUESTER_UID").as_deref(),
            Some("1000")
        );
        assert_eq!(
            field_value(&recorded_fields, "LAZARET_OUTCOME").as_deref(),
            Some("applied")
        );
        assert_eq!(
            field_value(&recorded_fields, "LAZARET_WEAKENS_PROTECTION").as_deref(),
            Some("yes")
        );
        assert_eq!(
            field_value(&recorded_fields, SHA256_FIELD).as_deref(),
            Some("abc")
        );
        assert_eq!(field_value(&recorded_fields, SIGNATURE_NAME_FIELD), None);
    }

    #[test]
    fn the_reduction_kind_is_recorded_and_reads_back() {
        let recorded_fields = journal_fields(&AdminAuditRecord {
            audited_action: AuditedAction::ChangeSettings,
            action_subject: "OnAccessPrevention no",
            requesting_user: RequestingUser::UnknownUser,
            audit_outcome: AuditOutcome::ActionApplied,
            protection_reduction: ProtectionReduction::BlockingTurnedOff,
        });
        assert_eq!(
            field_value(&recorded_fields, PROTECTION_REDUCTION_FIELD).as_deref(),
            Some(ProtectionReduction::BlockingTurnedOff.journal_field_value())
        );
        assert_eq!(
            field_value(&recorded_fields, "LAZARET_REQUESTER_UID").as_deref(),
            Some("unknown")
        );
        assert_eq!(field_value(&recorded_fields, SHA256_FIELD), None);
    }

    #[test]
    fn signature_requests_record_the_exact_signature_name() {
        let trust_request = TrustRequest::IgnoreSignature {
            signature_name: "Win.Test-1".to_owned(),
        };
        let recorded_fields = journal_fields(&AdminAuditRecord {
            audited_action: AuditedAction::TrustChange(&trust_request),
            action_subject: "ignore every detection named Win.Test-1",
            requesting_user: RequestingUser::KnownUser { user_id: 1000 },
            audit_outcome: AuditOutcome::ActionApplied,
            protection_reduction: ProtectionReduction::DetectionTrusted,
        });
        assert_eq!(
            field_value(&recorded_fields, SIGNATURE_NAME_FIELD).as_deref(),
            Some("Win.Test-1")
        );
    }
}
