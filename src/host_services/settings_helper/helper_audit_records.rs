use std::io;

use gettextrs::gettext;
use jiff::Timestamp;
use systemd::journal::Journal;

use crate::host_services::{
    clamav_scanner::scanner_output_parser::sanitize_scanner_line,
    settings_helper::protection_change_rules::ProtectionReduction,
    systemd_journal::unit_journal_reader::{journal_field_value, open_system_journal},
};

const HELPER_SERVICE_UNIT: &str = "lazaret-settings-helper.service";
const SYSTEMD_UNIT_FIELD: &str = "_SYSTEMD_UNIT";
const SENDER_USER_FIELD: &str = "_UID";
const ROOT_USER_ID: &str = "0";
const TRUST_FILE_ACTION: &str = "trust-file";
const IGNORE_SIGNATURE_ACTION: &str = "ignore-signature";
const FORGET_TRUSTED_FILE_ACTION: &str = "forget-trusted-file";
const STOP_IGNORING_SIGNATURE_ACTION: &str = "stop-ignoring-signature";
const CHANGE_SETTINGS_ACTION: &str = "change-settings";
const OLD_TRUST_FILE_PREFIX: &str = "trust the file with SHA-256 ";
const OLD_IGNORE_SIGNATURE_PREFIX: &str = "ignore every detection named ";
const OLD_FORGET_FILE_PREFIX: &str = "stop trusting the file with SHA-256 ";
const OLD_STOP_IGNORING_PREFIX: &str = "report detections named ";
const OLD_STOP_IGNORING_SUFFIX: &str = " again";
const SHA256_HEX_LENGTH: usize = 64;
const RECORDED_PROTECTION_REDUCTIONS: [ProtectionReduction; 8] = [
    ProtectionReduction::BlockingTurnedOff,
    ProtectionReduction::CheckTurnedOff,
    ProtectionReduction::WatchedFolderRemoved,
    ProtectionReduction::SkippedLocationAdded,
    ProtectionReduction::ScanLimitLowered,
    ProtectionReduction::CurrentValuesUnknown,
    ProtectionReduction::DetectionTrusted,
    ProtectionReduction::NoReduction,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditedOutcome {
    ActionApplied,
    ActionRolledBack,
    AuthorizationRefused,
    ActionFailed,
    OutcomeNotRecorded,
    UnrecognizedOutcome { outcome_field: String },
}

impl AuditedOutcome {
    fn from_field(outcome_field: &JournalFieldPresence) -> Self {
        match outcome_field {
            JournalFieldPresence::FieldPresent { field_value } => match field_value.as_str() {
                "applied" => Self::ActionApplied,
                "rolled-back" => Self::ActionRolledBack,
                "refused" => Self::AuthorizationRefused,
                "failed" => Self::ActionFailed,
                unrecognized_value => Self::UnrecognizedOutcome {
                    outcome_field: unrecognized_value.to_owned(),
                },
            },
            JournalFieldPresence::FieldAbsent => Self::OutcomeNotRecorded,
        }
    }

    pub fn described(&self) -> String {
        match self {
            Self::ActionApplied => gettext("Applied"),
            Self::ActionRolledBack => gettext("Rolled back"),
            Self::AuthorizationRefused => gettext("Refused without a password"),
            Self::ActionFailed => gettext("Failed"),
            Self::OutcomeNotRecorded => gettext("Outcome not recorded"),
            Self::UnrecognizedOutcome { outcome_field } => {
                gettext("Unrecognized outcome {outcome}")
                    .replace("{outcome}", &sanitize_scanner_line(outcome_field))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditedAction {
    TrustFile { sha256_hex: String },
    IgnoreSignature { signature_name: String },
    ForgetTrustedFile { sha256_hex: String },
    StopIgnoringSignature { signature_name: String },
    ChangeSettings,
    UnrecognizedAction { action_name: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Requester {
    KnownUser { user_id: u32 },
    UnknownUser,
}

impl Requester {
    fn from_field(requester_field: &JournalFieldPresence) -> Self {
        match requester_field {
            JournalFieldPresence::FieldPresent { field_value } => field_value
                .parse::<u32>()
                .map_or(Self::UnknownUser, |user_id| Self::KnownUser { user_id }),
            JournalFieldPresence::FieldAbsent => Self::UnknownUser,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordedReduction {
    ReductionRecorded(ProtectionReduction),
    WeakeningWithoutKind,
    UnrecognizedReduction { field_value: String },
    ReductionNotRecorded,
}

impl RecordedReduction {
    const fn weakens_protection(&self) -> bool {
        match self {
            Self::ReductionRecorded(protection_reduction) => {
                protection_reduction.weakens_protection()
            }
            Self::WeakeningWithoutKind
            | Self::UnrecognizedReduction { .. }
            | Self::ReductionNotRecorded => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperAuditEntry {
    pub recorded_at: Timestamp,
    pub audited_action: AuditedAction,
    pub action_subject: String,
    pub audited_outcome: AuditedOutcome,
    pub requester: Requester,
    pub recorded_reduction: RecordedReduction,
}

impl HelperAuditEntry {
    pub const fn lowered_protection(&self) -> bool {
        self.recorded_reduction.weakens_protection()
            && matches!(self.audited_outcome, AuditedOutcome::ActionApplied)
    }
}

pub fn latest_applied_entry<'entries>(
    audit_entries: &'entries [HelperAuditEntry],
    wanted_action: &AuditedAction,
) -> Option<&'entries HelperAuditEntry> {
    audit_entries.iter().find(|audit_entry| {
        audit_entry.audited_outcome == AuditedOutcome::ActionApplied
            && audit_entry.audited_action == *wanted_action
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AuditJournalFields {
    action_name: String,
    action_subject: String,
    outcome_field: JournalFieldPresence,
    requester_field: JournalFieldPresence,
    reduction_field: JournalFieldPresence,
    legacy_weakening_field: JournalFieldPresence,
    sha256_field: JournalFieldPresence,
    signature_name_field: JournalFieldPresence,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
enum JournalFieldPresence {
    #[default]
    FieldAbsent,
    FieldPresent {
        field_value: String,
    },
}

fn exact_text_between<'text>(
    subject_text: &'text str,
    subject_prefix: &str,
    subject_suffix: &str,
) -> Option<&'text str> {
    subject_text
        .strip_prefix(subject_prefix)?
        .strip_suffix(subject_suffix)
        .filter(|target_text| !target_text.is_empty() && !target_text.contains(' '))
}

fn hash_in_old_trust_subject(action_subject: &str) -> Option<&str> {
    let hash_and_size = action_subject.strip_prefix(OLD_TRUST_FILE_PREFIX)?;
    let (sha256_hex, size_text) = hash_and_size.split_once(" (")?;
    size_text
        .strip_suffix(" bytes)")?
        .parse::<u64>()
        .ok()
        .map(|_file_size| sha256_hex)
        .filter(|sha256_hex| is_sha256_hex(sha256_hex))
}

fn is_sha256_hex(hash_text: &str) -> bool {
    hash_text.len() == SHA256_HEX_LENGTH
        && hash_text
            .bytes()
            .all(|hash_byte| hash_byte.is_ascii_hexdigit())
}

fn target_from_field_or_subject(
    target_field: &JournalFieldPresence,
    old_subject_target: Option<&str>,
) -> Option<String> {
    match target_field {
        JournalFieldPresence::FieldPresent { field_value } => {
            Some(sanitize_scanner_line(field_value))
        }
        JournalFieldPresence::FieldAbsent => old_subject_target.map(sanitize_scanner_line),
    }
}

fn audited_action_from_fields(journal_fields: &AuditJournalFields) -> AuditedAction {
    let action_subject = journal_fields.action_subject.as_str();
    let file_target = |old_subject_target: Option<&str>| {
        target_from_field_or_subject(&journal_fields.sha256_field, old_subject_target)
    };
    let signature_target = |old_subject_target: Option<&str>| {
        target_from_field_or_subject(&journal_fields.signature_name_field, old_subject_target)
    };
    let parsed_action = match journal_fields.action_name.as_str() {
        TRUST_FILE_ACTION => file_target(hash_in_old_trust_subject(action_subject))
            .map(|sha256_hex| AuditedAction::TrustFile { sha256_hex }),
        IGNORE_SIGNATURE_ACTION => signature_target(exact_text_between(
            action_subject,
            OLD_IGNORE_SIGNATURE_PREFIX,
            "",
        ))
        .map(|signature_name| AuditedAction::IgnoreSignature { signature_name }),
        FORGET_TRUSTED_FILE_ACTION => file_target(
            action_subject
                .strip_prefix(OLD_FORGET_FILE_PREFIX)
                .filter(|sha256_hex| is_sha256_hex(sha256_hex)),
        )
        .map(|sha256_hex| AuditedAction::ForgetTrustedFile { sha256_hex }),
        STOP_IGNORING_SIGNATURE_ACTION => signature_target(exact_text_between(
            action_subject,
            OLD_STOP_IGNORING_PREFIX,
            OLD_STOP_IGNORING_SUFFIX,
        ))
        .map(|signature_name| AuditedAction::StopIgnoringSignature { signature_name }),
        CHANGE_SETTINGS_ACTION => Some(AuditedAction::ChangeSettings),
        _unrecognized_action => None,
    };
    parsed_action.unwrap_or_else(|| AuditedAction::UnrecognizedAction {
        action_name: sanitize_scanner_line(&journal_fields.action_name),
    })
}

fn reduction_from_journal_field(field_value: &str) -> Option<ProtectionReduction> {
    RECORDED_PROTECTION_REDUCTIONS
        .into_iter()
        .find(|protection_reduction| protection_reduction.journal_field_value() == field_value)
}

fn recorded_reduction_from_fields(journal_fields: &AuditJournalFields) -> RecordedReduction {
    match (
        &journal_fields.reduction_field,
        &journal_fields.legacy_weakening_field,
    ) {
        (JournalFieldPresence::FieldPresent { field_value }, _legacy_field) => {
            reduction_from_journal_field(field_value).map_or_else(
                || RecordedReduction::UnrecognizedReduction {
                    field_value: sanitize_scanner_line(field_value),
                },
                RecordedReduction::ReductionRecorded,
            )
        }
        (JournalFieldPresence::FieldAbsent, JournalFieldPresence::FieldPresent { field_value }) => {
            match field_value.as_str() {
                "yes" => RecordedReduction::WeakeningWithoutKind,
                "no" => RecordedReduction::ReductionRecorded(ProtectionReduction::NoReduction),
                unrecognized_value => RecordedReduction::UnrecognizedReduction {
                    field_value: sanitize_scanner_line(unrecognized_value),
                },
            }
        }
        (JournalFieldPresence::FieldAbsent, JournalFieldPresence::FieldAbsent) => {
            RecordedReduction::ReductionNotRecorded
        }
    }
}

fn audit_entry_from_fields(
    recorded_at: Timestamp,
    journal_fields: &AuditJournalFields,
) -> HelperAuditEntry {
    HelperAuditEntry {
        recorded_at,
        audited_action: audited_action_from_fields(journal_fields),
        action_subject: sanitize_scanner_line(&journal_fields.action_subject),
        audited_outcome: AuditedOutcome::from_field(&journal_fields.outcome_field),
        requester: Requester::from_field(&journal_fields.requester_field),
        recorded_reduction: recorded_reduction_from_fields(journal_fields),
    }
}

fn journal_field_presence(
    journal: &mut Journal,
    field_name: &str,
) -> systemd::Result<JournalFieldPresence> {
    Ok(journal_field_value(journal, field_name)?
        .map_or(JournalFieldPresence::FieldAbsent, |field_value| {
            JournalFieldPresence::FieldPresent { field_value }
        }))
}

pub fn newest_helper_audit_entries(entry_limit: usize) -> systemd::Result<Vec<HelperAuditEntry>> {
    let mut journal = open_system_journal()?;
    journal.match_add(SYSTEMD_UNIT_FIELD, HELPER_SERVICE_UNIT)?;
    journal.match_and()?;
    journal.match_add(SENDER_USER_FIELD, ROOT_USER_ID)?;
    journal.seek_tail()?;
    let mut newest_entries = Vec::new();
    while newest_entries.len() < entry_limit && journal.previous()? > 0 {
        let Some(action_name) = journal_field_value(&mut journal, "LAZARET_ACTION")?
            .filter(|action_name| !action_name.is_empty())
        else {
            continue;
        };
        let journal_fields = AuditJournalFields {
            action_name,
            action_subject: journal_field_value(&mut journal, "LAZARET_SUBJECT")?
                .unwrap_or_default(),
            outcome_field: journal_field_presence(&mut journal, "LAZARET_OUTCOME")?,
            requester_field: journal_field_presence(&mut journal, "LAZARET_REQUESTER_UID")?,
            reduction_field: journal_field_presence(&mut journal, "LAZARET_PROTECTION_REDUCTION")?,
            legacy_weakening_field: journal_field_presence(
                &mut journal,
                "LAZARET_WEAKENS_PROTECTION",
            )?,
            sha256_field: journal_field_presence(&mut journal, "LAZARET_SHA256")?,
            signature_name_field: journal_field_presence(&mut journal, "LAZARET_SIGNATURE_NAME")?,
        };
        newest_entries.push(audit_entry_from_fields(
            Timestamp::try_from(journal.timestamp()?).map_err(io::Error::other)?,
            &journal_fields,
        ));
    }
    Ok(newest_entries)
}

#[cfg(test)]
mod helper_audit_records_tests {
    use super::*;

    fn present_field(field_value: &str) -> JournalFieldPresence {
        JournalFieldPresence::FieldPresent {
            field_value: field_value.to_owned(),
        }
    }

    fn applied_fields(action_name: &str, action_subject: &str) -> AuditJournalFields {
        AuditJournalFields {
            action_name: action_name.to_owned(),
            action_subject: action_subject.to_owned(),
            outcome_field: present_field("applied"),
            requester_field: present_field("1000"),
            ..AuditJournalFields::default()
        }
    }

    fn entry_of(journal_fields: &AuditJournalFields) -> HelperAuditEntry {
        audit_entry_from_fields(Timestamp::UNIX_EPOCH, journal_fields)
    }

    const TEST_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn a_missing_outcome_is_not_reported_as_a_failure() {
        let audit_entry = entry_of(&AuditJournalFields {
            outcome_field: JournalFieldPresence::FieldAbsent,
            requester_field: JournalFieldPresence::FieldAbsent,
            ..applied_fields("change-settings", "MaxThreads 2")
        });
        assert_eq!(
            audit_entry.audited_outcome,
            AuditedOutcome::OutcomeNotRecorded
        );
        assert_eq!(audit_entry.requester, Requester::UnknownUser);
        assert_eq!(
            audit_entry.audited_outcome.described(),
            "Outcome not recorded"
        );
    }

    #[test]
    fn every_reduction_survives_its_journal_field_value() {
        RECORDED_PROTECTION_REDUCTIONS
            .into_iter()
            .for_each(|protection_reduction| {
                assert_eq!(
                    reduction_from_journal_field(protection_reduction.journal_field_value()),
                    Some(protection_reduction)
                );
            });
        assert_eq!(reduction_from_journal_field("surprise"), None);
    }

    #[test]
    fn only_applied_weakening_changes_lowered_protection() {
        let audit_entry = entry_of(&AuditJournalFields {
            outcome_field: present_field("refused"),
            reduction_field: present_field("detection-trusted"),
            ..applied_fields("trust-file", "")
        });
        assert!(!audit_entry.lowered_protection());
        assert!(
            HelperAuditEntry {
                audited_outcome: AuditedOutcome::ActionApplied,
                ..audit_entry
            }
            .lowered_protection()
        );
    }

    #[test]
    fn the_recorded_reduction_kind_is_read_back() {
        let audit_entry = entry_of(&AuditJournalFields {
            reduction_field: present_field(
                ProtectionReduction::WatchedFolderRemoved.journal_field_value(),
            ),
            legacy_weakening_field: present_field("yes"),
            ..applied_fields("change-settings", "OnAccessIncludePath /home")
        });
        assert_eq!(
            audit_entry.recorded_reduction,
            RecordedReduction::ReductionRecorded(ProtectionReduction::WatchedFolderRemoved)
        );
        assert_eq!(audit_entry.audited_action, AuditedAction::ChangeSettings);
        assert!(audit_entry.lowered_protection());
    }

    #[test]
    fn an_unknown_reduction_value_still_counts_as_lowered() {
        let audit_entry = entry_of(&AuditJournalFields {
            reduction_field: present_field("future-reduction"),
            ..applied_fields("change-settings", "MaxThreads 2")
        });
        assert_eq!(
            audit_entry.recorded_reduction,
            RecordedReduction::UnrecognizedReduction {
                field_value: "future-reduction".to_owned()
            }
        );
        assert!(audit_entry.lowered_protection());
    }

    #[test]
    fn old_entries_map_their_yes_or_no_field_explicitly() {
        let old_weakening = entry_of(&AuditJournalFields {
            legacy_weakening_field: present_field("yes"),
            ..applied_fields("change-settings", "DetectPUA no")
        });
        assert_eq!(
            old_weakening.recorded_reduction,
            RecordedReduction::WeakeningWithoutKind
        );
        assert!(old_weakening.lowered_protection());
        let old_harmless = entry_of(&AuditJournalFields {
            legacy_weakening_field: present_field("no"),
            ..applied_fields("change-settings", "MaxThreads 2")
        });
        assert_eq!(
            old_harmless.recorded_reduction,
            RecordedReduction::ReductionRecorded(ProtectionReduction::NoReduction)
        );
        assert!(!old_harmless.lowered_protection());
    }

    #[test]
    fn an_unknown_requester_is_not_a_user_id() {
        let audit_entry = entry_of(&AuditJournalFields {
            requester_field: present_field("unknown"),
            ..applied_fields("change-settings", "MaxThreads 2")
        });
        assert_eq!(audit_entry.requester, Requester::UnknownUser);
        assert_eq!(
            entry_of(&applied_fields("change-settings", "MaxThreads 2")).requester,
            Requester::KnownUser { user_id: 1000 }
        );
    }

    #[test]
    fn signature_names_are_attributed_exactly() {
        let audit_entries = [
            entry_of(&AuditJournalFields {
                signature_name_field: present_field("Win.Test-1"),
                ..applied_fields(
                    "ignore-signature",
                    "ignore every detection named Win.Test-1",
                )
            }),
            entry_of(&applied_fields(
                "ignore-signature",
                "ignore every detection named Win.Test",
            )),
        ];
        let attributed_entry = |signature_name: &str| {
            latest_applied_entry(
                &audit_entries,
                &AuditedAction::IgnoreSignature {
                    signature_name: signature_name.to_owned(),
                },
            )
            .map(|audit_entry| audit_entry.action_subject.clone())
        };
        assert_eq!(
            attributed_entry("Win.Test").as_deref(),
            Some("ignore every detection named Win.Test")
        );
        assert_eq!(
            attributed_entry("Win.Test-1").as_deref(),
            Some("ignore every detection named Win.Test-1")
        );
        assert_eq!(attributed_entry("Win"), None);
    }

    #[test]
    fn old_entries_fall_back_to_the_exact_subject_format() {
        assert_eq!(
            entry_of(&applied_fields(
                "trust-file",
                &format!("trust the file with SHA-256 {TEST_HASH} (68 bytes)"),
            ))
            .audited_action,
            AuditedAction::TrustFile {
                sha256_hex: TEST_HASH.to_owned()
            }
        );
        assert_eq!(
            entry_of(&applied_fields(
                "forget-trusted-file",
                &format!("stop trusting the file with SHA-256 {TEST_HASH}"),
            ))
            .audited_action,
            AuditedAction::ForgetTrustedFile {
                sha256_hex: TEST_HASH.to_owned()
            }
        );
        assert_eq!(
            entry_of(&applied_fields(
                "stop-ignoring-signature",
                "report detections named Win.Test again",
            ))
            .audited_action,
            AuditedAction::StopIgnoringSignature {
                signature_name: "Win.Test".to_owned()
            }
        );
        assert_eq!(
            entry_of(&applied_fields("trust-file", "trust something else")).audited_action,
            AuditedAction::UnrecognizedAction {
                action_name: "trust-file".to_owned()
            }
        );
        assert_eq!(
            entry_of(&applied_fields("rename-everything", "")).audited_action,
            AuditedAction::UnrecognizedAction {
                action_name: "rename-everything".to_owned()
            }
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

    #[test]
    fn an_unknown_outcome_is_not_reported_as_a_failure() {
        let audit_entry = entry_of(&AuditJournalFields {
            outcome_field: JournalFieldPresence::FieldPresent {
                field_value: "postponed".to_owned(),
            },
            ..applied_fields("change-settings", "MaxThreads 2")
        });
        assert_eq!(
            audit_entry.audited_outcome,
            AuditedOutcome::UnrecognizedOutcome {
                outcome_field: "postponed".to_owned()
            }
        );
        assert_eq!(
            audit_entry.audited_outcome.described(),
            "Unrecognized outcome postponed"
        );
    }
}
